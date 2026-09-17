"""What the syntactic tier can and cannot decide, per class.

§4.2's analysis-depth column was written by reasoning when the nine classes were
defined: no code existed, nothing was tested, and each "no" asserted that
something could not be done without a compiled backend. One of them collapsed on
an hour's inspection, which makes the rest claims about whoever wrote the table
until checked -- §1.3's rule pointed at the document that had been steering the
build.

These are that check, as tests rather than as a note, because an audit with no
test behind it decays into a claim about what somebody once measured. Each class
gets the concrete question it needs answered, a defect fixture and a sound one,
and the outcome is three-valued rather than two:

*   **collapses** -- the fact is in the syntax tree, and no tier is needed.
*   **needs a tier** -- the fact is derivable from the unit but not from its
    syntax alone.
*   **never closes** -- the fact is about another contract's bytes, so no
    analysis over this unit reaches it. An indeterminacy (§3.1), not a tier gap,
    and building a tier for it produces nothing.

Fixtures are hand-written and minimal: they reproduce shapes, not corpus source.
"""

from __future__ import annotations

import pytest
from tree_sitter import Node

from contract_assay.evidence.syntax import Syntax

pytestmark = pytest.mark.offline


def parsed(source: str) -> Syntax:
    syntax = Syntax.of(source)
    assert syntax is not None
    return syntax


def find(node: Node, *types: str) -> list[Node]:
    found: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in types:
            found.append(current)
        stack.extend(current.children)
    return found


def in_function(syntax: Syntax, name: str, *types: str) -> list[Node]:
    function = next(f for f in syntax.functions if f.declaration.names[0] == name)
    lines = range(function.site.start_line, function.site.end_line + 1)
    root = syntax._tree.root_node
    return [n for n in find(root, *types) if n.start_point[0] + 1 in lines]


class TestDenialOfServiceCollapses:
    """'A loop bounded by a storage array an outsider can grow.'

    Every part is in the tree: the declared type distinguishes a dynamic array
    from a fixed one and from a mapping, the loop names the array it bounds on,
    and the function that appends to it has a visibility. §4.2 said no.
    """

    SOURCE = """contract D {
    address[] public voters;
    address[3] public admins;
    mapping(address => uint256) balances;

    function payAll() external {
        for (uint256 i = 0; i < voters.length; i++) { payable(voters[i]).transfer(1); }
    }
    function payFixed() external {
        for (uint256 i = 0; i < admins.length; i++) { payable(admins[i]).transfer(1); }
    }
    function join() external { voters.push(msg.sender); }
}
"""

    def _declared_types(self) -> dict[str, str]:
        syntax = parsed(self.SOURCE)
        root = syntax._tree.root_node
        out: dict[str, str] = {}
        for declaration in find(root, "state_variable_declaration"):
            name = next(
                (syntax.text(i) for i in declaration.children if i.type == "identifier"), None
            )
            type_name = next(
                (syntax.text(t) for t in declaration.children if t.type == "type_name"), None
            )
            if name and type_name:
                out[name] = type_name
        return out

    def test_a_dynamic_array_is_distinguishable_from_a_fixed_one(self) -> None:
        types = self._declared_types()
        assert types["voters"].endswith("[]")
        assert not types["admins"].endswith("[]")
        assert types["balances"].startswith("mapping")

    def test_a_loop_names_the_array_it_bounds_on(self) -> None:
        syntax = parsed(self.SOURCE)
        for function, array in (("payAll", "voters"), ("payFixed", "admins")):
            [loop] = in_function(syntax, function, "for_statement")
            names = {syntax.text(i) for i in find(loop, "identifier")}
            assert {array, "length"} <= names

    def test_an_outsider_appending_to_it_is_visible(self) -> None:
        syntax = parsed(self.SOURCE)
        [push] = [c for c in syntax.calls if c.callee == "push"]
        host = syntax.host_at(push.site.start_line)
        appender = next(f for f in syntax.functions if f.declaration.names[0] == host.function)
        assert push.receiver == "voters"
        assert appender.is_externally_reachable


class TestOracleStalenessCollapses:
    """'A price used without checking the staleness it came with.'

    The tree gives the names a multi-return was destructured into, with their
    types, and the guards of the enclosing function with the identifiers each
    mentions. A timestamp bound and never mentioned in a guard is the defect,
    and it needs no knowledge of which interface was called -- naming the
    property rather than the oracle is what avoids the ABI (§2.3). §4.2 said no.
    """

    SOURCE = """contract O {
    function bad(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        last = price;
    }
    function good(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        last = price;
    }
    function singleReturn(address feed) external {
        last = IFeed(feed).latestAnswer();
    }
}
"""

    def _unguarded_bindings(self, function: str) -> list[str]:
        syntax = parsed(self.SOURCE)
        bound: list[str] = []
        for group in in_function(syntax, function, "variable_declaration_tuple"):
            for declaration in (c for c in group.children if c.type == "variable_declaration"):
                name = next(
                    (syntax.text(i) for i in declaration.children if i.type == "identifier"), None
                )
                if name:
                    bound.append(name)
        site = next(f for f in syntax.functions if f.declaration.names[0] == function).site
        mentioned = {
            identifier
            for guard in syntax.guards
            if site.start_line <= guard.site.start_line <= site.end_line
            for identifier in guard.identifiers
        }
        return [name for name in bound if name not in mentioned]

    def test_an_unchecked_timestamp_is_visible(self) -> None:
        assert self._unguarded_bindings("bad") == ["price", "updatedAt"]

    def test_a_checked_timestamp_is_visible_as_checked(self) -> None:
        # `price` remains unguarded and should: it is the value being used, not
        # the freshness claim about it.
        assert self._unguarded_bindings("good") == ["price"]

    def test_a_single_return_feed_destructures_nothing(self) -> None:
        # The older shape carries no timestamp at all, so there is nothing to
        # check rather than a check that is missing. A different situation, and
        # one this property must not silently report as sound.
        assert self._unguarded_bindings("singleReturn") == []


class TestArithmeticSplits:
    """Half of it collapses and half of it never closes.

    Division before multiplication is the shape of one expression, and declared
    integer widths are declarations -- both syntactic. A token's `decimals()` is
    a fact about another deployed contract, and no analysis over this unit
    reaches it. §4.2 said "types, decimals, evaluation order" and "no", merging
    three things with three different answers.
    """

    SOURCE = """contract A {
    uint8 small;
    uint256 big;
    function bad(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return a / b * c;
    }
    function good(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return a * c / b;
    }
    function decimalsDependent(address token, uint256 amount) external returns (uint256) {
        return amount * 10 ** IERC20(token).decimals();
    }
}
"""

    def _divides_before_multiplying(self, function: str) -> bool:
        syntax = parsed(self.SOURCE)
        for expression in in_function(syntax, function, "binary_expression"):
            operators = {c.type for c in expression.children}
            if "*" not in operators:
                continue
            left = next((c for c in expression.children if c.type == "expression"), None)
            if left is None:
                continue
            if any(
                "/" in {c.type for c in inner.children} for inner in find(left, "binary_expression")
            ):
                return True
        return False

    def test_evaluation_order_collapses(self) -> None:
        assert self._divides_before_multiplying("bad")
        assert not self._divides_before_multiplying("good")

    def test_declared_widths_collapse(self) -> None:
        syntax = parsed(self.SOURCE)
        root = syntax._tree.root_node
        widths = {
            syntax.text(t)
            for declaration in find(root, "state_variable_declaration")
            for t in declaration.children
            if t.type == "type_name"
        }
        assert {"uint8", "uint256"} <= widths

    def test_a_tokens_decimals_never_closes(self) -> None:
        # Visible as a call, and its *value* is in another contract's storage.
        # No tier over this unit reads it, so this is an indeterminacy rather
        # than a tier gap (§3.1).
        syntax = parsed(self.SOURCE)
        assert [c.callee for c in syntax.calls if c.callee == "decimals"] == ["decimals"]


class TestFlashloanNeverCloses:
    """The unit shows the callback and the calls, and not the thing that matters.

    Whether a callee is a spot market the caller can move is a fact about
    another deployed contract. §4.2 called this interprocedural reachability,
    which reads as a tier gap; it is an indeterminacy, and a tier built for it
    would produce nothing.
    """

    SOURCE = """contract F {
    function executeOperation(address asset, uint256 amount) external returns (bool) {
        uint256 price = pair.getReserves();
        vault.deposit(price);
        return true;
    }
}
"""

    def test_the_callback_and_its_calls_are_visible(self) -> None:
        syntax = parsed(self.SOURCE)
        [function] = syntax.functions
        assert function.is_externally_reachable
        assert {c.callee for c in syntax.calls} == {"getReserves", "deposit"}

    def test_but_nothing_says_the_callee_is_manipulable(self) -> None:
        # The receiver is an identifier. What it is bound to at deployment, and
        # whether a caller can move its reserves, is not in this unit at any
        # tier -- which is the whole finding.
        syntax = parsed(self.SOURCE)
        [reserves] = [c for c in syntax.calls if c.callee == "getReserves"]
        assert reserves.receiver == "pair"
        assert "pair" not in syntax.state_variables
