"""Shape-level queries over a parsed source unit.

The declaration index answers one question: what does this file declare, and
where. Predicates need more than that -- where the calls are, what is passed to
them, what is written, which functions are reachable from outside and what
guards them -- and this module answers those.

Everything here is syntactic. There are no types, no data flow and no call
graph, so a query can say "this argument is the literal zero" but never "this
argument is always zero at run time". Keeping the distinction visible is the
point: the tier travels with every piece of evidence, and a fact established
here is a weaker fact than the same one established from compiled output.

Shapes, not names
-----------------
An identifier is chosen by whoever wrote the contract and can be changed without
changing behaviour, so a query keyed on one measures naming habits rather than
code. The queries below are therefore keyed on node shape and on *language*
tokens -- `call`, `delegatecall`, `block.timestamp`, `external` -- which no
author can rename because they are not theirs to rename.

Where a user identifier is unavoidable, it is carried as a separate field and
labelled as such, so that a caller can correlate on it without being tempted to
report it. Solidity is case-sensitive throughout: nothing here case-folds an
identifier, because `owner` and `Owner` are different symbols and folding them
manufactures matches the compiler would never make.

Every site carries its host
---------------------------
A site without an enclosing contract and function is nearly useless downstream:
scoring is at function granularity, so evidence that knows only a line number
cannot be compared against anything. Host resolution reuses the declaration
index rather than re-deriving scope -- the innermost callable whose span
contains a node is its host, which is unambiguous because Solidity has no
nested functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

from contract_assay.evidence.solidity import (
    Declaration,
    DeclarationIndex,
    index_source,
    parse_bytes,
)
from contract_assay.models import Locator

if TYPE_CHECKING:
    from tree_sitter import Node

__all__ = [
    "CHAIN_STATE_MEMBERS",
    "LOW_LEVEL_CALL_MEMBERS",
    "VALUE_TRANSFER_MEMBERS",
    "Argument",
    "CallSite",
    "FunctionSite",
    "Host",
    "Site",
    "Syntax",
    "WriteSite",
    "WriteTarget",
]


LOW_LEVEL_CALL_MEMBERS = frozenset({"call", "delegatecall", "staticcall", "callcode"})
"""Members whose result is a success flag the caller must inspect.

Language members, not identifiers: a contract cannot rename `delegatecall`, so
matching on these is renaming-invariant in a way that matching on a helper's
name never is.
"""

VALUE_TRANSFER_MEMBERS = frozenset({"send", "transfer"})
"""Value-moving members. `send` returns a flag; `transfer` reverts instead."""

CHAIN_STATE_MEMBERS: dict[str, frozenset[str]] = {
    "block": frozenset(
        {"timestamp", "number", "difficulty", "prevrandao", "coinbase", "gaslimit", "basefee"}
    ),
    "tx": frozenset({"gasprice", "origin"}),
}
"""Chain state readable from a contract and influenced by whoever orders the block.

Grouped by receiver so that a query matches `block.timestamp` as a shape rather
than searching for the word `timestamp`, which a local variable may also carry.
"""

_NUMBER_UNITS = frozenset(
    {
        "wei",
        "gwei",
        "szabo",
        "finney",
        "ether",
        "seconds",
        "minutes",
        "hours",
        "days",
        "weeks",
        "years",
    }
)
"""Denomination suffixes a numeric literal may carry.

They have to be stripped before a literal can be compared to zero. `0 ether` is
zero, and a check that only understood bare digits would read it as not-a-number
and report the same coverage while missing the case.
"""

_BARE_STATEMENT = "expression_statement"

# The grammar wraps most expressions in an `expression` node, so an ancestor walk
# has to step over them to find the statement an expression belongs to.
_TRANSPARENT = frozenset({"expression"})


@dataclass(frozen=True, slots=True)
class Host:
    """The contract and function a site sits inside.

    `function_signature` is the declared form, which is what distinguishes one
    overload from another. `function` alone does not: Solidity permits
    overloading, so two different functions can share a name.
    """

    contract: str | None
    function: str | None
    function_signature: str | None


@dataclass(frozen=True, slots=True)
class Site:
    """One node of interest, with where it is."""

    node_type: str
    text: str
    start_line: int
    end_line: int
    host: Host

    def locator(self, file: str) -> Locator:
        """A `Locator` for this site, naming its host contract and function."""
        return Locator(
            file=file,
            contract=self.host.contract,
            function=self.host.function,
            start_line=self.start_line,
            end_line=self.end_line,
        )


@dataclass(frozen=True, slots=True)
class Argument:
    """One positional call argument, described by shape."""

    position: int
    text: str
    node_type: str

    @property
    def is_number_literal(self) -> bool:
        return self.node_type == "number_literal"

    @property
    def is_zero_literal(self) -> bool:
        """True for a literal zero in any of the spellings the compiler accepts.

        `0`, `0x0`, `0x0000...` and `0 ether` are the same value written four
        ways, and a check that recognised only the first would miss the rest
        while reporting the same coverage.
        """
        if not self.is_number_literal:
            return False
        text = self.text.replace("_", "").strip().lower()
        parts = text.split()
        if len(parts) == 2 and parts[1] in _NUMBER_UNITS:
            text = parts[0]
        elif len(parts) != 1:
            return False
        if text.startswith(("0x", "0b", "0o")):
            body = text[2:]
            return bool(body) and set(body) == {"0"}
        try:
            return float(text) == 0.0
        except ValueError:  # pragma: no cover - no current grammar path reaches it
            # Unreachable with the pinned grammar: anything it labels a
            # `number_literal` parses, and malformed text such as `1e` is
            # labelled an identifier instead. Kept because the alternative to a
            # guard here is a crash inside a predicate.
            return False

    @property
    def is_identifier(self) -> bool:
        return self.node_type == "identifier"


@dataclass(frozen=True, slots=True)
class CallSite:
    """One call, described by what is being called and how."""

    site: Site
    callee: str
    """The member name, or the plain function name for an unqualified call."""

    receiver: str | None
    """Text of the part before the dot, or None for an unqualified call.

    A user identifier in most cases, so it is here to be correlated on, not to
    be reported.
    """

    arguments: tuple[Argument, ...]
    is_bare_statement: bool
    """True when the call is an entire statement, so its result is discarded."""

    has_call_options: bool
    """True when the call carries `{value: ...}` or `{gas: ...}` options."""

    bound_names: tuple[str, ...]
    """Names the call's result is bound to. Empty when the result is discarded.

    User identifiers, so they are for correlating inside a function -- asking
    whether a bound result is ever read again -- and not for reporting.
    """

    @property
    def is_low_level(self) -> bool:
        return self.callee in LOW_LEVEL_CALL_MEMBERS

    @property
    def is_value_transfer(self) -> bool:
        return self.callee in VALUE_TRANSFER_MEMBERS

    def argument(self, position: int) -> Argument | None:
        return next((a for a in self.arguments if a.position == position), None)


class WriteTarget:
    """What an assignment writes to, as a shape rather than a name."""

    STATE_VARIABLE = "state_variable"
    STATE_COLLECTION_ELEMENT = "state_collection_element"
    STATE_MEMBER = "state_member"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class WriteSite:
    """One assignment, and what kind of thing it writes to."""

    site: Site
    target: str
    """A `WriteTarget` constant."""

    target_root: str
    """Base identifier written through. A user identifier: correlate, do not report."""

    operator: str
    """The assignment operator as written, e.g. `=` or `-=`. A language token."""

    @property
    def writes_state(self) -> bool:
        return self.target in (
            WriteTarget.STATE_VARIABLE,
            WriteTarget.STATE_COLLECTION_ELEMENT,
            WriteTarget.STATE_MEMBER,
        )


@dataclass(frozen=True, slots=True)
class FunctionSite:
    """One function-like declaration, with what the language says about its reach."""

    site: Site
    declaration: Declaration
    visibility: str | None
    """`external`, `public`, `internal`, `private`, or None when not written.

    None is not the same as private. Before Solidity 0.5 an omitted visibility
    defaulted to public, and corpus sources are pinned at historical commits, so
    reading the absence as restrictive would silently exempt the most exposed
    functions in exactly the oldest code.
    """

    state_mutability: str | None
    modifiers: tuple[str, ...]
    """Modifier invocations as written. User identifiers: correlate, do not report."""

    @property
    def is_externally_reachable(self) -> bool:
        """True when the language permits an outside caller, absent visibility included."""
        return self.visibility in (None, "external", "public")

    @property
    def is_read_only(self) -> bool:
        return self.state_mutability in ("view", "pure", "constant")


class Syntax:
    """A parsed source unit, queryable by shape.

    Construct with `Syntax.of(source)`. Queries are computed once and cached,
    because a detector runs several predicates over the same unit and each one
    would otherwise re-walk the whole tree.
    """

    def __init__(self, source: str) -> None:
        self._data = source.encode("utf-8")
        self._tree = parse_bytes(self._data)
        self.index: DeclarationIndex = index_source(source)

    @classmethod
    def of(cls, source: str) -> Syntax | None:
        """Parse `source`, or return None if nothing could be read from it.

        None means "this unit is not analysable", which is the gate's business.
        It is deliberately different from an empty query result, which means the
        unit was read and the shape is not present.
        """
        syntax = cls(source)
        return syntax if syntax.index.parsed else None

    # -- primitives -------------------------------------------------------

    def text(self, node: Node) -> str:
        return self._data[node.start_byte : node.end_byte].decode("utf-8", "replace")

    def _nodes(self, *types: str) -> list[Node]:
        wanted = frozenset(types)
        found: list[Node] = []
        stack: list[Node] = [self._tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in wanted:
                found.append(node)
            stack.extend(reversed(node.children))
        found.sort(key=lambda n: (n.start_point[0], n.start_byte))
        return found

    def _site(self, node: Node) -> Site:
        return Site(
            node_type=str(node.type),
            text=self.text(node),
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            host=self.host_at(node.start_point[0] + 1),
        )

    def host_at(self, line: int) -> Host:
        """The innermost contract and callable whose span contains `line`."""
        return self._hosts.get(line, Host(None, None, None))

    @cached_property
    def _hosts(self) -> dict[int, Host]:
        """Host per line, precomputed.

        A dict rather than a scan per node: several predicates each resolve a
        host for every site they find, and repeating a linear scan over all
        declarations for each one is the shape of an accidental quadratic.
        """
        spans = {
            line: Host(None, None, None)
            for decl in self.index.declarations
            for line in range(decl.start_line, decl.end_line + 1)
        }
        # Widest first, so an inner declaration overwrites an outer one.
        for decl in sorted(
            self.index.declarations, key=lambda d: d.end_line - d.start_line, reverse=True
        ):
            for line in range(decl.start_line, decl.end_line + 1):
                current = spans[line]
                if decl.kind.is_type:
                    spans[line] = Host(decl.names[0], current.function, current.function_signature)
                else:
                    spans[line] = Host(
                        decl.parent or current.contract, decl.names[0], decl.signature
                    )
        return spans

    def _statement_of(self, node: Node) -> Node | None:
        """The nearest ancestor that is a statement, stepping over `expression` wrappers."""
        parent = node.parent
        while parent is not None and parent.type in _TRANSPARENT:
            parent = parent.parent
        return parent

    # -- queries ----------------------------------------------------------

    @cached_property
    def state_variables(self) -> frozenset[str]:
        """Names declared at contract scope.

        Used to tell a state write from a local one. A name, so it stays inside
        this module's classification and does not travel outward.
        """
        names: set[str] = set()
        for node in self._nodes("state_variable_declaration"):
            name = node.child_by_field_name("name")
            if name is not None:
                names.add(self.text(name))
        return frozenset(names)

    @cached_property
    def calls(self) -> tuple[CallSite, ...]:
        """Every call in the unit, outermost member first."""
        found: list[CallSite] = []
        for node in self._nodes("call_expression"):
            function = node.child_by_field_name("function")
            if function is None:
                continue
            callee, receiver = self._split_callee(function)
            if callee is None:
                continue
            arguments = tuple(
                Argument(
                    position=position,
                    text=self.text(child),
                    node_type=self._expression_type(child),
                )
                for position, child in enumerate(
                    c for c in node.children if c.type == "call_argument"
                )
            )
            statement = self._statement_of(node)
            found.append(
                CallSite(
                    site=self._site(node),
                    callee=callee,
                    receiver=receiver,
                    arguments=arguments,
                    bound_names=self._bound_names(statement),
                    is_bare_statement=statement is not None and statement.type == _BARE_STATEMENT,
                    has_call_options=any(c.type == "struct_expression" for c in function.children)
                    or "{" in self.text(function),
                )
            )
        return tuple(found)

    def _expression_type(self, node: Node) -> str:
        """Node type of an argument, looking through `expression` wrappers."""
        current = node
        while current.type in _TRANSPARENT or current.type == "call_argument":
            children = [c for c in current.children if c.is_named]
            if len(children) != 1:
                break
            current = children[0]
        return str(current.type)

    def _split_callee(self, function: Node) -> tuple[str | None, str | None]:
        """Split a call's function expression into member name and receiver text.

        The outermost member is the one being called: in `a.b().c()` the callee
        is `c`, and taking the innermost would report `b`.
        """
        current = function
        while current.type in _TRANSPARENT:
            named = [c for c in current.children if c.is_named]
            if len(named) != 1:
                break
            current = named[0]

        if current.type == "member_expression":
            prop = current.child_by_field_name("property")
            obj = current.child_by_field_name("object")
            if prop is not None:
                return self.text(prop), (self.text(obj) if obj is not None else None)
            return None, None
        if current.type == "identifier":
            return self.text(current), None
        # A call through something with no name of its own -- a cast, an index, a
        # call option wrapper. Find the outermost member inside it, if any.
        stack: list[Node] = [current]
        while stack:
            node = stack.pop(0)
            if node.type == "member_expression":
                prop = node.child_by_field_name("property")
                obj = node.child_by_field_name("object")
                if prop is not None:
                    return self.text(prop), (self.text(obj) if obj is not None else None)
            stack.extend(node.children)
        return None, None

    @cached_property
    def member_reads(self) -> tuple[tuple[Site, str, str], ...]:
        """Every `object.property` access, as (site, receiver text, property name)."""
        found: list[tuple[Site, str, str]] = []
        for node in self._nodes("member_expression"):
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj is None or prop is None:
                continue
            found.append((self._site(node), self.text(obj), self.text(prop)))
        return tuple(found)

    @cached_property
    def writes(self) -> tuple[WriteSite, ...]:
        """Every assignment, classified by what it writes to."""
        found: list[WriteSite] = []
        for node in self._nodes("assignment_expression", "augmented_assignment_expression"):
            left = node.child_by_field_name("left")
            if left is None:
                continue
            operator = next(
                (self.text(c) for c in node.children if not c.is_named and self.text(c).strip()),
                "=",
            )
            site = self._site(node)
            for target_node in self._assignment_targets(left):
                kind, root = self._classify_target(target_node)
                found.append(
                    WriteSite(
                        site=site,
                        target=kind,
                        target_root=root,
                        operator=operator.strip(),
                    )
                )
        return tuple(found)

    def _assignment_targets(self, left: Node) -> list[Node]:
        """Every target an assignment writes to, not just the first.

        `(a, b) = (1, 2)` writes twice. Descending to the leftmost identifier
        would report only `a`, so a tuple assignment in which the second element
        is the state variable would drop that write entirely -- an omission that
        looks like an absence of evidence rather than a failure to look.
        """
        current = left
        while current.type in _TRANSPARENT:
            named = [c for c in current.children if c.is_named]
            if len(named) != 1:
                break
            current = named[0]
        if current.type == "tuple_expression":
            return [c for c in current.children if c.is_named]
        return [current]

    def _classify_target(self, left: Node) -> tuple[str, str]:
        current = left
        while current.type in _TRANSPARENT:
            named = [c for c in current.children if c.is_named]
            if len(named) != 1:
                break
            current = named[0]

        shape = str(current.type)
        root = self._leftmost_identifier(current)
        if root is None:
            return WriteTarget.UNKNOWN, ""
        is_state = root in self.state_variables
        if not is_state:
            return WriteTarget.LOCAL, root
        if shape == "array_access":
            return WriteTarget.STATE_COLLECTION_ELEMENT, root
        if shape == "member_expression":
            return WriteTarget.STATE_MEMBER, root
        return WriteTarget.STATE_VARIABLE, root

    def _leftmost_identifier(self, node: Node) -> str | None:
        current = node
        while current.type != "identifier":
            named = [c for c in current.children if c.is_named]
            if not named:
                return None
            current = named[0]
        return self.text(current)

    @cached_property
    def functions(self) -> tuple[FunctionSite, ...]:
        """Every function-like declaration, with visibility, mutability and modifiers."""
        by_line = {d.start_line: d for d in self.index.declarations if not d.kind.is_type}
        found: list[FunctionSite] = []
        for node in self._nodes(
            "function_definition",
            "constructor_definition",
            "modifier_definition",
            "fallback_receive_definition",
        ):
            declaration = by_line.get(node.start_point[0] + 1)
            if declaration is None:
                continue
            found.append(
                FunctionSite(
                    site=self._site(node),
                    declaration=declaration,
                    visibility=next(
                        (self.text(c) for c in node.children if c.type == "visibility"), None
                    ),
                    state_mutability=next(
                        (self.text(c) for c in node.children if c.type == "state_mutability"),
                        None,
                    ),
                    modifiers=tuple(
                        self.text(c) for c in node.children if c.type == "modifier_invocation"
                    ),
                )
            )
        return tuple(found)

    def within(self, declaration: Declaration, sites: tuple[Site, ...]) -> list[Site]:
        """Sites whose line falls inside a declaration's span."""
        return [s for s in sites if declaration.start_line <= s.start_line <= declaration.end_line]

    def identifier_uses(self, declaration: Declaration, name: str) -> int:
        """How many times `name` appears as an identifier inside a declaration.

        Counted for shallow reachability questions -- "is this bound result ever
        read again" -- which is as far as a syntactic tier can go. It cannot tell
        a read from a shadowed rebinding, so a caller should treat a count of one
        as evidence and a higher count as absence of it.
        """
        total = 0
        for node in self._nodes("identifier"):
            line = node.start_point[0] + 1
            if declaration.start_line <= line <= declaration.end_line and self.text(node) == name:
                total += 1
        return total

    def _bound_names(self, statement: Node | None) -> tuple[str, ...]:
        """Names the statement binds, read from the tree rather than from text.

        Destructuring is what makes the text approach wrong rather than merely
        ugly: `(, uint256 price, , , )` has four omitted slots, and splitting on
        commas cannot tell an omitted binding from a present one. The grammar
        already distinguishes them -- only a filled slot produces a
        `variable_declaration` node.

        The `value` subtree is excluded, or a call on the right-hand side would
        contribute any names declared inside it.
        """
        if statement is None:
            return ()
        if statement.type == "variable_declaration_statement":
            value = statement.child_by_field_name("value")
            # Keyed by byte offset and sorted, because the traversal below pops
            # from a stack and would otherwise return source order reversed.
            names: list[tuple[int, str]] = []
            stack: list[Node] = [c for c in statement.children if value is None or c.id != value.id]
            while stack:
                node = stack.pop()
                if node.type == "variable_declaration":
                    name = node.child_by_field_name("name")
                    if name is not None:
                        names.append((int(name.start_byte), self.text(name)))
                stack.extend(node.children)
            return tuple(name for _, name in sorted(names))
        if statement.type in ("assignment_expression", "augmented_assignment_expression"):
            left = statement.child_by_field_name("left")
            root = self._leftmost_identifier(left) if left is not None else None
            return (root,) if root else ()
        return ()
