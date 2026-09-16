"""Shape-level queries, and the shapes that are easy to get wrong.

Every query here exists to be renaming-invariant, so the tests check the shape
is found rather than that a particular identifier was seen. The cases that earn
their place are the ones where the obvious implementation is wrong: chained
calls, destructured bindings, literal zeros written three ways, and a function
whose visibility is absent rather than private.
"""

from __future__ import annotations

import pytest

from contract_assay.evidence.syntax import (
    Syntax,
    WriteTarget,
)

pytestmark = pytest.mark.offline


def syntax_of(source: str) -> Syntax:
    parsed = Syntax.of(source)
    assert parsed is not None, "source should have parsed"
    return parsed


class TestConstruction:
    def test_unreadable_source_yields_none(self) -> None:
        # None means "not analysable", which is the gate's business. It is
        # deliberately different from an empty query result, which means the
        # unit was read and the shape is absent.
        assert Syntax.of("}{ not solidity ][") is None

    def test_empty_source_yields_none(self) -> None:
        assert Syntax.of("   \n ") is None

    def test_a_readable_unit_with_no_calls_yields_an_empty_query(self) -> None:
        parsed = syntax_of("contract C { uint256 x; }")
        assert parsed.calls == ()


class TestHostResolution:
    SOURCE = """\
contract Vault {
    uint256 public total;

    function withdraw(uint256 amount) external {
        total -= amount;
    }

    function withdraw(uint256 amount, address to) external {
        total -= amount;
    }
}

library Math {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
"""

    def test_a_site_inside_a_function_names_both_contract_and_function(self) -> None:
        # Evidence that knows only a line cannot be compared with anything,
        # because scoring is at function granularity.
        host = syntax_of(self.SOURCE).host_at(5)
        assert (host.contract, host.function) == ("Vault", "withdraw")

    def test_the_host_signature_distinguishes_overloads(self) -> None:
        parsed = syntax_of(self.SOURCE)
        assert parsed.host_at(5).function_signature == "withdraw(uint256)"
        assert parsed.host_at(9).function_signature == "withdraw(uint256,address)"

    def test_contract_scope_has_no_host_function(self) -> None:
        host = syntax_of(self.SOURCE).host_at(2)
        assert (host.contract, host.function) == ("Vault", None)

    def test_a_library_is_a_host_like_any_other_type(self) -> None:
        host = syntax_of(self.SOURCE).host_at(15)
        assert (host.contract, host.function) == ("Math", "add")

    def test_a_line_outside_every_declaration_has_no_host(self) -> None:
        host = syntax_of(self.SOURCE).host_at(12)
        assert (host.contract, host.function) == (None, None)


class TestCalls:
    def test_a_member_call_reports_callee_and_receiver(self) -> None:
        [call] = syntax_of("contract C { function f() external { a.b(1); } }").calls
        assert (call.callee, call.receiver) == ("b", "a")

    def test_an_unqualified_call_has_no_receiver(self) -> None:
        calls = syntax_of('contract C { function f() external { require(x, "e"); } }').calls
        [req] = [c for c in calls if c.callee == "require"]
        assert req.receiver is None

    def test_a_chained_call_reports_the_outermost_member(self) -> None:
        # In `a.b().c()` the callee is `c`. Taking the innermost member would
        # report `b`, which is a different call entirely.
        calls = syntax_of("contract C { function f() external { a.b().c(); } }").calls
        outer = [c for c in calls if c.is_bare_statement]
        assert [c.callee for c in outer] == ["c"]

    def test_a_call_through_a_conversion_still_finds_its_member(self) -> None:
        # `payable(x).send(1)` has no bare identifier at the top, so a naive
        # implementation finds nothing and the value transfer goes unseen.
        [call] = [
            c
            for c in syntax_of("contract C { function f() external { payable(x).send(1); } }").calls
            if c.callee == "send"
        ]
        assert call.is_value_transfer

    def test_low_level_members_are_recognised_by_the_language_not_by_naming(self) -> None:
        source = """\
contract C {
    function f() external {
        a.call("");
        a.delegatecall("");
        a.staticcall("");
        a.transfer(1);
    }
}
"""
        calls = {c.callee: c for c in syntax_of(source).calls}
        assert [c for c in calls.values() if c.is_low_level] != []
        assert {k for k, v in calls.items() if v.is_low_level} == {
            "call",
            "delegatecall",
            "staticcall",
        }
        assert calls["transfer"].is_value_transfer

    def test_a_call_that_is_a_whole_statement_is_marked_bare(self) -> None:
        source = """\
contract C {
    function f() external {
        a.call("");
        bool ok = a.call("");
    }
}
"""
        bare = [c.is_bare_statement for c in syntax_of(source).calls]
        assert bare == [True, False]

    def test_call_options_are_detected(self) -> None:
        source = 'contract C { function f() external { a.call{value: 1}(""); } }'
        [call] = [c for c in syntax_of(source).calls if c.callee == "call"]
        assert call.has_call_options


class TestBoundNames:
    def test_a_tuple_binding_reports_its_names_in_source_order(self) -> None:
        source = """\
contract C {
    function f() external {
        (bool ok, bytes memory data) = a.call("");
    }
}
"""
        [call] = [c for c in syntax_of(source).calls if c.callee == "call"]
        assert call.bound_names == ("ok", "data")

    def test_omitted_slots_in_a_destructuring_are_not_counted(self) -> None:
        # Splitting the text on commas cannot tell an omitted binding from a
        # present one; only a filled slot produces a declaration node.
        source = """\
contract C {
    function f() external {
        (, uint256 price, , , ) = feed.latestRoundData();
    }
}
"""
        [call] = [c for c in syntax_of(source).calls if c.callee == "latestRoundData"]
        assert call.bound_names == ("price",)

    def test_a_plain_assignment_reports_its_target(self) -> None:
        source = 'contract C { uint256 ok; function f() external { ok = a.call(""); } }'
        [call] = [c for c in syntax_of(source).calls if c.callee == "call"]
        assert call.bound_names == ("ok",)

    def test_a_discarded_result_binds_nothing(self) -> None:
        source = 'contract C { function f() external { a.call(""); } }'
        [call] = syntax_of(source).calls
        assert call.bound_names == ()

    def test_names_declared_inside_the_value_are_not_treated_as_bindings(self) -> None:
        source = """\
contract C {
    function f() external {
        bool ok = a.call(abi.encode(1));
    }
}
"""
        [call] = [c for c in syntax_of(source).calls if c.callee == "call"]
        assert call.bound_names == ("ok",)


class TestArguments:
    def _args(self, call_text: str) -> tuple[object, ...]:
        source = f"contract C {{ function f() external {{ {call_text} }} }}"
        [call] = [c for c in syntax_of(source).calls if c.callee == "g"]
        return call.arguments

    def test_arguments_carry_their_position(self) -> None:
        # Position is structural, so it survives every renaming operator and is
        # safe to put in a compared payload.
        assert [a.position for a in self._args("r.g(a, 0, c);")] == [0, 1, 2]

    @pytest.mark.parametrize("literal", ["0", "0x0", "0x0000000000000000", "0_0"])
    def test_a_literal_zero_is_recognised_in_every_spelling(self, literal: str) -> None:
        # A predicate recognising only `0` would miss the others while reporting
        # the same coverage.
        [arg] = self._args(f"r.g({literal});")
        assert arg.is_zero_literal

    @pytest.mark.parametrize("literal", ["1", "0x1", "0x01", "minOut"])
    def test_a_non_zero_is_not_mistaken_for_zero(self, literal: str) -> None:
        [arg] = self._args(f"r.g({literal});")
        assert not arg.is_zero_literal

    def test_an_identifier_argument_is_marked_as_one(self) -> None:
        [arg] = self._args("r.g(minOut);")
        assert arg.is_identifier and not arg.is_number_literal

    def test_argument_lookup_by_position(self) -> None:
        source = "contract C { function f() external { r.g(a, 0); } }"
        [call] = [c for c in syntax_of(source).calls if c.callee == "g"]
        second = call.argument(1)
        assert second is not None and second.is_zero_literal
        assert call.argument(9) is None


class TestWrites:
    SOURCE = """\
contract C {
    uint256 public total;
    mapping(address => uint256) balances;
    Config config;

    function f(address to, uint256 n) external {
        uint256 scratch = 1;
        total = n;
        balances[to] -= n;
        config.fee = n;
        scratch = n;
    }
}
"""

    def test_writes_are_classified_by_shape_of_target(self) -> None:
        by_root = {w.target_root: w.target for w in syntax_of(self.SOURCE).writes}
        assert by_root["total"] == WriteTarget.STATE_VARIABLE
        assert by_root["balances"] == WriteTarget.STATE_COLLECTION_ELEMENT
        assert by_root["config"] == WriteTarget.STATE_MEMBER
        assert by_root["scratch"] == WriteTarget.LOCAL

    def test_only_state_targets_count_as_state_writes(self) -> None:
        state = {w.target_root for w in syntax_of(self.SOURCE).writes if w.writes_state}
        assert state == {"total", "balances", "config"}

    def test_the_operator_is_recorded_as_written(self) -> None:
        # A language token, so it is stable under renaming and safe to compare.
        ops = {w.target_root: w.operator for w in syntax_of(self.SOURCE).writes}
        assert ops["balances"] == "-="
        assert ops["total"] == "="

    def test_writes_carry_their_host_function(self) -> None:
        [write] = [w for w in syntax_of(self.SOURCE).writes if w.target_root == "total"]
        assert write.site.host.function == "f"


class TestFunctions:
    def test_visibility_and_mutability_are_read_from_the_language(self) -> None:
        source = """\
contract C {
    function a() external view returns (uint256) { return 1; }
    function b() internal {}
}
"""
        by_name = {f.declaration.names[0]: f for f in syntax_of(source).functions}
        assert by_name["a"].visibility == "external"
        assert by_name["a"].is_read_only
        assert by_name["b"].visibility == "internal"
        assert not by_name["b"].is_externally_reachable

    def test_absent_visibility_is_treated_as_reachable_not_as_private(self) -> None:
        # Before 0.5 an omitted visibility defaulted to public, and corpus
        # sources are pinned at historical commits. Reading the absence as
        # restrictive would exempt the most exposed functions in the oldest code.
        [fn] = syntax_of("contract C { function a() { x = 1; } }").functions
        assert fn.visibility is None
        assert fn.is_externally_reachable

    def test_modifier_invocations_are_collected(self) -> None:
        source = "contract C { function a() external onlyOwner nonReentrant {} }"
        [fn] = [f for f in syntax_of(source).functions if f.declaration.names[0] == "a"]
        assert fn.modifiers == ("onlyOwner", "nonReentrant")

    def test_a_function_with_no_modifiers_reports_an_empty_tuple(self) -> None:
        [fn] = syntax_of("contract C { function a() external {} }").functions
        assert fn.modifiers == ()

    def test_constructors_and_receive_are_function_sites_too(self) -> None:
        source = """\
contract C {
    constructor(address owner) {}
    receive() external payable {}
    modifier m() { _; }
}
"""
        kinds = {f.declaration.kind.value for f in syntax_of(source).functions}
        assert kinds == {"constructor", "receive_or_fallback", "modifier"}


class TestMemberReadsAndIdentifierUses:
    SOURCE = """\
contract C {
    function f() external returns (uint256) {
        uint256 seed = block.timestamp;
        return uint256(keccak256(abi.encodePacked(seed, block.number)));
    }
}
"""

    def test_chain_state_is_found_as_a_receiver_property_pair(self) -> None:
        # Matched as a shape, not by searching for the word `timestamp`, which a
        # local variable may also carry.
        pairs = {(recv, prop) for _, recv, prop in syntax_of(self.SOURCE).member_reads}
        assert ("block", "timestamp") in pairs
        assert ("block", "number") in pairs

    def test_identifier_uses_counts_occurrences_inside_a_declaration(self) -> None:
        parsed = syntax_of(self.SOURCE)
        [fn] = parsed.index.callables("f")
        assert parsed.identifier_uses(fn, "seed") == 2
        assert parsed.identifier_uses(fn, "absent") == 0

    def test_within_restricts_sites_to_a_declaration(self) -> None:
        parsed = syntax_of(self.SOURCE)
        [fn] = parsed.index.callables("f")
        sites = tuple(site for site, _, _ in parsed.member_reads)
        assert len(parsed.within(fn, sites)) == len(sites)


class TestSiteLocators:
    """Every predicate turns a site into a locator, so this is load-bearing."""

    SOURCE = """\
contract Vault {
    function withdraw(uint256 amount) external {
        payable(msg.sender).send(amount);
    }
}
"""

    def test_a_locator_names_the_host_contract_and_function(self) -> None:
        [call] = [c for c in syntax_of(self.SOURCE).calls if c.callee == "send"]
        locator = call.site.locator("src/Vault.sol")
        assert locator.file == "src/Vault.sol"
        assert locator.contract == "Vault"
        assert locator.function == "withdraw"
        assert locator.start_line == locator.end_line == 3


class TestKnownLimitations:
    """Gaps pinned deliberately, so a later change has to notice them."""

    def test_a_call_through_an_indexed_callee_is_not_reported(self) -> None:
        # `handlers[0](1)` has no member name, so there is nothing to key a
        # predicate on and the call is skipped. A real gap: it is an ordinary
        # dispatch pattern. Pinned rather than hidden, because a future fix
        # should break this test rather than pass it silently.
        parsed = syntax_of("contract C { function f() external { handlers[0](1); } }")
        assert parsed.calls == ()

    @pytest.mark.parametrize(
        "body",
        [
            'return a.call("");',
            'if (a.call("")) { x = 1; }',
        ],
    )
    def test_a_call_in_a_non_binding_position_binds_nothing(self, body: str) -> None:
        source = f"contract C {{ function f() external returns (bool) {{ {body} }} }}"
        [call] = [c for c in syntax_of(source).calls if c.callee == "call"]
        assert call.bound_names == ()
        assert not call.is_bare_statement


class TestTupleAssignmentsWriteMoreThanOnce:
    def test_every_target_of_a_tuple_assignment_is_reported(self) -> None:
        # Descending to the leftmost identifier would report only the first, so a
        # tuple whose *second* element is the state variable would lose that
        # write -- and the loss would read as an absence of evidence rather than
        # a failure to look.
        source = """\
contract C {
    uint256 a;
    mapping(uint256 => uint256) m;

    function f() external {
        (a, m[1]) = (1, 2);
    }
}
"""
        writes = [(w.target, w.target_root) for w in syntax_of(source).writes]
        assert writes == [
            (WriteTarget.STATE_VARIABLE, "a"),
            (WriteTarget.STATE_COLLECTION_ELEMENT, "m"),
        ]

    def test_a_tuple_assignment_whose_state_write_is_second_is_not_lost(self) -> None:
        source = """\
contract C {
    uint256 total;

    function f() external {
        uint256 scratch;
        (scratch, total) = (1, 2);
    }
}
"""
        state = [w.target_root for w in syntax_of(source).writes if w.writes_state]
        assert state == ["total"]


class TestDenominatedLiterals:
    def _arg(self, literal: str) -> object:
        source = f"contract C {{ function f() external {{ r.g({literal}); }} }}"
        [call] = [c for c in syntax_of(source).calls if c.callee == "g"]
        [arg] = call.arguments
        return arg

    @pytest.mark.parametrize("literal", ["0 ether", "0 wei", "0 days", "0 gwei"])
    def test_a_denominated_zero_is_still_zero(self, literal: str) -> None:
        # Zero times any denomination is zero. A check that only understood bare
        # digits would read these as not-a-number and miss them.
        assert self._arg(literal).is_zero_literal

    @pytest.mark.parametrize("literal", ["1 ether", "1 days", "100 wei"])
    def test_a_denominated_non_zero_is_not_zero(self, literal: str) -> None:
        assert not self._arg(literal).is_zero_literal


class TestNoQueryRaisesOnOddSource:
    """Corpus sources are pinned at historical commits across grammar revisions.

    A query that raises on source the grammar only partly understood would take
    the whole run down, and it would do so on exactly the old, badly-built
    repositories that host the hardest defects. Every guard in the module exists
    for this property; this exercises them together.
    """

    SOURCES = (
        "contract C { function f() external { a.(); } }",
        "contract C { function f() external { .call(); } }",
        "contract C { function f() external { = 1; } }",
        "contract C { function f() external { (a, ) = ; } }",
        "contract C { function f( } }",
        "contract C { uint256; }",
        "contract C { function f() external { a[; } }",
        "contract C { function f() external { ((x)) = ((1)); } }",
        "contract C { function f() external { a.b.c.d(1); } }",
        "contract C { function f() external { f()()(); } }",
        "library L { function f() { } }",
        "interface I { function f() external; }",
        "contract C is A(1), B { constructor() A(2) {} }",
        "abstract contract C { function f() external virtual; }",
        "contract C { fallback() external {} receive() external payable {} }",
    )

    @pytest.mark.parametrize("source", SOURCES)
    def test_every_query_survives(self, source: str) -> None:
        parsed = Syntax.of(source)
        if parsed is None:
            return
        # Touch every public query, and the derived properties on what they return.
        for call in parsed.calls:
            assert isinstance(call.callee, str)
            call.site.locator("f.sol")
            [(a.is_zero_literal, a.is_identifier, a.is_number_literal) for a in call.arguments]
            assert isinstance(call.is_low_level, bool)
            call.argument(0)
        for write in parsed.writes:
            assert isinstance(write.writes_state, bool)
            write.site.locator("f.sol")
        for function in parsed.functions:
            assert isinstance(function.is_externally_reachable, bool)
            assert isinstance(function.is_read_only, bool)
        for site, receiver, prop in parsed.member_reads:
            assert isinstance(receiver, str) and isinstance(prop, str)
            site.locator("f.sol")
        assert isinstance(parsed.state_variables, frozenset)
        for declaration in parsed.index.declarations:
            parsed.identifier_uses(declaration, "x")
            parsed.within(declaration, tuple(s for s, _, _ in parsed.member_reads))
