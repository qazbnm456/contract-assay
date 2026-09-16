"""The predicate library.

Most of this file is negatives. A predicate that fires on the right shape is
easy; the ones that matter are the shapes it must *not* fire on, because a false
fact in `evidence()` is recorded whatever the model concludes and is therefore
harder to notice than a false verdict.

The last class tests the property the whole compared-payload design rests on:
renaming every identifier in a contract must not change a single `detail` value.
"""

from __future__ import annotations

import pytest

from contract_assay.evidence.predicates import (
    coverage_by_class,
    predicates,
    run_all,
)
from contract_assay.evidence.syntax import Syntax
from contract_assay.models import EvidenceRef, EvidenceTier, VulnerabilityClass

pytestmark = pytest.mark.offline

PATH = "src/Vault.sol"


def evidence(source: str, **kwargs: object) -> list[EvidenceRef]:
    parsed = Syntax.of(source)
    assert parsed is not None, "source should have parsed"
    return run_all(parsed, PATH, **kwargs)  # type: ignore[arg-type]


def fired(source: str, predicate_id: str) -> list[EvidenceRef]:
    return [ref for ref in evidence(source) if ref.predicate == predicate_id]


def contract(body: str) -> str:
    return f"contract Vault {{\n{body}\n}}\n"


class TestRegistry:
    def test_every_predicate_id_is_unique(self) -> None:
        ids = [spec.predicate_id for spec in predicates()]
        assert len(ids) == len(set(ids))

    def test_every_predicate_declares_at_least_one_class(self) -> None:
        assert all(spec.classes for spec in predicates())

    def test_every_predicate_id_is_a_stable_slug(self) -> None:
        # Ids reach recorded evidence, so they are an interface.
        assert all(
            spec.predicate_id.replace("_", "").isalnum() and spec.predicate_id.islower()
            for spec in predicates()
        )

    def test_coverage_reports_every_class_including_the_empty_ones(self) -> None:
        # "This class has a predicate" and "this class is covered" are different
        # claims. A registry establishes only the first, and a report that
        # omitted the zeroes would imply the second.
        coverage = coverage_by_class()
        assert set(coverage) == set(VulnerabilityClass)
        assert coverage[VulnerabilityClass.ORACLE_INTEGRITY] == ()

    def test_results_can_be_restricted_to_one_class(self) -> None:
        source = contract('    function f(address to) external { to.call(""); }')
        assert evidence(source, classes=[VulnerabilityClass.INSECURE_RANDOMNESS]) == []
        assert evidence(source, classes=[VulnerabilityClass.UNCHECKED_EXTERNAL_CALL]) != []

    def test_results_are_ordered_deterministically(self) -> None:
        # An unstable order would make a recorded trace differ from its own
        # replay for no reason anybody could diagnose.
        source = contract("""\
    uint256 total;
    function f(address to) external {
        to.call("");
        total = block.timestamp;
    }
""")
        first = [(r.predicate, r.locator.start_line) for r in evidence(source)]
        assert first == sorted(first, key=lambda p: (p[1], p[0]))
        assert first == [(r.predicate, r.locator.start_line) for r in evidence(source)]

    def test_all_evidence_is_marked_syntactic(self) -> None:
        source = contract('    function f(address to) external { to.call(""); }')
        assert {r.tier for r in evidence(source)} == {EvidenceTier.SYNTACTIC}


class TestLowLevelCallResultDiscarded:
    @pytest.mark.parametrize("member", ["call", "delegatecall", "staticcall", "send"])
    def test_a_discarded_flag_is_reported(self, member: str) -> None:
        source = contract(f'    function f(address to) external {{ to.{member}(""); }}')
        [ref] = fired(source, "low_level_call_result_discarded")
        assert ref.detail["call_member"] == member
        assert ref.detail["result_bound"] is False

    def test_transfer_is_not_reported(self) -> None:
        # `transfer` reverts on failure, so discarding its result is not this
        # defect. Reporting it would be a false fact, not a conservative one.
        source = contract("    function f(address to) external { to.transfer(1); }")
        assert fired(source, "low_level_call_result_discarded") == []

    def test_a_bound_flag_is_not_this_predicate(self) -> None:
        source = contract('    function f(address to) external { (bool ok, ) = to.call(""); }')
        assert fired(source, "low_level_call_result_discarded") == []

    def test_the_receiver_is_diagnostic_not_compared(self) -> None:
        source = contract('    function f(address recipient) external { recipient.call(""); }')
        [ref] = fired(source, "low_level_call_result_discarded")
        assert ref.diagnostic["receiver"] == "recipient"
        assert "recipient" not in str(ref.detail)


class TestLowLevelCallResultBoundButUnread:
    def test_a_flag_never_mentioned_again_is_reported(self) -> None:
        source = contract("""\
    function f(address to) external {
        (bool ok, ) = to.call("");
    }
""")
        [ref] = fired(source, "low_level_call_result_bound_but_unread")
        assert ref.detail["unread_count"] == 1
        assert ref.detail["first_unread_position"] == 0
        assert ref.diagnostic["unread_names"] == "ok"

    def test_a_flag_that_is_checked_is_not_reported(self) -> None:
        source = contract("""\
    function f(address to) external {
        (bool ok, ) = to.call("");
        require(ok, "failed");
    }
""")
        assert fired(source, "low_level_call_result_bound_but_unread") == []

    def test_only_the_unread_bindings_are_counted(self) -> None:
        source = contract("""\
    function f(address to) external {
        (bool ok, bytes memory data) = to.call("");
        require(ok, "failed");
    }
""")
        [ref] = fired(source, "low_level_call_result_bound_but_unread")
        assert ref.detail["bound_count"] == 2
        assert ref.detail["unread_count"] == 1
        assert ref.detail["first_unread_position"] == 1

    def test_a_discarded_result_is_not_this_predicate(self) -> None:
        source = contract('    function f(address to) external { to.call(""); }')
        assert fired(source, "low_level_call_result_bound_but_unread") == []


class TestProducerControlledValueRead:
    @pytest.mark.parametrize(
        "expression",
        ["block.timestamp", "block.number", "block.prevrandao", "block.coinbase", "tx.origin"],
    )
    def test_chain_state_reads_are_reported_with_their_source(self, expression: str) -> None:
        source = contract(
            f"    uint256 s;\n    function f() external {{ s = uint256({expression}); }}"
        )
        [ref] = fired(source, "producer_controlled_value_read")
        assert ref.detail["source"] == expression

    def test_blockhash_is_reported(self) -> None:
        source = contract(
            "    uint256 s;\n    function f() external { s = uint256(blockhash(1)); }"
        )
        [ref] = fired(source, "producer_controlled_value_read")
        assert ref.detail["source"] == "blockhash"

    def test_a_local_named_like_chain_state_is_not_reported(self) -> None:
        # Matched as a receiver/property shape, not by searching for the word
        # `timestamp`, which a local variable may also carry.
        source = contract("""\
    uint256 s;
    function f(uint256 timestamp, Info memory info) external {
        s = timestamp + info.number;
    }
""")
        assert fired(source, "producer_controlled_value_read") == []

    def test_it_reports_the_read_not_the_use(self) -> None:
        # A deadline is not randomness, but the read is real. The predicate is
        # named for the read precisely so that this is not a false positive.
        source = contract("""\
    function f(uint256 amountIn) external {
        router.swap(amountIn, 1, block.timestamp);
    }
""")
        [ref] = fired(source, "producer_controlled_value_read")
        assert ref.detail["source"] == "block.timestamp"


class TestStateChangeReachableWithoutGuard:
    def test_an_unguarded_external_setter_is_reported(self) -> None:
        source = contract(
            "    address owner;\n    function setOwner(address o) external { owner = o; }"
        )
        [ref] = fired(source, "state_change_reachable_without_guard")
        assert ref.detail["visibility"] == "external"
        assert ref.detail["state_write_count"] == 1
        assert ref.locator.function == "setOwner"

    def test_a_modifier_is_taken_as_a_guard(self) -> None:
        source = contract(
            "    address owner;\n    function setOwner(address o) external onlyOwner { owner = o; }"
        )
        assert fired(source, "state_change_reachable_without_guard") == []

    def test_reading_msg_sender_is_taken_as_a_guard(self) -> None:
        source = contract("""\
    address owner;
    function setOwner(address o) external {
        require(msg.sender == owner);
        owner = o;
    }
""")
        assert fired(source, "state_change_reachable_without_guard") == []

    @pytest.mark.parametrize("visibility", ["internal", "private"])
    def test_an_unreachable_function_is_not_reported(self, visibility: str) -> None:
        source = contract(
            f"    address owner;\n    function setOwner(address o) {visibility} {{ owner = o; }}"
        )
        assert fired(source, "state_change_reachable_without_guard") == []

    def test_absent_visibility_is_reported_as_unspecified_and_still_reachable(self) -> None:
        # Before 0.5 an omitted visibility defaulted to public. Reading the
        # absence as restrictive would exempt the most exposed functions in
        # exactly the oldest code, which is where the hardest defects live.
        source = contract("    address owner;\n    function setOwner(address o) { owner = o; }")
        [ref] = fired(source, "state_change_reachable_without_guard")
        assert ref.detail["visibility"] == "unspecified"

    def test_a_constructor_is_not_reported(self) -> None:
        # It runs once at deployment, so an unguarded write in it is not an
        # instance of this property.
        source = contract("    address owner;\n    constructor(address o) { owner = o; }")
        assert fired(source, "state_change_reachable_without_guard") == []

    def test_a_modifier_definition_is_not_reported(self) -> None:
        source = contract("    uint256 n;\n    modifier m() { n = 1; _; }")
        assert fired(source, "state_change_reachable_without_guard") == []

    def test_a_function_writing_no_state_is_not_reported(self) -> None:
        source = contract("    function f(uint256 a) external { uint256 scratch = a; }")
        assert fired(source, "state_change_reachable_without_guard") == []

    def test_a_view_function_is_not_reported(self) -> None:
        source = contract(
            "    uint256 n;\n    function f() external view returns (uint256) { return n; }"
        )
        assert fired(source, "state_change_reachable_without_guard") == []


class TestStateWriteAfterRawExternalCall:
    def test_a_write_after_a_call_is_reported(self) -> None:
        source = contract("""\
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) external {
        payable(msg.sender).send(amount);
        balances[msg.sender] -= amount;
    }
""")
        [ref] = fired(source, "state_write_after_raw_external_call")
        assert ref.detail["ordering"] == "write_follows_call"
        assert ref.detail["state_writes_after"] == 1
        assert ref.detail["call_member"] == "send"

    def test_a_write_before_the_call_is_not_reported(self) -> None:
        # Which is the whole point of the predicate: it establishes an ordering.
        source = contract("""\
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).send(amount);
    }
""")
        assert fired(source, "state_write_after_raw_external_call") == []

    def test_a_local_write_after_the_call_is_not_reported(self) -> None:
        source = contract("""\
    function withdraw(uint256 amount) external {
        payable(msg.sender).send(amount);
        uint256 scratch = amount;
    }
""")
        assert fired(source, "state_write_after_raw_external_call") == []

    def test_a_write_in_a_different_function_is_not_reported(self) -> None:
        source = contract("""\
    uint256 total;
    function a(uint256 amount) external {
        payable(msg.sender).send(amount);
    }
    function b(uint256 amount) external {
        total = amount;
    }
""")
        assert fired(source, "state_write_after_raw_external_call") == []

    def test_transfer_counts_as_an_external_call_here(self) -> None:
        # Unlike the discarded-flag predicate: `transfer` reverting does not stop
        # it handing control to the recipient.
        source = contract("""\
    uint256 total;
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        total -= amount;
    }
""")
        [ref] = fired(source, "state_write_after_raw_external_call")
        assert ref.detail["call_member"] == "transfer"


class TestCallArgumentIsZeroLiteral:
    def test_the_position_is_reported(self) -> None:
        # Section 2.3's own example: the second positional argument of a swap.
        source = contract("""\
    function swap(uint256 amountIn) external {
        router.swapExactTokensForTokens(amountIn, 0, path, address(this), 1);
    }
""")
        [ref] = fired(source, "call_argument_is_zero_literal")
        assert ref.detail["position"] == 1
        assert ref.detail["argument_count"] == 5

    def test_a_denominated_zero_is_still_reported(self) -> None:
        source = contract("    function f() external { r.g(0 ether); }")
        assert fired(source, "call_argument_is_zero_literal") != []

    def test_a_non_zero_is_not_reported(self) -> None:
        source = contract("    function f() external { r.g(1, minOut); }")
        assert fired(source, "call_argument_is_zero_literal") == []

    def test_the_callee_is_diagnostic_not_compared(self) -> None:
        source = contract("    function f() external { router.swapExactTokensForTokens(1, 0); }")
        [ref] = fired(source, "call_argument_is_zero_literal")
        assert ref.diagnostic["callee"] == "swapExactTokensForTokens"
        assert "swap" not in str(ref.detail)


class TestRenamingDoesNotChangeTheComparedPayload:
    """The property the whole two-payload design rests on.

    `detail` is what gets compared -- between a detector's output and ground
    truth, and between a source and a variant of it. Renaming preserves
    behaviour, so if a rename changes a compared value, the comparison reports a
    difference where nothing changed, and a defect that survived an edit looks
    like one that was repaired.

    Locators are deliberately excluded from the comparison below. Host contract
    and function *do* change under renaming, and the comparison that consumes
    this evidence maps them; the payload is what must not need mapping.
    """

    ORIGINAL = """\
contract Vault {
    address owner;
    uint256 total;
    mapping(address => uint256) balances;

    function setOwner(address o) external { owner = o; }

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call("");
        balances[msg.sender] -= amount;
    }

    function lucky() external { total = uint256(blockhash(block.number)); }

    function swap(uint256 amountIn) external {
        router.swapExactTokensForTokens(amountIn, 0, path, block.timestamp);
    }
}
"""

    RENAMED = """\
contract Treasury {
    address administrator;
    uint256 aggregate;
    mapping(address => uint256) ledger;

    function assignAdministrator(address candidate) external { administrator = candidate; }

    function redeem(uint256 quantity) external {
        (bool succeeded, ) = msg.sender.call("");
        ledger[msg.sender] -= quantity;
    }

    function fortunate() external { aggregate = uint256(blockhash(block.number)); }

    function exchange(uint256 inbound) external {
        dex.swapExactTokensForTokens(inbound, 0, route, block.timestamp);
    }
}
"""

    def _payloads(self, source: str) -> list[tuple[str, tuple[tuple[str, object], ...]]]:
        return sorted(
            (ref.predicate, tuple(sorted(ref.detail.items()))) for ref in evidence(source)
        )

    def test_the_same_predicates_fire(self) -> None:
        original = sorted({r.predicate for r in evidence(self.ORIGINAL)})
        renamed = sorted({r.predicate for r in evidence(self.RENAMED)})
        assert original == renamed
        assert len(original) >= 4, "the fixture should exercise several predicates"

    def test_the_compared_payload_is_identical(self) -> None:
        assert self._payloads(self.ORIGINAL) == self._payloads(self.RENAMED)

    def test_no_compared_value_contains_a_renamed_identifier(self) -> None:
        renamed_identifiers = {
            "owner",
            "total",
            "balances",
            "setOwner",
            "withdraw",
            "amount",
            "ok",
            "lucky",
            "swap",
            "amountIn",
            "router",
            "path",
            "Vault",
        }
        values = {
            str(value)
            for ref in evidence(self.ORIGINAL)
            for value in (*ref.detail.keys(), *ref.detail.values())
        }
        assert values.isdisjoint(renamed_identifiers)

    def test_the_diagnostic_payload_does_change(self) -> None:
        # Confirming the split is real rather than vacuous: the unstable values
        # exist, are kept, and are kept out of the compared payload.
        def diagnostics(source: str) -> set[str]:
            return {f"{k}={v}" for ref in evidence(source) for k, v in ref.diagnostic.items() if v}

        assert diagnostics(self.ORIGINAL) != diagnostics(self.RENAMED)


class TestRegistryRefusesADuplicate:
    def test_registering_an_id_twice_is_rejected(self) -> None:
        # Predicate ids reach recorded evidence, so two predicates sharing one
        # would make the record ambiguous about which fact was established.
        from contract_assay.evidence import predicates as module

        existing = next(iter(module._REGISTRY))
        with pytest.raises(ValueError, match="already registered"):
            module._register(existing, VulnerabilityClass.SLIPPAGE, summary="clash")(
                lambda syntax, path: []
            )


class TestCallsOutsideAnyFunction:
    def test_a_call_at_contract_scope_does_not_break_ordering_predicates(self) -> None:
        # A state variable initialiser is not inside a callable, so there is no
        # function to establish an ordering within. Reported as nothing rather
        # than crashing on a missing host.
        source = 'contract C { bool ok = target.call(""); }'
        assert evidence(source) == []

    def test_a_chain_state_read_at_contract_scope_still_reports(self) -> None:
        # It has no host function, which is legitimate: the locator names the
        # contract and leaves the function absent.
        source = "contract C { uint256 t = block.timestamp; }"
        [ref] = evidence(source)
        assert ref.predicate == "producer_controlled_value_read"
        assert ref.locator.function is None
        assert ref.locator.contract == "C"
