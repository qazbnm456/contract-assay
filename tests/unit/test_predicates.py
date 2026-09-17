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

from contract_assay.detectors import reference
from contract_assay.detectors.base import Detector
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
        # Still one class with nothing behind it, and it is the one no analysis
        # over a single unit reaches (§4.2's audit): whether a callee is a market
        # the caller can move is another contract's fact.
        assert coverage[VulnerabilityClass.FLASHLOAN_MANIPULATION] == ()

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


class TestStateChangeReachableWithoutModifierOrSenderReference:
    def test_an_unguarded_external_setter_is_reported(self) -> None:
        source = contract(
            "    address owner;\n    function setOwner(address o) external { owner = o; }"
        )
        [ref] = fired(source, "state_change_reachable_without_modifier_or_sender_reference")
        assert ref.detail["visibility"] == "external"
        assert ref.detail["state_write_count"] == 1
        assert ref.locator.function == "setOwner"

    def test_a_modifier_is_taken_as_a_guard(self) -> None:
        source = contract(
            "    address owner;\n    function setOwner(address o) external onlyOwner { owner = o; }"
        )
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []

    def test_reading_msg_sender_is_taken_as_a_guard(self) -> None:
        source = contract("""\
    address owner;
    function setOwner(address o) external {
        require(msg.sender == owner);
        owner = o;
    }
""")
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []

    @pytest.mark.parametrize("visibility", ["internal", "private"])
    def test_an_unreachable_function_is_not_reported(self, visibility: str) -> None:
        source = contract(
            f"    address owner;\n    function setOwner(address o) {visibility} {{ owner = o; }}"
        )
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []

    def test_absent_visibility_is_reported_as_unspecified_and_still_reachable(self) -> None:
        # Before 0.5 an omitted visibility defaulted to public. Reading the
        # absence as restrictive would exempt the most exposed functions in
        # exactly the oldest code, which is where the hardest defects live.
        source = contract("    address owner;\n    function setOwner(address o) { owner = o; }")
        [ref] = fired(source, "state_change_reachable_without_modifier_or_sender_reference")
        assert ref.detail["visibility"] == "unspecified"

    def test_a_constructor_is_not_reported(self) -> None:
        # It runs once at deployment, so an unguarded write in it is not an
        # instance of this property.
        source = contract("    address owner;\n    constructor(address o) { owner = o; }")
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []

    def test_a_modifier_definition_is_not_reported(self) -> None:
        source = contract("    uint256 n;\n    modifier m() { n = 1; _; }")
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []

    def test_a_function_writing_no_state_is_not_reported(self) -> None:
        source = contract("    function f(uint256 a) external { uint256 scratch = a; }")
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []

    def test_a_view_function_is_not_reported(self) -> None:
        source = contract(
            "    uint256 n;\n    function f() external view returns (uint256) { return n; }"
        )
        assert fired(source, "state_change_reachable_without_modifier_or_sender_reference") == []


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
        assert ref.detail["call_member"] == "send"
        assert "state_writes_after" not in ref.detail

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


class TestTheSenderConditionIsCoarseOnPurpose:
    """Both directions of the coarseness are pinned, because both are deliberate."""

    NAME = "state_change_reachable_without_modifier_or_sender_reference"

    def test_a_sender_reference_used_only_for_logging_suppresses_the_fact(self) -> None:
        # A false negative, accepted knowingly. Tightening the condition to
        # "appears in a require or an if" would catch this one and then fire on
        # every permissionless-by-design function, of which there are far more.
        source = contract("""\
    address owner;
    event Changed(address by);
    function setOwner(address o) external {
        emit Changed(msg.sender);
        owner = o;
    }
""")
        assert fired(source, self.NAME) == []

    def test_a_permissionless_per_sender_write_is_not_reported(self) -> None:
        # The case that pays for the leniency: a deposit guards nothing and is
        # meant to guard nothing, so reporting it would be a false fact.
        source = contract("""\
    mapping(address => uint256) balances;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
""")
        assert fired(source, self.NAME) == []


class TestOrderingSurvivesFormChanges:
    """What the ordering predicate survives, and what it provably does not.

    These matter because a comparison of evidence before and after a
    behaviour-preserving edit is how a mutated variant gets confirmed to still
    carry its defect. A predicate whose output moves when the defect does not
    makes that comparison reject sound inputs.
    """

    NAME = "state_write_after_raw_external_call"

    TERNARY = """\
contract Vault {
    uint256 total;
    function f(uint256 a, bool c) external {
        payable(msg.sender).send(a);
        total = c ? a : 0;
    }
}
"""
    IF_FORM = """\
contract Vault {
    uint256 total;
    function f(uint256 a, bool c) external {
        payable(msg.sender).send(a);
        if (c) { total = a; } else { total = 0; }
    }
}
"""

    def test_rewriting_a_ternary_as_an_if_does_not_move_the_payload(self) -> None:
        # One state write becomes two and the property is untouched. This is the
        # case that cost the payload its write count.
        [before] = fired(self.TERNARY, self.NAME)
        [after] = fired(self.IF_FORM, self.NAME)
        assert before.detail == after.detail

    EXTRACTED = """\
contract Vault {
    mapping(address => uint256) balances;

    function _pay(uint256 amount) internal {
        payable(msg.sender).send(amount);
    }

    function withdraw(uint256 amount) external {
        _pay(amount);
        balances[msg.sender] -= amount;
    }
}
"""

    def test_moving_the_call_into_a_helper_silences_it(self) -> None:
        # First and foremost a RECALL GAP against ordinary Solidity: extracting a
        # payment into a helper is a normal thing to write, and the reentrancy is
        # fully intact. This tier sees no external call in `withdraw` and reports
        # nothing, so every real record of this shape scores zero evidence.
        #
        # It follows that a mutation which moves the call across the boundary
        # also changes whether the predicate fires. That is the cheaper of the
        # two costs: a wrongly rejected variant loses one test item, while an
        # invisible shape loses every record that has it, silently, and looks
        # like the predicate working.
        assert fired(self.EXTRACTED, self.NAME) == []

    INLINED_WRITE = """\
contract Vault {
    mapping(address => uint256) balances;

    function _debit(uint256 amount) internal {
        balances[msg.sender] -= amount;
    }

    function withdraw(uint256 amount) external {
        payable(msg.sender).send(amount);
        _debit(amount);
    }
}
"""

    def test_a_write_behind_a_helper_is_equally_invisible(self) -> None:
        # The mirror image, and just as ordinary: extracting a balance update
        # into `_debit` is routine. Neither direction is a payload problem --
        # inlining the helper would make the predicate start firing on code whose
        # behaviour never changed, and a payload does not exist at all when the
        # predicate is silent. Following a call across a boundary is what the
        # semantic tier is for.
        assert fired(self.INLINED_WRITE, self.NAME) == []


class TestWhatAMemberNameCannotEstablish:
    """A name match is a fact about the text, not about the call.

    `send`, `transfer` and `call` are address members at the language level, and
    also legal function names on a contract. At this tier `helper.send(x)` and
    `payableAddress.send(x)` are one shape, so the name bounds both precision and
    recall. Each case below is pinned so that a later fix -- which needs the
    receiver's type, and therefore the semantic tier -- breaks a test rather than
    passing one silently.
    """

    def test_a_local_helper_named_send_manufactures_evidence(self) -> None:
        # Nothing here is wrong: `send` is an internal function of this contract.
        # The predicate fires anyway, because the name is all it has. The general
        # form is worth remembering -- any rule keyed on a name can be made to
        # fire by picking that name.
        source = contract("""\
    function send(uint256 a) internal { emit Paid(a); }
    function f(uint256 a) external {
        helper.send(a);
    }
""")
        assert fired(source, "low_level_call_result_discarded") != []

    def test_a_discarded_token_transfer_return_is_invisible(self) -> None:
        # `IERC20.transfer` returns a bool that is very commonly discarded, and
        # that is a real and common defect. It is absent here because
        # `address.transfer` reverts instead of returning a flag, so `transfer`
        # is excluded from the flag-returning set -- correct for one meaning of
        # the name and wrong for the other, with no syntactic rule between them.
        source = contract("""\
    IERC20 token;
    function f(address to, uint256 a) external {
        token.transfer(to, a);
    }
""")
        assert fired(source, "low_level_call_result_discarded") == []
        assert fired(source, "low_level_call_result_bound_but_unread") == []

    def test_an_address_transfer_is_still_treated_as_an_external_call(self) -> None:
        # The other direction of the same ambiguity, and here the coarse reading
        # is the right one: whichever `transfer` this is, it hands control to the
        # recipient, so the ordering predicate should see it.
        source = contract("""\
    uint256 total;
    function f(address payable to, uint256 a) external {
        to.transfer(a);
        total -= a;
    }
""")
        [ref] = fired(source, "state_write_after_raw_external_call")
        assert ref.detail["call_member"] == "transfer"


class TestAGuardThatAsksTheCallerForItsAnswer:
    """Caller-taint at depth one, which needs no compiled backend.

    The register entry this closed predicted the semantic tier. A value an
    outside caller supplied enters the function under a parameter name, so an
    expression mentioning that name reads something the caller chose -- and the
    parser knows the parameter names and the identifiers in a condition already.
    """

    ID = "authorisation_reads_its_answer_from_caller_supplied_address"

    def _fires(self, guard: str, *, params: str = "address from, address to, uint256 id") -> bool:
        source = (
            "contract R {\n"
            f"    address owner;\n    address alchemech;\n"
            f"    function f({params}) external {{\n"
            f"        {guard}\n        total += 1;\n    }}\n}}\n"
        )
        parsed = Syntax.of(source)
        assert parsed is not None
        return any(e.predicate == self.ID for e in run_all(parsed, "src/R.sol"))

    def test_an_answer_read_from_a_caller_supplied_address_fires(self) -> None:
        assert self._fires("require(IVisor(from).owner() == msg.sender);")

    def test_a_bare_receiver_fires_too(self) -> None:
        # The receiver of `from.owner()` is a plain identifier rather than a
        # nested expression, which a selector written for the nested shape
        # misses -- and reports as an absence.
        assert self._fires("require(from.owner() == msg.sender);")

    def test_an_if_is_a_guard_as_much_as_a_require(self) -> None:
        assert self._fires("if (from.owner() == msg.sender) { total += 1; }")

    def test_a_caller_supplied_subject_does_not_fire(self) -> None:
        # The measured false-positive source, and the reason this predicate is
        # not simply "mentions msg.sender and a parameter": the caller passes an
        # id and the contract resolves it against its own state. Sound, and the
        # ordinary way to write the check.
        assert not self._fires("require(IEscrow(owner).isApprovedOrOwner(msg.sender, id));")

    def test_the_callers_own_account_does_not_fire(self) -> None:
        assert not self._fires("require(to == msg.sender);")

    def test_a_guard_reading_from_state_does_not_fire(self) -> None:
        assert not self._fires("require(IVisor(owner).owner() == msg.sender);")

    def test_a_mention_outside_a_guard_is_not_a_guard(self) -> None:
        # The distinction the neighbouring predicate cannot make.
        assert not self._fires("emit Changed(from, msg.sender);")

    def test_a_guard_with_no_sender_check_does_not_fire(self) -> None:
        # Ordinary input validation is not a broken authorisation.
        assert not self._fires("require(from.balance() > 0);")

    def test_a_function_with_no_parameters_cannot_be_tainted(self) -> None:
        assert not self._fires("require(owner == msg.sender);", params="")

    def test_it_reports_the_receiver_for_correlation_not_the_shape(self) -> None:
        source = (
            "contract R {\n    function f(address from) external {\n"
            "        require(IVisor(from).owner() == msg.sender);\n"
            "        total += 1;\n    }\n}\n"
        )
        parsed = Syntax.of(source)
        assert parsed is not None
        [ref] = [e for e in run_all(parsed, "src/R.sol") if e.predicate == self.ID]
        assert ref.detail["caller_supplied_receiver_count"] == 1
        assert ref.diagnostic["receivers"] == "from"
        assert ref.locator.function == "f"


class TestALoopAnOutsiderCanLengthen:
    """Three declarations and a shape, none of which needed a compiled backend.

    §4.2 recorded this class as needing storage and dynamic-array types from the
    semantic tier. The declaration states both in source text.
    """

    ID = "loop_bounded_by_externally_growable_storage_array"
    SOURCE = """contract D {
    address[] public voters;
    address[3] public admins;
    address[] internal hidden;

    function payAll() external {
        for (uint256 i = 0; i < voters.length; i++) { payable(voters[i]).transfer(1); }
    }
    function payFixed() external {
        for (uint256 i = 0; i < admins.length; i++) { payable(admins[i]).transfer(1); }
    }
    function payHidden() external {
        for (uint256 i = 0; i < hidden.length; i++) { payable(hidden[i]).transfer(1); }
    }
    function touchesWithoutBounding() external {
        for (uint256 i = 0; i < 10; i++) { payable(voters[i]).transfer(1); }
    }
    function join() external { voters.push(msg.sender); }
    function addHidden() internal { hidden.push(msg.sender); }
}
"""

    def _hits(self) -> list[str]:
        return sorted(
            e.diagnostic["arrays"]  # type: ignore[misc]
            for e in evidence(self.SOURCE)
            if e.predicate == self.ID
        )

    def test_a_dynamic_array_an_outsider_appends_to_fires(self) -> None:
        assert self._hits() == ["voters"]

    def test_a_fixed_array_does_not(self) -> None:
        # No length an outsider can change, so the iteration is bounded by the
        # declaration.
        assert "admins" not in self._hits()

    def test_an_array_only_an_insider_appends_to_does_not(self) -> None:
        # The array is dynamic and nothing external grows it, so the loop's
        # length is the contract's own business.
        assert "hidden" not in self._hits()

    def test_touching_an_array_is_not_being_bounded_by_it(self) -> None:
        # The distinction the condition-only bound exists for: this loop reads
        # `voters` in its body and is bounded by a literal.
        [ref] = [e for e in evidence(self.SOURCE) if e.predicate == self.ID]
        assert ref.locator.start_line == 7

    def test_it_names_the_appender_for_diagnosis(self) -> None:
        [ref] = [e for e in evidence(self.SOURCE) if e.predicate == self.ID]
        assert ref.diagnostic["appenders"] == "join"
        assert ref.detail["array_is_dynamic"] is True


class TestAFreshnessValueAskedForAndDiscarded:
    """Named for the property, which is what lets it work without an ABI.

    The class had been parked on knowing which interface returns a price. It
    does not need to know: a call that hands back a timestamp beside a value,
    whose caller binds the timestamp and never mentions it in a condition, asked
    for a freshness claim and threw it away.
    """

    ID = "multi_return_timestamp_never_reaches_a_guard"

    def _fires(self, body: str) -> bool:
        source = "contract O {\n    uint256 last;\n" + body + "\n}\n"
        return any(e.predicate == self.ID for e in evidence(source))

    def test_an_unconsulted_timestamp_fires(self) -> None:
        assert self._fires(
            """    function f(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        last = uint256(price);
    }"""
        )

    def test_a_consulted_timestamp_does_not(self) -> None:
        assert not self._fires(
            """    function f(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        last = uint256(price);
    }"""
        )

    def test_an_if_consults_it_as_much_as_a_require(self) -> None:
        assert not self._fires(
            """    function f(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        if (block.timestamp - updatedAt > 3600) { revert(); }
        last = uint256(price);
    }"""
        )

    def test_a_single_return_feed_is_silent_rather_than_sound(self) -> None:
        # There is no timestamp to discard. A different situation from a
        # discarded one -- arguably worse -- and not this property.
        assert not self._fires(
            """    function f(address feed) external {
        last = uint256(IFeed(feed).latestAnswer());
    }"""
        )

    def test_a_non_time_binding_does_not_fire(self) -> None:
        # Every uint256 is not a timestamp, which is why the type alone is not
        # the test.
        assert not self._fires(
            """    function f(address pool) external {
        (uint256 reserve0, uint256 reserve1) = IPair(pool).getReserves();
        last = reserve0 + reserve1;
    }"""
        )

    def test_a_time_named_binding_of_the_wrong_type_does_not_fire(self) -> None:
        assert not self._fires(
            """    function f(address feed) external {
        (bool ok, address updatedBy) = IFeed(feed).lastWriter();
        last = ok ? 1 : 0;
    }"""
        )


class TestDividingBeforeMultiplying:
    """Integer division truncates, so the order decides the result."""

    ID = "division_evaluated_before_multiplication"

    def _fires(self, expression: str) -> bool:
        source = (
            "contract A {\n"
            "    function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {\n"
            f"        return {expression};\n    }}\n}}\n"
        )
        return any(e.predicate == self.ID for e in evidence(source))

    def test_dividing_first_fires(self) -> None:
        assert self._fires("a / b * c")

    def test_multiplying_first_does_not(self) -> None:
        assert not self._fires("a * c / b")

    def test_parenthesised_division_first_still_fires(self) -> None:
        assert self._fires("(a / b) * c")

    def test_division_alone_does_not(self) -> None:
        # Truncation on its own is not this property: the property is the order
        # of two operations, and there is only one here.
        assert not self._fires("a / b")

    def test_multiplication_alone_does_not(self) -> None:
        assert not self._fires("a * b")


class TestEveryPredicateIsWiredUp:
    """A predicate nothing references is finished work that runs nowhere.

    It is invisible in a score report, because a class with an unwired predicate
    shows zero predictions exactly as a class with no predicate does -- two
    states sharing one appearance again. A report would surface it after a run;
    this is knowable without running anything, so it fails at commit time
    instead.

    The allowlist turns "deliberately not wired yet" from an invisible state
    into a named decision. And the detectors are *discovered* rather than
    listed: a hand-written list weakens itself the first time somebody adds a
    detector and does not add it here, which is the same silent decay the test
    exists to catch.
    """

    UNWIRED_ON_PURPOSE: frozenset[str] = frozenset()
    """Predicates with no detector, each here because somebody decided so."""

    @staticmethod
    def _detectors() -> list[type[Detector]]:
        found = [
            member
            for member in vars(reference).values()
            if isinstance(member, type)
            and issubclass(member, Detector)
            and getattr(member, "detector_id", None) is not None
        ]
        assert found, "no detectors discovered, so this test would pass vacuously"
        return found

    def test_every_predicate_is_referenced_by_a_detector(self) -> None:
        wired = {
            predicate_id
            for detector in self._detectors()
            for predicate_id in detector.predicate_ids  # type: ignore[attr-defined]
        }
        orphans = {spec.predicate_id for spec in predicates()} - wired
        assert orphans <= self.UNWIRED_ON_PURPOSE, (
            f"predicates no detector references: {sorted(orphans - self.UNWIRED_ON_PURPOSE)}. "
            "Wire them to a detector, or add them to UNWIRED_ON_PURPOSE with a reason."
        )

    def test_every_detector_references_predicates_that_exist(self) -> None:
        # The other direction, which fails just as silently: a detector naming a
        # predicate id that no longer exists reports no evidence and looks like
        # a detector that found nothing.
        known = {spec.predicate_id for spec in predicates()}
        for detector in self._detectors():
            missing = detector.predicate_ids - known  # type: ignore[attr-defined]
            assert not missing, (
                f"{detector.__name__} names predicates that do not exist: {sorted(missing)}"
            )


class TestOneHopAndOneAlias:
    """The two things a register entry said needed the semantic tier.

    Measured before building: a call graph's job is resolving which function a
    call names, and within one file with no overload that is name lookup, which
    is syntactic. A local assigned a collection's length once in a body is the
    same depth-one tracking caller-taint turned out to need. Both were filed as
    tier work by reasoning from the records, which is §4.2's error one layer
    down.
    """

    ID = "loop_bounded_by_externally_growable_storage_array"

    HOP = """contract H {
    address[] voters;

    function payAll() external {
        for (uint256 i = 0; i < voters.length; i++) { payable(voters[i]).transfer(1); }
    }
    function _add(address who) internal { voters.push(who); }
    function join() external { _add(msg.sender); }
}
"""

    ALIAS = """contract A {
    address[] voters;

    function payAll() external {
        uint256 n = voters.length;
        for (uint256 i = 0; i < n; i++) { payable(voters[i]).transfer(1); }
    }
    function join() external { voters.push(msg.sender); }
}
"""

    def _hits(self, source: str) -> list[dict[str, object]]:
        return [{**e.detail, **e.diagnostic} for e in evidence(source) if e.predicate == self.ID]

    def test_an_internal_appender_an_outsider_reaches_fires(self) -> None:
        [hit] = self._hits(self.HOP)
        assert hit["arrays"] == "voters"
        assert hit["appenders"] == "_add via join"

    def test_an_internal_appender_nobody_reaches_does_not(self) -> None:
        source = self.HOP.replace("    function join() external { _add(msg.sender); }\n", "")
        assert self._hits(source) == []

    def test_an_overloaded_appender_is_refused_rather_than_picked(self) -> None:
        # More than one declaration is an overload or an override, where name
        # lookup stops being sound. Refusing is the rule the declaration index
        # already applies to an overloaded name in a report.
        source = self.HOP.replace(
            "    function join() external { _add(msg.sender); }\n",
            "    function _add(address who, uint256 n) internal { voters.push(who); }\n"
            "    function join() external { _add(msg.sender); }\n",
        )
        assert self._hits(source) == []

    def test_a_bound_through_a_local_alias_fires(self) -> None:
        [hit] = self._hits(self.ALIAS)
        assert hit["bound_through_a_local"] is True
        assert hit["arrays"] == "voters"

    def test_an_alias_assigned_twice_is_refused(self) -> None:
        # A name whose value depends on control flow is what def-use is for, and
        # guessing which assignment reached the loop would be the approximation
        # this project refuses everywhere else.
        source = self.ALIAS.replace(
            "        uint256 n = voters.length;\n",
            "        uint256 n = voters.length;\n        n = admins.length;\n",
        ).replace("    address[] voters;", "    address[] voters;\n    address[] admins;")
        assert self._hits(source) == []

    def test_a_direct_bound_still_fires(self) -> None:
        # The path that already worked, kept under test so the extension cannot
        # quietly replace it.
        [hit] = self._hits(self.HOP)
        assert hit["bound_through_a_local"] is False


class TestNameLookupWithinAUnit:
    """What resolving a call amounts to when nothing overloads the name."""

    SOURCE = """contract N {
    function _helper() internal {}
    function caller() external { _helper(); }
    function other() internal { _helper(); }
    function _twice(uint256 a) internal {}
    function _twice(uint256 a, uint256 b) internal {}
}
"""

    def test_callers_are_found_by_name(self) -> None:
        syntax = Syntax.of(self.SOURCE)
        assert syntax is not None
        assert syntax.callers_of("_helper") == ("caller", "other")

    def test_a_qualified_call_is_not_a_caller_in_this_unit(self) -> None:
        syntax = Syntax.of("contract N {\n    function f() external { other._helper(); }\n}\n")
        assert syntax is not None
        assert syntax.callers_of("_helper") == ()

    def test_an_overload_set_is_countable(self) -> None:
        # The condition that decides whether name lookup is sound.
        syntax = Syntax.of(self.SOURCE)
        assert syntax is not None
        assert syntax.declarations_of("_helper") == 1
        assert syntax.declarations_of("_twice") == 2
