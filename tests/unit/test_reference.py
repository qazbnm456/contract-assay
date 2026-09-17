"""This project's own detectors.

The load-bearing test here is `TestVerdictIsNotBoundedByEvidence`. The obvious
verdict rule -- admit only what our predicates already found -- would cap a
detector's measured recall at its predicates' recall, so the benchmark would
score agreement with our static analysis rather than defect detection. That is
the opposite of the question §4.1 asks, and it is invisible in any aggregate
afterwards.
"""

from __future__ import annotations

import pytest

from contract_assay.detectors.base import (
    AnalysisContext,
    LabelSpaceSpec,
    SubmissionLimits,
    TaskOutput,
)
from contract_assay.detectors.reference import (
    AccessControlDetector,
    ArithmeticRoundingDetector,
    DenialOfServiceDetector,
    InsecureRandomnessDetector,
    OracleIntegrityDetector,
    ReentrancyDetector,
    SlippageDetector,
    UncheckedExternalCallDetector,
)
from contract_assay.models import (
    DifficultyLevel,
    EvidenceTier,
    Finding,
    Locator,
    RejectionKind,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline

PATH = "src/Vault.sol"

VAULT = """\
contract Vault {
    address owner;
    uint256 total;
    IERC20 token;

    function setOwner(address o) external { owner = o; }

    function drain(address to) external {
        to.call("");
    }

    function payout(address to, uint256 a) external {
        token.transfer(to, a);
    }

    function lucky() external { total = uint256(blockhash(block.number)); }

    function safe(uint256 a) external {
        (bool ok, ) = msg.sender.call("");
        require(ok, "failed");
        total = a;
    }

    function guarded(address o) external onlyOwner { owner = o; }

    function internalOnly(address o) internal { owner = o; }

    function inertHelper(uint256 a) internal onlyOwner { uint256 x = a; }
}
"""

LABELS = LabelSpaceSpec(
    name="example", version="1", tags={"access-control": []}, severities=["high"]
)


def a_context(level: DifficultyLevel, **over: object) -> AnalysisContext:
    base: dict[str, object] = {
        "source_id": "vault@abc:src/Vault.sol",
        "path": PATH,
        "source": VAULT,
        "tier": EvidenceTier.SYNTACTIC,
        "level": level,
        "limits": SubmissionLimits.for_level(
            level, wall_seconds=30, max_model_calls=2, max_tokens=500
        ),
    }
    return AnalysisContext(**{**base, **over})  # type: ignore[arg-type]


def a_finding(start: int, end: int, quote: str, **over: object) -> Finding:
    base: dict[str, object] = {
        "detector_id": "model",
        "quote": quote,
        "reasoning": "the model's justification",
        "locator": Locator(file=PATH, start_line=start, end_line=end),
    }
    return Finding(**{**base, **over})  # type: ignore[arg-type]


DETECTORS = [
    UncheckedExternalCallDetector,
    InsecureRandomnessDetector,
    AccessControlDetector,
]


class TestDeclarations:
    @pytest.mark.parametrize("cls", DETECTORS)
    def test_each_declares_itself_completely(self, cls: type) -> None:
        detector = cls()
        assert detector.detector_id.startswith("reference-")
        assert isinstance(detector.class_id, VulnerabilityClass)

    def test_difficulty_is_derived_from_the_class(self) -> None:
        assert UncheckedExternalCallDetector().level is DifficultyLevel.S
        assert AccessControlDetector().level is DifficultyLevel.M

    def test_the_escape_hatch_is_closed_at_s(self) -> None:
        # Graded S means a static analyser is expected to win, so a negative
        # result is a clear one and escalation would muddy it.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level)
        assert not ctx.limits.escalation_allowed

    def test_the_shared_base_is_not_a_detector(self) -> None:
        from contract_assay.detectors import reference

        assert getattr(reference._SyntacticDetector, "detector_id", None) is None


class TestEvidence:
    @pytest.mark.parametrize("cls", DETECTORS)
    def test_a_detector_reports_only_its_own_predicates(self, cls: type) -> None:
        # The record has to say which detector observed what, or per-class
        # reporting means nothing.
        detector = cls()
        refs = detector.evidence(a_context(detector.level))
        assert refs
        assert {ref.predicate for ref in refs} <= detector.predicate_ids

    def test_evidence_carries_its_host_function(self) -> None:
        detector = AccessControlDetector()
        refs = detector.evidence(a_context(detector.level))
        assert all(ref.locator.function for ref in refs)

    def test_evidence_is_syntactic_at_this_tier(self) -> None:
        detector = UncheckedExternalCallDetector()
        refs = detector.evidence(a_context(detector.level))
        assert {ref.tier for ref in refs} == {EvidenceTier.SYNTACTIC}

    def test_an_unparseable_unit_yields_no_evidence_rather_than_raising(self) -> None:
        # Unreachable through the harness, which gates such units out first, but
        # a detector is a public interface and may be called directly.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level, source="}{ not solidity ][")
        assert detector.evidence(ctx) == []


class TestPlan:
    @pytest.mark.parametrize("cls", DETECTORS)
    def test_the_instruction_never_contains_the_source(self, cls: type) -> None:
        # The contract is a variable the model explores. Pasting it into the
        # prompt would make the task's difficulty a function of file length.
        detector = cls()
        spec = detector.plan(a_context(detector.level), [])
        assert spec is not None
        assert "contract Vault" not in spec.instruction

    def test_classification_is_requested_only_in_competition_mode(self) -> None:
        detector = AccessControlDetector()
        plain = detector.plan(a_context(detector.level), [])
        labelled = detector.plan(a_context(detector.level, labels=LABELS), [])
        assert plain is not None and plain.expects is TaskOutput.FINDINGS
        assert labelled is not None and labelled.expects is TaskOutput.CLASSIFICATION

    @pytest.mark.parametrize("cls", DETECTORS)
    def test_no_labels_are_claimed_by_default(self, cls: type) -> None:
        detector = cls()
        assert detector.classify(a_context(detector.level, labels=LABELS), []) == ()


class TestVerdictIsNotBoundedByEvidence:
    """The property that keeps the benchmark measuring the right thing."""

    def test_a_defect_the_predicates_cannot_see_is_still_admitted(self) -> None:
        # `IERC20.transfer` returns a discardable bool, and the library cannot
        # tell that `transfer` from `address.transfer`, so no predicate fires
        # here. A model that finds it must be able to score for it.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level)
        assert all(ref.locator.start_line != 13 for ref in detector.evidence(ctx))

        finding = a_finding(13, 13, "token.transfer(to, a);")
        assert detector.verdict(ctx, finding, detector.evidence(ctx)) == []

    def test_the_verdict_does_not_consult_the_evidence_argument(self) -> None:
        # Passing no evidence at all must not change any outcome; the rules are
        # re-derived from the source at the stated location. A gate requiring
        # this detector's own evidence at the locator was written and reverted
        # against this test and the one above: it would cap a model's reach at
        # the deterministic tier's, which is the one thing the three layers
        # exist to avoid.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level)
        finding = a_finding(9, 9, 'to.call("");')
        assert detector.verdict(ctx, finding, []) == []
        assert detector.verdict(ctx, finding, list(detector.evidence(ctx))) == []


class TestUncheckedExternalCallVerdict:
    def _verdict(self, finding: Finding) -> list[str]:
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_a_discarded_result_stands(self) -> None:
        assert self._verdict(a_finding(9, 9, 'to.call("");')) == []

    def test_a_checked_result_is_refuted(self) -> None:
        assert self._verdict(a_finding(19, 19, 'msg.sender.call("");')) == [
            "call_result_is_inspected"
        ]

    def test_a_location_with_no_call_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "address owner;")) == ["no_call_at_locator"]

    def test_a_locator_naming_another_file_is_refuted(self) -> None:
        finding = a_finding(
            9, 9, 'to.call("");', locator=Locator(file="other.sol", start_line=9, end_line=9)
        )
        assert self._verdict(finding) == ["locator_names_another_file"]

    def test_every_rejection_is_a_judgement_not_an_error(self) -> None:
        # A rule was applied and the claim did not meet it, so the run remains a
        # measurement. Reporting it as a citation failure would turn a
        # conclusion into an infrastructure error.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level)
        checks = detector.verdict(ctx, a_finding(2, 2, "address owner;"), detector.evidence(ctx))
        assert all(check.kind is RejectionKind.VERDICT for check in checks)

    def test_an_unparseable_unit_is_a_citation_failure_not_a_verdict(self) -> None:
        # The claim could not be checked at all, so nothing was measured.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level, source="}{ not solidity ][")
        [check] = detector.verdict(ctx, a_finding(1, 1, "x"), detector.evidence(ctx))
        assert check.kind is RejectionKind.CITATION


class TestInsecureRandomnessVerdict:
    def _verdict(self, finding: Finding, **over: object) -> list[str]:
        detector = InsecureRandomnessDetector()
        ctx = a_context(detector.level, **over)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_a_blockhash_read_stands(self) -> None:
        assert self._verdict(a_finding(16, 16, "uint256(blockhash(block.number))")) == []

    def test_a_location_with_no_chain_state_read_is_refuted(self) -> None:
        assert self._verdict(a_finding(6, 6, "owner = o;")) == [
            "no_producer_controlled_read_at_locator"
        ]

    def test_a_claim_inside_a_pure_function_is_refuted(self) -> None:
        # A pure function cannot read block state; the compiler rejects it. So a
        # claim located in one does not describe this source.
        source = """\
contract C {
    function f() external pure returns (uint256) {
        return block.timestamp;
    }
}
"""
        assert self._verdict(a_finding(3, 3, "block.timestamp"), source=source) == [
            "host_cannot_read_chain_state"
        ]


class TestAccessControlVerdict:
    def _verdict(self, finding: Finding, **over: object) -> list[str]:
        detector = AccessControlDetector()
        ctx = a_context(detector.level, **over)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_an_unguarded_external_setter_stands(self) -> None:
        assert self._verdict(a_finding(6, 6, "function setOwner(address o) external")) == []

    def test_a_location_with_no_function_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "address owner;")) == ["no_function_at_locator"]

    def test_an_internal_function_is_refuted(self) -> None:
        assert "host_not_externally_reachable" in self._verdict(
            a_finding(26, 26, "function internalOnly(address o) internal")
        )

    def test_a_modifier_bearing_function_is_refuted(self) -> None:
        assert "host_carries_a_modifier" in self._verdict(
            a_finding(24, 24, "function guarded(address o) external onlyOwner")
        )

    NO_EFFECT = """\
contract Quiet {
    address owner;

    function readOnlyish(address to) external {
        uint256 unused = 1;
    }
}
"""

    def test_a_function_that_changes_and_calls_nothing_is_refuted(self) -> None:
        # The rejection asserts a fact here: nothing is written and nothing is
        # called, so there is genuinely nothing for a check to protect.
        assert "host_writes_no_state" in self._verdict(
            a_finding(4, 6, "function readOnlyish(address to) external"),
            source=self.NO_EFFECT,
        )

    def test_a_function_whose_effect_leaves_the_unit_is_refuted_for_that_reason(self) -> None:
        # `drain` writes nothing and does `to.call("")`, which may change state
        # anywhere. Still rejected -- §2.2 keeps the verdict side strict and an
        # undecided basis is not a confirmation -- but not by asserting that
        # there is nothing to protect, which would be false and would be used to
        # discard a true finding.
        checks = self._verdict(a_finding(8, 10, "function drain(address to) external"))
        assert "host_state_change_indeterminate" in checks
        assert "host_writes_no_state" not in checks

    def test_every_failing_condition_is_reported_not_just_the_first(self) -> None:
        # A conjunction expressed as `and` can say which conjunct failed, which
        # prose in a long prompt cannot. An author should learn all of them in
        # one run rather than discovering them over three submissions.
        # `inertHelper` is internal, carries a modifier, and writes no state.
        checks = self._verdict(a_finding(28, 28, "function inertHelper(uint256 a) internal"))
        assert set(checks) == {
            "host_not_externally_reachable",
            "host_carries_a_modifier",
            "host_writes_no_state",
        }


class TestDenialOfServiceVerdict:
    """The strict side of the class §4.2's audit moved out of the tier."""

    SOURCE = """contract D {
    address[] public voters;
    address[3] public admins;

    function payAll() external {
        for (uint256 i = 0; i < voters.length; i++) { payable(voters[i]).transfer(1); }
    }
    function payFixed() external {
        for (uint256 i = 0; i < admins.length; i++) { payable(admins[i]).transfer(1); }
    }
    function join() external { voters.push(msg.sender); }
}
"""

    def _verdict(self, finding: Finding, source: str | None = None) -> list[str]:
        detector = DenialOfServiceDetector()
        ctx = a_context(detector.level, source=source or self.SOURCE)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_a_loop_over_a_growable_array_stands(self) -> None:
        assert self._verdict(a_finding(6, 6, "for (uint256 i = 0; i < voters.length; i++)")) == []

    def test_a_location_with_no_loop_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "address[] public voters;")) == ["no_loop_at_locator"]

    def test_a_fixed_size_collection_is_refuted(self) -> None:
        # Its length is in the declaration, so no state can grow the iteration.
        assert "loop_not_bounded_by_a_dynamic_collection" in self._verdict(
            a_finding(9, 9, "for (uint256 i = 0; i < admins.length; i++)")
        )

    def test_a_unit_where_nothing_appends_is_refuted(self) -> None:
        source = self.SOURCE.replace(
            "    function join() external { voters.push(msg.sender); }\n", ""
        )
        assert "nothing_an_outsider_can_reach_appends_to_it" in self._verdict(
            a_finding(6, 6, "for (uint256 i = 0; i < voters.length; i++)"), source=source
        )

    def test_an_append_to_a_different_array_does_not_count(self) -> None:
        # Both halves were quantified separately, so a loop over one dynamic
        # array and a push to *another* satisfied the pair with neither being
        # about the other.
        source = self.SOURCE.replace(
            "    function join() external { voters.push(msg.sender); }",
            "    address[] public watchers;\n"
            "    function watch() external { watchers.push(msg.sender); }",
        )
        assert "nothing_an_outsider_can_reach_appends_to_it" in self._verdict(
            a_finding(6, 6, "for (uint256 i = 0; i < voters.length; i++)"), source=source
        )

    def test_an_append_no_outsider_can_reach_does_not_count(self) -> None:
        # "Externally growable" is the whole property, and the verdict never
        # asked: the predicate checks the appender's visibility and the strict
        # side did not. An array only an internal path appends to is not one an
        # outsider makes longer.
        source = self.SOURCE.replace(
            "    function join() external { voters.push(msg.sender); }",
            "    function _join() internal { voters.push(msg.sender); }",
        )
        assert "nothing_an_outsider_can_reach_appends_to_it" in self._verdict(
            a_finding(6, 6, "for (uint256 i = 0; i < voters.length; i++)"), source=source
        )


class TestOracleIntegrityVerdict:
    """The class the audit found was parked on a misdescribed blocker."""

    SOURCE = """contract O {
    uint256 last;

    function stale(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        last = uint256(price);
    }
    function fresh(address feed) external {
        (, int256 price, , uint256 updatedAt, ) = IFeed(feed).latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        last = uint256(price);
    }
}
"""

    def _verdict(self, finding: Finding) -> list[str]:
        detector = OracleIntegrityDetector()
        ctx = a_context(detector.level, source=self.SOURCE)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_a_discarded_freshness_value_stands(self) -> None:
        assert self._verdict(a_finding(4, 6, "function stale(address feed) external")) == []

    def test_a_consulted_one_is_refuted(self) -> None:
        assert "the_freshness_value_does_reach_a_guard" in self._verdict(
            a_finding(8, 12, "function fresh(address feed) external")
        )

    def test_a_location_unpacking_nothing_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "uint256 last;")) == ["no_multi_return_at_locator"]

    OTHER_MULTI_RETURNS = """contract M {
    uint256 last;

    function holder(uint256 id, address who) external returns (bool) {
        (, uint256 amount) = shares[id].tryGet(who);
        return amount > 0;
    }
    function claimable(uint256 id) external returns (uint256) {
        (uint256 toDistribute, , , ) = _claimable(id);
        return toDistribute;
    }
}
"""

    @pytest.mark.parametrize(
        ("lo", "hi", "cited"),
        [(4, 7, "function holder("), (8, 11, "function claimable(")],
    )
    def test_a_discarded_value_of_another_kind_is_not_a_freshness_claim(
        self, lo: int, hi: int, cited: str
    ) -> None:
        # The conjunction used to be about any multi-return, and this is what
        # that admitted: a success flag from `EnumerableMap.tryGet` and three
        # unnamed slots from an internal call. Fifteen firings over one sample,
        # none of them an oracle, while the evidence layer had the right rule --
        # a binding that is a time by type *and* name -- and the verdict never
        # asked for it.
        detector = OracleIntegrityDetector()
        ctx = a_context(detector.level, source=self.OTHER_MULTI_RETURNS)
        checks = [
            check.check
            for check in detector.verdict(ctx, a_finding(lo, hi, cited), detector.evidence(ctx))
        ]
        assert checks == ["no_time_typed_binding_at_locator"]


class TestArithmeticRoundingVerdict:
    """One of the three things §4.2 had merged under this class."""

    SOURCE = """contract A {
    uint256 last;

    function loses(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return a / b * c;
    }
    function keeps(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return a * c / b;
    }
}
"""

    def _verdict(self, finding: Finding) -> list[str]:
        detector = ArithmeticRoundingDetector()
        ctx = a_context(detector.level, source=self.SOURCE)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_dividing_before_multiplying_stands(self) -> None:
        assert self._verdict(a_finding(5, 5, "return a / b * c;")) == []

    def test_the_other_order_is_refuted(self) -> None:
        assert self._verdict(a_finding(8, 8, "return a * c / b;")) == [
            "nothing_divides_before_multiplying"
        ]

    def test_a_location_with_no_arithmetic_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "uint256 last;")) == ["no_arithmetic_at_locator"]


class TestReentrancyVerdict:
    """Single-function scope, declared rather than implied."""

    SOURCE = """contract R {
    uint256 total;
    mapping(address => uint256) balances;

    function withdrawUnsafe(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
    function withdrawSafe(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    function readOnly(address to) external {
        IERC20(to).balanceOf(to);
    }
}
"""

    def _verdict(self, finding: Finding) -> list[str]:
        detector = ReentrancyDetector()
        ctx = a_context(detector.level, source=self.SOURCE)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_a_write_after_a_transfer_stands(self) -> None:
        assert self._verdict(a_finding(6, 6, "payable(msg.sender).transfer(amount);")) == []

    def test_writing_before_the_call_is_refuted(self) -> None:
        assert self._verdict(a_finding(11, 11, "payable(msg.sender).transfer(amount);")) == [
            "no_state_written_after_the_call"
        ]

    def test_a_location_with_no_call_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "uint256 total;")) == ["no_call_at_locator"]

    def test_an_ordinary_member_call_is_refuted(self) -> None:
        # Not a language-level hand-off of control, so re-entry through it is
        # not what this tier can see.
        assert self._verdict(a_finding(14, 14, "IERC20(to).balanceOf(to);")) == [
            "call_is_not_a_language_level_transfer"
        ]


class TestSlippageVerdict:
    """Where the unscoped predicate gets scoped, countably."""

    SOURCE = """contract S {
    function swapUnbounded(uint256 amount, address[] calldata path) external {
        router.swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp);
    }
    function approveZero(address token) external {
        IERC20(token).approve(address(router), 0);
    }
    function reset() external {
        counter.set(0);
    }
}
"""

    def _verdict(self, finding: Finding) -> list[str]:
        detector = SlippageDetector()
        ctx = a_context(detector.level, source=self.SOURCE)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_a_zero_minimum_in_a_multi_argument_call_stands(self) -> None:
        assert self._verdict(a_finding(3, 3, "router.swapExactTokensForTokens(")) == []

    def test_a_two_argument_call_passing_zero_also_stands(self) -> None:
        # Deliberately admitted: the verdict layer scopes by argument count, not
        # by the callee's name, because a name cannot survive an aliased import.
        # An approval of zero is a false positive this detector pays for (§7.2)
        # rather than one it suppresses by guessing at the callee.
        assert self._verdict(a_finding(6, 6, "IERC20(token).approve(")) == []

    def test_a_single_argument_call_is_refuted(self) -> None:
        assert "call_takes_too_few_arguments_to_be_an_exchange" in self._verdict(
            a_finding(9, 9, "counter.set(0);")
        )

    def test_a_location_with_no_call_is_refuted(self) -> None:
        assert self._verdict(a_finding(1, 1, "contract S {")) == ["no_call_at_locator"]

    WHOLE_FUNCTION = """contract V {
    function merge(uint256 from, uint256 to) external {
        IFluxToken(FLUX).mergeFlux(from, to);
        locked[from] = LockedBalance(0, 0, false, 0);
        _checkpoint(from, locked[from], LockedBalance(0, 0, false, 0));
    }
}
"""

    def test_three_conditions_met_by_three_different_calls_is_not_an_exchange(self) -> None:
        # The defect this closes. Over a whole function,
        # `IFluxToken(FLUX).mergeFlux(from, to)` supplies the receiver and the
        # two arguments while `LockedBalance(0, 0, false, 0)` supplies the zero,
        # and each condition was written as its own `any(...)` over the set of
        # calls -- so the verdict passed on a function that exchanges nothing.
        # The receiver rule had been added for exactly that struct construction
        # and did not close it, because it was about the set and not about a
        # call. Measured: three of four firings over one corpus were this.
        detector = SlippageDetector()
        ctx = a_context(detector.level, source=self.WHOLE_FUNCTION)
        checks = [
            check.check
            for check in detector.verdict(
                ctx, a_finding(2, 6, "    function merge("), detector.evidence(ctx)
            )
        ]
        assert checks == ["no_one_call_is_an_unbounded_exchange"]

    def test_one_call_holding_all_three_still_stands(self) -> None:
        # The conjunction is the point, not strictness: a genuine unbounded
        # exchange in the same span still passes.
        source = self.WHOLE_FUNCTION.replace(
            "IFluxToken(FLUX).mergeFlux(from, to);",
            "router.swapExactTokensForTokens(from, 0, path, address(this), to);",
        )
        detector = SlippageDetector()
        ctx = a_context(detector.level, source=source)
        assert (
            detector.verdict(ctx, a_finding(2, 6, "    function merge("), detector.evidence(ctx))
            == []
        )


class TestAValueReadIsNotAValueUsedAsRandom:
    """The class is about using a producer-chosen value *as though unpredictable*.

    A value reaches a selection three ways without leaving the expression: a
    hash, a modulo, or a subscript's index. One that reaches none of them is
    read as a quantity -- a deadline, a stamp -- however unpredictable its
    source. Measured: of 88 firings over one corpus, none reached any of the
    three, and the detector had been claiming all of them.

    Two mistakes on the way here are pinned below, because both passed the
    fires-correctly cases and failed the refuses-correctly one.
    """

    def _verdict(self, body: str, cited: str, lo: int, hi: int) -> list[str]:
        source = (
            "contract R {\n"
            "    uint256 deadline;\n"
            "    mapping(uint256 => uint256) lastEarn;\n"
            f"{body}\n}}\n"
        )
        detector = InsecureRandomnessDetector()
        ctx = a_context(detector.level, source=source)
        finding = a_finding(lo, hi, cited)
        return [check.check for check in detector.verdict(ctx, finding, detector.evidence(ctx))]

    def test_hashing_the_value_stands(self) -> None:
        body = (
            "    function f() external view returns (uint256) {\n"
            "        return uint256(keccak256(abi.encode(block.timestamp)));\n    }"
        )
        assert self._verdict(body, "uint256(keccak256(abi.encode(block.timestamp)))", 5, 5) == []

    def test_indexing_by_the_value_stands(self) -> None:
        body = (
            "    function f(uint256[] memory xs) external view returns (uint256) {\n"
            "        return xs[block.number % xs.length];\n    }"
        )
        assert self._verdict(body, "xs[block.number % xs.length]", 5, 5) == []

    def test_a_deadline_comparison_is_refuted(self) -> None:
        body = (
            "    function f() external view returns (bool) {\n"
            "        return block.timestamp > deadline;\n    }"
        )
        assert self._verdict(body, "block.timestamp > deadline", 5, 5) == [
            "the_value_reaches_no_selection"
        ]

    def test_a_subscript_on_the_line_is_not_a_selection_of_the_value(self) -> None:
        # The first version compared line numbers, and two nodes on one line
        # contain each other by line -- so `lastEarn[id] = block.timestamp;`
        # read as a timestamp used as an index. That was 21 of 88 firings.
        body = (
            "    function f(uint256 id) external {\n        lastEarn[id] = block.timestamp;\n    }"
        )
        assert self._verdict(body, "lastEarn[id] = block.timestamp;", 5, 5) == [
            "the_value_reaches_no_selection"
        ]

    def test_a_comparison_beside_a_subscript_is_not_a_selection(self) -> None:
        # The second version took the whole subscript node, and the grammar
        # gives `block.timestamp > locked[id]` a subscript whose *base* is
        # `block.timestamp > locked` -- so the node contained a read nowhere
        # near the index. The index child is what matters, and indexing by a
        # value is the property anyway.
        body = (
            "    function f(uint256 id) external view returns (bool) {\n"
            "        return block.timestamp > lastEarn[id];\n    }"
        )
        assert self._verdict(body, "block.timestamp > lastEarn[id]", 5, 5) == [
            "the_value_reaches_no_selection"
        ]


class TestAClassAboutOneSiteIsCheckedAtOneSite:
    """Three verdicts had conditions quantified over a *set* of sites.

    Found in the slippage verdict, where three conditions were met by three
    different calls and the verdict passed on a function that exchanges
    nothing. The same shape was then in the reentrancy verdict -- a write after
    any call rather than after the transfer -- and in access control, where a
    quoted excerpt covering two functions could satisfy every condition with
    neither function satisfying all of them.

    The access-control case changed nothing on the sample that prompted the
    look: 66 predictions before and after. It is a restriction held by argument
    and by this test rather than by a measured false positive, and worth saying
    so plainly.
    """

    TWO_FUNCTIONS = """contract V {
    uint256 total;

    function reachableButHarmless(uint256 a) external returns (uint256) {
        return a + 1;
    }

    function _internalStateChange(uint256 a) internal {
        total = a;
    }
}
"""

    def test_two_functions_in_one_span_do_not_add_up_to_one_instance(self) -> None:
        # `reachableButHarmless` is externally reachable and unguarded but
        # writes nothing; `_internalStateChange` writes state but cannot be
        # called from outside. Neither is an unguarded state change.
        detector = AccessControlDetector()
        ctx = a_context(detector.level, source=self.TWO_FUNCTIONS)
        checks = [
            check.check
            for check in detector.verdict(
                ctx, a_finding(4, 10, "contract V {"), detector.evidence(ctx)
            )
        ]
        assert checks
        assert "host_writes_no_state" in checks or "host_not_externally_reachable" in checks

    def test_one_function_holding_both_properties_still_stands(self) -> None:
        source = """contract V {
    uint256 total;

    function setTotal(uint256 a) external {
        total = a;
    }
}
"""
        detector = AccessControlDetector()
        ctx = a_context(detector.level, source=source)
        assert (
            detector.verdict(ctx, a_finding(4, 6, "    function setTotal("), detector.evidence(ctx))
            == []
        )

    def test_a_write_after_an_unrelated_call_is_not_reentrancy(self) -> None:
        # The low-level call is below the write; the call above it is internal.
        # Quantified over every call, the write counted as "after a call".
        source = """contract V {
    mapping(address => uint256) balances;

    function withdraw(uint256 amount) external {
        _accrue(amount);
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""
        detector = ReentrancyDetector()
        ctx = a_context(detector.level, source=source)
        checks = [
            check.check
            for check in detector.verdict(
                ctx, a_finding(4, 9, "    function withdraw("), detector.evidence(ctx)
            )
        ]
        assert checks == ["no_state_written_after_the_call"]


class TestTheRoundingIdiomStaysExcluded:
    """`(a / b) * b` rounds down to a multiple of `b`, deliberately.

    The predicate was narrowed to exclude it after it accounted for 22 of 26
    reported sites, and the verdict was not -- so the verdict went on accepting
    exactly what the evidence layer had been narrowed to reject. Second class
    where the property lived in the layer that does not decide.
    """

    SOURCE = """contract E {
    uint256 last;

    function epoch() external view returns (uint256) {
        return (block.timestamp / DURATION) * DURATION;
    }
    function scaled(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return (a / b) * c;
    }
}
"""

    def _verdict(self, lo: int, hi: int, cited: str) -> list[str]:
        detector = ArithmeticRoundingDetector()
        ctx = a_context(detector.level, source=self.SOURCE)
        return [
            check.check
            for check in detector.verdict(ctx, a_finding(lo, hi, cited), detector.evidence(ctx))
        ]

    def test_scaling_by_the_divisor_is_refuted(self) -> None:
        assert self._verdict(4, 6, "    function epoch()") == ["the_multiplier_is_the_divisor"]

    def test_a_different_multiplier_still_stands(self) -> None:
        assert self._verdict(7, 9, "    function scaled(") == []


class TestReadingTheSenderIsNotGuardingOnIt:
    """And this tier cannot tell the two apart, so it declines both.

    The predicate has treated a body that reads `msg.sender` as a non-finding
    from the start -- coarse on purpose, because requiring the reference to sit
    inside a condition would fire on every permissionless-by-design function.
    The verdict never asked, and 47 of 59 unadjudicated predictions over one
    sample were exactly those functions. Fourth class in a row where the strict
    layer was looser than its own evidence.
    """

    SOURCE = """contract P {
    mapping(address => uint256) balances;
    address owner;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    function setOwner(address who) external {
        owner = who;
    }
}
"""

    def _verdict(self, lo: int, hi: int, cited: str) -> list[str]:
        detector = AccessControlDetector()
        ctx = a_context(detector.level, source=self.SOURCE)
        return [
            check.check
            for check in detector.verdict(ctx, a_finding(lo, hi, cited), detector.evidence(ctx))
        ]

    def test_a_permissionless_deposit_is_refuted(self) -> None:
        assert self._verdict(5, 7, "    function deposit()") == ["host_reads_the_sender"]

    def test_an_unguarded_setter_still_stands(self) -> None:
        assert self._verdict(8, 10, "    function setOwner(") == []
