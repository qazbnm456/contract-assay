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
        assert detector.verdict(ctx, finding, []) == []

    def test_the_verdict_does_not_consult_the_evidence_argument(self) -> None:
        # Passing no evidence at all must not change any outcome; the rules are
        # re-derived from the source at the stated location.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level)
        finding = a_finding(9, 9, 'to.call("");')
        assert detector.verdict(ctx, finding, []) == []
        assert detector.verdict(ctx, finding, list(detector.evidence(ctx))) == []


class TestUncheckedExternalCallVerdict:
    def _verdict(self, finding: Finding) -> list[str]:
        detector = UncheckedExternalCallDetector()
        return [check.check for check in detector.verdict(a_context(detector.level), finding, [])]

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
        checks = detector.verdict(a_context(detector.level), a_finding(2, 2, "address owner;"), [])
        assert all(check.kind is RejectionKind.VERDICT for check in checks)

    def test_an_unparseable_unit_is_a_citation_failure_not_a_verdict(self) -> None:
        # The claim could not be checked at all, so nothing was measured.
        detector = UncheckedExternalCallDetector()
        ctx = a_context(detector.level, source="}{ not solidity ][")
        [check] = detector.verdict(ctx, a_finding(1, 1, "x"), [])
        assert check.kind is RejectionKind.CITATION


class TestInsecureRandomnessVerdict:
    def _verdict(self, finding: Finding, **over: object) -> list[str]:
        detector = InsecureRandomnessDetector()
        ctx = a_context(detector.level, **over)
        return [check.check for check in detector.verdict(ctx, finding, [])]

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
        return [check.check for check in detector.verdict(ctx, finding, [])]

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
        return [check.check for check in detector.verdict(ctx, finding, [])]

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
        assert "nothing_appends_to_it_in_this_unit" in self._verdict(
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
        return [check.check for check in detector.verdict(ctx, finding, [])]

    def test_a_discarded_freshness_value_stands(self) -> None:
        assert self._verdict(a_finding(4, 6, "function stale(address feed) external")) == []

    def test_a_consulted_one_is_refuted(self) -> None:
        assert "an_unpacked_value_does_reach_a_guard" in self._verdict(
            a_finding(8, 12, "function fresh(address feed) external")
        )

    def test_a_location_unpacking_nothing_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "uint256 last;")) == ["no_multi_return_at_locator"]


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
        return [check.check for check in detector.verdict(ctx, finding, [])]

    def test_dividing_before_multiplying_stands(self) -> None:
        assert self._verdict(a_finding(5, 5, "return a / b * c;")) == []

    def test_the_other_order_is_refuted(self) -> None:
        assert self._verdict(a_finding(8, 8, "return a * c / b;")) == [
            "nothing_divides_before_multiplying"
        ]

    def test_a_location_with_no_arithmetic_is_refuted(self) -> None:
        assert self._verdict(a_finding(2, 2, "uint256 last;")) == ["no_arithmetic_at_locator"]
