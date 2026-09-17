"""The whole deterministic pipeline: no model, no network, no toolchain.

Every test here goes from a source unit to a `DetectorRun`, which is the only
artefact anything downstream scores. What it checks is not that the detectors
are clever -- the unit suites do that -- but that the pieces compose into a
record whose outcome means what §1.2 says it means.

The two outcomes that are *not* measurements are the ones worth the most
attention, because both are easy to produce accidentally and impossible to spot
afterwards: an error recorded as a clean result, and a skipped unit recorded as
a negative.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from contract_assay.detectors.base import AnalysisContext, Detector, SubmissionLimits
from contract_assay.detectors.reference import (
    AccessControlDetector,
    InsecureRandomnessDetector,
    UncheckedExternalCallDetector,
)
from contract_assay.detectors.runner import run_detector
from contract_assay.models import (
    CitationStatus,
    DifficultyLevel,
    EvidenceRef,
    EvidenceTier,
    FailedCheck,
    Finding,
    InvalidReason,
    Locator,
    Outcome,
    RejectionKind,
    SkipReason,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline

PATH = "src/Vault.sol"

VULNERABLE = """\
contract Vault {
    address owner;
    uint256 total;

    function setOwner(address o) external {
        owner = o;
    }

    function drain(address to) external {
        to.call("");
    }
}
"""

GUARDED = """\
contract Vault {
    address owner;

    function setOwner(address o) external {
        require(msg.sender == owner, "not owner");
        owner = o;
    }
}
"""


def a_context(level: DifficultyLevel, source: str = VULNERABLE, **over: object) -> AnalysisContext:
    base: dict[str, object] = {
        "source_id": "vault@abc123def456:src/Vault.sol",
        "path": PATH,
        "source": source,
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


class TestAMeasuredRun:
    def test_a_correct_claim_produces_a_vulnerable_measurement(self) -> None:
        run = run_detector(
            UncheckedExternalCallDetector(),
            a_context(DifficultyLevel.S),
            model_findings=[a_finding(10, 10, 'to.call("");')],
            produced_without_a_model=True,
        )
        assert run.outcome is Outcome.VULNERABLE
        assert run.outcome.is_measurement
        assert len(run.verified_findings) == 1
        assert run.evidence_tier is EvidenceTier.SYNTACTIC
        assert run.level is DifficultyLevel.S

    def test_a_silent_model_produces_a_clean_measurement(self) -> None:
        run = run_detector(UncheckedExternalCallDetector(), a_context(DifficultyLevel.S))
        assert run.outcome is Outcome.CLEAN
        assert run.findings == []

    def test_evidence_is_recorded_even_when_the_model_says_nothing(self) -> None:
        # §2.1, which is the guarantee no amount of prompt tuning can restore
        # once lost: the model may decline to report, and it still cannot remove
        # an evidence item from the record.
        run = run_detector(UncheckedExternalCallDetector(), a_context(DifficultyLevel.S))
        assert run.outcome is Outcome.CLEAN
        assert run.evidence, "a clean verdict must still carry what was observed"
        assert {ref.predicate for ref in run.evidence} == {"low_level_call_result_discarded"}

    def test_a_rejected_claim_is_a_clean_measurement_and_is_retained(self) -> None:
        # A verdict predicate applied its rule, so the run measured something.
        # The rejected finding stays in the record with the reason, so the recall
        # cost of the rule is a number someone can argue with.
        run = run_detector(
            UncheckedExternalCallDetector(),
            a_context(DifficultyLevel.S),
            model_findings=[a_finding(2, 2, "address owner;")],
            produced_without_a_model=True,
        )
        assert run.outcome is Outcome.CLEAN
        assert run.verified_findings == []
        [rejected] = run.findings
        assert rejected.status is CitationStatus.UNVERIFIED
        assert [c.check for c in rejected.failed_checks] == ["no_call_at_locator"]
        assert all(c.kind is RejectionKind.VERDICT for c in rejected.failed_checks)

    def test_a_clean_run_on_guarded_source_reports_no_evidence(self) -> None:
        # The unit was read and the shape is absent, which is a different answer
        # from "could not read it".
        run = run_detector(AccessControlDetector(), a_context(DifficultyLevel.M, source=GUARDED))
        assert run.outcome is Outcome.CLEAN
        assert run.evidence == []


class TestRunsThatAreNotMeasurements:
    def test_a_broken_citation_is_invalid_not_clean(self) -> None:
        # The subtlest failure in the whole design: recording this as `clean`
        # asserts "nothing here" on the strength of a citation nobody confirmed.
        run = run_detector(
            UncheckedExternalCallDetector(),
            a_context(DifficultyLevel.S),
            model_findings=[a_finding(10, 10, "selfdestruct(owner);")],
            produced_without_a_model=True,
        )
        assert run.outcome is Outcome.INVALID
        assert not run.outcome.is_measurement
        assert run.invalid_reason is InvalidReason.CITATION_UNVERIFIED
        assert run.has_citation_failure

    def test_a_verified_finding_survives_a_broken_citation_elsewhere(self) -> None:
        # One unconfirmable claim does not undo a claim that checked out: the run
        # measured something positive, and that is what `vulnerable` records.
        run = run_detector(
            UncheckedExternalCallDetector(),
            a_context(DifficultyLevel.S),
            model_findings=[
                a_finding(10, 10, 'to.call("");'),
                a_finding(10, 10, "selfdestruct(owner);"),
            ],
            produced_without_a_model=True,
        )
        assert run.outcome is Outcome.VULNERABLE
        assert len(run.verified_findings) == 1
        assert run.has_citation_failure

    def test_an_unreadable_unit_is_skipped_with_a_cause(self) -> None:
        run = run_detector(
            UncheckedExternalCallDetector(),
            a_context(DifficultyLevel.S, source="}{ not solidity ]["),
        )
        assert run.outcome is Outcome.SKIPPED
        assert run.skip_reason is SkipReason.UNPARSEABLE
        # A unit that was never analysed cannot report any of these.
        assert run.findings == [] and run.evidence == [] and run.evidence_tier is None

    def test_a_unit_declaring_no_contract_is_skipped(self) -> None:
        source = (
            "pragma solidity ^0.8.20;\n"
            "function free(uint256 x) pure returns (uint256) { return x; }\n"
        )
        run = run_detector(
            UncheckedExternalCallDetector(), a_context(DifficultyLevel.S, source=source)
        )
        assert run.outcome is Outcome.SKIPPED
        assert run.skip_reason is SkipReason.NO_CONTRACT_DECLARATION

    def test_a_misbehaving_submission_is_invalid_not_clean(self) -> None:
        # A submission's bug must never be recorded as the code under test being
        # sound.
        class Rogue(Detector):
            detector_id = "rogue"
            class_id = VulnerabilityClass.UNCHECKED_EXTERNAL_CALL
            api_version = "1.1"

            def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
                return None  # type: ignore[return-value]

            def verdict(
                self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
            ) -> Sequence[FailedCheck]:
                return []

        run = run_detector(Rogue(), a_context(DifficultyLevel.S))
        assert run.outcome is Outcome.INVALID
        assert run.invalid_reason is InvalidReason.SCHEMA_VIOLATION
        assert run.findings == []

    def test_a_detector_that_raises_is_invalid_not_a_crash(self) -> None:
        class Exploding(Detector):
            detector_id = "exploding"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = "1.1"

            def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
                raise RuntimeError("submission bug")

            def verdict(
                self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
            ) -> Sequence[FailedCheck]:
                return []

        run = run_detector(Exploding(), a_context(DifficultyLevel.M))
        assert run.outcome is Outcome.INVALID
        assert run.invalid_reason is InvalidReason.SCHEMA_VIOLATION


class TestTheRecordIsSelfConsistent:
    """Whatever the input, the run that comes back has to be constructible.

    `DetectorRun`'s validators are the point of the data contract, so a runner
    that could produce a state they reject would be a defect discovered at the
    worst possible moment -- mid-benchmark, on one unit in a thousand.
    """

    DETECTORS: tuple[type[Detector], ...] = (
        UncheckedExternalCallDetector,
        InsecureRandomnessDetector,
        AccessControlDetector,
    )

    SOURCES = (
        VULNERABLE,
        GUARDED,
        "}{ not solidity ][",
        "   ",
        "contract C {}",
        "contract C { uint256 x; }",
        "interface I { function f() external; }",
        "contract C { function f() external { a.b().c(); } }",
    )

    CLAIMS: tuple[tuple[int, int, str], ...] = (
        (10, 10, 'to.call("");'),
        (1, 1, "contract Vault {"),
        (999, 999, "off the end"),
        (2, 2, "nonsense that is not in any source"),
    )

    @pytest.mark.parametrize("cls", DETECTORS)
    @pytest.mark.parametrize("source", SOURCES)
    def test_every_pairing_yields_a_valid_run(self, cls: type[Detector], source: str) -> None:
        detector = cls()
        ctx = a_context(detector.level, source=source)
        for start, end, quote in self.CLAIMS:
            run = run_detector(
                detector,
                ctx,
                model_findings=[a_finding(start, end, quote)],
                produced_without_a_model=True,
            )
            # The invariants the type promises, restated as assertions so a
            # failure names which one broke.
            assert run.outcome.is_measurement == (
                run.outcome in (Outcome.VULNERABLE, Outcome.CLEAN)
            )
            if run.outcome is Outcome.CLEAN:
                assert not run.has_citation_failure
                assert run.verified_findings == []
            if run.outcome is Outcome.INVALID:
                assert run.invalid_reason is not None
                assert run.verified_findings == []
            if run.outcome is Outcome.SKIPPED:
                assert run.skip_reason is not None
                assert not run.findings and not run.evidence
            if run.outcome.is_measurement:
                assert run.evidence_tier is not None

    @pytest.mark.parametrize("cls", DETECTORS)
    def test_a_run_round_trips_through_json(self, cls: type[Detector]) -> None:
        # The record is what a scorer reads, and it reads it from a file.
        detector = cls()
        run = run_detector(
            detector,
            a_context(detector.level),
            model_findings=[a_finding(10, 10, 'to.call("");')],
            produced_without_a_model=True,
        )
        restored: Any = type(run).model_validate_json(run.model_dump_json())
        assert restored == run
