"""The data contract's invariants, stated as tests.

Each test here names the failure mode it forbids. A record that violates one of
these must fail to construct: discipline in review is not a substitute for a type
that cannot be built wrong, because the failures guarded against here are silent
ones. They do not raise; they produce plausible numbers.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contract_assay.models import (
    CitationStatus,
    DetectorRun,
    DifficultyLevel,
    EvidenceRef,
    EvidenceTier,
    Finding,
    InvalidReason,
    Locator,
    Outcome,
    SkipReason,
    VerifiedFinding,
)

pytestmark = pytest.mark.offline


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def a_locator(**over: object) -> Locator:
    base: dict[str, object] = {
        "file": "src/Vault.sol",
        "contract": "Vault",
        "function": "withdraw",
        "start_line": 120,
        "end_line": 126,
    }
    return Locator(**{**base, **over})  # type: ignore[arg-type]


def an_evidence_ref() -> EvidenceRef:
    return EvidenceRef(
        predicate="swap_call_min_out_is_literal_zero",
        tier=EvidenceTier.SEMANTIC,
        locator=a_locator(),
        detail={"argument_index": 1, "literal": 0},
    )


def a_finding() -> Finding:
    return Finding(
        detector_id="slippage.no_min_out",
        locator=a_locator(),
        quote="router.swapExactTokensForTokens(amountIn, 0, path, address(this), deadline);",
        reasoning="The minimum-output argument is the literal 0, so any output is accepted.",
        evidence=[an_evidence_ref()],
    )


def a_verified(status: CitationStatus = CitationStatus.VERIFIED) -> VerifiedFinding:
    return VerifiedFinding(
        finding=a_finding(),
        status=status,
        failed_checks=[] if status is CitationStatus.VERIFIED else ["quote_matches_source"],
    )


def a_run(**over: object) -> DetectorRun:
    base: dict[str, object] = {
        "detector_id": "slippage.no_min_out",
        "class_id": "slippage",
        "level": DifficultyLevel.Q,
        "source_id": "vault@a1b2c3d",
        "outcome": Outcome.VULNERABLE,
        "evidence_tier": EvidenceTier.SEMANTIC,
        "findings": [a_verified()],
        "evidence": [an_evidence_ref()],
    }
    return DetectorRun(**{**base, **over})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Localization (A1)
# ---------------------------------------------------------------------------


class TestLocator:
    def test_rejects_inverted_span(self) -> None:
        with pytest.raises(ValidationError, match="precedes"):
            a_locator(start_line=200, end_line=100)

    def test_rejects_zero_indexed_lines(self) -> None:
        # Compilers and editors are 1-indexed; a 0 here means someone converted wrong.
        with pytest.raises(ValidationError):
            a_locator(start_line=0)

    def test_renders_a_clickable_reference(self) -> None:
        assert str(a_locator()) == "src/Vault.sol:120-126 (Vault:withdraw)"
        assert str(a_locator(start_line=120, end_line=120)) == "src/Vault.sol:120 (Vault:withdraw)"

    def test_renders_without_optional_qualifiers(self) -> None:
        bare = Locator(file="src/Vault.sol", start_line=1, end_line=2)
        assert str(bare) == "src/Vault.sol:1-2"

    def test_is_immutable(self) -> None:
        with pytest.raises(ValidationError):
            a_locator().file = "other.sol"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Citation status (D1): a rejection must name itself
# ---------------------------------------------------------------------------


class TestVerifiedFinding:
    def test_verified_finding_cannot_carry_failed_checks(self) -> None:
        with pytest.raises(ValidationError, match="cannot carry failed checks"):
            VerifiedFinding(
                finding=a_finding(),
                status=CitationStatus.VERIFIED,
                failed_checks=["quote_matches_source"],
            )

    def test_unverified_finding_must_name_what_failed(self) -> None:
        # A silent rejection is the defect. If a verdict predicate turns a finding
        # away, the predicate is named, counted and reportable.
        with pytest.raises(ValidationError, match="must name what failed"):
            VerifiedFinding(finding=a_finding(), status=CitationStatus.UNVERIFIED)

    def test_a_finding_must_quote_something(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                detector_id="d",
                locator=a_locator(),
                quote="",
                reasoning="...",
            )


# ---------------------------------------------------------------------------
# Outcome accounting (A2): failures never become measurements
# ---------------------------------------------------------------------------


class TestOutcomeAccounting:
    def test_only_vulnerable_and_clean_are_scored(self) -> None:
        assert Outcome.VULNERABLE.is_measurement
        assert Outcome.CLEAN.is_measurement
        assert not Outcome.INVALID.is_measurement
        assert not Outcome.SKIPPED.is_measurement

    def test_clean_must_not_carry_a_failure_reason(self) -> None:
        # Conflating the two turns a false-negative count into a blend of model
        # misses and infrastructure failures, attributable to neither.
        with pytest.raises(ValidationError, match="must not carry a failure reason"):
            a_run(
                outcome=Outcome.CLEAN,
                findings=[],
                invalid_reason=InvalidReason.TRANSPORT_FAILURE,
            )

    def test_invalid_must_state_its_cause(self) -> None:
        with pytest.raises(ValidationError, match="must state its cause"):
            a_run(outcome=Outcome.INVALID, findings=[], evidence_tier=None)

    def test_skipped_must_state_its_cause(self) -> None:
        with pytest.raises(ValidationError, match="must state its cause"):
            a_run(outcome=Outcome.SKIPPED, findings=[], evidence_tier=None)

    def test_vulnerable_requires_a_verified_finding(self) -> None:
        with pytest.raises(ValidationError, match="requires at least one verified finding"):
            a_run(findings=[a_verified(CitationStatus.UNVERIFIED)])

    def test_clean_contradicts_a_verified_finding(self) -> None:
        with pytest.raises(ValidationError, match="contradicts a verified finding"):
            a_run(outcome=Outcome.CLEAN)

    def test_a_scored_outcome_records_its_evidence_tier(self) -> None:
        # A 'clean' reached on syntactic evidence is a weaker claim than one reached
        # with def-use and call-graph data. Reports must be able to tell them apart.
        with pytest.raises(ValidationError, match="must record the evidence tier"):
            a_run(evidence_tier=None)

    def test_a_skipped_source_has_no_evidence_tier(self) -> None:
        with pytest.raises(ValidationError, match="no evidence tier"):
            a_run(
                outcome=Outcome.SKIPPED,
                findings=[],
                skip_reason=SkipReason.UNPARSEABLE,
                evidence_tier=EvidenceTier.SYNTACTIC,
            )

    def test_failure_reasons_do_not_leak_onto_other_outcomes(self) -> None:
        with pytest.raises(ValidationError, match="invalid_reason set on a vulnerable"):
            a_run(invalid_reason=InvalidReason.BUDGET_EXHAUSTED)


class TestValidConstructions:
    def test_a_vulnerable_run_is_accepted(self) -> None:
        run = a_run()
        assert run.outcome is Outcome.VULNERABLE
        assert len(run.verified_findings) == 1

    def test_a_clean_run_is_accepted(self) -> None:
        run = a_run(outcome=Outcome.CLEAN, findings=[])
        assert run.verified_findings == []

    def test_an_invalid_run_keeps_its_unverified_findings(self) -> None:
        # The claim is retained with its reason. Dropping it would erase the evidence
        # that the model said something unverifiable.
        run = a_run(
            outcome=Outcome.INVALID,
            findings=[a_verified(CitationStatus.UNVERIFIED)],
            invalid_reason=InvalidReason.CITATION_UNVERIFIED,
            evidence_tier=None,
        )
        assert run.verified_findings == []
        assert run.findings[0].failed_checks == ["quote_matches_source"]

    def test_evidence_survives_a_clean_verdict(self) -> None:
        # The model declined to report; the deterministic phase still observed what
        # it observed. A verdict cannot erase an evidence item.
        run = a_run(outcome=Outcome.CLEAN, findings=[])
        assert run.evidence[0].predicate == "swap_call_min_out_is_literal_zero"


class TestSeverityIsAbsent:
    def test_the_model_is_never_asked_for_a_severity(self) -> None:
        # Severity is a value judgement, not an observation. Requiring it in a
        # schema while leaving it unmentioned in the instructions guarantees
        # omissions, and defaulting an omission to a concrete level silently
        # inflates every one of them. The field does not exist here, so none of
        # that is reachable.
        for model in (Finding, VerifiedFinding, DetectorRun, EvidenceRef):
            assert "severity" not in model.model_fields

    def test_unknown_fields_are_rejected_rather_than_absorbed(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                detector_id="d",
                locator=a_locator(),
                quote="x",
                reasoning="y",
                severity="high",  # type: ignore[call-arg]
            )
