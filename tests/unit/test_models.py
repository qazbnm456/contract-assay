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
    MAX_QUOTE_CHARS,
    MAX_REASONING_CHARS,
    CitationStatus,
    DetectorRun,
    DifficultyLevel,
    Escalation,
    EvidenceRef,
    EvidenceTier,
    FailedCheck,
    Finding,
    InvalidReason,
    Locator,
    Outcome,
    RejectionKind,
    SkipReason,
    VerifiedFinding,
    VulnerabilityClass,
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


def a_check(kind: RejectionKind = RejectionKind.VERDICT) -> FailedCheck:
    return FailedCheck(check="min_out_flows_into_guard", kind=kind)


def a_verified(
    status: CitationStatus = CitationStatus.VERIFIED,
    kind: RejectionKind = RejectionKind.VERDICT,
) -> VerifiedFinding:
    return VerifiedFinding(
        finding=a_finding(),
        status=status,
        failed_checks=[] if status is CitationStatus.VERIFIED else [a_check(kind)],
    )


def a_run(**over: object) -> DetectorRun:
    base: dict[str, object] = {
        "detector_id": "slippage.no_min_out",
        "class_id": VulnerabilityClass.SLIPPAGE,
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
                failed_checks=[a_check()],
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
        assert run.findings[0].failed_checks[0].check == "min_out_flows_into_guard"

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


class TestCitationFailureIsNotAMeasurement:
    """The subtlest way an error becomes a measurement.

    A verdict predicate rejecting a claim is a judgement: the detector looked and
    concluded this is not an instance, so `clean` is the right answer. A citation
    that could not be checked is an error: nothing was measured at all. Recording
    both as "a check failed" makes the second indistinguishable from the first,
    which is how infrastructure failures come to be counted as model judgements.
    """

    def test_clean_cannot_stand_over_an_uncheckable_finding(self) -> None:
        with pytest.raises(ValidationError, match="could not be checked"):
            a_run(
                outcome=Outcome.CLEAN,
                findings=[a_verified(CitationStatus.UNVERIFIED, RejectionKind.CITATION)],
            )

    def test_clean_does_stand_over_a_verdict_rejection(self) -> None:
        # The detector applied its rules and said no. That is a measurement.
        run = a_run(
            outcome=Outcome.CLEAN,
            findings=[a_verified(CitationStatus.UNVERIFIED, RejectionKind.VERDICT)],
        )
        assert run.outcome.is_measurement
        assert not run.has_citation_failure

    def test_the_two_kinds_are_distinguishable_on_the_record(self) -> None:
        verdict = a_verified(CitationStatus.UNVERIFIED, RejectionKind.VERDICT)
        citation = a_verified(CitationStatus.UNVERIFIED, RejectionKind.CITATION)
        assert not verdict.has_citation_failure
        assert citation.has_citation_failure

    def test_an_uncheckable_finding_belongs_to_an_invalid_run(self) -> None:
        run = a_run(
            outcome=Outcome.INVALID,
            findings=[a_verified(CitationStatus.UNVERIFIED, RejectionKind.CITATION)],
            invalid_reason=InvalidReason.CITATION_UNVERIFIED,
            evidence_tier=None,
        )
        assert not run.outcome.is_measurement
        assert run.has_citation_failure


class TestSkippedMeansNothingWasAnalysed:
    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("findings", [a_verified()], "cannot report findings"),
            ("evidence", [an_evidence_ref()], "cannot report evidence"),
            (
                "escalations",
                [Escalation(reason="r", from_model="a", to_model="b", changed_verdict=False)],
                "cannot have escalated",
            ),
        ],
    )
    def test_a_skipped_run_reports_nothing(self, field: str, value: object, message: str) -> None:
        kwargs: dict[str, object] = {
            "outcome": Outcome.SKIPPED,
            "skip_reason": SkipReason.UNPARSEABLE,
            "evidence_tier": None,
            "findings": [],
            "evidence": [],
            field: value,
        }
        with pytest.raises(ValidationError, match=message):
            a_run(**kwargs)

    def test_a_genuinely_skipped_run_is_accepted(self) -> None:
        run = a_run(
            outcome=Outcome.SKIPPED,
            skip_reason=SkipReason.UNPARSEABLE,
            evidence_tier=None,
            findings=[],
            evidence=[],
        )
        assert not run.outcome.is_measurement


class TestDifficultyIsDerived:
    def test_a_run_cannot_contradict_its_class_grade(self) -> None:
        # Storing class and level separately permits a run that claims one class
        # and the grade of another, with nothing able to say which to believe.
        assert "level" not in DetectorRun.model_fields
        assert a_run().level is DifficultyLevel.Q

    def test_every_class_carries_a_grade(self) -> None:
        for cls in VulnerabilityClass:
            assert isinstance(cls.level, DifficultyLevel)

    @pytest.mark.parametrize(
        ("cls", "level"),
        [
            (VulnerabilityClass.UNCHECKED_EXTERNAL_CALL, DifficultyLevel.S),
            (VulnerabilityClass.ACCESS_CONTROL, DifficultyLevel.M),
            (VulnerabilityClass.REENTRANCY, DifficultyLevel.M),
            (VulnerabilityClass.DENIAL_OF_SERVICE, DifficultyLevel.M),
            (VulnerabilityClass.INSECURE_RANDOMNESS, DifficultyLevel.M),
            (VulnerabilityClass.ORACLE_INTEGRITY, DifficultyLevel.Q),
            (VulnerabilityClass.ARITHMETIC_ROUNDING, DifficultyLevel.Q),
            (VulnerabilityClass.SLIPPAGE, DifficultyLevel.Q),
            (VulnerabilityClass.FLASHLOAN_MANIPULATION, DifficultyLevel.Q),
        ],
    )
    def test_each_grade_matches_the_design_document(
        self, cls: VulnerabilityClass, level: DifficultyLevel
    ) -> None:
        # All nine pinned, so drift between docs/design.md and the code is a
        # failing test rather than a discrepancy nobody notices.
        assert cls.level is level

    def test_grades_order_by_depth_not_by_text(self) -> None:
        # StrEnum compares as text, which sorts M < Q < S. Ranking must not.
        assert DifficultyLevel.S.rank < DifficultyLevel.M.rank < DifficultyLevel.Q.rank


class TestEscalationPolicy:
    def test_an_s_level_class_cannot_escalate(self) -> None:
        # Static analysis is expected to handle S outright. Reaching for a larger
        # model there is a policy violation, not a recordable event.
        with pytest.raises(ValidationError, match="graded S"):
            a_run(
                class_id=VulnerabilityClass.UNCHECKED_EXTERNAL_CALL,
                escalations=[
                    Escalation(
                        reason="unsure", from_model="small", to_model="large", changed_verdict=True
                    )
                ],
            )

    def test_a_q_level_class_may_escalate(self) -> None:
        run = a_run(
            escalations=[
                Escalation(
                    reason="needs protocol knowledge",
                    from_model="small",
                    to_model="large",
                    changed_verdict=True,
                )
            ]
        )
        assert run.escalations[0].changed_verdict


class TestTextIsBounded:
    """Free-text fields are bounded because untrusted code fills them.

    A submission runs inside a sandbox with no egress, so the only channel out is
    the result it is supposed to return. Every unbounded string on a finding is
    that channel.
    """

    def _finding(self, **over: object) -> Finding:
        base: dict[str, object] = {
            "detector_id": "example",
            "locator": Locator(file="src/Vault.sol", start_line=1, end_line=2),
            "quote": "x = 1;",
            "reasoning": "because",
        }
        return Finding(**{**base, **over})  # type: ignore[arg-type]

    def test_reasoning_is_capped(self) -> None:
        with pytest.raises(ValidationError):
            self._finding(reasoning="x" * (MAX_REASONING_CHARS + 1))

    def test_quoted_source_is_capped_too(self) -> None:
        # Capping only the obvious field buys the appearance of a control: the
        # payload moves to `quote` in one line.
        with pytest.raises(ValidationError):
            self._finding(quote="x" * (MAX_QUOTE_CHARS + 1))

    def test_the_bounds_are_generous_enough_for_an_honest_finding(self) -> None:
        # They bound a channel's bandwidth; they are not a style rule.
        assert (
            self._finding(
                reasoning="x" * MAX_REASONING_CHARS, quote="y" * MAX_QUOTE_CHARS
            ).detector_id
            == "example"
        )
