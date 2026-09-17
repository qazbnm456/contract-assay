"""Composing one detector, one source unit, one `DetectorRun`.

This is the deterministic half of a run. The model is not called here; its
findings are passed in, the same way `corpus.verify` takes a resolver rather
than a network client. The reason is the same too: the whole thing stays
testable with no model, no network and no toolchain, which is what makes the
offline gate meaningful.

That injection is not only a testing convenience. A detector whose `plan()`
returns `None` runs no model at all, and for such a detector this function *is*
the entire run -- which is what it means for a purely deterministic detector to
be a first-class submission rather than a special case.

Deriving the outcome is the delicate part, and the order of the three questions
is the whole design:

1.  Did anything survive verification? Then the run is `vulnerable`. A citation
    failure on some *other* finding does not undo a finding that checked out.
2.  Otherwise, did any finding fail to check against source? Then the run is
    `invalid`, because it measured nothing -- a citation that could not be
    confirmed is an error, not a conclusion that the defect is absent.
3.  Only then is the run `clean`.

Getting 2 and 3 the wrong way round is the failure `models.DetectorRun` refuses
to represent: an error wearing a measurement's clothes, counted as a true
negative, indistinguishable afterwards from the detector having looked and found
nothing.
"""

from __future__ import annotations

from collections.abc import Sequence

from contract_assay.detectors.base import AnalysisContext, Detector, check_citation, gate
from contract_assay.detectors.loading import (
    SubmissionFault,
    call_evidence,
    call_plan,
    call_verdict,
)
from contract_assay.models import (
    CitationStatus,
    DetectorRun,
    EvidenceRef,
    Finding,
    InvalidReason,
    ModelUse,
    Outcome,
    VerifiedFinding,
)

__all__ = ["run_detector"]


def run_detector(
    detector: Detector,
    ctx: AnalysisContext,
    *,
    model_findings: Sequence[Finding] = (),
    models: Sequence[ModelUse] = (),
    produced_without_a_model: bool = False,
) -> DetectorRun:
    """Run one detector over one unit and record what happened.

    `model_findings` are what the model claimed. An empty sequence is the
    ordinary case for a detector that runs no model, not an error.

    `models` is what the host called to obtain them, and it is the host's to
    state because only the host knows: `plan()` says what to ask and the model
    is called outside this function. A finding whose producer is unnamed leaves
    a leaderboard unable to say what it measured, and an exercise that agreed a
    baseline cannot check that the baseline is what ran -- so findings with
    neither `models` nor `produced_without_a_model` raise here rather than being
    recorded as a submission fault. The omission is the host's.
    """
    if model_findings and not models and not produced_without_a_model:
        raise ValueError(
            "model_findings were supplied with no producer: pass `models` for what was "
            "called, or `produced_without_a_model=True` for findings deterministic code made"
        )
    skip_reason = gate(ctx.source)
    if skip_reason is not None:
        # A skipped unit was never analysed, so it reports no tier, no evidence
        # and no findings. `DetectorRun` enforces that; stating it here as well
        # keeps the two from drifting.
        return DetectorRun(
            detector_id=detector.detector_id,
            class_id=detector.class_id,
            source_id=ctx.source_id,
            outcome=Outcome.SKIPPED,
            skip_reason=skip_reason,
            declared_limits=list(detector.declared_limits),
        )

    try:
        evidence = call_evidence(detector, ctx)
        # Called for its effect on the record rather than its value: a detector
        # that cannot produce a coherent plan has not run correctly, and finding
        # that out here attributes the failure to `plan` instead of to whatever
        # breaks downstream of it.
        call_plan(detector, ctx, evidence)
        findings = _verify(detector, ctx, model_findings, evidence)
    except SubmissionFault as fault:
        # The submission did not honour its contract. Reported as harness health,
        # never as the absence of a finding.
        return DetectorRun(
            detector_id=detector.detector_id,
            class_id=detector.class_id,
            source_id=ctx.source_id,
            outcome=Outcome.INVALID,
            invalid_reason=fault.invalid_reason,
            declared_limits=list(detector.declared_limits),
            evidence_tier=ctx.tier,
            trace_path=None,
            models=list(models),
            produced_without_a_model=produced_without_a_model,
        )

    verified = [f for f in findings if f.status is CitationStatus.VERIFIED]
    uncheckable = any(f.has_citation_failure for f in findings)

    if verified:
        outcome, invalid_reason = Outcome.VULNERABLE, None
    elif uncheckable:
        outcome, invalid_reason = Outcome.INVALID, InvalidReason.CITATION_UNVERIFIED
    else:
        outcome, invalid_reason = Outcome.CLEAN, None

    return DetectorRun(
        detector_id=detector.detector_id,
        class_id=detector.class_id,
        source_id=ctx.source_id,
        outcome=outcome,
        invalid_reason=invalid_reason,
        evidence_tier=ctx.tier,
        findings=findings,
        evidence=list(evidence),
        models=list(models),
        produced_without_a_model=produced_without_a_model,
        # Copied by the harness, not asserted by the submission at report time:
        # a detector cannot have its score printed without its declared
        # blindnesses travelling beside it.
        declared_limits=list(detector.declared_limits),
    )


def _verify(
    detector: Detector,
    ctx: AnalysisContext,
    model_findings: Sequence[Finding],
    evidence: Sequence[EvidenceRef],
) -> list[VerifiedFinding]:
    """Check every claim, and retain the ones that fail with the reasons they failed.

    The citation check runs first and unconditionally. It is the harness's, not
    the detector's, so a submission cannot arrange for its unverifiable claims to
    be accepted; and running it before `verdict()` means a detector is never
    asked to reason about a location whose quote does not match, where any answer
    it gave would be about the wrong code.
    """
    checked: list[VerifiedFinding] = []
    for finding in model_findings:
        citation_failure = check_citation(ctx, finding)
        if citation_failure is not None:
            checked.append(
                VerifiedFinding(
                    finding=finding,
                    status=CitationStatus.UNVERIFIED,
                    failed_checks=[citation_failure],
                )
            )
            continue

        rejections = list(call_verdict(detector, ctx, finding, evidence))
        checked.append(
            VerifiedFinding(
                finding=finding,
                status=(CitationStatus.UNVERIFIED if rejections else CitationStatus.VERIFIED),
                failed_checks=rejections,
            )
        )
    return checked
