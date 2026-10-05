"""The adapter: your harness behind the benchmark's one seam. No dependency.

`contract-assay run` loops over every source unit and every detector and calls
this function when a detector asks for a model. This module turns that call
into one call of your harness and turns what it returns into a `ModelReply`.
That is the whole job:

    contract-assay run --manifest access_control.manifest.json \\
        --records corpus/records --source-root ./checkout \\
        --model-caller byo_caller:call --out runs.jsonl

`byo_caller:call` is a module name. The loader looks for it in the working
directory and in the directory of each manifest you pass, and it looks for a
manifest's detector module in that manifest's directory only, so keep the
manifests, `byo_detectors.py` and this file together and the command works from
anywhere.

Four things here are not obvious, and each of them produces figures that look
fine when it is skipped:

1. Your harness runs once per unit, not once per detector. The loop is units
   outside and detectors inside, so a harness covering several classes would be
   called once for each of them over the same file. `_analysis_for` runs it once
   and hands each detector the claims that belong to its class.
2. Findings carry no class. A finding's class is its detector's, so a harness
   with its own taxonomy maps it onto the nine classes below. A claim with no
   mapping cannot be scored and is dropped, and its category is printed so that
   a misspelt key does not turn every run into `clean` without a word.
3. The cost is attributed once. The first detector for a unit is charged the
   analysis and later ones report zero, because charging all of them would
   multiply what you spent by the number of classes.
4. A failure is a value. Return `ModelReply(failed=...)` and the run is `invalid`
   with the cause printed by `run`, which is a different fact from "found
   nothing". If you know what the failed call cost, name it in `models`.
"""

from __future__ import annotations

import sys

from byo_harness import Analysis, analyze

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec, check_citation
from contract_assay.harness import ModelReply
from contract_assay.models import Finding, Locator, ModelRole, ModelUse, VulnerabilityClass

CATEGORY_TO_CLASS: dict[str, VulnerabilityClass] = {
    # Left side: what YOUR harness calls a finding. Right side: the benchmark's.
    "authorization": VulnerabilityClass.ACCESS_CONTROL,
    "reentrancy": VulnerabilityClass.REENTRANCY,
}

_last_source_id: str | None = None
_last: Analysis | Exception | None = None
_served: set[str] = set()


def _analysis_for(ctx: AnalysisContext, detector: Detector) -> tuple[Analysis | Exception, bool]:
    """Your harness's result for this unit, and whether this call is the one that ran it.

    Only the current unit is kept, which is enough because the loop finishes one
    unit before it starts the next. A detector asking twice for the same unit
    means a new sweep has started over it, so the result is not reused.
    """
    global _last_source_id, _last
    if (
        ctx.source_id == _last_source_id
        and _last is not None
        and detector.detector_id not in _served
    ):
        _served.add(detector.detector_id)
        return _last, False
    try:
        _last = analyze(ctx.source)
    except Exception as failure:
        _last = failure
    _last_source_id = ctx.source_id
    _served.clear()
    _served.add(detector.detector_id)
    return _last, True


def call(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
    analysis, first = _analysis_for(ctx, detector)
    if isinstance(analysis, Exception):
        return ModelReply(failed=f"{type(analysis).__name__}: {analysis}")

    if first:
        for limit, spent, name in (
            (ctx.limits.max_model_calls, analysis.calls, "calls"),
            (ctx.limits.max_tokens, analysis.tokens, "tokens"),
        ):
            if spent > limit:
                # Not enforced here, and not by `run` either: a competition host
                # meters from outside and refuses the call. Said out loud so an
                # overrun is not first discovered there.
                print(
                    f"  {ctx.path}: {spent} {name} exceeds the {limit} a round allows",
                    file=sys.stderr,
                )
        for category in sorted({c.category for c in analysis.claims} - CATEGORY_TO_CLASS.keys()):
            print(
                f"  {ctx.path}: dropped claims in category {category!r}, "
                "which CATEGORY_TO_CLASS does not map",
                file=sys.stderr,
            )

    findings = tuple(
        Finding(
            detector_id=detector.detector_id,
            locator=Locator(file=ctx.path, start_line=c.start_line, end_line=c.end_line),
            quote=c.quote,
            reasoning=c.reasoning,
        )
        for c in analysis.claims
        if CATEGORY_TO_CLASS.get(c.category) is detector.class_id
    )
    for finding in findings:
        failure = check_citation(ctx, finding)
        if failure is not None:
            # Reported and still returned. The benchmark records a claim it cannot
            # check as `invalid`, and dropping it here would turn that into `clean`.
            print(
                f"  {ctx.path}:{finding.locator.start_line}-{finding.locator.end_line}: "
                "the quote is not whole lines of the source at that range "
                f"({failure.detail or failure.check})",
                file=sys.stderr,
            )
    return ModelReply(
        findings=findings,
        models=(
            ModelUse(
                model_id=analysis.model_id,
                role=ModelRole.MAIN,
                calls=analysis.calls if first else 0,
                tokens=analysis.tokens if first else 0,
            ),
        ),
    )
