"""The host side of a run: units from the corpus, detectors over them, runs out.

What this closes. Everything needed to score a submission existed and the loop
between them did not, so every consumer wrote its own -- and the first two that
did got the same two things wrong: reading the corpus (each reimplemented it)
and naming what produced a finding (easy to omit, and the benchmark then refuses
the run). A loop nobody has to write is a loop nobody gets wrong.

**No model library is imported here, and that is not an oversight.** An
instrument whose own correctness depended on the thing it measures could not
tell a broken instrument from a weak model. So the default calls no model at
all -- which is a real submission, since a deterministic detector is this
benchmark's own control group -- and a model is supplied as a `ModelCaller`
resolved from an import path, exactly the way a submission is. The package
therefore stays free of a provider, and a user with a model writes a function
rather than a loop. `examples/reference_runner/` is a worked caller.

This is deliberately not the loop a competition uses. A host running somebody
else's harness must meter the calls from outside the process running it, confine
that process, and re-check every citation against its own copy of the source.
None of that belongs in a convenience command, and a consumer that needs it
should read `docs/api.md` §8 rather than reach for this.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from contract_assay.corpus.records import CorpusRecord
from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec, SubmissionLimits
from contract_assay.detectors.loading import SubmissionFault, call_evidence, call_plan
from contract_assay.detectors.runner import run_detector
from contract_assay.models import (
    DetectorRun,
    EvidenceTier,
    Finding,
    InvalidReason,
    ModelUse,
    Outcome,
)

__all__ = [
    "ModelCaller",
    "ModelReply",
    "SourceUnit",
    "load_caller",
    "run_submission",
    "units_from",
]


@dataclass(frozen=True, slots=True)
class SourceUnit:
    """One source file of the corpus, as the records' pins name it."""

    source_id: str
    path: str
    source: str


@dataclass(frozen=True, slots=True)
class ModelReply:
    """What a model call produced, and what produced it.

    `models` is not optional politeness. A run carrying findings must name what
    produced them or the benchmark refuses it: a figure that cannot say what
    produced it cannot be compared with one produced by something else. Putting
    it in the return type is how a caller is stopped from forgetting.

    A failed call returns `findings=()` with whatever `models` records the cost,
    and `failed` set. It is never an exception: a transport failure ending the
    whole run would publish a submission as having measured nothing.
    """

    findings: tuple[Finding, ...] = ()
    models: tuple[ModelUse, ...] = ()
    failed: str | None = None


class ModelCaller(Protocol):
    """How a run reaches a model. Supplied by the caller, never by this package."""

    def __call__(
        self, detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext
    ) -> ModelReply: ...


def units_from(
    records: Iterable[CorpusRecord], source_root: Path
) -> tuple[list[SourceUnit], list[str]]:
    """Every distinct source unit the records point at, and the ones missing.

    Distinct, because two records in one file are two defects in one unit --
    running it twice would give a detector two attempts at the same file and
    count its budget twice.

    The missing list is returned rather than logged, because a unit absent from
    a checkout scores as a submission that missed it. `contract-assay fetch`
    builds the checkout; a caller that ignores this list is reporting recall
    over a subset nobody chose.
    """
    found: dict[str, SourceUnit] = {}
    missing: list[str] = []
    for record in sorted(records, key=lambda r: r.record_id):
        pin = record.pin
        if pin.source_id in found or pin.source_id in missing:
            continue
        path = source_root / pin.path
        if not path.is_file():
            missing.append(pin.source_id)
            continue
        found[pin.source_id] = SourceUnit(
            source_id=pin.source_id, path=pin.path, source=path.read_text(encoding="utf-8")
        )
    return list(found.values()), missing


def load_caller(spec: str) -> ModelCaller:
    """Resolve `module.path:function` to a `ModelCaller`.

    The same shape a submission's entry point takes, for the same reason: a
    caller is somebody else's code and naming it in a manifest-like string keeps
    this package from importing a provider.
    """
    module_path, separator, attribute = spec.partition(":")
    if not separator or not module_path.strip() or not attribute.strip():
        raise ValueError(f"expected 'module.path:function', got {spec!r}")
    try:
        module = importlib.import_module(module_path)
    except Exception as failure:
        raise ValueError(f"importing {module_path!r} failed: {failure}") from failure
    caller = getattr(module, attribute, None)
    if caller is None or not callable(caller):
        raise ValueError(f"{spec!r} does not name a callable")
    return caller  # type: ignore[no-any-return]


def run_submission(
    detectors: Sequence[Detector],
    units: Sequence[SourceUnit],
    *,
    model: ModelCaller | None = None,
    wall_seconds: int = 30,
    max_calls: int = 4,
    max_tokens: int = 20_000,
    predictions_per_unit: int | None = None,
    on_unit: Callable[[int, SourceUnit], None] | None = None,
) -> Iterator[DetectorRun]:
    """Run every detector against every unit, yielding one run at a time.

    Yielded rather than returned so a caller can write as it goes: a sweep that
    dies at unit 90 of 141 should leave 90 units of runs behind it, not nothing.

    `predictions_per_unit` caps what is handed to the benchmark, as a courtesy
    to keep a runaway model from filling a file. It is **not** the cap that
    counts -- `contract-assay score --predictions-per-unit` is, because the
    scorer is the only layer that sees a whole submission's runs at once and can
    see two detectors for one class using the quota between them.
    """
    for index, unit in enumerate(units):
        if on_unit is not None:
            on_unit(index, unit)
        for detector in detectors:
            ctx = AnalysisContext(
                source_id=unit.source_id,
                path=unit.path,
                source=unit.source,
                tier=EvidenceTier.SYNTACTIC,
                level=detector.level,
                limits=SubmissionLimits.for_level(
                    detector.level,
                    wall_seconds=wall_seconds,
                    max_model_calls=max_calls,
                    max_tokens=max_tokens,
                ),
            )
            try:
                evidence = call_evidence(detector, ctx)
                spec = call_plan(detector, ctx, evidence)
            except SubmissionFault as fault:
                # Attributed to the stage that raised. A crash recorded without
                # its stage reads as a defect in the detector's logic wherever
                # it happens to surface.
                yield DetectorRun(
                    detector_id=detector.detector_id,
                    class_id=detector.class_id,
                    source_id=unit.source_id,
                    outcome=Outcome.INVALID,
                    invalid_reason=fault.invalid_reason,
                    evidence_tier=ctx.tier,
                    declared_limits=list(detector.declared_limits),
                )
                continue

            if spec is None or model is None:
                # Deterministic. `produced_without_a_model` is a claim and is
                # set only when there are findings to attribute; an empty run
                # claiming it would describe a production that never happened.
                yield run_detector(detector, ctx, model_findings=(), produced_without_a_model=False)
                continue

            reply = model(detector, spec, ctx)
            if reply.failed is not None:
                yield DetectorRun(
                    detector_id=detector.detector_id,
                    class_id=detector.class_id,
                    source_id=unit.source_id,
                    outcome=Outcome.INVALID,
                    invalid_reason=InvalidReason.TRANSPORT_FAILURE,
                    evidence_tier=ctx.tier,
                    models=list(reply.models),
                    declared_limits=list(detector.declared_limits),
                )
                continue

            findings = reply.findings
            if predictions_per_unit is not None:
                findings = findings[:predictions_per_unit]
            yield run_detector(
                detector,
                ctx,
                model_findings=findings,
                models=list(reply.models),
                produced_without_a_model=not reply.models and bool(findings),
            )
