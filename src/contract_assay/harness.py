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
rather than a loop. `examples/bring_your_own_harness/` is the smallest one, with no
dependency, and `examples/reference_runner/` is one over a real endpoint.

This is deliberately not the loop a competition uses. A host running somebody
else's harness must meter the calls from outside the process running it, confine
that process, and re-check every citation against its own copy of the source.
None of that belongs in a convenience command, and a consumer that needs it
should read `docs/api.md` §8 rather than reach for this.
"""

from __future__ import annotations

import hashlib
import importlib
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from contract_assay.corpus.fetch import checkout_file
from contract_assay.corpus.records import CorpusRecord, SourcePin
from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec, SubmissionLimits
from contract_assay.detectors.loading import SubmissionFault, call_evidence, call_plan
from contract_assay.detectors.runner import run_detector
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
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
    produced it cannot be compared with one produced by something else. A caller
    that forgets is recorded as a failed call, with that cause, rather than
    allowed to end the sweep -- the type alone does not stop the omission.

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
    # A pin carrying a digest first, then by `record_id`. Sorting by id alone
    # meant a digest-less record named earlier than its digest-bearing sibling
    # decided the unit -- and a pin with no digest is a unit read without a
    # check. `recheck_citations`, `_pins` and `corpus/units.unit_manifest` apply
    # the same rule; four different answers to "which pin represents this unit"
    # is how one of them ends up wrong.
    ordered = sorted(records, key=lambda r: (r.pin.sha256 is None, r.record_id))
    return units_from_pins([record.pin for record in ordered], source_root)


def units_from_pins(
    pins: Iterable[SourcePin], source_root: Path
) -> tuple[list[SourceUnit], list[str]]:
    """The same, from pins alone: what a **unit manifest** carries.

    Split out so a holdout can be published as questions without answers. A
    record's locator is the answer and its `classes` is the answer at one
    remove, so a participant running against a held-out split is handed pins and
    reads the source; nothing they receive says what is wrong with it.

    Order is the caller's. `units_from` sorts first, because which of two pins
    for one file wins is its rule to apply, and a manifest has already applied
    it by the time it is written.
    """
    found: dict[str, SourceUnit] = {}
    missing: list[str] = []
    for pin in pins:
        if pin.source_id in found or pin.source_id in missing:
            continue
        if not pin.is_filesystem_path:
            # An import specifier or a deployed address is not a path. Joining it
            # to a root reads the wrong file, or no file, and says nothing about
            # why -- which is what `_Pin.is_filesystem_path` exists to stop, and
            # what `_local_resolver` and `fetch_records` already ask. This was
            # the unswept third site.
            missing.append(pin.source_id)
            continue
        path = checkout_file(source_root, pin)
        if path is None:
            missing.append(pin.source_id)
            continue
        try:
            body = path.read_bytes()
        except OSError:
            # A permission error, or a symlink that lost the race with
            # `is_file()`. One unreadable file aborted the whole command before
            # any unit was analysed.
            missing.append(pin.source_id)
            continue
        if pin.sha256 is not None and hashlib.sha256(body).hexdigest() != pin.sha256:
            # The case `fetch` deliberately leaves on disk with a warning is the
            # case this used to consume in silence. The record's locators index
            # lines that have moved, so a score over these bytes is a real number
            # about the wrong source -- a failure with no symptom, which is why
            # `fetch` refuses to write them and why this refuses to read them.
            missing.append(pin.source_id)
            continue
        found[pin.source_id] = SourceUnit(
            source_id=pin.source_id,
            path=pin.path,
            # `errors="replace"`, matching `_local_resolver`. A latin-1 byte in
            # one comment is routine in pre-0.5 Solidity, and decoding strictly
            # here while the scorer decodes leniently meant `run` died on a
            # checkout `score` reads fine.
            source=body.decode("utf-8", errors="replace"),
        )
    return list(found.values()), missing


def load_caller(spec: str, *, search_path: Path | None = None) -> ModelCaller:
    """Resolve `module.path:function` to a `ModelCaller`.

    The same shape a submission's entry point takes, and now the same
    *resolution*: `search_path` is prepended to `sys.path`, as `load_detector`
    does. Both this docstring and the CLI help claimed that parity before the
    code had it, and the consequence was that the documented way to use a model
    could not work -- for an installed console script `sys.path[0]` is the venv's
    `bin` directory, so `--model-caller my_caller:call` for `./my_caller.py`
    raised `No module named 'my_caller'`. Defaults to the working directory,
    which is where somebody running the command keeps that file.

    The mutation is not undone, for the reason `load_detector` gives: the
    intended deployment is one submission per process, and unpicking `sys.path`
    afterwards would imply otherwise while doing nothing about the modules the
    import already cached.
    """
    module_path, separator, attribute = (part.strip() for part in spec.partition(":"))
    if not separator or not module_path or not attribute:
        raise ValueError(f"expected 'module.path:function', got {spec!r}")
    resolved = str((search_path or Path.cwd()).resolve())
    if resolved not in sys.path:
        sys.path.insert(0, resolved)
    try:
        module = importlib.import_module(module_path)
    except Exception as failure:
        # The type is kept, as `load_detector` keeps it. The CLI prints this as
        # one red line with no traceback, so a bare `'CONTRACT_ASSAY_KEY'` is the
        # whole of what a user gets to diagnose a `KeyError` at import.
        raise ValueError(
            f"importing {module_path!r} failed: {type(failure).__name__}: {failure}"
        ) from failure
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
    predictions_per_unit: int | None = DEFAULT_PREDICTIONS_PER_UNIT,
    on_unit: Callable[[int, SourceUnit], None] | None = None,
    on_failure: Callable[[SourceUnit, Detector, str], None] | None = None,
) -> Iterator[DetectorRun]:
    """Run every detector against every unit, yielding one run at a time.

    Yielded rather than returned so a caller can write as it goes: a sweep that
    dies at unit 90 of 141 should leave 90 units of runs behind it, not nothing.

    `predictions_per_unit` caps what is handed to the benchmark, and it defaults
    to what the scorer will count, so that what a submission hands over is what
    gets scored. It is **not** the cap that counts -- `contract-assay score
    --predictions-per-unit` is, because the scorer is the only layer that sees a
    whole submission's runs at once and can see two detectors for one class
    using the quota between them, and because it charges for a finding whose
    citation it refuses while this cannot know which those are.

    The default used to be `None`. A submission then emitted everything, the
    scorer charged for all of it in the runner's own unit order, and a docstring
    defending the cap with "the order is the submission's own, so spending slots
    on guesses is its choice" was describing a choice the documented workflow
    never offered.

    `on_failure` receives the cause of every model call that failed, and exists
    because a run records only that it failed: `InvalidReason` has no value that
    says *what* the transport did, so a raised `HTTP 429` and a caller with the
    wrong signature are the same `transport_failure` in the output. The cause is
    the first thing anybody goes looking for, and without this it is nowhere.
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
                # Called here to learn whether a model is wanted and what to ask
                # it. `run_detector` calls both again to build the run's own
                # record, so a detector's `evidence()` and `plan()` have to give
                # the same answer twice: the evidence on the run is from that
                # second call, and the model's prompt was built from this one.
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

            if spec is not None and model is None:
                # The detector asked for a model and the host has none. That is
                # not a measurement: recording it `clean` publishes a real-looking
                # zero and attributes it to the detector, which is the founding
                # conflation this package refuses one layer down -- an error
                # wearing a measurement's clothes, indistinguishable afterwards
                # from having looked and found nothing.
                yield DetectorRun(
                    detector_id=detector.detector_id,
                    class_id=detector.class_id,
                    source_id=unit.source_id,
                    outcome=Outcome.INVALID,
                    invalid_reason=InvalidReason.MODEL_NOT_PERMITTED,
                    evidence_tier=ctx.tier,
                    declared_limits=list(detector.declared_limits),
                )
                continue

            if spec is None or model is None:
                # Deterministic by the detector's own choice. `model is None` is
                # unreachable here -- the branch above returned for it -- and is
                # written so the narrowing is visible to a reader and a checker. `propose()` may
                # still have asserted findings, and `run_detector` sets
                # `produced_without_a_model` itself when it did -- so nothing is
                # claimed here about a production that may not have happened.
                yield run_detector(detector, ctx, model_findings=())
                continue

            try:
                reply = model(detector, spec, ctx)
            except Exception as failure:
                # `ModelReply` states that a failed call is a value and never an
                # exception, and then asserted that about third-party code while
                # enforcing it nowhere. Every real HTTP client raises. One blip
                # on unit 40 of 141 ended the sweep with a traceback; now it
                # costs one unit, recorded with its cause.
                reply = ModelReply(failed=f"{type(failure).__name__}: {failure}")
            if not isinstance(reply, ModelReply):
                # A caller that *returns* the wrong thing, which is the likeliest
                # bug in a hand-written adapter and the one shape this did not
                # cover: `None` or a dict gave `AttributeError: 'NoneType' object
                # has no attribute 'failed'`, a traceback, and **zero runs
                # written** -- the whole sweep lost to one unit's caller. A
                # raising caller has always cost one unit and been recorded with
                # its cause; returning nonsense now costs the same.
                reply = ModelReply(  # type: ignore[unreachable]
                    failed=f"the model caller returned {type(reply).__name__} rather than a "
                    "ModelReply; a failed call is a value, not an exception, and not a guess"
                )
            if reply.failed is None and reply.findings and not reply.models:
                # `run_detector` raises for findings with no producer, and that
                # `ValueError` ended the whole sweep: one unit's caller forgot
                # `models` and every later unit was lost. The omission is the
                # caller's, so it is recorded as the caller's failed call, with
                # the cause that names the fix.
                reply = ModelReply(
                    failed=f"the model caller returned {len(reply.findings)} finding(s) with "
                    "no `models`; name what produced them with "
                    "ModelReply(models=(ModelUse(...),))"
                )
            if reply.failed is not None:
                if on_failure is not None:
                    on_failure(unit, detector, reply.failed)
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
                # Applied to the model's findings only, and that is the honest
                # description rather than the advertised one: `propose()` runs
                # inside `run_detector`, one frame down, so this cannot reach a
                # deterministic detector's output. The cap that counts is the
                # scorer's `--predictions-per-unit`, which walks every finding on
                # the run -- see `run_submission`'s docstring.
                findings = findings[:predictions_per_unit]
            yield run_detector(
                detector,
                ctx,
                model_findings=findings,
                models=list(reply.models),
            )
