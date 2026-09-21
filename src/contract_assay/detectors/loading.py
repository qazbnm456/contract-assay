"""Loading a submission, and believing nothing it says without checking.

Two jobs, and the second is the reason this module exists separately from the
interface it loads.

**Loading** resolves a declared entry point to a `Detector` subclass and refuses
a version it cannot run. Entry points are *declared*, in a manifest, rather than
discovered by importing a package and seeing what registered itself. Registration
by import side effect means the only way to learn what a submission contains is
to run its module-level code, which is the one thing you want to decide about
before doing it. A manifest is readable without executing anything.

**Checking** re-validates the *shape* of everything the submission hands back,
and the truth of exactly one thing. The distinction matters and was stated
imprecisely here for a while: every returned value is validated against its
model and dropped if it does not conform, and a `Finding`'s quote is
additionally re-read against the source (`check_citation`, the host's, always
run, not overridable). An `EvidenceRef`'s *claim* is **not** verified -- nothing
re-reads the source to confirm that a predicate fired where the submission says
it did. That is affordable because the only thing an evidence item feeds is the
submission's own `verdict()`, so a false one can cost it recall and cannot buy
it anything. The interface in
`base` describes what a detector returns; across an untrusted boundary that is a
claim, not a guarantee. A submission can return a dict where a list belongs, a
string where a sequence belongs -- `str` is iterable, so this one type-checks
nowhere and iterates fine -- or nothing at all. It can raise. None of that may
become a crash, and none of it may become `clean`: both destroy the accounting,
the first by losing the run and the second by recording a submission's bug as a
measurement that the code under test is sound.

So every fault here maps to `Outcome.INVALID` with `InvalidReason.SCHEMA_VIOLATION`,
which is reported as harness health and never enters a confusion matrix.

What this module does not do
----------------------------
It does not isolate anything. `load_detector` imports a module, and importing a
module runs its top-level code in this process with this process's privileges.
Every real protection -- container boundary, denied egress, killed-on-timeout,
token accounting -- is infrastructure outside this package, and the manifest is
what lets that infrastructure decide what to run before running it. Calling this
module a sandbox would be the exact error `docs/design.md` warns about: reporting
an intention as a capability.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from contract_assay.detectors.base import (
    API_VERSION,
    AnalysisContext,
    ClassificationClaim,
    Detector,
    ModelTaskSpec,
    is_compatible,
)
from contract_assay.models import EvidenceRef, FailedCheck, Finding, InvalidReason

__all__ = [
    "IncompatibleSubmission",
    "MalformedSubmission",
    "SubmissionFault",
    "SubmissionManifest",
    "call_classify",
    "call_evidence",
    "call_plan",
    "call_verdict",
    "load_detector",
]


class MalformedSubmission(Exception):
    """The submission could not be loaded: bad manifest, bad entry point, bad class."""


class IncompatibleSubmission(MalformedSubmission):
    """The submission was written against an API major version this host cannot run."""


class SubmissionFault(Exception):
    """A submission returned something unusable, or raised, while running.

    Carries the stage so that a report can say *where* a submission broke.
    "Failed" aggregated across four stages is not actionable to the author and
    not diagnosable by whoever runs the exercise.
    """

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail

    @property
    def invalid_reason(self) -> InvalidReason:
        """Always `SCHEMA_VIOLATION`: the submission did not honour its contract."""
        return InvalidReason.SCHEMA_VIOLATION


class SubmissionManifest(BaseModel):
    """What a submission declares about itself, before any of its code runs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    submission_id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{2,63}$")
    api_version: str = Field(pattern=r"^\d+\.\d+$")
    entry_point: str = Field(
        description="Import path of the detector class, as 'module.path:ClassName'."
    )
    author: str = Field(default="", description="Free-text attribution; not used for scoring.")

    @model_validator(mode="after")
    def _entry_point_is_resolvable_in_principle(self) -> SubmissionManifest:
        module, sep, attr = self.entry_point.partition(":")
        if not sep or not module.strip() or not attr.strip():
            raise ValueError(
                f"entry_point must be 'module.path:ClassName', got {self.entry_point!r}"
            )
        if any(not part.isidentifier() for part in module.split(".")):
            raise ValueError(f"{module!r} is not a valid module path")
        if not attr.isidentifier():
            raise ValueError(f"{attr!r} is not a valid class name")
        return self

    @property
    def module_path(self) -> str:
        return self.entry_point.partition(":")[0]

    @property
    def class_name(self) -> str:
        return self.entry_point.partition(":")[2]


def load_detector(manifest: SubmissionManifest, *, search_path: Path | None = None) -> Detector:
    """Resolve a manifest to an instantiated detector.

    The version check runs *before* the import, which is the only order that
    helps: importing first means an incompatible submission gets to execute its
    module-level code before being turned away, and the refusal it then receives
    is one it has already had a chance to interfere with.

    `search_path`, when given, is prepended to `sys.path` and left there. That is
    a process-global mutation and it is not undone, because the intended
    deployment is one submission per process inside a container -- the same
    isolation that makes the mutation harmless is the isolation that makes
    running untrusted code acceptable at all. Loading two submissions into one
    interpreter is outside what this function supports, and unpicking `sys.path`
    afterwards would imply otherwise while doing nothing about the modules the
    first import already cached.
    """
    if not is_compatible(manifest.api_version):
        raise IncompatibleSubmission(
            f"submission {manifest.submission_id!r} declares api_version "
            f"{manifest.api_version!r}; this host runs {API_VERSION!r}"
        )

    if search_path is not None:
        resolved = str(search_path.resolve())
        if resolved not in sys.path:
            sys.path.insert(0, resolved)

    try:
        module = importlib.import_module(manifest.module_path)
    except Exception as exc:
        # Deliberately broad. A submission's module body is arbitrary code and
        # can fail in any way at all, including ways that are not ImportError.
        raise MalformedSubmission(
            f"importing {manifest.module_path!r} failed: {type(exc).__name__}: {exc}"
        ) from exc

    obj = getattr(module, manifest.class_name, None)
    if obj is None:
        raise MalformedSubmission(f"{manifest.module_path!r} declares no {manifest.class_name!r}")
    if not (isinstance(obj, type) and issubclass(obj, Detector)):
        raise MalformedSubmission(
            f"{manifest.entry_point} is not a Detector subclass (got {obj!r})"
        )

    try:
        detector = obj()
    except Exception as exc:
        raise MalformedSubmission(
            f"instantiating {manifest.entry_point} failed: {type(exc).__name__}: {exc}"
        ) from exc

    # Re-read from the instance rather than trusting the definition-time check.
    # A class declaring none of the three is a legitimate shared base, which
    # `__init_subclass__` lets through precisely because it is not meant to be an
    # entry point -- and a manifest can still point at one. A submission can also
    # delete an attribute after the class body has passed.
    missing = [
        field
        for field in ("detector_id", "class_id", "api_version")
        if getattr(detector, field, None) is None
    ]
    if missing:
        raise MalformedSubmission(
            f"{manifest.entry_point} declares no {', '.join(missing)}; it looks like a "
            "shared base rather than a detector"
        )

    if not is_compatible(detector.api_version):
        raise IncompatibleSubmission(
            f"{manifest.entry_point} declares api_version {detector.api_version!r}; "
            f"this host runs {API_VERSION!r}"
        )
    return detector


# ---------------------------------------------------------------------------
# Calling across the boundary
# ---------------------------------------------------------------------------


def _as_list(raw: object, stage: str, what: str) -> list[Any]:
    """Coerce a returned sequence to a list, refusing the shapes that look like one.

    `None` is refused rather than read as "nothing". The charitable reading is
    tempting and wrong: a detector whose exception path falls off the end returns
    `None`, and if that means "no rejections" then a broken `verdict()` accepts
    every finding handed to it, scoring a submission's bug as a detection.

    `str` and `bytes` are refused for the same reason in the other direction --
    both iterate, so a returned string would silently become a list of
    characters and fail validation one layer deeper with an unrecognisable
    message.
    """
    if raw is None:
        raise SubmissionFault(stage, f"returned None instead of a sequence of {what}")
    if isinstance(raw, str | bytes):
        raise SubmissionFault(stage, f"returned {type(raw).__name__} instead of {what}")
    if not isinstance(raw, Sequence):
        raise SubmissionFault(
            stage, f"returned {type(raw).__name__}, which is not a sequence of {what}"
        )
    return list(raw)


def _validate_each(items: list[Any], model: type[Any], stage: str, what: str) -> list[Any]:
    out: list[Any] = []
    for position, item in enumerate(items):
        if isinstance(item, model):
            out.append(item)
            continue
        try:
            out.append(model.model_validate(item))
        except ValidationError as exc:
            raise SubmissionFault(
                stage,
                f"{what}[{position}] is not a valid {model.__name__}: "
                f"{exc.error_count()} problem(s); first: {exc.errors()[0]['msg']}",
            ) from exc
    return out


def _guard(stage: str, call: Any) -> Any:
    try:
        return call()
    except SubmissionFault:
        raise
    except Exception as exc:
        # A submission that raises has produced no answer. That is an error, and
        # it must not be reported as the absence of a finding.
        raise SubmissionFault(stage, f"raised {type(exc).__name__}: {exc}") from exc


def call_evidence(detector: Detector, ctx: AnalysisContext) -> list[EvidenceRef]:
    """Run `evidence()` and return only what validates as `EvidenceRef`."""
    raw = _guard("evidence", lambda: detector.evidence(ctx))
    items = _as_list(raw, "evidence", "EvidenceRef")
    return list(_validate_each(items, EvidenceRef, "evidence", "evidence"))


def call_plan(
    detector: Detector, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
) -> ModelTaskSpec | None:
    """Run `plan()`. `None` is a legitimate answer here, and means no model runs."""
    raw = _guard("plan", lambda: detector.plan(ctx, evidence))
    if raw is None:
        return None
    if isinstance(raw, ModelTaskSpec):
        return raw
    try:
        return ModelTaskSpec.model_validate(raw)
    except ValidationError as exc:
        raise SubmissionFault(
            "plan", f"returned something that is not a ModelTaskSpec: {exc.errors()[0]['msg']}"
        ) from exc


def call_verdict(
    detector: Detector,
    ctx: AnalysisContext,
    finding: Finding,
    evidence: Sequence[EvidenceRef],
) -> list[FailedCheck]:
    """Run `verdict()` and return the rejections it named. Empty means accepted."""
    raw = _guard("verdict", lambda: detector.verdict(ctx, finding, evidence))
    items = _as_list(raw, "verdict", "FailedCheck")
    return list(_validate_each(items, FailedCheck, "verdict", "failed_checks"))


def call_classify(
    detector: Detector, ctx: AnalysisContext, findings: Sequence[Finding]
) -> list[ClassificationClaim]:
    """Run `classify()` and return the claims that are structurally valid.

    Only the *shape* is enforced here. A claim whose tag is outside the label
    space it was handed is kept, not dropped, and left for the scorer to count as
    a false positive. Dropping it would reward invalid output: an unusable claim
    that disappears costs the submission nothing, while the same claim retained
    carries the false-positive penalty it earned. `base.validate_claim` is
    available to authors who want to catch this themselves first.
    """
    raw = _guard("classify", lambda: detector.classify(ctx, findings))
    items = _as_list(raw, "classify", "ClassificationClaim")
    return list(_validate_each(items, ClassificationClaim, "classify", "claims"))
