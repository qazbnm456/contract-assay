"""Detectors: the public interface submissions implement, and the boundary it crosses.

`contract_assay.detectors.base` is a versioned public API. `docs/api.md` states
what is covered by that commitment and what changing it costs.
"""

from contract_assay.detectors.base import (
    API_VERSION,
    AnalysisContext,
    ClassificationClaim,
    Detector,
    LabelSpaceSpec,
    ModelTaskSpec,
    SubmissionLimits,
    TaskOutput,
    gate,
    is_compatible,
    validate_claim,
)
from contract_assay.detectors.loading import (
    IncompatibleSubmission,
    MalformedSubmission,
    SubmissionFault,
    SubmissionManifest,
    call_classify,
    call_evidence,
    call_plan,
    call_verdict,
    load_detector,
)

__all__ = [
    "API_VERSION",
    "AnalysisContext",
    "ClassificationClaim",
    "Detector",
    "IncompatibleSubmission",
    "LabelSpaceSpec",
    "MalformedSubmission",
    "ModelTaskSpec",
    "SubmissionFault",
    "SubmissionLimits",
    "SubmissionManifest",
    "TaskOutput",
    "call_classify",
    "call_evidence",
    "call_plan",
    "call_verdict",
    "gate",
    "is_compatible",
    "load_detector",
    "validate_claim",
]
