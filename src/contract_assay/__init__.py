"""contract-assay: benchmark infrastructure for LLM smart contract auditing."""

from contract_assay.models import (
    CitationStatus,
    DetectorRun,
    DifficultyLevel,
    Escalation,
    EvidenceRef,
    EvidenceTier,
    Finding,
    InvalidReason,
    Locator,
    Outcome,
    SkipReason,
    VerifiedFinding,
)

__version__ = "0.1.0.dev2"

__all__ = [
    "CitationStatus",
    "DetectorRun",
    "DifficultyLevel",
    "Escalation",
    "EvidenceRef",
    "EvidenceTier",
    "Finding",
    "InvalidReason",
    "Locator",
    "Outcome",
    "SkipReason",
    "VerifiedFinding",
    "__version__",
]
