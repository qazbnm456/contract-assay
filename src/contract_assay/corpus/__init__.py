"""Corpus: pointer-based ground-truth records and their verification."""

from contract_assay.corpus.harvest import (
    Candidate,
    DraftRecord,
    HarvestReport,
    RawReport,
    ReportAdapter,
    Skip,
    SkipCause,
    SkippedCandidate,
    harvest,
)
from contract_assay.corpus.normalize import (
    NormalizeCause,
    NormalizedSkip,
    NormalizeReport,
    normalize,
)
from contract_assay.corpus.records import (
    CorpusRecord,
    CorpusSplit,
    LocatorProvenance,
    NegativeKind,
    Provenance,
    SourcePin,
    VulnerabilityClass,
)
from contract_assay.corpus.verify import (
    CheckFailure,
    SourceResolver,
    VerificationReport,
    VerificationResult,
    verify_all,
    verify_record,
)

__all__ = [
    "Candidate",
    "CheckFailure",
    "CorpusRecord",
    "CorpusSplit",
    "DraftRecord",
    "HarvestReport",
    "LocatorProvenance",
    "NegativeKind",
    "NormalizeCause",
    "NormalizeReport",
    "NormalizedSkip",
    "Provenance",
    "RawReport",
    "ReportAdapter",
    "Skip",
    "SkipCause",
    "SkippedCandidate",
    "SourcePin",
    "SourceResolver",
    "VerificationReport",
    "VerificationResult",
    "VulnerabilityClass",
    "harvest",
    "normalize",
    "verify_all",
    "verify_record",
]
