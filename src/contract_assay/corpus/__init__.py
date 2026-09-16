"""Corpus: pointer-based ground-truth records and their verification."""

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
    "CheckFailure",
    "CorpusRecord",
    "CorpusSplit",
    "LocatorProvenance",
    "NegativeKind",
    "Provenance",
    "SourcePin",
    "SourceResolver",
    "VerificationReport",
    "VerificationResult",
    "VulnerabilityClass",
    "verify_all",
    "verify_record",
]
