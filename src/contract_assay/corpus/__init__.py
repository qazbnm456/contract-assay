"""Corpus: pointer-based ground-truth records and their verification."""

from contract_assay.corpus.records import (
    CorpusRecord,
    CorpusSplit,
    NegativeKind,
    Provenance,
    SourcePin,
    VulnerabilityClass,
)
from contract_assay.corpus.verify import (
    CheckFailure,
    SourceResolver,
    VerificationResult,
    verify_all,
    verify_record,
)

__all__ = [
    "CheckFailure",
    "CorpusRecord",
    "CorpusSplit",
    "NegativeKind",
    "Provenance",
    "SourcePin",
    "SourceResolver",
    "VerificationResult",
    "VulnerabilityClass",
    "verify_all",
    "verify_record",
]
