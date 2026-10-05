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

__version__ = "0.1.3"
"""The only place a version is written. `pyproject.toml` reads it from here.

Two hardcoded copies used to exist, and that is worse than untidy:
`report/wire.py` writes this value into every score document as
`engine_version`, and `engine_version` is one of the fields two published
results must agree on before their totals mean the same thing. A forgotten copy
would produce documents claiming a version the package does not have, grouping
with genuine results of that version -- and PyPI does not allow re-uploading a
version, so the only remedy would be burning one.

`importlib.metadata.version` was the first attempt at fixing that and is the
wrong single source: it reads the *installed* distribution, which an editable
install leaves stale. It reported the previous version immediately after the
bump, which is the same class of drift one layer out."""

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
