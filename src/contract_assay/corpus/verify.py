"""Corpus verification.

Every record is checked against reality before it is admitted: the commit
resolves, the file exists at that commit, the stated line span is inside the
file, the named function is actually there, and the content digest matches what
was recorded.

A record that fails any check is **rejected**, not admitted with a warning. A
corpus is ground truth. Ground truth that might be wrong is worse than a smaller
corpus that is right, because every score computed against it inherits the doubt
and nothing downstream can detect it.

Source resolution is injected rather than hard-wired to a network client, so the
whole module is testable offline. The default resolver is supplied by the
harvest layer; tests pass an in-memory one.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from contract_assay.corpus.records import CorpusRecord

__all__ = [
    "CheckFailure",
    "SourceResolver",
    "VerificationResult",
    "verify_all",
    "verify_record",
]


SourceResolver = Callable[[str, str, str], str | None]
"""(repo_url, commit, path) -> file contents, or None if it cannot be resolved."""


class CheckFailure(StrEnum):
    """Why a record was rejected. Each names a specific, checkable claim."""

    SOURCE_UNRESOLVABLE = "source_unresolvable"
    """The pinned commit or path could not be fetched."""

    DIGEST_MISMATCH = "digest_mismatch"
    """The file's bytes differ from the digest recorded on the pin."""

    SPAN_OUT_OF_RANGE = "span_out_of_range"
    """The line span extends past the end of the file."""

    FUNCTION_NOT_IN_SPAN = "function_not_in_span"
    """The named function was not found within the stated line span."""

    CONTRACT_NOT_FOUND = "contract_not_found"
    """The named contract, library or interface is not declared in the file."""

    EMPTY_SOURCE = "empty_source"
    """The resolved file has no content."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    record_id: str
    ok: bool
    failures: list[CheckFailure]
    detail: str = ""
    computed_sha256: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"{self.record_id}: ok"
        reasons = ", ".join(f.value for f in self.failures)
        return f"{self.record_id}: rejected ({reasons})" + (
            f" -- {self.detail}" if self.detail else ""
        )


# Declaration matching is intentionally shape-based and permissive about
# formatting. It is looking for "is this symbol declared here at all", which is a
# far weaker question than parsing, and must not fail because a signature wraps
# across lines or carries unusual modifiers.
_FUNCTION_DECL = r"""
    \b(?:function|constructor|modifier|receive|fallback)\s+{name}\s*\(
    |
    \b{name}\s*\([^)]*\)\s*(?:external|public|internal|private)
"""
_CONTRACT_DECL = r"\b(?:contract|library|interface|abstract\s+contract)\s+{name}\b"


def _declares_function(text: str, name: str) -> bool:
    pattern = _FUNCTION_DECL.format(name=re.escape(name))
    return re.search(pattern, text, re.VERBOSE | re.MULTILINE) is not None


def _declares_contract(text: str, name: str) -> bool:
    pattern = _CONTRACT_DECL.format(name=re.escape(name))
    return re.search(pattern, text) is not None


def verify_record(record: CorpusRecord, resolve: SourceResolver) -> VerificationResult:
    """Check one record against its pinned source."""
    failures: list[CheckFailure] = []
    detail_parts: list[str] = []

    source = resolve(record.pin.repo_url, record.pin.commit, record.pin.path)
    if source is None:
        return VerificationResult(
            record.record_id,
            ok=False,
            failures=[CheckFailure.SOURCE_UNRESOLVABLE],
            detail=f"{record.pin.repo_url}@{record.pin.commit[:12]}:{record.pin.path}",
        )
    if not source.strip():
        return VerificationResult(record.record_id, ok=False, failures=[CheckFailure.EMPTY_SOURCE])

    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if record.pin.sha256 is not None and record.pin.sha256 != digest:
        failures.append(CheckFailure.DIGEST_MISMATCH)
        detail_parts.append(f"recorded {record.pin.sha256[:12]}, computed {digest[:12]}")

    locator = record.locator
    if locator is not None:
        lines = source.splitlines()
        if locator.end_line > len(lines):
            failures.append(CheckFailure.SPAN_OUT_OF_RANGE)
            detail_parts.append(f"span ends at {locator.end_line}, file has {len(lines)} lines")
        else:
            span = "\n".join(lines[locator.start_line - 1 : locator.end_line])

            if locator.function and not _declares_function(span, locator.function):
                failures.append(CheckFailure.FUNCTION_NOT_IN_SPAN)
                detail_parts.append(
                    f"{locator.function!r} not declared in lines "
                    f"{locator.start_line}-{locator.end_line}"
                )

            if locator.contract and not _declares_contract(source, locator.contract):
                failures.append(CheckFailure.CONTRACT_NOT_FOUND)
                detail_parts.append(f"{locator.contract!r} not declared in file")

    return VerificationResult(
        record.record_id,
        ok=not failures,
        failures=failures,
        detail="; ".join(detail_parts),
        computed_sha256=digest,
    )


def verify_all(
    records: list[CorpusRecord], resolve: SourceResolver
) -> tuple[list[CorpusRecord], list[VerificationResult]]:
    """Partition records into admitted and rejected.

    Returns the records that passed and the results for those that did not. The
    caller decides what to do with rejections; nothing here writes or mutates.
    """
    admitted: list[CorpusRecord] = []
    rejected: list[VerificationResult] = []

    for record in records:
        result = verify_record(record, resolve)
        if result.ok:
            admitted.append(record)
        else:
            rejected.append(result)

    return admitted, rejected
