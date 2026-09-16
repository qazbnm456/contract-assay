"""Corpus verification.

Every record is checked against reality before it is admitted: the commit
resolves, the digest matches, the stated line span is inside the file, and the
named function and contract are actually declared where the record says they
are -- with the function found *within the span* and, when a contract is named,
found inside that contract.

A record that fails any check is **rejected**, not admitted with a warning. A
corpus is ground truth. Ground truth that might be wrong is worse than a smaller
corpus that is right, because every later score inherits the doubt and nothing
downstream can detect it.

Two consequences of taking that seriously:

*   Declaration checks go through a parser, not a pattern match. A comment
    mentioning a function is not a declaration of it, and text matching cannot
    tell the difference -- so a text-matching verifier certifies locations that
    contain no code, while rejecting constructors, which carry neither the
    `function` keyword nor a visibility modifier.

*   A function name is not a function. Solidity permits overloading, so a record
    naming `swap` in a contract declaring two of them has not said which one it
    means -- and the span cannot always settle it. Admitting such a record means
    verifying it against an overload the annotator may not have intended, so it
    is rejected as ambiguous instead.

*   A synthetic variant cannot be verified here at all, and is rejected rather
    than approximated. A pin identifies bytes in a repository, and a variant's
    bytes exist in no repository; pointing its pin at the original makes the
    record verify against source that does not contain the mutation, and the
    digest written back then certifies the wrong bytes under the name of
    reproducibility. Verifying a variant means regenerating it deterministically
    from the pinned original plus the transformation that produced it, which
    needs a recipe this schema does not yet carry. Storing the mutated bytes
    instead is not an alternative: a structure-preserving mutation is a
    derivative work, so vendoring it would break the corpus's pointer-only
    property and attach the original's licence to the result.

*   A file that cannot be parsed is rejected rather than waved through. "I could
    not read this" is not evidence that the record is sound. This is distinct
    from *analysis*, where an unreadable compilation unit degrades to a weaker
    tier and continues: there a weaker answer is still an answer, whereas an
    unverified record would poison everything scored against it.

Source resolution is injected rather than hard-wired to a network client, so the
whole module is testable offline.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from contract_assay.corpus.records import CorpusRecord, CorpusSplit
from contract_assay.evidence.solidity import SolidityUnavailable, index_source

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

    EMPTY_SOURCE = "empty_source"
    """The resolved file has no content."""

    UNPARSEABLE_SOURCE = "unparseable_source"
    """No declaration could be read, so nothing about the file can be confirmed."""

    DIGEST_MISMATCH = "digest_mismatch"
    """The file's bytes differ from the digest recorded on the pin."""

    SPAN_OUT_OF_RANGE = "span_out_of_range"
    """The line span extends past the end of the file."""

    FUNCTION_NOT_IN_SPAN = "function_not_in_span"
    """The named function is not declared within the stated line span."""

    CONTRACT_NOT_FOUND = "contract_not_found"
    """The named contract, library or interface is not declared in the file."""

    FUNCTION_NOT_IN_CONTRACT = "function_not_in_contract"
    """The function is declared, but not inside the contract the record names."""

    FUNCTION_AMBIGUOUS_IN_SPAN = "function_ambiguous_in_span"
    """Several overloads of the named function fall in the span, so it identifies none."""

    VARIANT_NOT_REGENERABLE = "variant_not_regenerable"
    """The record is a synthetic variant, whose bytes no commit can pin."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    record_id: str
    ok: bool
    failures: tuple[CheckFailure, ...]
    detail: str = ""
    computed_sha256: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"{self.record_id}: ok"
        reasons = ", ".join(f.value for f in self.failures)
        return f"{self.record_id}: rejected ({reasons})" + (
            f" -- {self.detail}" if self.detail else ""
        )


def _reject(record_id: str, failure: CheckFailure, detail: str = "") -> VerificationResult:
    return VerificationResult(record_id, ok=False, failures=(failure,), detail=detail)


def verify_record(record: CorpusRecord, resolve: SourceResolver) -> VerificationResult:
    """Check one record against its pinned source.

    On success the result carries the digest of the bytes checked, which
    `verify_all` writes onto the pin.
    """
    if record.split is CorpusSplit.SYNTHETIC_VARIANT:
        # Refused before anything is resolved, so no digest is computed and none
        # can be written back. A variant's pin can only describe the source it
        # was mutated from, so every check below would run against bytes that do
        # not contain the mutation -- and pass.
        return _reject(
            record.record_id,
            CheckFailure.VARIANT_NOT_REGENERABLE,
            "a synthetic variant must be regenerated from its source record and the "
            "transformation that produced it; verifying it against a pinned commit "
            "checks the unmutated source and certifies the wrong bytes",
        )

    source = resolve(record.pin.repo_url, record.pin.commit, record.pin.path)
    if source is None:
        return _reject(
            record.record_id,
            CheckFailure.SOURCE_UNRESOLVABLE,
            f"{record.pin.repo_url}@{record.pin.commit[:12]}:{record.pin.path}",
        )
    if not source.strip():
        return _reject(record.record_id, CheckFailure.EMPTY_SOURCE)

    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    failures: list[CheckFailure] = []
    detail: list[str] = []

    if record.pin.sha256 is not None and record.pin.sha256 != digest:
        failures.append(CheckFailure.DIGEST_MISMATCH)
        detail.append(f"recorded {record.pin.sha256[:12]}, computed {digest[:12]}")

    try:
        index = index_source(source)
    except SolidityUnavailable as exc:  # pragma: no cover - requires the dep to be absent
        return _reject(record.record_id, CheckFailure.UNPARSEABLE_SOURCE, str(exc))

    if not index.parsed:
        failures.append(CheckFailure.UNPARSEABLE_SOURCE)
        detail.append("no declaration could be read from the file")

    locator = record.locator
    if locator is not None and index.parsed:
        # Split on "\n" only. str.splitlines() also breaks on \v, \f, \x1c-\x1e
        # and U+2028/2029, none of which a compiler or an editor treats as a line
        # break -- one of those inside a string literal would shift every line
        # number away from what the annotator saw.
        line_count = len(source.split("\n"))

        if locator.end_line > line_count:
            failures.append(CheckFailure.SPAN_OUT_OF_RANGE)
            detail.append(f"span ends at {locator.end_line}, file has {line_count} lines")
        else:
            if locator.contract and not index.declares_type(locator.contract):
                failures.append(CheckFailure.CONTRACT_NOT_FOUND)
                detail.append(f"{locator.contract!r} is not declared in this file")

            if locator.function:
                in_span = index.callables(
                    locator.function, within=(locator.start_line, locator.end_line)
                )
                if not in_span:
                    failures.append(CheckFailure.FUNCTION_NOT_IN_SPAN)
                    detail.append(
                        f"{locator.function!r} is not declared in lines "
                        f"{locator.start_line}-{locator.end_line}"
                    )
                elif locator.contract and not any(d.parent == locator.contract for d in in_span):
                    # Declared, but inside a different type. A record naming both
                    # must have them agree, or it does not describe the place it
                    # claims to describe.
                    holders = sorted({d.parent or "<file scope>" for d in in_span})
                    failures.append(CheckFailure.FUNCTION_NOT_IN_CONTRACT)
                    detail.append(
                        f"{locator.function!r} is declared in {', '.join(holders)}, "
                        f"not in {locator.contract!r}"
                    )
                else:
                    # Overloads share a name, so resolving to more than one means
                    # the record has not identified a function. Picking either
                    # would verify it against an overload nobody chose.
                    candidates = (
                        [d for d in in_span if d.parent == locator.contract]
                        if locator.contract
                        else in_span
                    )
                    if len(candidates) > 1:
                        failures.append(CheckFailure.FUNCTION_AMBIGUOUS_IN_SPAN)
                        overloads = ", ".join(sorted(d.signature for d in candidates))
                        detail.append(
                            f"{locator.function!r} resolves to several overloads in lines "
                            f"{locator.start_line}-{locator.end_line} ({overloads}); the "
                            "record does not say which one it means"
                        )

    return VerificationResult(
        record.record_id,
        ok=not failures,
        failures=tuple(failures),
        detail="; ".join(detail),
        computed_sha256=digest,
    )


def verify_all(
    records: list[CorpusRecord], resolve: SourceResolver
) -> tuple[list[CorpusRecord], list[VerificationResult]]:
    """Partition records into admitted and rejected.

    Admitted records come back with `pin.sha256` set to the digest of the bytes
    they were verified against. Without that write-back the pin's promise is
    empty: a record carrying no digest would be admitted today against one file
    and tomorrow against different bytes, and nothing would notice.

    Inputs are never mutated; records that gain a digest are rebuilt.
    """
    admitted: list[CorpusRecord] = []
    rejected: list[VerificationResult] = []

    for record in records:
        result = verify_record(record, resolve)
        if not result.ok:
            rejected.append(result)
            continue

        if record.pin.sha256 is None and result.computed_sha256 is not None:
            pinned = record.pin.model_copy(update={"sha256": result.computed_sha256})
            record = record.model_copy(update={"pin": pinned})
        admitted.append(record)

    return admitted, rejected
