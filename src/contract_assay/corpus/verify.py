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
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from contract_assay.corpus.records import (
    CorpusRecord,
    CorpusSplit,
    LocatorProvenance,
    SourcePin,
    defect_key,
    fold_preference,
)
from contract_assay.evidence.solidity import SolidityUnavailable, index_source
from contract_assay.models import VulnerabilityClass

__all__ = [
    "CheckFailure",
    "SourceResolver",
    "VerificationReport",
    "VerificationResult",
    "verify_all",
    "verify_record",
]


SourceResolver = Callable[[SourcePin], str | None]
"""(pin) -> file contents, or None if it cannot be resolved.

Takes the pin rather than its parts because there is more than one kind of pin
and they resolve from different places: a repository host for a commit, a
verification repository for an address. A three-argument signature spelled the
commit kind into every resolver ever written against it.
"""


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

    source = resolve(record.pin)
    if source is None:
        return _reject(
            record.record_id,
            CheckFailure.SOURCE_UNRESOLVABLE,
            record.pin.describe(),
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


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """What was admitted, what was not, and what the survivors are a sample of.

    The tallies are part of the result rather than something a caller may
    compute, because the thing they exist to prevent is their absence.
    Verification rejects what it cannot confirm, which is correct and is what
    makes the corpus worth having -- and it also means the corpus is not a sample
    of real defects but a sample of defects sitting where the declaration index
    can parse and name them unambiguously. Assembly-heavy contracts, generated
    code and heavily overloaded interfaces are thinner in it than in the world.

    That bias cannot be removed without giving up the property that makes the
    corpus trustworthy, so the answer is to stop it being invisible. "Recall
    0.62" and "recall 0.62 over a corpus that rejected 11% of candidates as
    unverifiable, concentrated in these classes" are different claims, and only
    the second is true. See section 1.3 of docs/design.md.
    """

    admitted: tuple[CorpusRecord, ...] = ()
    rejected: tuple[VerificationResult, ...] = ()
    duplicates: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """Admitted records describing a defect another admitted record already does.

    Keyed by the record this stage would keep, valued by the ones it would fold
    into it (§6.7's `defect_key` and `fold_preference`, the same pair
    `normalize` uses). Asked here because `normalize` folds within one *batch*
    and the corpus on disk is the union of every batch ever run: a defect whose
    second report arrived in a later harvest was held twice, forty-five times
    over, and a duplicate halves the recall its location can show. Reported
    rather than deleted -- removing a record is the caller's decision and this
    stage does not own the files.
    """

    by_failure: Mapping[CheckFailure, int] = field(default_factory=dict)
    """How many records each check turned away. A record may appear under several."""

    rejected_by_class: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    admitted_by_class: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    admitted_by_locator_provenance: Mapping[LocatorProvenance, int] = field(default_factory=dict)
    """Admitted records split by whether their span was stated or derived.

    Without this the admitted count mixes records whose span verification
    cross-checked with records whose span it could not -- see
    `LocatorProvenance`. The mix is invisible in a single total, which is the
    failure §1.3 describes, occurring inside the report built to implement it.
    """

    @property
    def candidates(self) -> int:
        return len(self.admitted) + len(self.rejected)

    @property
    def rejection_rate(self) -> float:
        """Share of candidates rejected. Zero when there were none, not undefined."""
        return len(self.rejected) / self.candidates if self.candidates else 0.0

    def rejection_rate_for(self, cls: VulnerabilityClass) -> float:
        """Per-class rejection rate, which is where a bias shows up.

        An overall rate can look tolerable while one class is decimated, and that
        class is then quietly under-represented in everything scored against the
        corpus.
        """
        seen = self.rejected_by_class.get(cls, 0) + self.admitted_by_class.get(cls, 0)
        return self.rejected_by_class.get(cls, 0) / seen if seen else 0.0

    @property
    def derived_locator_count(self) -> int:
        return self.admitted_by_locator_provenance.get(LocatorProvenance.DERIVED, 0)

    def sampling_statement(self) -> str:
        """One sentence a report must carry beside any number computed from this.

        Provided as a method rather than left to each caller so that the sentence
        is the same everywhere, and so that omitting it is a visible choice
        rather than an oversight.
        """
        admitted = _plural(len(self.admitted), "record")
        count = self.derived_locator_count
        derived = (
            f" {count} of those {'carries' if count == 1 else 'carry'} a derived "
            f"locator, whose span verification cannot cross-check."
            if count
            else ""
        )
        # The scope sentence closes every branch, including the clean one. A
        # reader quoting a number should not have to have hit a rejection to
        # learn what the number is over.
        scope = " Every number computed over this corpus describes the admitted records only."
        # A duplicate is not a rejection and belongs in the same sentence
        # anyway: it halves the recall its location can show, and nothing else
        # in a report would say so.
        folded = sum(len(v) for v in self.duplicates.values())
        if folded:
            scope = (
                f" {_plural(folded, 'admitted record')} describe a defect another admitted "
                "record already describes, across "
                f"{_plural(len(self.duplicates), 'location')}; each such pair halves the "
                "recall that location can show (§6.7)." + scope
            )
        if not self.rejected:
            return f"{admitted} admitted; no candidates were rejected.{derived}{scope}"

        failures = ", ".join(
            f"{failure.value} {count}"
            for failure, count in sorted(
                self.by_failure.items(), key=lambda item: (-item[1], item[0].value)
            )
        )
        worst = sorted(self.rejected_by_class.items(), key=lambda item: (-item[1], item[0].value))[
            :3
        ]
        concentration = (
            " Concentrated in " + ", ".join(f"{cls.value} ({count})" for cls, count in worst) + "."
            if worst
            else ""
        )
        return (
            f"{admitted} admitted; {len(self.rejected)} of "
            f"{_plural(self.candidates, 'candidate')} ({self.rejection_rate:.1%}) rejected as "
            f"unverifiable -- {failures}.{concentration}{derived}{scope}"
        )


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _classes_of(record: CorpusRecord) -> tuple[VulnerabilityClass, ...]:
    """What a record is about, whichever polarity it has."""
    return tuple(record.classes or record.negative_for)


def _duplicate_groups(admitted: list[CorpusRecord]) -> dict[str, tuple[str, ...]]:
    """Which admitted records describe a defect another one already describes."""
    groups: dict[tuple[str, ...], list[CorpusRecord]] = {}
    for record in admitted:
        if record.locator is None:
            continue
        groups.setdefault(defect_key(record), []).append(record)
    folded: dict[str, tuple[str, ...]] = {}
    for members in groups.values():
        if len(members) < 2:
            continue
        ranked = sorted(members, key=fold_preference)
        folded[ranked[0].record_id] = tuple(r.record_id for r in ranked[1:])
    return folded


def verify_all(records: list[CorpusRecord], resolve: SourceResolver) -> VerificationReport:
    """Check every record and report what survived, what did not, and why.

    Admitted records come back with `pin.sha256` set to the digest of the bytes
    they were verified against. Without that write-back the pin's promise is
    empty: a record carrying no digest would be admitted today against one file
    and tomorrow against different bytes, and nothing would notice.

    Inputs are never mutated; records that gain a digest are rebuilt.
    """
    admitted: list[CorpusRecord] = []
    rejected: list[VerificationResult] = []
    by_failure: Counter[CheckFailure] = Counter()
    rejected_by_class: Counter[VulnerabilityClass] = Counter()
    admitted_by_class: Counter[VulnerabilityClass] = Counter()
    admitted_by_provenance: Counter[LocatorProvenance] = Counter()

    for record in records:
        result = verify_record(record, resolve)
        if not result.ok:
            rejected.append(result)
            by_failure.update(result.failures)
            rejected_by_class.update(_classes_of(record))
            continue

        if record.pin.sha256 is None and result.computed_sha256 is not None:
            pinned = record.pin.model_copy(update={"sha256": result.computed_sha256})
            record = record.model_copy(update={"pin": pinned})
        admitted.append(record)
        admitted_by_class.update(_classes_of(record))
        if record.locator_provenance is not None:
            admitted_by_provenance[record.locator_provenance] += 1

    return VerificationReport(
        admitted=tuple(admitted),
        duplicates=_duplicate_groups(admitted),
        rejected=tuple(rejected),
        by_failure=dict(by_failure),
        rejected_by_class=dict(rejected_by_class),
        admitted_by_class=dict(admitted_by_class),
        admitted_by_locator_provenance=dict(admitted_by_provenance),
    )
