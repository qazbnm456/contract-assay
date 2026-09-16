"""Turning drafts into records: resolving locations, deriving spans, pinning bytes.

The second pipeline stage (§6.3). A draft says which repository, commit and file
a finding is in, and either a line span or just a function name. This stage
produces `CorpusRecord`s, which means it has to settle the location and pin the
bytes it settled it against.

Deriving a span is the part that earns its keep
-----------------------------------------------
A report naming a file and a function but no line numbers is not a lost finding.
The function can be looked up in the declaration index and its span taken. That
converts the whole prose-located category from unusable to usable, and that
category is exactly the one whose loss biases the corpus by era: linking
discipline correlates with recency, recency with language version, and version
with which classes were common.

Derivation obeys the same ambiguity discipline as verification. A name is only
resolved when it is declared exactly once within the scope the report named --
two overloads, or two contracts declaring it, and the draft is skipped. Picking
one would silently choose, and a record that describes a function nobody selected
is worse than no record.

Why this stage pins the digest
------------------------------
`verify` writes a digest onto any record arriving without one, which is right for
hand-authored records. It would be useless here. A derived span is not
cross-checked by verification -- asking the declaration index whether a function
sits inside a span that index produced is a tautology (§1.3) -- and the one
guarantee that *does* survive is that the file has not changed since the
derivation ran. That guarantee only exists if the digest is recorded **at
derivation time**. If this stage left it blank and let `verify` fill it in later,
verification would be comparing the file to itself, and the only real check on a
derived locator would be gone.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from contract_assay.corpus.harvest import DraftRecord
from contract_assay.corpus.records import (
    CorpusRecord,
    CorpusSplit,
    LocatorProvenance,
    SourcePin,
)
from contract_assay.corpus.verify import SourceResolver
from contract_assay.evidence.solidity import index_source
from contract_assay.models import Locator, VulnerabilityClass

__all__ = [
    "NormalizeCause",
    "NormalizeReport",
    "NormalizedSkip",
    "normalize",
]

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


class NormalizeCause(StrEnum):
    """Why a draft could not become a record."""

    SOURCE_UNRESOLVABLE = "source_unresolvable"
    """The pinned commit or path could not be fetched."""

    UNPARSEABLE_SOURCE = "unparseable_source"
    """Nothing could be read from the file, so no span can be derived or checked."""

    SPAN_OUT_OF_RANGE = "span_out_of_range"
    """A stated span extends past the end of the file."""

    CONTRACT_NOT_FOUND = "contract_not_found"
    """The report named a type that the file does not declare."""

    FUNCTION_NOT_FOUND = "function_not_found"
    """The report named a function that is not declared where it said."""

    FUNCTION_AMBIGUOUS = "function_ambiguous"
    """The name resolves to several declarations, so it identifies none of them."""


@dataclass(frozen=True, slots=True)
class NormalizedSkip:
    draft: DraftRecord
    cause: NormalizeCause
    detail: str = ""


@dataclass(frozen=True, slots=True)
class NormalizeReport:
    """Records produced, drafts lost, and how many locations had to be derived."""

    records: tuple[CorpusRecord, ...] = ()
    skipped: tuple[NormalizedSkip, ...] = ()
    by_cause: Mapping[NormalizeCause, int] = field(default_factory=dict)
    skipped_by_class: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    records_by_class: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    records_by_provenance: Mapping[LocatorProvenance, int] = field(default_factory=dict)

    @property
    def drafts(self) -> int:
        return len(self.records) + len(self.skipped)

    @property
    def loss_rate(self) -> float:
        return len(self.skipped) / self.drafts if self.drafts else 0.0

    def loss_rate_for(self, cls: VulnerabilityClass) -> float:
        lost = self.skipped_by_class.get(cls, 0)
        seen = lost + self.records_by_class.get(cls, 0)
        return lost / seen if seen else 0.0

    def statement(self) -> str:
        """The sentence that goes beside any count of what this stage produced.

        Unlike the harvest and verification statements, this one discloses no
        floor on its own accuracy, and that is a fact about the stage rather than
        an omission. Every draft handed in gets exactly one outcome, so these
        counts are complete with respect to their input. What was lost before the
        drafts existed is harvest's to disclose, and it does.
        """
        if not self.drafts:
            return "No drafts were normalized."

        derived = self.records_by_provenance.get(LocatorProvenance.DERIVED, 0)
        produced = f"{len(self.records)} of {self.drafts} drafts normalized"
        derivation = (
            f" {derived} had {'its' if derived == 1 else 'their'} span derived from the "
            "declaration index, which verification cannot cross-check."
            if derived
            else ""
        )
        if not self.skipped:
            return f"{produced}; none were lost.{derivation}"

        causes = ", ".join(
            f"{cause.value} {count}"
            for cause, count in sorted(
                self.by_cause.items(), key=lambda item: (-item[1], item[0].value)
            )
        )
        worst = sorted(
            ((cls, self.loss_rate_for(cls)) for cls in self.skipped_by_class),
            key=lambda item: (-item[1], item[0].value),
        )[:3]
        concentration = (
            " Heaviest class losses: "
            + ", ".join(f"{cls.value} {rate:.0%}" for cls, rate in worst)
            + "."
            if worst
            else ""
        )
        return (
            f"{produced} ({1 - self.loss_rate:.1%}); {len(self.skipped)} lost -- "
            f"{causes}.{concentration}{derivation}"
        )


def _record_id(draft: DraftRecord) -> str:
    """A stable, readable, unique id for the record a draft becomes.

    Derived from the draft rather than assigned by position, so that running the
    pipeline twice over the same reports produces the same ids. Position-based
    ids would make a record's identity depend on how many other reports happened
    to be in the batch.
    """
    repo = _SLUG_STRIP.sub("-", draft.repo_url.rstrip("/").rsplit("/", 1)[-1].lower())
    digest = hashlib.sha256(
        "\0".join((draft.repo_url, draft.commit, draft.path, draft.candidate_id)).encode()
    ).hexdigest()[:8]
    return f"{repo.strip('-') or 'repo'}-{draft.classes[0].value.replace('_', '-')}-{digest}"


def _locate(draft: DraftRecord, source: str) -> tuple[Locator, LocatorProvenance] | NormalizeCause:
    """Settle a draft's location, deriving the span when the report gave none."""
    lines = len(source.split("\n"))

    if draft.start_line is not None and draft.end_line is not None:
        if draft.end_line > lines:
            return NormalizeCause.SPAN_OUT_OF_RANGE
        return (
            Locator(
                file=draft.path,
                contract=draft.contract,
                function=draft.function,
                start_line=draft.start_line,
                end_line=draft.end_line,
            ),
            LocatorProvenance.STATED,
        )

    index = index_source(source)
    if not index.parsed:
        return NormalizeCause.UNPARSEABLE_SOURCE
    if draft.contract and not index.declares_type(draft.contract):
        return NormalizeCause.CONTRACT_NOT_FOUND

    assert draft.function is not None  # DraftRecord refuses neither-span-nor-function
    found = index.callables(draft.function, inside_type=draft.contract or None)
    if not found:
        return NormalizeCause.FUNCTION_NOT_FOUND
    if len(found) > 1:
        # Two overloads, or the same name in two types. Choosing one would
        # produce a record describing a function nobody selected.
        return NormalizeCause.FUNCTION_AMBIGUOUS

    declaration = found[0]
    return (
        Locator(
            file=draft.path,
            contract=draft.contract or declaration.parent,
            function=draft.function,
            start_line=declaration.start_line,
            end_line=declaration.end_line,
        ),
        LocatorProvenance.DERIVED,
    )


def normalize(
    drafts: Iterable[DraftRecord],
    resolve: SourceResolver,
    *,
    split: CorpusSplit,
) -> NormalizeReport:
    """Resolve every draft's location and pin the bytes it was resolved against.

    `split` is a parameter because it is a policy decision about what the corpus
    is for, not a fact recoverable from a report. There is no default: a
    forgotten split would publish a record meant to be withheld.
    """
    records: list[CorpusRecord] = []
    skipped: list[NormalizedSkip] = []
    by_cause: Counter[NormalizeCause] = Counter()
    skipped_by_class: Counter[VulnerabilityClass] = Counter()
    records_by_class: Counter[VulnerabilityClass] = Counter()
    records_by_provenance: Counter[LocatorProvenance] = Counter()

    def lose(draft: DraftRecord, cause: NormalizeCause, detail: str = "") -> None:
        skipped.append(NormalizedSkip(draft, cause, detail))
        by_cause[cause] += 1
        skipped_by_class.update(draft.classes)

    for draft in drafts:
        source = resolve(draft.repo_url, draft.commit, draft.path)
        if source is None or not source.strip():
            lose(
                draft,
                NormalizeCause.SOURCE_UNRESOLVABLE,
                f"{draft.repo_url}@{draft.commit[:12]}:{draft.path}",
            )
            continue

        located = _locate(draft, source)
        if isinstance(located, NormalizeCause):
            lose(draft, located, f"{draft.contract or '?'}.{draft.function or '?'}")
            continue

        locator, provenance = located
        records.append(
            CorpusRecord(
                record_id=_record_id(draft),
                split=split,
                pin=SourcePin(
                    repo_url=draft.repo_url,
                    commit=draft.commit,
                    path=draft.path,
                    # Pinned here, not left for `verify`. For a derived span this
                    # is the only real check that remains, and it exists only if
                    # the digest witnesses the bytes the derivation ran against.
                    sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                ),
                locator=locator,
                locator_provenance=provenance,
                classes=list(draft.classes),
                provenance=draft.provenance,
            )
        )
        records_by_class.update(draft.classes)
        records_by_provenance[provenance] += 1

    return NormalizeReport(
        records=tuple(records),
        skipped=tuple(skipped),
        by_cause=dict(by_cause),
        skipped_by_class=dict(skipped_by_class),
        records_by_class=dict(records_by_class),
        records_by_provenance=dict(records_by_provenance),
    )
