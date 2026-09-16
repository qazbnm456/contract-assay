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
    Population,
    SourcePin,
)
from contract_assay.corpus.verify import SourceResolver
from contract_assay.evidence.syntax import Syntax
from contract_assay.models import Locator, VulnerabilityClass

__all__ = [
    "Located",
    "NormalizeCause",
    "NormalizeReport",
    "NormalizedSkip",
    "normalize",
]

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_COMMENT = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_LINE_PREFIX = re.compile(r"^\s*\d+:\s?")
_ELISION = frozenset({"...", "\u2026", "..", "/* ... */"})

MIN_QUOTE_LINES = 3
"""Shortest excerpt worth matching.

A one- or two-line snippet is too easily duplicated elsewhere in a file to
locate anything, and a match that is unique by accident is a wrong record
waiting to happen.
"""


def _normalised_lines(text: str) -> list[str]:
    """Code lines with comments, line-number prefixes and elisions removed.

    Comments go because reviewers annotate the code they quote. Line-number
    prefixes go because some report tooling adds them. Whitespace collapses
    because indentation is not semantic -- the same reasoning `check_citation`
    applies to a detector's quote, and for consistency the same treatment.
    """
    stripped = _COMMENT.sub("", text)
    out: list[str] = []
    for raw in stripped.split("\n"):
        line = " ".join(_LINE_PREFIX.sub("", raw).split())
        if line and line not in _ELISION:
            out.append(line)
    return out


def _match_quote(quote: str, source: str) -> tuple[int, int] | NormalizeCause | None:
    """Where a quoted excerpt uniquely occurs in a file, as 1-indexed lines.

    Matching is exact and contiguous over normalised lines. That is deliberately
    strict: an excerpt with an elision removed is no longer contiguous in the
    source, so it will not match, and it becomes a counted loss rather than a
    fuzzy match placed somewhere plausible. A wrong record scores every
    submission against a lie, where a missing one costs a single test item.

    Uniqueness is required. An excerpt occurring twice locates nothing, and
    taking the first would be a wrong record that no contiguity test catches,
    because a wrong match can be perfectly contiguous.

    Returns None when the excerpt is too short to be worth matching, so the
    caller can fall through to a weaker route rather than record a loss.
    """
    want = _normalised_lines(quote)
    if len(want) < MIN_QUOTE_LINES:
        return None

    numbered = [
        (n, " ".join(_LINE_PREFIX.sub("", raw).split()))
        for n, raw in enumerate(_COMMENT.sub("", source).split("\n"), 1)
    ]
    kept = [(n, line) for n, line in numbered if line and line not in _ELISION]
    haystack = [line for _, line in kept]

    hits = [i for i in range(len(haystack) - len(want) + 1) if haystack[i : i + len(want)] == want]
    if not hits:
        return NormalizeCause.QUOTE_NOT_FOUND
    if len(hits) > 1:
        return NormalizeCause.QUOTE_AMBIGUOUS
    start = kept[hits[0]][0]
    end = kept[hits[0] + len(want) - 1][0]
    return start, end


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

    QUOTE_NOT_FOUND = "quote_not_found"
    """The excerpt the report quoted does not occur in the pinned file."""

    QUOTE_AMBIGUOUS = "quote_ambiguous"
    """The excerpt occurs more than once, so it locates nothing."""

    QUOTE_CONTRADICTS_SPAN = "quote_contradicts_span"
    """The report's stated span and its quoted excerpt point at different code."""

    NO_DECLARATION_AT_ANCHOR = "no_declaration_at_anchor"
    """The line the report pointed at is not inside any function-like declaration."""

    ANCHOR_CONTRADICTS_CONTRACT = "anchor_contradicts_contract"
    """The report named a contract, and the line it pointed at is in a different one."""


@dataclass(frozen=True, slots=True)
class Located:
    """A settled location, and how it was settled."""

    locator: Locator
    provenance: LocatorProvenance
    anchor_line: int | None = None


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
        anchored = self.records_by_provenance.get(LocatorProvenance.ANCHORED, 0)
        produced = f"{len(self.records)} of {self.drafts} drafts normalized"
        derivation = "".join(
            part
            for part in (
                (
                    f" {anchored} {'is' if anchored == 1 else 'are'} anchored to a stated "
                    "line and widened to its declaration."
                    if anchored
                    else ""
                ),
                (
                    f" {derived} had {'its' if derived == 1 else 'their'} span inferred from "
                    "a function named in prose, which supports no exact-location match."
                    if derived
                    else ""
                ),
            )
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


def _locate(draft: DraftRecord, source: str) -> Located | NormalizeCause:
    """Settle a draft's location by the strongest route the report supports.

    Three routes, in descending order of what the report actually asserted: a
    stated line range, a single stated line widened to the declaration
    containing it, and a function named in prose.
    """
    lines = len(source.split("\n"))
    quoted: tuple[int, int] | NormalizeCause | None = None
    if draft.quoted_source and draft.quoted_source.strip():
        quoted = _match_quote(draft.quoted_source, source)

    if draft.start_line is not None and draft.end_line is not None:
        if draft.end_line > lines:
            return NormalizeCause.SPAN_OUT_OF_RANGE
        if isinstance(quoted, tuple) and not (
            draft.start_line <= quoted[1] and quoted[0] <= draft.end_line
        ):
            # Two assertions from the report, adjudicated by the repository's
            # bytes, and they disagree about where the defect is. Neither is
            # obviously the wrong one, so the record is refused rather than
            # decided by preference.
            return NormalizeCause.QUOTE_CONTRADICTS_SPAN
        # The span is the report's, and stays the report's. Only the labels are
        # filled in where it gave none: a report citing a line range without
        # naming the function is common, and a record with no function cannot be
        # scored at function granularity -- so it would be lost for the sake of a
        # name the index can read off the span it was already given.
        enclosing = parsed_contract_of(source, draft.start_line)
        return Located(
            Locator(
                file=draft.path,
                contract=draft.contract or enclosing[0],
                function=draft.function or enclosing[1],
                start_line=draft.start_line,
                end_line=draft.end_line,
            ),
            LocatorProvenance.STATED,
        )

    if isinstance(quoted, tuple):
        start, end = quoted
        enclosing = parsed_contract_of(source, start)
        return Located(
            Locator(
                file=draft.path,
                contract=draft.contract or enclosing[0],
                function=draft.function or enclosing[1],
                start_line=start,
                end_line=end,
            ),
            LocatorProvenance.QUOTED,
        )
    if quoted is not None:
        return quoted

    parsed = Syntax.of(source)
    if parsed is None:
        return NormalizeCause.UNPARSEABLE_SOURCE

    if draft.anchor_line is not None:
        if draft.anchor_line > lines:
            return NormalizeCause.SPAN_OUT_OF_RANGE
        declaration = parsed.callable_at(draft.anchor_line)
        if declaration is None:
            # A line in a state variable block, an import or a comment. The
            # report pointed somewhere real and this stage cannot name a function
            # for it, which is a loss rather than a licence to guess.
            return NormalizeCause.NO_DECLARATION_AT_ANCHOR
        if draft.contract and declaration.parent != draft.contract:
            # The report gave two independent signals -- a contract name and a
            # line -- and they disagree. This is the one genuine cross-check an
            # anchored locator has: neither signal came from the declaration
            # index, so their agreement is evidence, and their disagreement means
            # the record does not describe what it claims to.
            return NormalizeCause.ANCHOR_CONTRADICTS_CONTRACT
        return Located(
            Locator(
                file=draft.path,
                contract=declaration.parent,
                function=declaration.names[0],
                start_line=declaration.start_line,
                end_line=declaration.end_line,
            ),
            LocatorProvenance.ANCHORED,
            anchor_line=draft.anchor_line,
        )

    if draft.contract and not parsed.index.declares_type(draft.contract):
        return NormalizeCause.CONTRACT_NOT_FOUND

    assert draft.function is not None  # DraftRecord refuses a draft with none of the three
    found = parsed.index.callables(draft.function, inside_type=draft.contract or None)
    if not found:
        return NormalizeCause.FUNCTION_NOT_FOUND
    if len(found) > 1:
        # Two overloads, or the same name in two types. Choosing one would
        # produce a record describing a function nobody selected.
        return NormalizeCause.FUNCTION_AMBIGUOUS

    declaration = found[0]
    return Located(
        Locator(
            file=draft.path,
            contract=draft.contract or declaration.parent,
            function=draft.function,
            start_line=declaration.start_line,
            end_line=declaration.end_line,
        ),
        LocatorProvenance.DERIVED,
    )


def parsed_contract_of(source: str, line: int) -> tuple[str | None, str | None]:
    """The contract and function containing a line, for labelling a matched span."""
    parsed = Syntax.of(source)
    if parsed is None:
        return None, None
    host = parsed.host_at(line)
    return host.contract, host.function


def normalize(
    drafts: Iterable[DraftRecord],
    resolve: SourceResolver,
    *,
    split: CorpusSplit,
    population: Population,
) -> NormalizeReport:
    """Resolve every draft's location and pin the bytes it was resolved against.

    `split` and `population` are parameters because neither is recoverable from a
    report: the first is a policy decision about what the corpus is for, and the
    second is a property of the body of work the reports came from. Neither has a
    default -- a forgotten split would publish a record meant to be withheld, and
    a forgotten population would put records from two oppositely-skewed bodies of
    work into one undifferentiated count.
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

        records.append(
            CorpusRecord(
                record_id=_record_id(draft),
                population=population,
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
                locator=located.locator,
                locator_provenance=located.provenance,
                anchor_line=located.anchor_line,
                classes=list(draft.classes),
                provenance=draft.provenance,
            )
        )
        records_by_class.update(draft.classes)
        records_by_provenance[located.provenance] += 1

    return NormalizeReport(
        records=tuple(records),
        skipped=tuple(skipped),
        by_cause=dict(by_cause),
        skipped_by_class=dict(skipped_by_class),
        records_by_class=dict(records_by_class),
        records_by_provenance=dict(records_by_provenance),
    )
