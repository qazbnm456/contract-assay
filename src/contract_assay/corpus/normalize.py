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
    CommitPin,
    CorpusRecord,
    CorpusSplit,
    LocatorLabel,
    LocatorProvenance,
    Population,
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


def _blank_comments(text: str) -> str:
    """Comments removed **without moving any line**.

    `sub("", ...)` collapses a block comment spanning several lines into
    nothing, which removes its newlines and shifts the number of every line
    after it. A quoted excerpt then matched at a plausible-looking but wrong
    span -- one file's banner comments shifted a match by 28 lines -- and the
    match was *unique*, so nothing in the matcher noticed.

    What noticed was `verify`, whose declaration check found the named function
    absent from the matched span. That is the whole reason a record is checked
    against the source after being built rather than trusted from the stage
    that built it.
    """
    return _COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)


_LINE_PREFIX = re.compile(r"^\s*\d+:\s?")
_POINTER = re.compile(r"^\s*(@>|\|>|=>)\s?")
"""A reviewer's marker pointing at the line that matters.

Two conventions seen in published reports -- `@> return x;` and
`|>  require(...)` -- and they were costing whole records rather than one line
each: the marked line failed to match, which broke *contiguity*, so an excerpt
whose every other line was present matched nothing at all.
"""


def _comparable(raw: str) -> str:
    """One line reduced to what a match should be sensitive to.

    All whitespace goes, not merely runs of it. A report writing
    `if(oracleTimestamp > lastPriceTimestamp){` against a source written
    `if (oracleTimestamp > lastPriceTimestamp) {` is quoting the same code, and
    collapsing runs left the two unequal -- an excerpt of fifteen lines matched
    its first four and then stopped, and the record was lost to a space. Nothing
    in Solidity's grammar makes whitespace meaningful outside a string literal,
    and two literals differing only in spacing would at worst make a match
    ambiguous, which is refused rather than recorded.
    """
    return "".join(_annotation_free(raw).split())


def _annotation_free(raw: str) -> str:
    """One line with the report's annotations removed, in either order.

    Number prefixes and pointer markers both occur first, and both occur
    together, so the two strips run twice rather than assuming an order.
    """
    line = raw
    for _ in range(2):
        line = _POINTER.sub("", _LINE_PREFIX.sub("", line))
    return line


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
    prefixes and pointer markers go because some report tooling adds them.
    Whitespace goes entirely because it is not semantic -- the same reasoning
    `check_citation` applies to a detector's quote, and for consistency the same
    treatment.
    """
    stripped = _COMMENT.sub("", text)
    out: list[str] = []
    for raw in stripped.split("\n"):
        line = _comparable(raw)
        if line and line not in _ELISION:
            out.append(line)
    return out


def _file_the_quote_names(draft: DraftRecord, resolve: SourceResolver) -> str | NormalizeCause:
    """Which of the cited files the excerpt occurs in, or why none was chosen.

    The adapter hands over the whole cited set when a finding names several
    Solidity files, because a quoted excerpt states which one if it occurs in
    exactly one of them -- and only this stage holds the bytes to check. Which
    file the adapter put in `path` is not load-bearing: every candidate is
    resolved and the excerpt has to occur uniquely in exactly one.

    Two files containing it identifies neither, which is `quote_ambiguous` for
    the same reason two occurrences in one file are. None containing it is a
    different loss, since the file was never stated and the excerpt was supposed
    to choose it.
    """
    assert draft.quoted_source is not None
    matched: list[str] = []
    for path in (draft.path, *draft.alternative_paths):
        pin = CommitPin(
            repo_url=draft.repo_url,
            commit=draft.commit,
            path=path,
            resolved_from=draft.commit_resolved_from,
        )
        source = resolve(pin)
        if source is None or not source.strip():
            continue
        if isinstance(_match_quote(draft.quoted_source, source), tuple):
            matched.append(path)
    if len(matched) == 1:
        return matched[0]
    if len(matched) > 1:
        return NormalizeCause.QUOTE_AMBIGUOUS
    return NormalizeCause.FILE_NOT_DETERMINED


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
        (n, _comparable(raw)) for n, raw in enumerate(_blank_comments(source).split("\n"), 1)
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
    """The excerpt occurs more than once, so it locates nothing.

    Within one file or across the candidate set a finding cited -- the two are
    the same failure. An excerpt occurring in two of the cited files identifies
    neither, and taking the first would be a wrong record that no contiguity
    test catches.
    """

    FILE_NOT_DETERMINED = "file_not_determined"
    """The excerpt occurs in none of the files the finding cited.

    Counted apart from `quote_not_found`, which is about one stated file. Here
    the file was never stated and the excerpt was supposed to choose it, so what
    failed is the choosing -- and a loss filed under the wrong cause points
    investigation away from the fix (§1.3).
    """

    QUOTE_CONTRADICTS_SPAN = "quote_contradicts_span"
    """The report's stated span and its quoted excerpt point at different code."""

    NO_DECLARATION_AT_ANCHOR = "no_declaration_at_anchor"
    """The line the report pointed at is not inside any function-like declaration."""

    SPAN_STRADDLES_DECLARATIONS = "span_straddles_declarations"
    """The located span overlaps more than one declaration, so it names no function.

    Found in a published record rather than in a test. An excerpt matched a
    region beginning on a function's closing brace and running into the next
    function's body; the enclosing declaration was read off the span's *first*
    line, so the record named `claimFlux` while the defect -- and the report's
    own title -- said `getClaimableFlux`. Every check passed: the span was
    inside the file, the name was not asserted by the report so there was
    nothing to cross-check, and the function it named really does exist.

    A span covering two functions has not located one, in the same way a finding
    naming two places has not said which (`location_contradicts_name`). Refused
    rather than resolved by preference, because either function is a defensible
    reading of a quote that covers both.
    """

    LOCATION_CONTRADICTS_NAME = "location_contradicts_name"
    """The finding named a function that is not declared where its location points.

    Measured on six drafts, and the shape was identical in all six: the prose
    named a function declared in *another file* -- a library's
    `validateVariablePoolHasEnoughLiquidity` called from the quoted lines,
    `nuke` when the quote shows `burn`, a hook's `onQueueWithdrawal` when the
    quote shows `closeMarket` -- so the finding pointed at two places and said
    nothing about which holds the defect. §7.3's rule, arriving in curation: a
    call edge is not the same function.

    Preferring the quote would have pinned three of the six to code the title
    was not about. Preferring the name would have thrown away the only signal
    the source can confirm. So the draft is refused, and refused *here*, where
    both signals are in hand -- `verify` reported this as a span with a missing
    declaration, which reads as a defect in the span and sends the reader to the
    wrong place.
    """

    NO_ENCLOSING_FUNCTION = "no_enclosing_function"
    """The located span is in no function, and the report named none either.

    A span covering a whole contract, a state variable block or a modifier. The
    location may well be right; it is not a location this benchmark can score,
    because scoring is at function granularity. Counted apart from
    `no_declaration_at_anchor` because that one is about a line the report
    pointed at, and this one is about a span the report gave outright.
    """

    ANCHOR_CONTRADICTS_CONTRACT = "anchor_contradicts_contract"
    """The report named a contract, and the line it pointed at is in a different one."""


@dataclass(frozen=True, slots=True)
class Located:
    """A settled location, and how it was settled."""

    locator: Locator
    provenance: LocatorProvenance
    anchor_line: int | None = None
    asserted_labels: tuple[LocatorLabel, ...] = ()
    """Labels the report supplied, as opposed to ones read off the index.

    Carried through because whether the location was independently confirmed
    depends on it, and a record cannot recover it afterwards: once the index has
    filled a label in, nothing distinguishes it from one the report stated.
    """


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
    duplicates: int = 0
    """Records folded into an earlier one describing the same defect.

    Not a loss, and counted apart from losses for that reason. Some platforms
    deduplicate submissions before publishing and some do not, so the same
    defect can arrive several times -- one observed competition had four
    submissions pointing at one function. Kept as separate records they would
    inflate recall directly: a detector finding that defect once would match all
    four, and nothing in the output would say the corpus had counted it four
    times.
    """

    @property
    def drafts(self) -> int:
        return len(self.records) + len(self.skipped) + self.duplicates

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
        folded = (
            f" {_plural(self.duplicates, 'further draft')} described a defect already "
            f"recorded and {'was' if self.duplicates == 1 else 'were'} folded in."
            if self.duplicates
            else ""
        )
        if not self.skipped:
            return f"{produced}; none were lost.{folded}{derivation}"

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
            f"{causes}.{concentration}{folded}{derivation}"
        )


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


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


def _labels_from(draft: DraftRecord, *, function: bool = True) -> tuple[LocatorLabel, ...]:
    """Which locator labels this draft's report actually stated.

    `function` is False where the span's own route supplies the name: an
    anchored span is labelled from the declaration the line landed in, so a name
    on the locator did not come from the report and cannot corroborate anything.
    """
    labels: list[LocatorLabel] = []
    if draft.contract:
        labels.append(LocatorLabel.CONTRACT)
    if function and draft.function:
        labels.append(LocatorLabel.FUNCTION)
    return tuple(labels)


def _straddles_declarations(source: str, span: tuple[int, int]) -> bool:
    """Whether more than one function-like declaration overlaps the span."""
    parsed = Syntax.of(source)
    if parsed is None:
        return False
    start, end = span
    overlapping = [
        declaration
        for declaration in parsed.index.declarations
        if not declaration.kind.is_type
        and declaration.start_line <= end
        and start <= declaration.end_line
    ]
    return len(overlapping) > 1


def _declared_within(source: str, name: str, span: tuple[int, int]) -> bool:
    """Whether a function of that name is declared inside the located lines.

    The same question `verify` asks of the assembled record, asked at the stage
    that still holds both signals. Unparseable source answers False, which
    costs the draft; it would have been refused as unparseable a moment later
    anyway.
    """
    parsed = Syntax.of(source)
    if parsed is None:
        return False
    return bool(parsed.index.callables(name, within=span))


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
        if _straddles_declarations(source, (draft.start_line, draft.end_line)):
            return NormalizeCause.SPAN_STRADDLES_DECLARATIONS
        if draft.function and not _declared_within(
            source, draft.function, (draft.start_line, draft.end_line)
        ):
            return NormalizeCause.LOCATION_CONTRADICTS_NAME
        if not (draft.function or enclosing[1]):
            return NormalizeCause.NO_ENCLOSING_FUNCTION
        return Located(
            Locator(
                file=draft.path,
                contract=draft.contract or enclosing[0],
                function=draft.function or enclosing[1],
                start_line=draft.start_line,
                end_line=draft.end_line,
            ),
            LocatorProvenance.STATED,
            asserted_labels=_labels_from(draft),
        )

    if isinstance(quoted, tuple):
        start, end = quoted
        enclosing = parsed_contract_of(source, start)
        if _straddles_declarations(source, (start, end)):
            return NormalizeCause.SPAN_STRADDLES_DECLARATIONS
        # The prose name overrode the enclosing declaration here, which is how
        # a finding that quoted a caller and named a callee became a record
        # pinning the callee's name to the caller's lines.
        if draft.function and not _declared_within(source, draft.function, (start, end)):
            return NormalizeCause.LOCATION_CONTRADICTS_NAME
        if not (draft.function or enclosing[1]):
            return NormalizeCause.NO_ENCLOSING_FUNCTION
        return Located(
            Locator(
                file=draft.path,
                contract=draft.contract or enclosing[0],
                function=draft.function or enclosing[1],
                start_line=start,
                end_line=end,
            ),
            LocatorProvenance.QUOTED,
            asserted_labels=_labels_from(draft),
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
            # The function name came from the declaration the anchor landed in,
            # never from the report, so it cannot corroborate the span.
            asserted_labels=_labels_from(draft, function=False),
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
        asserted_labels=_labels_from(draft),
    )


def parsed_contract_of(source: str, line: int) -> tuple[str | None, str | None]:
    """The contract and function containing a line, for labelling a matched span."""
    parsed = Syntax.of(source)
    if parsed is None:
        return None, None
    host = parsed.host_at(line)
    return host.contract, host.function


def _defect_key(record: CorpusRecord) -> tuple[str, ...]:
    """What makes two records the same defect.

    The pinned bytes, the function, and the class. Two reports naming the same
    function of the same commit for the same class are describing one defect in
    all but pathological cases; two *different* defects in one function would be
    merged, which is the error this trade accepts, and it is the smaller one --
    an under-counted corpus understates recall where a duplicated one overstates
    it, and only the second is invisible.
    """
    assert record.locator is not None
    return (
        record.pin.source_id,
        record.locator.function or "",
        ",".join(sorted(c.value for c in record.classes)),
    )


def _preference(record: CorpusRecord) -> tuple[int, int, int, str]:
    """Which of two records describing one defect to keep.

    Confirmation first, then how many claims the report made, then the narrower
    span, then the id so the choice is deterministic. Deliberately not a ranking
    of provenances against each other: `stated` and `quoted` fail differently
    and neither outranks the other (§6.6), so the tie is broken on what the
    report asserted rather than on how the span was obtained.
    """
    assert record.locator is not None
    width = record.locator.end_line - record.locator.start_line
    return (
        -int(record.is_cross_checked),
        -record.report_assertion_count,
        width,
        record.record_id,
    )


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
        # The pin is built before resolution rather than after, because
        # resolution is now asked for a pin: where bytes come from depends on
        # what kind of coordinates name them, and only the pin knows that.
        pin = CommitPin(
            repo_url=draft.repo_url,
            commit=draft.commit,
            path=draft.path,
            resolved_from=draft.commit_resolved_from,
        )
        if draft.alternative_paths:
            chosen = _file_the_quote_names(draft, resolve)
            if isinstance(chosen, NormalizeCause):
                lose(draft, chosen, ", ".join((draft.path, *draft.alternative_paths))[:120])
                continue
            # The *draft* is narrowed, not only the pin. Updating the pin alone
            # left the locator's file taken from the draft, so a record chosen
            # from an alternative named one file in its pin and another in its
            # locator -- which the record's own invariant then refused, loudly
            # and one stage too late.
            draft = draft.model_copy(update={"path": chosen, "alternative_paths": ()})
            pin = pin.model_copy(update={"path": chosen})
        source = resolve(pin)
        if source is None or not source.strip():
            lose(draft, NormalizeCause.SOURCE_UNRESOLVABLE, pin.describe())
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
                # Digested here, not left for `verify`. For a derived span this
                # is the only real check that remains, and it exists only if the
                # digest witnesses the bytes the derivation ran against.
                pin=pin.model_copy(
                    update={"sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()}
                ),
                locator=located.locator,
                locator_provenance=located.provenance,
                anchor_line=located.anchor_line,
                asserted_labels=list(located.asserted_labels),
                classes=list(draft.classes),
                provenance=draft.provenance,
            )
        )
        records_by_class.update(draft.classes)
        records_by_provenance[located.provenance] += 1

    # Fold records describing one defect, keeping the best-supported of each.
    best: dict[tuple[str, ...], CorpusRecord] = {}
    duplicates = 0
    for record in records:
        key = _defect_key(record)
        existing = best.get(key)
        if existing is None:
            best[key] = record
            continue
        duplicates += 1
        if _preference(record) < _preference(existing):
            best[key] = record

    kept = sorted(best.values(), key=lambda r: r.record_id)
    records_by_class = Counter(c for r in kept for c in r.classes)
    records_by_provenance = Counter(
        r.locator_provenance for r in kept if r.locator_provenance is not None
    )

    return NormalizeReport(
        records=tuple(kept),
        skipped=tuple(skipped),
        by_cause=dict(by_cause),
        skipped_by_class=dict(skipped_by_class),
        records_by_class=dict(records_by_class),
        records_by_provenance=dict(records_by_provenance),
        duplicates=duplicates,
    )
