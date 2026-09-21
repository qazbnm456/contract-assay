"""Turning public audit reports into draft records, and counting what was lost.

Harvest is the first pipeline stage (§6.3). It reads reports as data -- fetching
is somebody else's problem, injected the same way `verify` takes a resolver --
and produces `DraftRecord`s for `normalize` to locate and pin.

The accounting is not a side feature. A harvester parsing only certain report
shapes yields a corpus skewed toward the platforms it happens to read well, and
the skew is invisible in the output, because what is missing left no record. So
this module counts every candidate it identified and what became of it, and it
counts the losses **by class**, which is the part that turns magnitude into
diagnosis: a per-platform count cannot separate "we skipped 40% of this
platform" from "this platform has a different class mix", whereas "skipped 61% of
arithmetic candidates and 9% of oracle candidates" says outright that the
surviving distribution is an artefact. Class survives location failure, because
a report states the vulnerability type even when it describes the place in prose.

Why the adapter protocol has two phases
---------------------------------------
An adapter that returned "the findings I could use" would make its own
accounting optional: a candidate it quietly dropped is indistinguishable from a
candidate that was never there. So an adapter instead *enumerates* candidates
and then resolves them one at a time, and this module drives the loop. The count
of candidates and the count of outcomes are then the same number by
construction, and an adapter cannot omit a skip without also omitting the
candidate -- which is visible.

The floor on that, stated rather than papered over
--------------------------------------------------
An adapter can only account for what it recognised as a finding in the first
place. A report section it failed to identify at all is absent from the skip
tally, because the mechanism that finds findings and the mechanism that counts
missed ones are the same mechanism. That is §1.3 again and it is not fixable
here, so `yield_statement()` says it, in the same way the corpus statement says
what the corpus is a sample of.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contract_assay.corpus.records import Provenance, check_unit_path
from contract_assay.models import VulnerabilityClass

SAMPLES = 3
"""How many inputs to retain per not-stated verdict.

Enough to tell a reader failure from a genuine absence -- one sample is an
anecdote and the whole set is the input -- and small enough that a statement
stays readable.
"""

__all__ = [
    "Candidate",
    "CommitResolver",
    "DraftRecord",
    "HarvestReport",
    "RawReport",
    "ReportAdapter",
    "Skip",
    "SkipCause",
    "SkippedCandidate",
    "harvest",
]

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class SkipCause(StrEnum):
    """Why an identified candidate could not become a draft record.

    Each names a specific missing thing, because "could not extract" aggregated
    across seven causes tells an adapter author nothing about what to fix and
    tells a reader nothing about which shapes are being lost.
    """

    NO_REPOSITORY = "no_repository"
    """No repository could be determined, so nothing can be pinned."""

    NO_COMMIT = "no_commit"
    """No full commit SHA. A branch name or a tag is not reproducible."""

    NO_FILE_PATH = "no_file_path"
    """A location was described but no file could be resolved from it."""

    NO_SOURCE_AT_ADDRESS = "no_source_at_address"
    """The report located a deployed contract, and no verified source was found.

    Counted apart from `no_file_path` because the two point at different fixes,
    and one of them is not a fix to this pipeline at all. A target naming a
    document states no location; a target naming `/address/0x...` states a
    perfectly good one, in coordinates an `AddressPin` can hold (§6.1). What is
    missing is the source at that address, which is a fact about what has been
    verified on that chain rather than about the report or the reader.

    Found by reading the inputs behind a `no_file_path` count of 35: every
    retained sample was an explorer address URL, and filing them as stating no
    location was the reader again.
    """

    NO_LOCATION = "no_location"
    """Neither a line span nor a function name, so nothing can be derived."""

    UNMAPPED_CLASS = "unmapped_class"
    """The report's vulnerability label does not map onto any of the nine."""

    NO_CLASS = "no_class"
    """The report states no vulnerability type at all."""

    CITES_ANOTHER_REPOSITORY = "cites_another_repository"
    """The only location the finding states is outside the code under review.

    A report cites a dependency to show what the reviewed code was derived from
    or ought to have done, and a finding whose sole citation points there has
    not located a defect in the reviewed code. Pinning the record to the
    dependency would attribute the defect to a third party the report never
    claimed was defective -- which the first run of the quote route did, to an
    upstream library, for a finding about a port of it.

    Its own cause rather than `no_file_path`, because the fix differs: this one
    needs the report's scope read, not a better path parser (§1.3).
    """

    NOT_A_FINDING = "not_a_finding"
    """Identified as a candidate but turned out to be an informational note."""

    MALFORMED_REPORT = "malformed_report"
    """The report could not be read far enough to judge."""

    @property
    def is_an_absence(self) -> bool:
        """Whether this cause is a claim that the input did not state something.

        These are the causes that have been wrong every time they were checked.
        A quarter of one archive was filed as out of scope by a reader that
        could not parse its metadata block; four incident populations were
        written off as unpinnable by a schema that could not express an address;
        a proof-of-concept archive was reported as stating no fork points by a
        pattern that wanted a literal. Every case opened was the reader, none
        was the input.

        So a zero under one of these causes is a hypothesis, and the report
        carries samples of the inputs that produced it (§6.3).
        """
        return self in (
            SkipCause.NO_REPOSITORY,
            SkipCause.NO_COMMIT,
            SkipCause.NO_FILE_PATH,
            SkipCause.NO_LOCATION,
            SkipCause.NO_CLASS,
            SkipCause.MALFORMED_REPORT,
        )


class RawReport(BaseModel):
    """One audit report as fetched, before anything is parsed out of it.

    Passed in rather than fetched. Fetching is an outward-facing action with its
    own licensing and rate-limit questions, and keeping it outside this module is
    what lets the whole stage run in the offline gate.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    platform: str = Field(min_length=1)
    report_url: str = Field(min_length=1)
    body: str = Field(description="The report as fetched: markdown, HTML or JSON.")
    published: str | None = Field(
        default=None,
        description=(
            "ISO date the platform recorded for this report, where it keeps one outside "
            "the document. Used to bound a commit recovery, never to locate anything."
        ),
    )


class Candidate(BaseModel):
    """A finding an adapter believes a report contains, before extraction.

    Carries the class signal so that a candidate which fails extraction can
    still be counted under its class. That is the whole point of separating
    identification from extraction: a location can be unrecoverable while the
    vulnerability type remains perfectly clear.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str = Field(min_length=1, description="Stable within one report.")
    classes: tuple[VulnerabilityClass, ...] = Field(
        default=(),
        description="Mapped classes. Empty when the report's label maps onto none of the nine.",
    )
    raw_labels: tuple[str, ...] = Field(
        default=(), description="The report's own labels, kept for diagnosis."
    )
    title: str = Field(default="", description="Diagnostic only; never scored.")


class DraftRecord(BaseModel):
    """An extracted finding, before its location is resolved and its bytes pinned.

    Invariants here rather than in `normalize`, so that a draft which cannot
    become a record is refused at the point it is built, where the adapter that
    built it is still identifiable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str = Field(min_length=1)
    repo_url: str = Field(min_length=1)
    commit: str = Field(description="Full 40-hex SHA. Refs and short SHAs move.")
    path: str = Field(min_length=1)
    alternative_paths: tuple[str, ...] = Field(
        default=(),
        description=(
            "Other files the finding cited, when a quoted excerpt is what will decide "
            "which of them the defect is in. Empty when the file was stated."
        ),
    )
    commit_resolved_from: str | None = Field(
        default=None,
        description=(
            "Set when the adapter inferred the commit rather than reading it, stating "
            "how. Carried onto the pin so the assumption is visible on the record."
        ),
    )
    contract: str | None = None
    function: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    # `path` plus `alternative_paths` is a *set* of candidate files, not a guess
    # followed by fallbacks. A finding that cites several Solidity files has not
    # stated which one holds the defect -- but a quoted excerpt has, if it occurs
    # in exactly one of them, and only the stage holding the bytes can say. So
    # the adapter hands over the whole cited set and `normalize` adjudicates,
    # refusing when the excerpt occurs in more than one file for the same reason
    # it refuses an excerpt occurring twice in one file.
    quoted_source: str | None = Field(
        default=None,
        description=(
            "Source the report quoted, for `normalize` to locate by matching. Carried in "
            "transit only: storing it on a record would vendor source text, which §6.1 "
            "forbids, so only the span it produces survives."
        ),
    )
    anchor_line: int | None = Field(
        default=None,
        ge=1,
        description=(
            "A single line the report pointed at, when it gave no range. `normalize` "
            "widens it to the declaration containing it and keeps it on the record."
        ),
    )
    classes: tuple[VulnerabilityClass, ...] = Field(min_length=1)
    provenance: Provenance

    @model_validator(mode="after")
    def _every_cited_path_can_name_a_file(self) -> DraftRecord:
        """Refuse a draft whose path cannot become a pin, with the adapter named.

        The same rule `corpus.records.check_unit_path` applies to a pin, applied
        where this class's docstring says invariants belong. Without it,
        `normalize` built a `CommitPin` from this path at two sites with no
        `try` around either, so one malformed permalink -- `adapters.markdown`
        takes the path from a blob URL with nothing but `lstrip("/")`, which
        happily yields `../../etc/passwd.sol` -- aborted the whole corpus build
        instead of being one counted rejection. A draft refused here is a
        `ValidationError` naming the candidate, at the adapter that built it.
        """
        for cited in (self.path, *self.alternative_paths):
            check_unit_path(cited)
        return self

    @model_validator(mode="after")
    def _draft_can_become_a_record(self) -> DraftRecord:
        if not _SHA1.match(self.commit):
            raise ValueError(
                f"commit must be a full 40-character lowercase hex SHA, got {self.commit!r}"
            )
        if (
            self.start_line is None
            and self.anchor_line is None
            and self.function is None
            and not (self.quoted_source or "").strip()
        ):
            raise ValueError(
                "a draft needs a line span, an anchor line, a quoted excerpt or a function "
                "name; with none of the four there is nothing for normalize to resolve, and "
                "the candidate should have been skipped as no_location instead"
            )
        if self.start_line is not None and self.anchor_line is not None:
            raise ValueError(
                "a draft states either a span or a single anchor line, not both; a report "
                "that gave a range stated its span, and one that gave a line did not"
            )
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("a line span needs both ends or neither")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError(f"end_line {self.end_line} precedes start_line {self.start_line}")
        return self

    @property
    def has_stated_span(self) -> bool:
        """True when the report gave a line range, so no widening is needed."""
        return self.start_line is not None

    @property
    def has_anchor(self) -> bool:
        """True when the report pointed at one line, to be widened to its declaration."""
        return self.anchor_line is not None


@dataclass(frozen=True, slots=True)
class Skip:
    """An adapter's answer when a candidate cannot be extracted."""

    cause: SkipCause
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SkippedCandidate:
    """A candidate that did not survive extraction, with its class signal intact."""

    platform: str
    candidate: Candidate
    skip: Skip
    report_url: str = ""
    """Which document this candidate came from, so a loss can be re-read.

    Held rather than derived because the point of retaining it is to make a
    not-stated verdict checkable without re-running the harvest, and a candidate
    id is not always a locator back to the source document.
    """


class CommitResolver(Protocol):
    """Resolves a repository to the commit it was at on a date.

    Reports routinely cite a *branch*, which names whatever it currently points
    at and cannot be pinned. Resolving one as it stands today ties a record to
    code that may be far removed from the version reviewed, on no assumption
    anyone can write down. Resolving it as of the report's own date is a bounded
    inference instead -- it assumes the reviewed code is the code that was there
    then, which is a sentence somebody can agree or disagree with.

    Injected rather than performed inside an adapter, so harvesting stays
    runnable with no network. An adapter built without one refuses branch
    references and counts them, which is the honest default.

    Returns None when it cannot answer. That is a counted loss, never a licence
    to substitute something else.
    """

    def __call__(self, repo_url: str, iso_date: str) -> str | None: ...


class ReportAdapter(Protocol):
    """One platform's report format, in two phases.

    Two phases rather than one because a single `extract() -> list[DraftRecord]`
    would make the adapter's own accounting optional -- a candidate it dropped
    silently would be indistinguishable from one that was never in the report.
    Enumerating first and resolving one at a time lets `harvest` drive the loop,
    so candidates and outcomes are the same count by construction.
    """

    platform: str

    def candidates(self, report: RawReport) -> Sequence[Candidate]:
        """Every finding this report appears to contain.

        Include candidates that will certainly fail extraction. One reported and
        skipped is a measured loss; one never reported is an invisible one, and
        the difference is the entire value of the tally.
        """
        ...

    def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
        """Resolve one candidate to a draft, or say precisely why not."""
        ...


@dataclass(frozen=True, slots=True)
class HarvestReport:
    """What was harvested, what was lost, and what the survivors are a sample of."""

    drafts: tuple[DraftRecord, ...] = ()
    skipped: tuple[SkippedCandidate, ...] = ()
    by_cause: Mapping[SkipCause, int] = field(default_factory=dict)
    skipped_by_class: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    extracted_by_class: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    candidates_by_platform: Mapping[str, int] = field(default_factory=dict)
    skipped_by_platform: Mapping[str, int] = field(default_factory=dict)
    unclassified_skips: int = 0
    """Skips whose report label mapped onto none of the nine classes.

    Counted apart from `skipped_by_class` because they are a different loss: not
    a class under-sampled, but a candidate whose class is unknown -- so it cannot
    be attributed and must not be silently distributed across the classes that
    are known.
    """

    absence_samples: Mapping[SkipCause, tuple[str, ...]] = field(default_factory=dict)
    """A few inputs behind each not-stated verdict, so the verdict can be checked.

    `SkipCause.is_an_absence` says which causes get them and why: every such
    zero that has been investigated here turned out to be the reader rather than
    the input, without exception. The rule that follows -- when a reader reports
    that its input does not state something, that is a claim about the reader
    until a sample says otherwise -- needed something better than a reminder to
    go and look, so the reader retains the evidence and the statement prints
    some of it.

    Diagnostic only, and deliberately never part of a record: these strings can
    contain report prose, which is third-party writing, and a corpus record
    carries pointers rather than text (§6.1).
    """

    anchored_drafts: int = 0
    """Drafts stating one line, to be widened to the declaration containing it."""

    quoted_drafts: int = 0
    """Drafts whose span will come from matching the report's own excerpt.

    Counted apart from `derived_span_drafts` because they are the opposite kind
    of locator, not a variant of it. A derived span is the declaration index
    answering a question the report left open; a quoted span is the report's
    text and the repository's bytes agreeing, which is the confirmation §6.6
    says a derived locator lacks. Folding them together reported the strongest
    unstated locator as the weakest.
    """

    derived_span_drafts: int = 0
    """Drafts naming only a function, whose span must be guessed from prose.

    Counted apart from `anchored_drafts` because the two resolve to different
    strengths of ground truth: an anchor is an assertion the report made, where
    a prose-derived span is an inference about what it meant.
    """

    @property
    def candidates(self) -> int:
        return len(self.drafts) + len(self.skipped)

    @property
    def yield_rate(self) -> float:
        return len(self.drafts) / self.candidates if self.candidates else 0.0

    def skip_rate_for(self, cls: VulnerabilityClass) -> float:
        """Per-class loss, which is where the bias lives.

        An overall yield can look healthy while one class is almost entirely
        lost, and that class is then under-represented in every number computed
        over the corpus afterwards.
        """
        skipped = self.skipped_by_class.get(cls, 0)
        seen = skipped + self.extracted_by_class.get(cls, 0)
        return skipped / seen if seen else 0.0

    def absence_evidence(self) -> str:
        """One retained input behind the largest not-stated verdict.

        Printed rather than merely held, because a check that needs somebody to
        decide to run it is the kind this project has spent its history moving
        into the artefact. A zero arrives with a sample of what produced it, and
        whoever reads the number reads the evidence in the same sentence.

        The largest cause only: a statement that printed every sample would stop
        being read, and the largest absence is where a reader defect costs most.
        """
        if not self.absence_samples:
            return ""
        cause, samples = max(
            self.absence_samples.items(),
            key=lambda item: (self.by_cause.get(item[0], 0), item[0].value),
        )
        return (
            f" The largest not-stated verdict is {cause.value}"
            f" ({self.by_cause.get(cause, 0)}); {len(samples)} of its inputs"
            f" {'is' if len(samples) == 1 else 'are'} retained, one being:"
            f" {samples[0][:160]}. A not-stated verdict is a claim about the reader"
            " until one of these says otherwise."
        )

    def yield_statement(self) -> str:
        """The sentence a report must carry beside any claim about corpus content.

        Ends by naming the floor on its own accuracy. An adapter can only count
        what it recognised as a finding, so a report section it never identified
        is absent from every number above -- and a statement that omitted that
        would overstate its own completeness.
        """
        floor = (
            " These counts cover only candidates an adapter identified; a report section "
            "never recognised as a finding is absent from them."
        )
        if not self.candidates:
            return f"No candidates were identified.{floor}"

        drafts = f"{len(self.drafts)} of {self.candidates} candidates extracted"
        if not self.skipped:
            return f"{drafts}; none were skipped.{floor}"

        causes = ", ".join(
            f"{cause.value} {count}"
            for cause, count in sorted(
                self.by_cause.items(), key=lambda item: (-item[1], item[0].value)
            )
        )
        worst = sorted(
            ((cls, self.skip_rate_for(cls)) for cls in self.skipped_by_class),
            key=lambda item: (-item[1], item[0].value),
        )[:3]
        concentration = (
            " Heaviest class losses: "
            + ", ".join(f"{cls.value} {rate:.0%}" for cls, rate in worst)
            + "."
            if worst
            else ""
        )
        unclassified = (
            f" {self.unclassified_skips} skipped candidates could not be attributed to a class."
            if self.unclassified_skips
            else ""
        )
        spanless = self.derived_span_drafts
        derived = (
            f" {spanless} {'draft names' if spanless == 1 else 'drafts name'} only a "
            "function, so the span must be inferred from prose."
            if spanless
            else ""
        )
        anchored = (
            f" {self.anchored_drafts} state a single line, to be widened to the "
            "declaration containing it."
            if self.anchored_drafts
            else ""
        )
        quoted = (
            f" {self.quoted_drafts} quote source, to be located by matching the excerpt "
            "against the repository's bytes."
            if self.quoted_drafts
            else ""
        )
        derived = anchored + quoted + derived + self.absence_evidence()
        return (
            f"{drafts} ({self.yield_rate:.1%}); {len(self.skipped)} skipped -- {causes}."
            f"{concentration}{unclassified}{derived}{floor}"
        )


def harvest(adapter: ReportAdapter, reports: Iterable[RawReport]) -> HarvestReport:
    """Run one adapter over reports, accounting for every candidate it identified.

    The loop lives here rather than in the adapter so that the accounting cannot
    be skipped: every candidate the adapter enumerates gets exactly one outcome,
    and an adapter that wanted to hide a loss would have to hide the candidate
    too, which changes a number it does not control.

    An adapter that raises while extracting one candidate does not take the run
    down. That is deliberate and it is not leniency -- the alternative is losing
    the accounting for every other candidate in the batch, which is a larger and
    less visible loss than one malformed report.
    """
    drafts: list[DraftRecord] = []
    skipped: list[SkippedCandidate] = []
    quoted_drafts = 0
    by_cause: Counter[SkipCause] = Counter()
    absence_samples: defaultdict[SkipCause, list[str]] = defaultdict(list)
    skipped_by_class: Counter[VulnerabilityClass] = Counter()
    extracted_by_class: Counter[VulnerabilityClass] = Counter()
    candidates_by_platform: Counter[str] = Counter()
    skipped_by_platform: Counter[str] = Counter()
    unclassified_skips = 0
    anchored_drafts = 0
    derived_span_drafts = 0

    for report in reports:
        for candidate in adapter.candidates(report):
            candidates_by_platform[report.platform] += 1
            try:
                outcome = adapter.extract(report, candidate)
            except Exception as exc:
                outcome = Skip(
                    cause=SkipCause.MALFORMED_REPORT,
                    detail=f"{type(exc).__name__}: {exc}",
                )

            if isinstance(outcome, DraftRecord):
                drafts.append(outcome)
                extracted_by_class.update(outcome.classes)
                if outcome.has_anchor:
                    anchored_drafts += 1
                elif outcome.quoted_source:
                    # A quote is the report's own text, matched against the
                    # repository's bytes -- two sources, neither of which is the
                    # declaration index. Counting it as prose-inferred called
                    # the strongest unstated locator the weakest.
                    quoted_drafts += 1
                elif not outcome.has_stated_span:
                    derived_span_drafts += 1
                continue

            skipped.append(SkippedCandidate(report.platform, candidate, outcome, report.report_url))
            by_cause[outcome.cause] += 1
            if outcome.cause.is_an_absence and len(absence_samples[outcome.cause]) < SAMPLES:
                absence_samples[outcome.cause].append(
                    f"{report.report_url} -- "
                    f"{outcome.detail or candidate.title[:80] or '(no detail)'}"
                )
            skipped_by_platform[report.platform] += 1
            if candidate.classes:
                skipped_by_class.update(candidate.classes)
            else:
                unclassified_skips += 1

    return HarvestReport(
        absence_samples={c: tuple(v) for c, v in absence_samples.items() if v},
        drafts=tuple(drafts),
        skipped=tuple(skipped),
        by_cause=dict(by_cause),
        skipped_by_class=dict(skipped_by_class),
        extracted_by_class=dict(extracted_by_class),
        candidates_by_platform=dict(candidates_by_platform),
        skipped_by_platform=dict(skipped_by_platform),
        unclassified_skips=unclassified_skips,
        anchored_drafts=anchored_drafts,
        quoted_drafts=quoted_drafts,
        derived_span_drafts=derived_span_drafts,
    )
