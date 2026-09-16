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
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contract_assay.corpus.records import Provenance
from contract_assay.models import VulnerabilityClass

__all__ = [
    "Candidate",
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

    NO_LOCATION = "no_location"
    """Neither a line span nor a function name, so nothing can be derived."""

    UNMAPPED_CLASS = "unmapped_class"
    """The report's vulnerability label does not map onto any of the nine."""

    NO_CLASS = "no_class"
    """The report states no vulnerability type at all."""

    NOT_A_FINDING = "not_a_finding"
    """Identified as a candidate but turned out to be an informational note."""

    MALFORMED_REPORT = "malformed_report"
    """The report could not be read far enough to judge."""


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

    anchored_drafts: int = 0
    """Drafts stating one line, to be widened to the declaration containing it."""

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
        derived = anchored + derived
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
    by_cause: Counter[SkipCause] = Counter()
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
                elif not outcome.has_stated_span:
                    derived_span_drafts += 1
                continue

            skipped.append(SkippedCandidate(report.platform, candidate, outcome))
            by_cause[outcome.cause] += 1
            skipped_by_platform[report.platform] += 1
            if candidate.classes:
                skipped_by_class.update(candidate.classes)
            else:
                unclassified_skips += 1

    return HarvestReport(
        drafts=tuple(drafts),
        skipped=tuple(skipped),
        by_cause=dict(by_cause),
        skipped_by_class=dict(skipped_by_class),
        extracted_by_class=dict(extracted_by_class),
        candidates_by_platform=dict(candidates_by_platform),
        skipped_by_platform=dict(skipped_by_platform),
        unclassified_skips=unclassified_skips,
        anchored_drafts=anchored_drafts,
        derived_span_drafts=derived_span_drafts,
    )
