"""An adapter for Immunefi audit-competition reports.

Each report is one markdown file carrying a metadata block the platform's own
tooling writes:

    # Unauthorized minting of unlimited FLUX in 1 transaction

    Submitted on May 2nd 2024 at 16:22:35 UTC by @someone for [Boost | X](...)
    Report ID: #30634
    Report type: Smart Contract
    Report severity: Critical
    Target: https://github.com/owner/repo/blob/main/src/Voter.sol

That block is worth more than its brevity suggests. It states the submission
date, distinguishes smart-contract reports from the other kinds the platform
runs competitions for, and names a target file outright rather than leaving it
to be inferred from prose.

Recovering the commit
---------------------
Every observed target names a **branch**, so nothing is pinned as written. A
branch names whatever it currently points at, and resolving it today would tie a
record to code that may be years removed from the version reviewed.

The submission date makes a bounded inference available instead: resolve the
repository as it stood when the report was submitted. The assumption is
stateable -- that the reviewed code is the code that was there on that date --
and it is recorded on the pin via `commit_resolved_from`, so a report can
stratify on it or exclude it. That is the whole difference from resolving the
branch as it stands now, which rests on no assumption anybody can write down.

Resolution is injected rather than performed here, so the stage stays runnable
with no network. An adapter built without a resolver skips branch targets as
`no_commit` and counts them, which is what the previous adapters do
unconditionally.

Impacts are not classes
-----------------------
The metadata block also lists Immunefi's own impact categories -- "direct theft
of user funds", "permanent freezing of funds". Those are *consequences* and the
nine classes are *mechanisms*, and the two axes are orthogonal: theft of funds
can follow from reentrancy, from oracle manipulation or from missing access
control. So the impact list is kept as provenance and the class still comes from
the title, with the same low mapping rate every review source shows.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from contract_assay.corpus.adapters.classify import classify_title
from contract_assay.corpus.adapters.markdown import (
    SourceCitation,
    permalinks,
    quoted_source,
    section,
)
from contract_assay.corpus.harvest import (
    Candidate,
    CommitResolver,
    DraftRecord,
    RawReport,
    Skip,
    SkipCause,
)
from contract_assay.corpus.records import Provenance

__all__ = ["ImmunefiAdapter", "ImmunefiEnumerator", "ImmunefiReport"]

_TITLE = re.compile(r"^#\s+(?P<title>\S.*?)\s*$", re.M)
_FIELD = re.compile(r"^(?P<key>Report type|Report severity|Target):\s*(?P<value>.+?)\s*$", re.M)
_SUBMITTED = re.compile(
    r"^Submitted on (?P<day>\d{1,2})(?:st|nd|rd|th) (?P<month>[A-Z][a-z]+) (?P<year>\d{4})"
    r"|^Submitted on (?P<month2>[A-Z][a-z]+) (?P<day2>\d{1,2})(?:st|nd|rd|th) (?P<year2>\d{4})",
    re.M,
)
_MONTHS = {
    name: number
    for number, name in enumerate(
        (
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ),
        start=1,
    )
}


@dataclass(frozen=True, slots=True)
class ImmunefiReport:
    """One competition report, as its metadata block presents it."""

    title: str
    report_type: str
    severity: str
    target: str
    submitted: str
    """ISO date of submission, or the empty string when it could not be read."""

    body: str

    @property
    def is_smart_contract(self) -> bool:
        return self.report_type.strip().lower() == "smart contract"


class ImmunefiEnumerator:
    """Reads one report out of one document.

    Separate and runnable for the same reason as the other platforms': what
    counts as a report sets the denominator of every rate derived from it.
    """

    accepted_severities = ("critical", "high", "medium")

    def report(self, body: str) -> ImmunefiReport | None:
        title = _TITLE.search(body)
        if title is None:
            return None
        fields = {m.group("key"): m.group("value") for m in _FIELD.finditer(body)}
        return ImmunefiReport(
            title=title.group("title"),
            report_type=fields.get("Report type", ""),
            severity=fields.get("Report severity", "").strip().lower(),
            target=fields.get("Target", ""),
            submitted=_submission_date(body),
            body=body,
        )

    def enumeration_basis(self, body: str) -> str:
        report = self.report(body)
        if report is None:
            return "unrecognised: no title, so this document contributes nothing"
        missing = [
            name
            for name, value in (
                ("Report type", report.report_type),
                ("Report severity", report.severity),
                ("Target", report.target),
                ("submission date", report.submitted),
            )
            if not value
        ]
        if missing:
            return f"partial: metadata block present but missing {', '.join(missing)}"
        return (
            "externally confirmed: one report per file in the platform's published "
            "archive, with type, severity, target and date all read from the "
            "platform's own metadata block"
        )


class ImmunefiAdapter:
    """Immunefi competition reports, in the two phases `harvest` drives."""

    platform = "immunefi"

    def __init__(
        self,
        enumerator: ImmunefiEnumerator | None = None,
        resolve_commit: CommitResolver | None = None,
    ) -> None:
        self.enumerator = enumerator or ImmunefiEnumerator()
        self.resolve_commit = resolve_commit

    def candidates(self, report: RawReport) -> Sequence[Candidate]:
        parsed = self.enumerator.report(report.body)
        if parsed is None:
            return [Candidate(candidate_id=report.report_url, title="")]
        return [
            Candidate(
                candidate_id=report.report_url,
                classes=classify_title(parsed.title),
                raw_labels=(parsed.severity,),
                title=parsed.title,
            )
        ]

    def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
        parsed = self.enumerator.report(report.body)
        if parsed is None:
            return Skip(SkipCause.MALFORMED_REPORT, "no title in the document")
        if not parsed.is_smart_contract:
            # The platform runs competitions for other targets too, and a
            # non-Solidity report is out of language scope rather than a loss
            # this corpus could ever have recovered.
            return Skip(SkipCause.NOT_A_FINDING, f"report type {parsed.report_type!r}")
        if parsed.severity not in self.enumerator.accepted_severities:
            return Skip(SkipCause.NOT_A_FINDING, f"severity {parsed.severity!r} is out of scope")
        if not candidate.classes:
            return Skip(SkipCause.UNMAPPED_CLASS, f"title: {parsed.title[:80]}")

        cited = [c for c in permalinks(parsed.target) if c.is_solidity]
        if not cited:
            return Skip(SkipCause.NO_FILE_PATH, f"target is not a Solidity file: {parsed.target}")
        target = _with_line_from_body(cited[0], parsed.body)

        pinned, resolved_from = self._pin(target, parsed, report.published)
        if pinned is None:
            return Skip(
                SkipCause.NO_COMMIT,
                f"target names {target.ref!r} and no commit could be resolved for it",
            )

        excerpt = _vulnerable_excerpt(parsed.body)
        if target.start_line is None and excerpt is None:
            # The metadata named a file and nothing narrowed it further. A
            # location loss, not a malformed report -- filing it as the latter
            # would point investigation at the document instead of at the gap.
            return Skip(
                SkipCause.NO_LOCATION,
                f"target names {target.path} with no line, and no excerpt to locate",
            )

        ranged = target.start_line is not None and target.start_line != target.end_line
        return DraftRecord(
            candidate_id=candidate.candidate_id,
            repo_url=target.repo_url,
            commit=pinned,
            commit_resolved_from=resolved_from,
            path=target.path,
            start_line=target.start_line if ranged else None,
            end_line=target.end_line if ranged else None,
            anchor_line=None if ranged else target.start_line,
            quoted_source=excerpt,
            classes=candidate.classes,
            provenance=Provenance(
                platform=report.platform,
                report_url=report.report_url,
                reported_severity=parsed.severity,
            ),
        )

    def _pin(
        self, target: SourceCitation, parsed: ImmunefiReport, published: str | None
    ) -> tuple[str | None, str | None]:
        """The commit to pin, and how it was obtained."""
        if target.is_pinned:
            return target.ref, None
        # The in-body submission date is the most precise available; a date the
        # platform keeps outside the document is the fallback.
        dated = parsed.submitted or (published or "")
        if self.resolve_commit is None or not dated:
            return None, None
        resolved = self.resolve_commit(target.repo_url, dated)
        if resolved is None:
            return None, None
        return (
            resolved,
            f"repository head at the report's date, {dated}",
        )


def _with_line_from_body(target: SourceCitation, body: str) -> SourceCitation:
    """Add a line number to the target from a body link pointing at the same file.

    The metadata block names the file and never a line; the prose around it
    frequently links the same file with one. Borrowing a line across *files*
    would be guessing, so only a link whose path matches the target counts, and
    only when the body offers exactly one such line -- two candidates state no
    single location, which is the rule every other adapter applies.
    """
    if target.start_line is not None:
        return target
    lines = {
        (c.start_line, c.end_line)
        for c in permalinks(body)
        if c.path == target.path and c.start_line is not None
    }
    if len(lines) != 1:
        return target
    start, end = next(iter(lines))
    return SourceCitation(
        repo_url=target.repo_url,
        ref=target.ref,
        path=target.path,
        start_line=start,
        end_line=end,
    )


def _submission_date(body: str) -> str:
    """The submission date as ISO, or empty when the line cannot be read."""
    match = _SUBMITTED.search(body)
    if match is None:
        return ""
    day = match.group("day") or match.group("day2")
    month = match.group("month") or match.group("month2")
    year = match.group("year") or match.group("year2")
    if not (day and month and year) or month not in _MONTHS:
        return ""
    return f"{year}-{_MONTHS[month]:02d}-{int(day):02d}"


def _vulnerable_excerpt(body: str) -> str | None:
    """Source the report quoted while describing the defect, not while exploiting it.

    "Vulnerability Details" describes the defect; "Proof of Concept" exercises
    it. Reading the first and not the second is the same distinction the Sherlock
    adapter draws with its root-cause section, and for the same reason: a PoC
    quotes the test, which is not where the defect lives.
    """
    for heading in ("Vulnerability Details", "Description", "Brief/Intro"):
        scope = section(body, heading, level=2) or section(body, heading, level=3)
        if scope:
            quoted = quoted_source(scope)
            if quoted:
                return quoted
    return None
