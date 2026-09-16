"""An adapter for Sherlock audit contest submissions.

Sherlock publishes judging repositories laid out one directory per *deduplicated*
issue, each containing the submissions that were judged to be that issue. Every
submission follows a template: a handle, a severity on its own line, a title, and
then fixed sections -- Summary, Root Cause, Impact, PoC, Mitigation.

That template is why this platform is a better source than a consolidated report,
and the difference is concentrated in one section. `### Root Cause` exists to say
*where and why*, so a link inside it is the finding's location rather than an
aside -- unlike a link in a proof of concept, which cites whatever the exploit
touched. Reading only that section is what makes the distinction free.

One unit per report
-------------------
A `RawReport` here is one issue, not one contest, so `candidates()` returns a
single candidate. That looks degenerate against the two-phase protocol and is
not: the protocol's purpose is that every identified candidate gets exactly one
recorded outcome, which holds whether a document contains one finding or ninety.
What it does mean is that the denominator comes from the platform's own directory
layout rather than from anything this adapter counts -- see
`SherlockEnumerator.enumeration_basis`.

The reference problem
---------------------
Roughly half of observed permalinks point at a branch rather than a commit.
`main` names whatever it currently points at, so such a citation is not
reproducible as written.

Unlike some platforms, a submission here carries no date of its own -- but the
platform keeps one outside the document, in the issue its judging repository
syncs. Supplied as `RawReport.published`, that date bounds the recovery: resolve
the repository as it stood then, assuming the reviewed code is the code that was
there. The assumption is recorded on the pin and a report can stratify on it.

Without a resolver or without a date, a branch citation is skipped as
`no_commit` and counted. Resolving the branch as it stands today is refused in
either case: it rests on no assumption anybody can write down.
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

__all__ = ["SherlockAdapter", "SherlockEnumerator", "SherlockIssue"]

_TITLE = re.compile(r"^#\s+(?P<title>\S.*?)\s*$", re.M)
_SEVERITY = re.compile(r"^(?P<severity>High|Medium|Low)\s*$", re.M)
_ROOT_CAUSE = "Root Cause"


@dataclass(frozen=True, slots=True)
class SherlockIssue:
    """One judged submission, as its template presents it."""

    title: str
    severity: str
    body: str

    @property
    def root_cause(self) -> str | None:
        """The section that exists to say where the defect is."""
        return section(self.body, _ROOT_CAUSE)


class SherlockEnumerator:
    """Reads one judged submission out of one document.

    Separate from the adapter for the same reason Code4rena's is: what counts as
    a finding decides the denominator of every rate derived from it, so it has to
    be runnable and testable on its own rather than buried in extraction.
    """

    accepted_severities = ("high", "medium")

    def issue(self, body: str) -> SherlockIssue | None:
        """The submission this document describes, or None if it is not one."""
        title = _TITLE.search(body)
        severity = _SEVERITY.search(body)
        if title is None or severity is None:
            return None
        return SherlockIssue(
            title=title.group("title"),
            severity=severity.group("severity").lower(),
            body=body,
        )

    def enumeration_basis(self, body: str) -> str:
        """Where this platform's denominator comes from.

        Not from this adapter. Sherlock's judging repository has one directory
        per deduplicated issue, produced by its own judging process, so the issue
        count is established outside anything here and an over-cautious reader of
        a single document cannot flatter it. What this enumerator can still get
        wrong is *within* a document, which is why it reports whether the
        template it relies on was actually present.
        """
        issue = self.issue(body)
        if issue is None:
            return (
                "unrecognised: no title and severity in the expected template, so this "
                "document contributes nothing and is counted as such"
            )
        if issue.root_cause is None:
            return (
                f"partial: severity {issue.severity!r} read from the template, but no "
                f"{_ROOT_CAUSE!r} section, so the location must come from the whole body"
            )
        return (
            f"externally confirmed: one issue per directory in the platform's judging "
            f"repository; severity {issue.severity!r} and a {_ROOT_CAUSE!r} section both "
            "read from the template"
        )


class SherlockAdapter:
    """Sherlock judging submissions, in the two phases `harvest` drives."""

    platform = "sherlock"

    def __init__(
        self,
        enumerator: SherlockEnumerator | None = None,
        resolve_commit: CommitResolver | None = None,
    ) -> None:
        self.enumerator = enumerator or SherlockEnumerator()
        self.resolve_commit = resolve_commit

    def candidates(self, report: RawReport) -> Sequence[Candidate]:
        issue = self.enumerator.issue(report.body)
        if issue is None:
            # Reported as a candidate that will fail rather than as nothing: a
            # document the template did not match is a measured loss, where a
            # document silently ignored is an invisible one.
            return [Candidate(candidate_id=report.report_url, title="")]
        return [
            Candidate(
                candidate_id=report.report_url,
                classes=classify_title(issue.title),
                raw_labels=(issue.severity,),
                title=issue.title,
            )
        ]

    def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
        issue = self.enumerator.issue(report.body)
        if issue is None:
            return Skip(SkipCause.MALFORMED_REPORT, "no title and severity in the template")
        if issue.severity not in self.enumerator.accepted_severities:
            return Skip(SkipCause.NOT_A_FINDING, f"severity {issue.severity!r} is out of scope")
        if not candidate.classes:
            return Skip(SkipCause.UNMAPPED_CLASS, f"title: {issue.title[:80]}")

        # Root Cause first, and only fall back to the whole body when the
        # template is absent. A link in a proof of concept cites what the
        # exploit touched, which is not the same as where the defect is.
        scope = issue.root_cause or issue.body
        cited = [c for c in permalinks(scope) if c.is_solidity]
        if not cited:
            return Skip(
                SkipCause.NO_LOCATION,
                f"no Solidity link in the {_ROOT_CAUSE!r} section or the body",
            )

        pinned = [c for c in cited if c.is_pinned]
        resolved_from: str | None = None
        if not pinned:
            recovered = self._recover(cited, report.published)
            if recovered is None:
                return Skip(
                    SkipCause.NO_COMMIT,
                    f"cites {cited[0].path} at {cited[0].ref!r}, which names a moving target",
                )
            pinned, resolved_from = recovered

        if len({(c.path, c.start_line, c.end_line) for c in pinned}) > 1:
            return Skip(
                SkipCause.NO_LOCATION,
                f"{len(pinned)} distinct locations cited, so none is stated",
            )

        return _draft(report, issue, candidate, pinned[0], quoted_source(scope), resolved_from)

    def _recover(
        self, cited: list[SourceCitation], published: str | None
    ) -> tuple[list[SourceCitation], str] | None:
        """Re-pin branch citations against the repository as of the report's date.

        All citations must name the same repository: a branch reference into a
        dependency is a different repository at a different state, and resolving
        one against this report's date would assert something about a project the
        report never dated.
        """
        if self.resolve_commit is None or not published:
            return None
        repos = {c.repo_url for c in cited}
        if len(repos) != 1:
            return None
        resolved = self.resolve_commit(next(iter(repos)), published)
        if resolved is None:
            return None
        return (
            [
                SourceCitation(
                    repo_url=c.repo_url,
                    ref=resolved,
                    path=c.path,
                    start_line=c.start_line,
                    end_line=c.end_line,
                )
                for c in cited
            ],
            f"repository head at the report's date, {published}",
        )


def _draft(
    report: RawReport,
    issue: SherlockIssue,
    candidate: Candidate,
    citation: SourceCitation,
    quoted: str | None,
    resolved_from: str | None,
) -> DraftRecord:
    """Build a draft from one pinned citation.

    A cited *range* is a span the submission chose. A cited single line is a
    place it pointed at and says nothing about where the defect ends, so it
    becomes an anchor for `normalize` to widen -- the same distinction the
    Code4rena adapter draws, for the same reason.
    """
    ranged = citation.start_line is not None and citation.start_line != citation.end_line
    return DraftRecord(
        candidate_id=candidate.candidate_id,
        repo_url=citation.repo_url,
        commit=citation.ref,
        commit_resolved_from=resolved_from,
        path=citation.path,
        start_line=citation.start_line if ranged else None,
        end_line=citation.end_line if ranged else None,
        anchor_line=None if ranged else citation.start_line,
        quoted_source=quoted,
        classes=candidate.classes,
        provenance=Provenance(
            platform=report.platform,
            report_url=report.report_url,
            reported_severity=issue.severity,
        ),
    )
