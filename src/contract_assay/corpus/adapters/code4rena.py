"""An adapter for Code4rena audit reports.

The consolidated report of a Code4rena contest is a markdown file with a fixed
skeleton: severity sections whose headings state their own counts, and one
heading per accepted finding linking to the finding's issue.

Two properties of that format shape everything below.

**The report states its own finding counts.** `# High Risk Findings (3)` is a
number this adapter did not produce, so it can be compared against what the
enumerator found. That matters more than it looks: an adapter's enumeration sets
the denominator of every rate the harvest report goes on to quote, so an
enumerator that quietly skipped awkward sections would flatter its own yield with
nothing able to contradict it. An external count removes the judgement instead of
disclosing it. Where a platform publishes no such count, the honest fallback is
to say so -- see `Code4renaEnumerator.enumeration_basis`.

**Locations are usually prose.** Measured over six published reports and 87
accepted findings, 2% carried an explicit "Lines of code" section and about half
carried any source permalink at all. Deriving a span from a named function
(§6.3) is therefore the ordinary path through this adapter, not a rescue for
awkward cases -- which is also why that derivation had to exist before any
adapter was written.

A permalink appearing anywhere in a finding's body is *not* taken as its
location. Proof-of-concept sections routinely cite dozens of lines, and one
observed finding carried 36 permalinks none of which was the defect. Only a
"Lines of code" section, or a body citing exactly one distinct source location,
is treated as stating one.

A permalink to a line *range* and a permalink to a single line are different
assertions, and the adapter keeps them apart. `#L136-L150` is a span the report
chose. `#L220` says the defect is at line 220 and says nothing about where it
ends, so it becomes an anchor: `normalize` widens it to the declaration
containing it and keeps the line, because that line is the finest thing the
report actually asserted and it is what such a record is scored against (§7).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from contract_assay.corpus.harvest import (
    Candidate,
    DraftRecord,
    RawReport,
    Skip,
    SkipCause,
)
from contract_assay.corpus.records import Provenance
from contract_assay.models import VulnerabilityClass

__all__ = ["Code4renaAdapter", "Code4renaEnumerator", "EnumeratedFinding"]

_SEVERITY_SECTION = re.compile(r"^# (High|Medium) Risk Findings \((\d+)\)\s*$", re.M)
_FINDING_HEADING = re.compile(r"^## \[?\[([HM]-\d+)\]\s*(.*?)\]\((\S+?)\)\s*$", re.M)
_LINES_OF_CODE = re.compile(r"^### Lines of code\s*$(.*?)(?=^### |\Z)", re.M | re.S)
# Findings name their subject in backticks far more often than they link to it:
# `onQueueWithdrawal()`, `OperatorDelegator.completeQueuedWithdrawal`. Extraction
# here is deliberately generous, because resolution is strict -- `normalize`
# admits a name only if it is declared exactly once in the pinned file, so a
# match on `tick.rs` or on a local variable is rejected there and counted as a
# loss rather than becoming a wrong record. That asymmetry is the same one §2.2
# applies to gates and verdicts, arriving in a third place.
# The platform's submission tooling emits line-numbered excerpts headed by the
# file they came from:
#
#     File: src/access/FixedTermLoanHooks.sol
#     848:   function onQueueWithdrawal(
#     849:     address lender,
#
# This is the best location signal the format offers, and the only one that
# arrives with a quote attached -- the excerpt can be checked against the pinned
# source, which is the same falsifiability `Finding.quote` gives detector output.
# It appears in about one finding in nine, so it is a minority convention rather
# than the format, and worth taking wherever it shows up.
_FILE_BLOCK = re.compile(
    r"^File:\s*(?P<path>\S+\.sol)\s*$\n(?P<lines>(?:^[ \t]*\d+:.*$\n?)+)", re.M
)
_NUMBERED_LINE = re.compile(r"^[ \t]*(\d+):", re.M)

# Findings quote the vulnerable code inline far more often than they cite it.
# The quote is not a location by itself, but `normalize` can locate it by
# matching it against the pinned file -- deterministically, with no judgement.
# Blocks that are clearly a test harness are excluded: a proof of concept
# exercises the defect rather than containing it, so matching one would locate
# the test.
_FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)
_LOOKS_LIKE_SOURCE = re.compile(
    r"\b(function|require|modifier|mapping|uint\d*|address|emit|return)\b"
)
_LOOKS_LIKE_HARNESS = re.compile(r"\bfunction\s+test\w*\s*\(|\bvm\.|\bconsole\.log")

_BACKTICK_QUALIFIED = re.compile(r"`([A-Z]\w*)\.(\w+)\(?\)?`")
_BACKTICK_CALL = re.compile(r"`(\w+)\(\)`")

_PERMALINK = re.compile(
    r"https://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
    r"/blob/(?P<commit>[0-9a-f]{40})/(?P<path>[^\s>)#]+)"
    r"(?:#L(?P<start>\d+)(?:-L?(?P<end>\d+))?)?"
)

# Report titles carry no vulnerability taxonomy -- Code4rena classifies by
# severity only -- so a class has to be read out of English prose. This table is
# deliberately small, explicit and conservative: a title matching nothing is
# skipped as `unmapped_class` rather than guessed at, which turns "how much of
# this platform do our nine classes even cover" into a number the harvest report
# reports rather than a question nobody asked.
#
# Keyword matching on prose is not the thing §2.3 forbids. That rule is about
# predicates over *code*, where an identifier is the author's to rename and a
# name match is therefore evidence that can be manufactured. Nobody renames the
# English word "reentrancy" to defeat a harvester.
_CLASS_KEYWORDS: tuple[tuple[str, VulnerabilityClass], ...] = (
    ("reentran", VulnerabilityClass.REENTRANCY),
    ("access control", VulnerabilityClass.ACCESS_CONTROL),
    ("unauthori", VulnerabilityClass.ACCESS_CONTROL),
    ("permission", VulnerabilityClass.ACCESS_CONTROL),
    ("only owner", VulnerabilityClass.ACCESS_CONTROL),
    ("slippage", VulnerabilityClass.SLIPPAGE),
    ("min amount out", VulnerabilityClass.SLIPPAGE),
    ("oracle", VulnerabilityClass.ORACLE_INTEGRITY),
    ("stale price", VulnerabilityClass.ORACLE_INTEGRITY),
    ("price feed", VulnerabilityClass.ORACLE_INTEGRITY),
    ("flash loan", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("flashloan", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("rounding", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("precision loss", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("overflow", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("underflow", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("denial of service", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("dos", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("griefing", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("randomness", VulnerabilityClass.INSECURE_RANDOMNESS),
    ("unchecked return", VulnerabilityClass.UNCHECKED_EXTERNAL_CALL),
    ("return value", VulnerabilityClass.UNCHECKED_EXTERNAL_CALL),
)


@dataclass(frozen=True, slots=True)
class EnumeratedFinding:
    """One accepted finding, as the report's own structure presents it."""

    ident: str
    severity: str
    title: str
    issue_url: str
    body: str


@dataclass(frozen=True, slots=True)
class SourceCitation:
    """A source location a report stated outright."""

    repo_url: str
    commit: str
    path: str
    start_line: int | None
    end_line: int | None


class Code4renaEnumerator:
    """Finds the accepted findings in a report, and the report's own count of them.

    A separate component rather than the opening of the adapter, for a reason
    that is not tidiness. Enumeration sets the denominator of every rate derived
    from it, so it needs to be runnable on its own: countable against the
    report's declared totals, comparable across platforms, and regression-tested
    so that a later change quietly narrowing it shows up as a failing test rather
    than as an improved yield.
    """

    #: Severity sections this project accepts. Low-risk, QA, gas and
    #: informational sections are excluded by design, which is why the declared
    #: denominator below is "findings in the accepted categories" and not "all
    #: findings in the report".
    accepted_severities = ("High", "Medium")

    def declared_counts(self, body: str) -> Mapping[str, int]:
        """Counts the report states for each accepted severity section."""
        return {
            severity: int(count)
            for severity, count in _SEVERITY_SECTION.findall(body)
            if severity in self.accepted_severities
        }

    def declared_total(self, body: str) -> int | None:
        """The report's own total for the accepted categories, if it states one."""
        counts = self.declared_counts(body)
        return sum(counts.values()) if counts else None

    def findings(self, body: str) -> list[EnumeratedFinding]:
        """Every accepted finding, in report order."""
        headings = list(_FINDING_HEADING.finditer(body))
        found: list[EnumeratedFinding] = []
        for position, match in enumerate(headings):
            end = headings[position + 1].start() if position + 1 < len(headings) else len(body)
            ident = match.group(1)
            found.append(
                EnumeratedFinding(
                    ident=ident,
                    severity="high" if ident.startswith("H") else "medium",
                    title=match.group(2).strip(),
                    issue_url=match.group(3),
                    body=body[match.end() : end],
                )
            )
        return found

    def enumeration_basis(self, body: str) -> str:
        """Whether this report's denominator is measured or merely declared by us.

        Reported so a reader can tell the two apart. An enumeration checked
        against a count the platform published is a different quality of claim
        from one checked against nothing, and collapsing them would hide which
        platforms are trustworthy on this axis.
        """
        declared = self.declared_total(body)
        if declared is None:
            return "self-declared: the report states no finding count to check against"
        found = len(self.findings(body))
        if found == declared:
            return f"externally confirmed: {found} enumerated, {declared} declared by the report"
        return (
            f"MISMATCH: {found} enumerated against {declared} declared -- the enumerator "
            "is missing findings or counting extra ones, and every rate derived from it "
            "is suspect until that is resolved"
        )


class Code4renaAdapter:
    """Code4rena consolidated reports, in the two phases `harvest` drives."""

    platform = "code4rena"

    def _from_excerpt(self, report: RawReport, finding: EnumeratedFinding) -> SourceCitation | None:
        """A location from a line-numbered excerpt, if the finding carries one.

        The excerpt states a path and line numbers but not a commit, because a
        commit is a property of the contest rather than of the finding. It is
        taken from the report's own permalinks, which all point at the audited
        snapshot; a report containing none is one where nothing can be pinned.
        """
        block = _FILE_BLOCK.search(finding.body)
        if block is None:
            return None
        numbers = [int(n) for n in _NUMBERED_LINE.findall(block.group("lines"))]
        snapshot = _contest_snapshot(report.body)
        if not numbers or snapshot is None:
            return None
        repo_url, commit = snapshot
        return SourceCitation(
            repo_url=repo_url,
            commit=commit,
            path=block.group("path").lstrip("/"),
            start_line=min(numbers),
            end_line=max(numbers),
        )

    def _by_name(
        self, report: RawReport, candidate: Candidate, finding: EnumeratedFinding
    ) -> DraftRecord | Skip:
        """Fall back to the file the finding cites plus the name its prose gives.

        Reached when no single source location was stated, which is the ordinary
        case. A file with several lines cited in it has not stated a span, but a
        file plus a named function is enough for `normalize` to resolve -- and if
        that name does not resolve to exactly one declaration there, the draft is
        lost and counted rather than guessed at.
        """
        file = _sole_solidity_file(finding.body)
        if file is None:
            return Skip(
                SkipCause.NO_LOCATION,
                "no stated location, and the finding cites either no Solidity file or several",
            )
        named = _named_function(finding.title, finding.body)
        quoted = _quoted_source(finding.body)
        if named is None and quoted is None:
            return Skip(
                SkipCause.NO_LOCATION,
                f"cites {file.path} but neither quotes source nor names a function for it",
            )
        contract, function = named or (None, None)
        return DraftRecord(
            candidate_id=finding.ident,
            repo_url=file.repo_url,
            commit=file.commit,
            path=file.path,
            contract=contract,
            function=function,
            quoted_source=quoted,
            classes=candidate.classes,
            provenance=Provenance(
                platform=report.platform,
                report_url=finding.issue_url or report.report_url,
                reported_severity=finding.severity,
            ),
        )

    def __init__(self, enumerator: Code4renaEnumerator | None = None) -> None:
        self.enumerator = enumerator or Code4renaEnumerator()

    def candidates(self, report: RawReport) -> Sequence[Candidate]:
        return [
            Candidate(
                candidate_id=finding.ident,
                classes=_classify(finding.title),
                raw_labels=(finding.severity,),
                title=finding.title,
            )
            for finding in self.enumerator.findings(report.body)
        ]

    def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
        finding = next(
            (f for f in self.enumerator.findings(report.body) if f.ident == candidate.candidate_id),
            None,
        )
        if finding is None:
            return Skip(SkipCause.MALFORMED_REPORT, f"{candidate.candidate_id} vanished")
        if not candidate.classes:
            return Skip(SkipCause.UNMAPPED_CLASS, f"title: {finding.title[:80]}")

        citation = _cite(finding.body) or self._from_excerpt(report, finding)
        if citation is None:
            return self._by_name(report, candidate, finding)
        if not citation.path.endswith(".sol"):
            return Skip(SkipCause.NO_FILE_PATH, f"cited {citation.path}, which is not Solidity")

        # A permalink to a *range* is a span the report chose. A permalink to a
        # single line is a place it pointed at, which is not the same assertion:
        # nothing in `#L220` says the defect stops at line 220. So a range
        # becomes a stated span and a single line becomes an anchor, to be
        # widened to its enclosing declaration while the line itself is kept.
        ranged = citation.start_line != citation.end_line
        return DraftRecord(
            candidate_id=finding.ident,
            repo_url=citation.repo_url,
            commit=citation.commit,
            path=citation.path,
            start_line=citation.start_line if ranged else None,
            end_line=citation.end_line if ranged else None,
            anchor_line=None if ranged else citation.start_line,
            # Carried even alongside a stated span: `normalize` cross-checks the
            # two against the repository's bytes and refuses the record if they
            # point at different code.
            quoted_source=_quoted_source(finding.body),
            classes=candidate.classes,
            provenance=Provenance(
                platform=report.platform,
                report_url=finding.issue_url or report.report_url,
                reported_severity=finding.severity,
            ),
        )


def _contest_snapshot(report_body: str) -> tuple[str, str] | None:
    """The repository and commit the contest audited, from anywhere in the report.

    A commit identifies the snapshot under audit, so any permalink in the report
    establishes it -- unlike a *location*, which is specific to one finding and
    cannot be borrowed from another. The most frequently cited pair wins, so a
    stray link to an unrelated repository does not decide it.
    """
    from collections import Counter

    seen = Counter((citation.repo_url, citation.commit) for citation in _permalinks(report_body))
    return seen.most_common(1)[0][0] if seen else None


def _quoted_source(body: str) -> str | None:
    """The longest fenced block that looks like contract source, if any.

    Longest because an excerpt carrying more lines is both likelier to locate
    uniquely and likelier to be the passage under discussion rather than an
    aside.
    """
    candidates = [
        match.group(2)
        for match in _FENCE.finditer(body)
        if _LOOKS_LIKE_SOURCE.search(match.group(2))
        and not _LOOKS_LIKE_HARNESS.search(match.group(2))
    ]
    return max(candidates, key=len) if candidates else None


def _named_function(title: str, body: str) -> tuple[str | None, str] | None:
    """A function the finding names in backticks, with its type where given.

    Title first, then the opening of the body. A finding's subject is stated
    where it is introduced; a name appearing only deep in a proof of concept is
    as likely to be incidental as the permalinks around it.
    """
    for text in (title, body[:1500]):
        qualified = _BACKTICK_QUALIFIED.search(text)
        if qualified is not None:
            return qualified.group(1), qualified.group(2)
        call = _BACKTICK_CALL.search(text)
        if call is not None:
            return None, call.group(1)
    return None


def _classify(title: str) -> tuple[VulnerabilityClass, ...]:
    """Map a finding title onto the nine classes, or onto none.

    First match wins and only one class is assigned. A title mentioning two
    concepts is usually about one of them, and multi-labelling from prose would
    put confidence in a keyword table that does not deserve it -- §6.1 permits
    multi-labelled records because one *location* can host several classes, which
    is a different claim from one title matching several words.
    """
    lowered = title.lower()
    for keyword, cls in _CLASS_KEYWORDS:
        if keyword in lowered:
            return (cls,)
    return ()


def _sole_solidity_file(body: str) -> SourceCitation | None:
    """The one Solidity file a finding cites, ignoring which lines it cites in it.

    A finding citing several lines of one file has not stated a span, but it has
    stated a file -- and a file plus a name the prose supplies is enough for
    `normalize` to resolve. A finding citing several files has stated neither.
    """
    cited = [c for c in _permalinks(body) if c.path.endswith(".sol")]
    paths = {c.path for c in cited}
    return cited[0] if len(paths) == 1 else None


def _cite(body: str) -> SourceCitation | None:
    """The one source location a finding states, or None if it states none.

    A "Lines of code" section is authoritative. Failing that, a body citing
    exactly one distinct source location is taken to state it, and a body citing
    several is taken to state none -- proof-of-concept sections cite freely, and
    one observed finding carried 36 permalinks of which none was the defect.
    """
    section = _LINES_OF_CODE.search(body)
    if section is not None:
        cited = _permalinks(section.group(1))
        if cited:
            return cited[0]

    cited = _permalinks(body)
    distinct = {(c.repo_url, c.commit, c.path, c.start_line, c.end_line) for c in cited}
    return cited[0] if len(distinct) == 1 else None


def _permalinks(text: str) -> list[SourceCitation]:
    found: list[SourceCitation] = []
    for match in _PERMALINK.finditer(text):
        start = int(match.group("start")) if match.group("start") else None
        end = int(match.group("end")) if match.group("end") else start
        found.append(
            SourceCitation(
                repo_url=f"https://github.com/{match.group('owner')}/{match.group('repo')}",
                commit=match.group("commit"),
                path=match.group("path"),
                start_line=start,
                end_line=end,
            )
        )
    return found
