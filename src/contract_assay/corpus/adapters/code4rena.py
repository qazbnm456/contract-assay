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
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from contract_assay.corpus.adapters.classify import classify_title
from contract_assay.corpus.adapters.markdown import (
    SourceCitation,
    contest_snapshot,
    permalinks,
    quoted_source,
)
from contract_assay.corpus.harvest import (
    Candidate,
    DraftRecord,
    RawReport,
    Skip,
    SkipCause,
)
from contract_assay.corpus.records import Provenance

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
# A proof of concept exercises the defect rather than containing it, so a block
# quoting the harness is not a location -- one observed finding quoted the
# vulnerable library and `TestUser.sol` side by side.
#
# The directory forms were added after a record was written against
# `test/mocks/PoolMock.sol`: the finding's diff was of a library, and its
# context lines occurred in the mock, so the excerpt route's restriction was
# right and the *candidate set* had no restriction at all. Third time this
# check has been needed somewhere it was not, hence one predicate, applied
# where citations enter.
_LOOKS_LIKE_A_TEST = re.compile(
    r"(^|/)(test|tests|mock|mocks)/|(^|/)(Test\w*|\w+Test|\w+\.t)\.sol$"
)

# Findings quote the vulnerable code inline far more often than they cite it.
# The quote is not a location by itself, but `normalize` can locate it by
# matching it against the pinned file -- deterministically, with no judgement.
# Blocks that are clearly a test harness are excluded: a proof of concept
# exercises the defect rather than containing it, so matching one would locate
# the test.
_FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)
_LOOKS_LIKE_HARNESS = re.compile(r"\bfunction\s+test\w*\s*\(|\bvm\.|\bconsole\.log")

_BACKTICK_QUALIFIED = re.compile(r"`([A-Z]\w*)\.(\w+)\(?\)?`")
_BACKTICK_CALL = re.compile(r"`(\w+)\(\)`")


@dataclass(frozen=True, slots=True)
class EnumeratedFinding:
    """One accepted finding, as the report's own structure presents it."""

    ident: str
    severity: str
    title: str
    issue_url: str
    body: str


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

    def _from_excerpt(
        self,
        report: RawReport,
        finding: EnumeratedFinding,
        audited: str | None = None,
        commit: str | None = None,
    ) -> _Excerpt | None:
        """A quote from a line-numbered excerpt, and the assumptions it rests on.

        **The excerpt's line numbers are not a location.** One finding's excerpt
        read `503: function erc20TransferOutBidAmountToLiqudity(...)`; in the
        pinned file that declaration is at 496, and 503 is inside the next
        function. Every check downstream passed -- the file resolved, the span
        parsed, and the function was *derived from the span*, so it agreed with
        itself -- and the record would have pinned a defect to an untouched
        function. The same self-consistency trap as a matcher that shifted a
        quote by 28 lines and found it unique anyway, arriving this time from the
        report's side rather than the instrument's.

        So the numbers are dropped and the excerpt's *text* is handed over as a
        quote, to be found in the source or refused. That is the falsifiability
        this route was valued for in the first place; trusting the numbers threw
        it away. Nothing is lost by dropping them: a quote locates a span
        exactly, and one that cannot be found is a claim the source denies.

        The excerpt states line numbers and a file, but not a commit -- a commit
        is a property of the contest rather than of the finding -- and often not
        a directory either: the heading above the excerpt frequently carries a
        bare `Vault.sol`. Neither is a location, and four of 22 drafts over one
        sample died of the second, resolving against no file in the repository.

        A finding quoting *several* numbered regions has not stated a location,
        and taking the first is a guess that lands on the wrong one: of four such
        findings, three quoted a helper or an explanatory call first and the
        defect site later, and one quoted a test file. So several blocks means
        the excerpt route declines and the quote route gets its turn, where an
        excerpt has to be found in the source rather than trusted.

        Both are recoverable from the report rather than guessed at. The commit
        comes from its permalinks, which point at the audited snapshot; the
        directory comes from its own citation of that file name, and only when
        exactly one cited path ends in it. Two files of the same name in
        different directories is the case where the report has not said which,
        and the draft is lost rather than assigned to whichever was cited first.

        The prose comes back with the citation because this route knows which
        assumptions it made and the caller does not: a directory completed from
        a citation and a directory the excerpt stated are the same bytes and
        different claims, and `pin.resolved_from` is where that difference is
        published.
        """
        blocks_raw = [
            (match.group("path").lstrip("/"), match.group("lines"))
            for match in _FILE_BLOCK.finditer(finding.body)
            if not _LOOKS_LIKE_A_TEST.search(match.group("path"))
            and _NUMBERED_LINE.search(match.group("lines"))
        ]
        if len(blocks_raw) != 1:
            return None
        cited_path, numbered = blocks_raw[0]
        quote = _NUMBERED_LINE.sub("", numbered).strip("\n")
        if not quote.strip():
            return None
        snapshot = contest_snapshot(report.body)
        if snapshot is None:
            return None
        repo_url, snapshot_commit = snapshot
        path = cited_path
        assumption = _FROM_CONTEST_SNAPSHOT
        if "/" not in path:
            cited = {
                reviewed.citation.path
                for reviewed in _reviewed(report.body, audited, commit)
                if reviewed.citation.path.rsplit("/", 1)[-1] == path
            }
            if len(cited) != 1:
                return None
            path = cited.pop()
            if "/" in path:
                assumption += _AND_CITED_DIRECTORY
        return _Excerpt(
            repo_url=repo_url,
            commit=snapshot_commit,
            path=path,
            quote=quote,
            assumption=assumption,
        )

    def _by_name(
        self,
        report: RawReport,
        candidate: Candidate,
        finding: EnumeratedFinding,
        audited: str | None = None,
        commit: str | None = None,
        recovered_from: str | None = None,
    ) -> DraftRecord | Skip:
        """Fall back to the file the finding cites plus the name its prose gives.

        Reached when no single source location was stated, which is the ordinary
        case. A file with several lines cited in it has not stated a span, but a
        file plus a named function is enough for `normalize` to resolve -- and if
        that name does not resolve to exactly one declaration there, the draft is
        lost and counted rather than guessed at.
        """
        quoted = quoted_source(finding.body)
        # Restricted once, here, and every candidate derived from the
        # restricted set. The repository check needed to hold in three places
        # -- the stated citation, the sole cited file, and the candidate set --
        # and applying it in two of them let a finding whose single Solidity
        # citation was a dependency through, producing a record pinned to an
        # upstream library. A check that has to be repeated is a check that
        # will be forgotten in one of its places.
        cited = _solidity_files(finding.body, audited, commit)
        chosen = cited[0] if len({r.citation.path for r in cited}) == 1 else None
        alternatives: tuple[str, ...] = ()
        if chosen is None:
            # Several files cited, or none. A quoted excerpt still states which
            # one, if it occurs in exactly one of them -- and only the stage
            # holding the bytes can decide that, so the whole cited set is
            # handed over rather than a guess being made here. Six of eleven
            # losses over one sample were exactly this: a usable excerpt
            # discarded because the *file* was not unique.
            if not cited:
                return _why_nothing_reviewed(finding.body, audited)
            if quoted is None:
                return Skip(
                    SkipCause.NO_LOCATION,
                    f"cites {len(cited)} files in the code under review and quotes nothing "
                    "to choose between them",
                )
            chosen = cited[0]
            alternatives = tuple(
                dict.fromkeys(
                    r.citation.path for r in cited[1:] if r.citation.path != chosen.citation.path
                )
            )
        file = chosen.citation
        named = _named_function(finding.title, finding.body)
        if named is None and quoted is None:
            return Skip(
                SkipCause.NO_LOCATION,
                f"cites {file.path} but neither quotes source nor names a function for it",
            )
        contract, function = named or (None, None)
        return DraftRecord(
            candidate_id=finding.ident,
            repo_url=file.repo_url,
            commit=file.ref,
            commit_resolved_from=recovered_from if chosen.recovered else None,
            path=file.path,
            alternative_paths=alternatives,
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
                classes=classify_title(finding.title),
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

        audited = _audited_repository(report.body)
        commit = _audited_commit(report.body, audited)
        # Recorded on every draft whose commit the report supplied rather than
        # the finding: the finding cited a branch, and which commit that branch
        # was when its line numbers were written is the assumption.
        recovered_from = _FROM_DOMINANT_CITATION if commit is not None else None
        # Two routes, two different assumptions, and for a while one label: the
        # stated route attached `recovered_from` to every draft it produced,
        # including findings that pinned their own commit in the citation used.
        stated = _cite(finding.body, audited, commit)
        if stated is None:
            # The excerpt states a file and quotes it, but no commit, and often
            # no directory either. It names its own assumptions, because it is
            # the only thing that knows which of them it had to make.
            excerpt = self._from_excerpt(report, finding, audited, commit)
            if excerpt is None:
                return self._by_name(report, candidate, finding, audited, commit, recovered_from)
            if audited is not None and excerpt.repo_url != audited:
                return Skip(
                    SkipCause.CITES_ANOTHER_REPOSITORY,
                    f"quotes {excerpt.repo_url.split('/')[-1]}/{excerpt.path}, which is not "
                    "the code under review",
                )
            return DraftRecord(
                candidate_id=finding.ident,
                repo_url=excerpt.repo_url,
                commit=excerpt.commit,
                commit_resolved_from=excerpt.assumption,
                path=excerpt.path,
                quoted_source=excerpt.quote,
                classes=candidate.classes,
                provenance=Provenance(
                    platform=report.platform,
                    report_url=finding.issue_url or report.report_url,
                    reported_severity=finding.severity,
                ),
            )
        citation = stated.citation
        resolved_from = recovered_from if stated.recovered else None
        if audited is not None and citation.repo_url != audited:
            return Skip(
                SkipCause.CITES_ANOTHER_REPOSITORY,
                f"cites {citation.repo_url.split('/')[-1]}/{citation.path}, which is not "
                "the code under review",
            )
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
            commit=citation.ref,
            commit_resolved_from=resolved_from,
            path=citation.path,
            start_line=citation.start_line if ranged else None,
            end_line=citation.end_line if ranged else None,
            anchor_line=None if ranged else citation.start_line,
            # Carried even alongside a stated span: `normalize` cross-checks the
            # two against the repository's bytes and refuses the record if they
            # point at different code.
            quoted_source=quoted_source(finding.body),
            classes=candidate.classes,
            provenance=Provenance(
                platform=report.platform,
                report_url=finding.issue_url or report.report_url,
                reported_severity=finding.severity,
            ),
        )


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


def _audited_repository(report_body: str) -> str | None:
    """The repository under review, from the whole report rather than one finding.

    A finding quotes a dependency to show what the audited code was derived
    from, or ought to have done. An excerpt matched in that dependency would
    attribute the defect to a third party the report never claimed was
    defective, and the first run of the quote route produced exactly that: a
    record pinned to an upstream library for a finding about a port of it.

    Decided across the report because within one finding the dependency can
    easily be cited more often than the code under review -- which is how that
    record got made. Across a report the reviewed repository dominates by one
    to two orders of magnitude, so this is a count rather than a tie-break, and
    a tie returns nothing rather than choosing.
    """
    counts: Counter[str] = Counter(
        citation.repo_url for citation in permalinks(report_body) if citation.is_solidity
    )
    if not counts:
        return None
    ranked = counts.most_common()
    if len(ranked) > 1 and ranked[1][1] == ranked[0][1]:
        return None
    return ranked[0][0]


def _audited_commit(report_body: str, repository: str | None) -> str | None:
    """The commit the report's own citations of the reviewed repository name.

    A finding frequently cites a *branch* -- `blob/main/src/X.sol#L10-L20` --
    which names whatever that branch points at now and cannot be pinned. The
    report itself cites the same repository at a commit, in its scope and
    throughout, and across six held reports one commit dominated every time
    (11 to 44 citations against a runner-up of 2 to 5).

    So this is recovery from something the report **states**, not an inference
    about dates or a resolution of the branch as it stands today. What remains
    an assumption is that the line numbers a finding wrote against the branch
    were written while the branch was that commit, which is what
    `commit_resolved_from` records so a report can stratify on it -- and what
    `verify` then checks, by requiring the named declaration to be in the
    resolved span. A recovery that lands on the wrong bytes is rejected rather
    than admitted.

    A tie returns nothing: choosing between two commits on a tie-break would
    pin records to a snapshot nobody reviewed.
    """
    if repository is None:
        return None
    counts: Counter[str] = Counter(
        citation.ref
        for citation in permalinks(report_body)
        if citation.is_solidity and citation.repo_url == repository and citation.is_pinned
    )
    if not counts:
        return None
    ranked = counts.most_common()
    if len(ranked) > 1 and ranked[1][1] == ranked[0][1]:
        return None
    return ranked[0][0]


_FROM_DOMINANT_CITATION = "the commit the report's own citations of this repository name most often"
_FROM_CONTEST_SNAPSHOT = (
    "the commit the report states for the contest, the finding's excerpt naming none"
)
_AND_CITED_DIRECTORY = ", and the directory the report's own citation of this file name gives"


@dataclass(frozen=True)
class _Excerpt:
    """A line-numbered excerpt: where it came from, what it quotes, what that rests on."""

    repo_url: str
    commit: str
    path: str
    quote: str
    assumption: str


@dataclass(frozen=True)
class _Reviewed:
    """A citation of the code under review, and whether its commit was recovered.

    The flag exists because the recovery *erases its own evidence*: rewriting a
    moving ref to a commit makes the citation indistinguishable from one the
    finding pinned itself, and `is_pinned` -- which is what the two callers
    asked -- then answers True for both. Every draft was consequently labelled
    the wrong way round: findings that pinned their own commit were recorded as
    resting on a recovery, and the recovered ones as stated outright. A cause
    recorded wrongly points investigation away from the fix, and here the cause
    was a *property of the record*, published in `pin.resolved_from`.
    """

    citation: SourceCitation
    recovered: bool


def _why_nothing_reviewed(body: str, repository: str | None) -> Skip:
    """The accurate cause when no citation survives the reviewed-repository filter.

    Restricting in one place cost the explanation: a finding citing a
    dependency, one citing a Markdown file, and one citing nothing all arrived
    here indistinguishable, and all three were reported as `no_location`. Each
    calls for a different fix -- read the report's scope, parse a path, or
    nothing at all -- and **a cause recorded wrongly points investigation away
    from the fix**. So the causes are read back off the unfiltered citations,
    which is where the difference between them still exists.
    """
    cited = permalinks(body)
    if not cited:
        return Skip(SkipCause.NO_LOCATION, "the finding cites no source location")
    solidity = [c for c in cited if c.is_solidity]
    if not solidity:
        return Skip(SkipCause.NO_FILE_PATH, f"cited {cited[0].path}, which is not Solidity")
    if repository is None:
        return Skip(
            SkipCause.NO_LOCATION,
            "the report states no single repository under review, so a citation cannot be "
            "told from a citation of a dependency",
        )
    if all(c.repo_url != repository for c in solidity):
        return Skip(
            SkipCause.CITES_ANOTHER_REPOSITORY,
            f"cites {solidity[0].repo_url.split('/')[-1]}/{solidity[0].path}, which is not "
            "the code under review",
        )
    return Skip(
        SkipCause.NO_COMMIT,
        f"cites {solidity[0].path} at {solidity[0].ref!r}, which names a moving target, "
        "and the report pins no single commit for that repository",
    )


def _reviewed(body: str, repository: str | None, commit: str | None) -> list[_Reviewed]:
    """Solidity citations in the reviewed repository, every one of them pinned.

    The single place both the repository restriction and the commit recovery
    apply. Each had to hold wherever a citation enters, and each was written
    twice and forgotten once -- a dependency slipped through as "the one file it
    cites", and a recovery added to the stated-citation path never fired because
    the other path filtered moving refs out before reaching it. **A check that
    has to be repeated is a check that will be forgotten in one of its
    places**, so citations enter here and nowhere else.

    A moving ref is rewritten to the commit the report states for that
    repository (`_audited_commit`). Nothing is dropped for being unpinned any
    more; what is dropped is a citation outside the reviewed repository, one of
    test or mock code, or any citation at all when the report pins no single
    commit.
    """
    if repository is None:
        return []
    found: list[_Reviewed] = []
    for citation in permalinks(body):
        if not citation.is_solidity or citation.repo_url != repository:
            continue
        if _LOOKS_LIKE_A_TEST.search(citation.path):
            continue
        if citation.is_pinned:
            found.append(_Reviewed(citation, recovered=False))
        elif commit is not None:
            found.append(_Reviewed(replace(citation, ref=commit), recovered=True))
    return found


def _solidity_files(body: str, repository: str | None, commit: str | None) -> list[_Reviewed]:
    """One citation per distinct path, the candidate set an excerpt chooses from.

    Ordered by first appearance so a rerun hands over the same set -- which of
    them ends up in `path` is not load-bearing, since `normalize` requires the
    excerpt to occur in exactly one of them however they are ordered.
    """
    seen: dict[str, _Reviewed] = {}
    for reviewed in _reviewed(body, repository, commit):
        if reviewed.citation.path not in seen:
            seen[reviewed.citation.path] = reviewed
    return list(seen.values())


def _cite(body: str, repository: str | None, commit: str | None) -> _Reviewed | None:
    """The one source location a finding states, or None if it states none.

    A "Lines of code" section is authoritative. Failing that, a body citing
    exactly one distinct source location is taken to state it, and a body citing
    several is taken to state none -- proof-of-concept sections cite freely, and
    one observed finding carried 36 permalinks of which none was the defect.
    """
    section = _LINES_OF_CODE.search(body)
    if section is not None:
        cited = _reviewed(section.group(1), repository, commit)
        if cited:
            return cited[0]

    cited = _reviewed(body, repository, commit)
    distinct = {
        (
            r.citation.repo_url,
            r.citation.ref,
            r.citation.path,
            r.citation.start_line,
            r.citation.end_line,
        )
        for r in cited
    }
    return cited[0] if len(distinct) == 1 else None
