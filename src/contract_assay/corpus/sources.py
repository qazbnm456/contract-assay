"""Turning a platform's current publication format into the reports an adapter reads.

An adapter takes a `RawReport` whose `body` is one finding in that platform's
submission template. This module is what produces those bodies when the platform
has stopped publishing one file per finding — which both of the corpus's main
sources now have.

**Fetching is not here**, for the reason `harvest.RawReport` gives: it is an
outward-facing act with its own licensing and rate-limit questions, and keeping
it out is what lets the whole harvest stage run in the offline gate. Everything
here is a pure function of text, and the tests are text in and reports out.

## Why a reshape rather than a new adapter

Sherlock's judging repositories used to hold one markdown file per deduplicated
issue, each in the submission template: a handle, a bare severity line, a
`# Title`, then `### Summary`, `### Root Cause` and the rest. From 2025-06-18
they hold a consolidated `README.md` instead, one section per deduplicated
issue, with the same `###` sections inside and two differences that matter:

1. The heading is `# Issue M-1: <title>`, so a title read straight from it
   carries an `Issue M-1: ` prefix into classification.
2. There is **no bare severity line**. The severity is in the `M`/`H` of the
   heading, so `SherlockAdapter`'s `^(High|Medium|Low)$` never matches and every
   finding is refused as a malformed report.

Both are presentation. The finding, its sections, its permalinks and the
platform's own deduplication are unchanged, so the honest move is to restore the
template the adapter documents rather than to write a second parser of the same
content and let the two disagree about what a Sherlock finding is.

`split_sherlock_judging` therefore emits, per section:

    <the handles that found it>

    <High|Medium>

    # <title, with the Issue M-1 prefix removed>

    ### Summary
    ...

The severity line is emitted **first** deliberately. `_SEVERITY` is an
unanchored multiline search, so a body containing a line that happens to read
`Medium` — a severity discussion, a table cell — would otherwise decide the
finding's severity. Putting the real one first makes it the one that matches.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

from contract_assay.corpus.adapters.markdown import permalinks
from contract_assay.corpus.harvest import RawReport

__all__ = [
    "JudgingSection",
    "dominant_commits",
    "sections_of_sherlock_judging",
    "split_sherlock_judging",
]

_HEADING = re.compile(
    r"^#[ \t]+Issue[ \t]+(?P<severity>[HM])-(?P<number>\d+)[ \t]*:[ \t]*(?P<title>\S.*?)[ \t]*$",
    re.M,
)
_SOURCE = re.compile(r"^Source:[ \t]*(?P<url>\S+)[ \t]*$", re.M)
_FOUND_BY = re.compile(r"^##[ \t]+Found by[ \t]*$(?P<handles>.*?)(?=^###|\Z)", re.M | re.S)

_SEVERITY_OF = {"H": "High", "M": "Medium"}


@dataclass(frozen=True, slots=True)
class JudgingSection:
    """One deduplicated issue, as the consolidated README presents it."""

    severity: str
    """`High` or `Medium`, from the heading's `H`/`M`."""

    number: int
    """The `1` of `H-1`. The platform's own ordering, kept for traceability."""

    title: str
    """The heading's title, with the `Issue H-1:` prefix removed."""

    source_url: str | None
    """The `Source:` line: the issue this section was consolidated from."""

    handles: tuple[str, ...]
    """Who found it, from `## Found by`. Not used by the adapter; carried so the
    reshaped body stays a faithful rendering of the section rather than a
    reconstruction with parts dropped."""

    body: str
    """Everything from the first `###` section onward."""

    @property
    def label(self) -> str:
        return f"{self.severity[0]}-{self.number}"


def sections_of_sherlock_judging(readme: str) -> list[JudgingSection]:
    """Every deduplicated issue in a consolidated judging README.

    Sections are delimited by the headings themselves rather than by a
    separator, so a section runs to the next heading or to the end of the file.
    A README with no such heading yields nothing: that is either an older
    layout, which the adapter already reads one file at a time, or a repository
    whose judging has not been published, and inventing a section from the whole
    file would put one record's location on another record's finding.
    """
    found: list[JudgingSection] = []
    matches = list(_HEADING.finditer(readme))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(readme)
        chunk = readme[start:end]
        source = _SOURCE.search(chunk)
        handles = _handles(chunk)
        # From the first `###` onward. `## Found by` and `Source:` are the
        # consolidation's own framing and are lifted into fields above; leaving
        # them in the body would put a handle list inside `### Summary`'s
        # neighbourhood, and `section()` reads by heading rather than by offset.
        body_start = chunk.find("###")
        body = chunk[body_start:] if body_start >= 0 else ""
        found.append(
            JudgingSection(
                severity=_SEVERITY_OF[match.group("severity")],
                number=int(match.group("number")),
                title=match.group("title"),
                source_url=source.group("url") if source else None,
                handles=handles,
                body=body,
            )
        )
    return found


def _handles(chunk: str) -> tuple[str, ...]:
    match = _FOUND_BY.search(chunk)
    if match is None:
        return ()
    # Escaped underscores are a markdown artefact of the handle, not part of it.
    raw = match.group("handles").replace("\\_", "_")
    return tuple(
        handle for handle in (part.strip() for part in raw.replace("\n", ",").split(",")) if handle
    )


def split_sherlock_judging(
    readme: str,
    *,
    repo_url: str,
    published: str | None = None,
) -> list[RawReport]:
    """One `RawReport` per deduplicated issue, in the template the adapter reads.

    `repo_url` is the judging repository, used only to build a `report_url` for a
    section whose `Source:` line is missing — a section still has to be
    identifiable, and an empty `report_url` would collapse every such section
    onto one candidate id.

    `published` bounds a branch-citation recovery and belongs to the contest
    rather than to the section: the consolidated README carries no per-issue
    date. Pass the contest's own date, and pass nothing rather than today's —
    resolving a branch as it stands now rests on no assumption anybody can
    write down, which is what `SherlockAdapter` already refuses.
    """
    reports: list[RawReport] = []
    for section in sections_of_sherlock_judging(readme):
        reports.append(
            RawReport(
                platform="sherlock",
                report_url=section.source_url or f"{repo_url}#{section.label}",
                body=_as_submission_template(section),
                published=published,
            )
        )
    return reports


def _as_submission_template(section: JudgingSection) -> str:
    """The section, rendered as one submission in Sherlock's own template."""
    handles = ", ".join(section.handles) if section.handles else "unattributed"
    return f"{handles}\n\n{section.severity}\n\n# {section.title}\n\n{section.body}".rstrip() + "\n"


def dominant_commits(texts: Sequence[str] | Iterator[str]) -> Mapping[str, str]:
    """Per repository, the commit the texts pin most often.

    `SherlockAdapter` takes this as `cited_commits` and documents why it is
    computed outside: one contest's submissions all cite the same reviewed code
    and most of them pin it, so the count belongs to the contest rather than to
    any one document. A consolidated README is the whole contest in one file,
    which makes the count available here without any fetching.

    Only pinned references are counted. Counting branch names would let `main`
    win by appearing everywhere and then resolve every location against
    whatever it points at today.

    Ties are broken by the lexicographically smaller SHA, so two runs over one
    contest agree. A tie means the contest cited two commits equally often and
    neither is more the reviewed state than the other; the pin records which
    assumption was made either way.
    """
    counted: dict[str, Counter[str]] = {}
    for text in texts:
        for citation in permalinks(text):
            if not citation.is_pinned:
                continue
            counted.setdefault(citation.repo_url, Counter())[citation.ref] += 1
    return {
        repo_url: min(tally.most_common(), key=lambda pair: (-pair[1], pair[0]))[0]
        for repo_url, tally in counted.items()
        if tally
    }
