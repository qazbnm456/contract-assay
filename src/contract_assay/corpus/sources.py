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

import json
import re
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from html import unescape

from contract_assay.corpus.adapters.markdown import permalinks
from contract_assay.corpus.harvest import RawReport

__all__ = [
    "JudgingSection",
    "code4rena_report",
    "dominant_commits",
    "rsc_payload",
    "rsc_text_blob",
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


# --------------------------------------------------------------------------
# Code4rena: the report is a web page now
# --------------------------------------------------------------------------
#
# `Code4renaAdapter` takes one whole contest report as markdown and reads five
# things out of it: `# High Risk Findings (n)` for the platform's own count,
# `## [[H-01] Title](url)` per finding, `### Lines of code` where present,
# fenced blocks for `quoted_source`, and every GitHub permalink for
# `reviewed_repository`, `contest_snapshot` and `dominant_commit`.
#
# Code4rena's last `-findings` repository was published 2024-11-29. Since then a
# report exists only at `code4rena.com/reports/<slug>`, as pre-rendered HTML
# inside a Next.js RSC payload -- and the markdown files that *are* in recent
# contest repositories are pre-contest automated scan reports handed to
# participants, which say "Not all issues are guaranteed to be correct" and
# carry a contract and a function but no line numbers.
#
# The HTML is that same markdown skeleton rendered by one generator, heading for
# heading. So this converts it back rather than parsing HTML as a new format:
# the adapter keeps deciding what a Code4rena finding is, and its external count
# check keeps working, which is the thing that would be lost by writing a second
# reader.

_RSC_BLOB = re.compile(r"(?P<id>\w+):T(?P<length>[0-9a-f]+),")
_PUSH = re.compile(r'self\.__next_f\.push\(\[1,\s*(?P<chunk>".*?")\]\)', re.S)
_SELF_ANCHOR = re.compile(r'<a href="#[^"]*"[^>]*>.*?</a>', re.S)
_HEADING_TAG = re.compile(r"<h(?P<level>[1-6])\b[^>]*>(?P<inner>.*?)</h\1>", re.S)
_LINK = re.compile(r'<a\b[^>]*?href="(?P<href>[^"]*)"[^>]*>(?P<text>.*?)</a>', re.S)
_CODE_BLOCK = re.compile(
    r"<pre\b[^>]*>(?:\s*<code\b[^>]*>)?(?P<code>.*?)(?:</code>\s*)?</pre>", re.S
)
_TAG = re.compile(r"<[^>]+>")
_BLANKS = re.compile(r"\n{3,}")


def rsc_payload(page: str) -> str:
    """The concatenated RSC stream of a Next.js page.

    The chunks are JSON string literals inside `self.__next_f.push`, so they are
    decoded with `json.loads` rather than by unescaping by hand: the stream
    carries `\\u003c` for every `<`, and a hand-written unescape that missed one
    escape form would silently truncate a report.
    """
    return "".join(json.loads(match.group("chunk")) for match in _PUSH.finditer(page))


def rsc_text_blob(payload: str, *, containing: str) -> str | None:
    """The longest `id:T<hexlen>,` text blob that contains a marker.

    Length-prefixed rather than delimited, so the blob is sliced by its declared
    length instead of by looking for where it ends. A page carries the report
    twice -- server render and client payload -- and both blobs are identical,
    so the longest match is the report either way and picking one is not a
    choice about content.
    """
    found: list[str] = []
    for match in _RSC_BLOB.finditer(payload):
        body = payload[match.end() : match.end() + int(match.group("length"), 16)]
        if containing in body:
            found.append(body)
    return max(found, key=len) if found else None


def code4rena_report(page: str) -> str | None:
    """A published Code4rena report page, back as the markdown its adapter reads.

    `None` when the page holds no report: a 404, a redirect, or a contest whose
    report is not published. Returning empty markdown instead would let the
    adapter report zero findings for a contest that has some, which is a loss
    with no symptom.

    Deliberately not a general HTML-to-markdown converter. It handles the tags
    this one generator emits -- headings with a self-anchor, links, `<pre><code>`
    with syntax-highlighting spans, paragraphs and lists -- and flattens
    everything else to its text. Anything it does not handle degrades to text
    rather than to nothing, which keeps a permalink readable by `permalinks()`
    even inside a construct this has never seen.
    """
    payload = rsc_payload(page) or page
    report = rsc_text_blob(payload, containing="Risk Findings")
    if report is None or "<h1" not in report:
        return None
    return _as_markdown(report)


def _as_markdown(html: str) -> str:
    """The generator's HTML, as the markdown it was rendered from.

    **Entities are unescaped exactly once, at the end, after every tag has been
    stripped.** Nothing in here may unescape earlier, and the rule is not
    stylistic. Solidity is full of `<` and `>`; the generator emits them as
    `&lt;` and `&gt;`; and `_TAG` matches `<[^>]+>`. So an early unescape inside
    a code block turns `require(slippage &lt;= max, "x");` into
    `require(slippage <= max, "x");` while the strip is still to come, and the
    strip then deletes from that `<` to the next `>` -- swallowing the operator,
    the rest of the statement and, observed, the line after it.

    Found by the corpus pipeline rather than by a test: three Code4rena findings
    came back `quote_not_found` because the quote this produced was not the
    source any more.
    """

    def heading(match: re.Match[str]) -> str:
        hashes = "#" * int(match.group("level"))
        # The self-anchor is a permalink widget, not content: it wraps an svg and
        # points at the heading's own id. Left in, its `href="#m-01-..."` becomes
        # a markdown link and the finding heading no longer matches.
        inner = _SELF_ANCHOR.sub("", match.group("inner"))
        link = _LINK.search(inner)
        if link is not None:
            text = _text(link.group("text"))
            return f"\n\n{hashes} [{text}]({link.group('href')})\n\n"
        return f"\n\n{hashes} {_text(inner)}\n\n"

    def code(match: re.Match[str]) -> str:
        # Tags stripped, entities **left alone**. See `_as_markdown`'s docstring:
        # unescaping here turns `&lt;` into `<` while the global tag strip is
        # still to come, and that strip then eats from it to the next `>`.
        body = _TAG.sub("", match.group("code"))
        return "\n\n```\n" + body.strip("\n") + "\n```\n\n"

    def link(match: re.Match[str]) -> str:
        return f"[{_text(match.group('text'))}]({match.group('href')})"

    text = _CODE_BLOCK.sub(code, html)
    text = _HEADING_TAG.sub(heading, text)
    text = _LINK.sub(link, text)
    for tag, replacement in (
        ("</p>", "\n\n"),
        ("<br>", "\n"),
        ("<br/>", "\n"),
        ("<br />", "\n"),
        ("</li>", "\n"),
        ("</tr>", "\n"),
        ("</ul>", "\n"),
        ("</ol>", "\n"),
        ("</blockquote>", "\n\n"),
    ):
        text = text.replace(tag, replacement)
    text = _TAG.sub("", text)
    return _BLANKS.sub("\n\n", unescape(text)).strip() + "\n"


def _text(inner: str) -> str:
    """One heading's or link's text, with its markup flattened.

    Entities are left escaped for the single unescape at the end, for the reason
    `_as_markdown` gives: a heading containing `&lt;` would otherwise become a
    heading containing `<`, and the global tag strip would eat the rest of it.
    """
    return " ".join(_TAG.sub("", inner).split())
