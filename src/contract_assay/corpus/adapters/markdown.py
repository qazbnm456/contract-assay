"""Reading locations out of markdown audit reports.

Shared by every adapter, because none of it is platform knowledge: GitHub
permalinks and fenced code blocks look the same wherever they appear. What
differs per platform is the document structure around them, and that stays in
the platform's own module.

Keeping the regexes here rather than copied into each adapter is the same
argument `NODE_KINDS` settles for the analysis backends: two modules maintaining
private answers to one question is how they come to disagree about it.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

__all__ = [
    "SourceCitation",
    "contest_snapshot",
    "permalinks",
    "quoted_source",
    "section",
]

_PERMALINK = re.compile(
    r"https://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
    r"/blob/(?P<ref>[^/\s]+)/(?P<path>[^\s>)#?]+?)"
    # A permalink often carries a query string -- `?plain=1` is the common one --
    # between the path and the line anchor. Left in the path it makes the file
    # look like it has an unrecognised extension, so a Solidity file stops being
    # one for a reason that has nothing to do with the file.
    r"(?:\?[^\s>)#]*)?"
    r"(?:#L(?P<start>\d+)(?:-L?(?P<end>\d+))?)?(?=[\s>)\]]|$)"
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)
_LOOKS_LIKE_SOURCE = re.compile(
    r"\b(function|require|modifier|mapping|uint\d*|address|emit|return)\b"
)
_LOOKS_LIKE_HARNESS = re.compile(r"\bfunction\s+test\w*\s*\(|\bvm\.|\bconsole\.log")


@dataclass(frozen=True, slots=True)
class SourceCitation:
    """A source location a report linked to."""

    repo_url: str
    ref: str
    """Whatever followed `/blob/`: a commit SHA, or a branch or tag name."""

    path: str
    start_line: int | None
    end_line: int | None

    @property
    def is_pinned(self) -> bool:
        """True when the reference is a full commit SHA rather than a moving name.

        A branch or tag names whatever it currently points at, so a location
        cited that way is not reproducible and cannot become a `SourcePin`
        without resolving it first -- which is a separate act with its own
        uncertainty about whether today's target is the audited state.
        """
        return bool(_SHA.match(self.ref))

    @property
    def is_solidity(self) -> bool:
        return self.path.endswith(".sol")


def permalinks(text: str) -> list[SourceCitation]:
    """Every GitHub blob link in order, pinned or not."""
    found: list[SourceCitation] = []
    for match in _PERMALINK.finditer(text):
        start = int(match.group("start")) if match.group("start") else None
        end = int(match.group("end")) if match.group("end") else start
        found.append(
            SourceCitation(
                repo_url=f"https://github.com/{match.group('owner')}/{match.group('repo')}",
                ref=match.group("ref"),
                path=match.group("path").lstrip("/"),
                start_line=start,
                end_line=end,
            )
        )
    return found


def contest_snapshot(text: str) -> tuple[str, str] | None:
    """The repository and commit a document cites most often, if it cites one.

    A commit identifies the snapshot under audit, so any pinned link in a
    document establishes it -- unlike a *location*, which belongs to one finding
    and cannot be borrowed from another. The most frequently cited pair wins, so
    a stray link to an unrelated repository does not decide it.
    """
    seen = Counter(
        (citation.repo_url, citation.ref) for citation in permalinks(text) if citation.is_pinned
    )
    return seen.most_common(1)[0][0] if seen else None


def quoted_source(text: str) -> str | None:
    """The longest fenced block that looks like contract source, if any.

    Blocks that look like a test harness are excluded: a proof of concept
    exercises the defect rather than containing it, so locating one would locate
    the test. Longest wins, because a longer excerpt is both likelier to locate
    uniquely and likelier to be the passage under discussion than an aside.
    """
    candidates = [
        match.group(2)
        for match in _FENCE.finditer(text)
        if _LOOKS_LIKE_SOURCE.search(match.group(2))
        and not _LOOKS_LIKE_HARNESS.search(match.group(2))
    ]
    return max(candidates, key=len) if candidates else None


def section(text: str, heading: str, *, level: int = 3) -> str | None:
    """The body of a named section, up to the next heading of that level or above.

    Reports built from a template put the defect's location in a predictable
    section, and reading only that section is what keeps a proof-of-concept
    citation from being mistaken for the location.
    """
    marker = "#" * level
    pattern = re.compile(
        rf"^{marker}\s+{re.escape(heading)}\s*$(.*?)(?=^#{{1,{level}}}\s|\Z)",
        re.M | re.S,
    )
    found = pattern.search(text)
    return found.group(1) if found else None
