#!/usr/bin/env python3
"""Compare each record's pin against the file its own report points at.

    python tools/audit_locators.py --records corpus/records --cache .audit-cache

The network half, as the harvest tools are. What it checks is the one thing no
local pass can: **a record can be perfectly verifiable and still be about a
different file.**

`verify` re-reads the quote inside the cited span and passes when the bytes
match, so a record whose span is a real function in a real file is admitted --
whether or not that function is the one the finding is about. Measured on a
55-record holdout: 54 admitted, and one of those pins
`src/market/WildcatMarket.sol#226-287` (`closeMarket`) for a finding whose own
`# Lines of code` section reads
`src/access/AccessControlHooks.sol#L812` and whose every paragraph is about
`onQueueWithdrawal`. `closeMarket` never calls it.

`docs/design.md` §7.3 names that exact pair -- "a hook's `onQueueWithdrawal`
where the quote shows `closeMarket`" -- as a draft `normalize` refuses under
`location_contradicts_name`. The refusal is implemented. It did not fire here,
and the reason is in the sibling cause's own docstring: the cross-check needs a
function name extracted from the prose, and where none is extracted there is
nothing to compare. So the guard's reach is the extractor's reach, and this
compares something an extractor cannot miss: the URL the finding puts at the
top of itself.

**A mismatch is a report to read, not a verdict.** A finding can legitimately
cite a caller, and a curator may have repinned deliberately -- the holdout's
hand-adjudicated records exist for that. What this cannot do is tell those from
the other kind, so it prints the pair and stops.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from contract_assay.corpus.adapters.code4rena import Code4renaEnumerator
from contract_assay.corpus.fetch import urllib_fetcher
from contract_assay.corpus.records import CommitPin, load_records
from contract_assay.corpus.sources import code4rena_report

_ISSUE = re.compile(r"github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/issues/(?P<number>\d+)")
_BLOB = re.compile(
    r"github\.com/[\w.-]+/(?P<repo>[\w.-]+)/blob/(?P<ref>[^/\s]+)/(?P<path>[^\s#)\"']+)"
    r"(?:#L(?P<line>\d+))?"
)
_HEADING = re.compile(r"^#+\s*Lines of code\s*$", re.M | re.I)
_C4 = re.compile(r"code4rena\.com/(?:reports|audits)/(?P<slug>[\w-]+)")
_REPORT = "https://code4rena.com/reports/{slug}"


def report_body(url: str, cache: Path) -> str | None:
    """A finding's body, from the cache or from the forge.

    Cached because the audit is re-run far more often than a published finding
    changes, and because a loop that refetches 55 issues to adjust one regex is
    a loop nobody runs twice.
    """
    found = _ISSUE.search(url)
    if found is None:
        return None
    key = f"{found['owner']}--{found['repo']}--{found['number']}.md"
    held = cache / key
    if held.is_file():
        return held.read_text(encoding="utf-8")
    done = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{found['owner']}/{found['repo']}/issues/{found['number']}",
            "--jq",
            ".body",
        ],
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        return None
    cache.mkdir(parents=True, exist_ok=True)
    held.write_text(done.stdout, encoding="utf-8")
    return done.stdout


def cited_paths(body: str) -> tuple[list[str], list[str]]:
    """Paths the finding links to: the ones under its own heading, then the rest.

    The heading's links first because Code4rena's template puts the finding's
    location there, and a body quotes plenty of other files while arguing. A
    record agreeing with any link is not the same as agreeing with the one the
    finding nominated.
    """
    heading = _HEADING.search(body)
    under: list[str] = []
    if heading is not None:
        # Until the next heading, which is where the template's next section
        # starts. Taking the whole body would fold the nomination back into the
        # argument and the distinction above would be lost.
        rest = body[heading.end() :]
        end = re.search(r"^#+\s", rest, re.M)
        under = [m["path"] for m in _BLOB.finditer(rest[: end.start() if end else len(rest)])]
    everywhere = [m["path"] for m in _BLOB.finditer(body)]
    return under, everywhere


def c4_body(url: str, cache: Path) -> str | None:
    """One finding's body, out of the contest report page that holds it.

    Two thirds of this holdout cites `code4rena.com`, not a GitHub issue: 13
    records point at `/reports/<slug>#M-nn` and 23 at
    `/audits/<slug>/submissions/F-nn`. Both live in the same published report,
    which `sources.code4rena_report` already converts, so the audit reuses the
    harvest path rather than parsing the page a second way -- two parsers of one
    format eventually disagree, and the one nobody runs is the one that is wrong.

    Matched on the finding's own `issue_url` first. The enumerator reads that out
    of the report, so it is the report's own statement of which submission a
    section is, rather than an anchor this function guessed at.
    """
    found = _C4.search(url)
    if found is None:
        return None
    slug = found["slug"]
    held = cache / f"c4--{slug}.md"
    if held.is_file():
        markdown: str | None = held.read_text(encoding="utf-8")
    else:
        try:
            page = urllib_fetcher()(_REPORT.format(slug=slug)).decode("utf-8", errors="replace")
        except OSError:
            return None
        markdown = code4rena_report(page)
        if markdown is None:
            return None
        cache.mkdir(parents=True, exist_ok=True)
        held.write_text(markdown, encoding="utf-8")
    if markdown is None:
        return None

    findings = Code4renaEnumerator().findings(markdown)
    for finding in findings:
        if finding.issue_url and finding.issue_url.rstrip("/") == url.rstrip("/"):
            return finding.body
    # Falling back to the anchor, for a `/reports/<slug>#M-26` citation whose
    # section names its submission page rather than itself.
    anchor = url.partition("#")[2]
    if anchor:
        for finding in findings:
            if finding.ident and finding.ident.upper() == anchor.upper():
                return finding.body
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(".audit-cache"))
    args = parser.parse_args(argv)

    records = load_records(args.records)
    outcomes: Counter[str] = Counter()
    mismatched: list[tuple[str, str, str, list[str]]] = []
    for record in records:
        pin = record.pin
        if not isinstance(pin, CommitPin):
            outcomes["not a commit pin"] += 1
            continue
        url = str(record.provenance.report_url)
        body = report_body(url, args.cache) or c4_body(url, args.cache)
        if body is None:
            outcomes["report not fetched"] += 1
            continue
        under, everywhere = cited_paths(body)
        if not everywhere:
            outcomes["the report links no source"] += 1
            continue
        if pin.path in under:
            outcomes["the pin is what the finding nominated"] += 1
        elif not under and pin.path in everywhere:
            outcomes["no nomination; the pin is linked somewhere"] += 1
        elif pin.path in everywhere:
            outcomes["linked, but not what the finding nominated"] += 1
            mismatched.append((record.record_id, pin.path, "linked elsewhere in the body", under))
        else:
            outcomes["the report never links this file"] += 1
            mismatched.append((record.record_id, pin.path, "never linked", under or everywhere))

    print(f"{len(records)} record(s)\n")
    for outcome, count in outcomes.most_common():
        print(f"  {count:>4}  {outcome}")
    if mismatched:
        print(f"\n=== {len(mismatched)} record(s) to read ===")
        for record_id, path, why, cited in mismatched:
            print(f"\n  {record_id}")
            print(f"    pinned:     {path}")
            print(f"    {why}")
            for other in dict.fromkeys(cited):
                if other != path:
                    print(f"    nominated:  {other}")
    print(
        "\nA mismatch is a report to read, not a verdict: a finding can cite a caller, and a "
        "curator may have repinned deliberately. What this cannot do is tell those apart."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
