#!/usr/bin/env python3
"""Harvest a Sherlock contest's consolidated judging README into corpus records.

Outside the package on purpose. `corpus/sources.py` is the pure half — text in,
`RawReport`s out — and this is the half that reaches the network, which
`harvest.RawReport` says explicitly does not belong in the module: it has its own
licensing and rate-limit questions, and keeping it out is what lets the whole
harvest stage run in the offline gate.

    python tools/harvest_sherlock.py --out /tmp/holdout --cache /tmp/hcache

What it does, and it is the documented pipeline with nothing added:

    fetch the judging README        (gh api, cached)
    split into one report per issue (corpus/sources.py)
    count the dominant commit       (corpus/sources.py)
    harvest(SherlockAdapter, ...)   -> drafts, and an accounting of the losses
    normalize(drafts, resolve, ...) -> records, and an accounting of those losses
    write one JSON per record

Both accountings are printed rather than summarised, because the yield of a
platform is the number that decides whether the next contest is worth the time,
and a pipeline that reports only its successes cannot answer that.

`--split` defaults to `private_holdout`. That is a deliberate default for the use
this was written for and it is the field that decides whether a record is
published, so it is printed back at the end of every run.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from contract_assay.corpus.adapters.sherlock import SherlockAdapter
from contract_assay.corpus.fetch import raw_url, urllib_fetcher
from contract_assay.corpus.harvest import RawReport, harvest
from contract_assay.corpus.normalize import normalize
from contract_assay.corpus.records import (
    CorpusSplit,
    Population,
    SourcePin,
)
from contract_assay.corpus.sources import (
    dominant_commits,
    split_sherlock_judging,
)

# The contests whose judging repository uses the consolidated README, with the
# date the repository was created. The date bounds a branch-citation recovery and
# is the contest's, not the finding's -- the consolidated README carries no
# per-issue date, and `sources.split_sherlock_judging` says why today's date is
# refused instead of guessed at.
#
# This list ends where Sherlock's GitHub publication does. The organisation holds
# 49 judging repositories; the newest is 2025-07-25, and the two 2026 contests
# have no judging repository at all. Anything after that is not a gap in this
# list.
CONTESTS: tuple[tuple[str, str], ...] = (
    ("2025-06-symbiotic-relay", "2025-06-18"),
    ("2025-06-notional-exponent", "2025-06-27"),
    ("2025-07-debank", "2025-07-01"),
    ("2025-07-cap", "2025-07-07"),
    ("2025-07-mellow-flexible-vaults", "2025-07-12"),
    ("2025-07-malda", "2025-07-22"),
    ("2025-07-allbridge-core-yield", "2025-07-23"),
    ("2025-07-oku-trade-order-types", "2025-07-25"),
)


def judging_readme(contest: str, cache: Path) -> str | None:
    """The consolidated README, from the cache or from GitHub.

    Cached because a re-run is the normal case -- the pipeline downstream changes
    far more often than a finished contest does -- and because a loop that
    re-fetches eight repositories to change one regex is a loop nobody runs
    twice.
    """
    held = cache / f"{contest}-judging.md"
    if held.is_file():
        return held.read_text(encoding="utf-8")
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/sherlock-audit/{contest}-judging/contents/README.md",
            "--jq",
            ".content",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  {contest}: no README ({result.stderr.strip()[:80]})", file=sys.stderr)
        return None
    text = base64.b64decode(result.stdout.strip()).decode("utf-8", errors="replace")
    cache.mkdir(parents=True, exist_ok=True)
    held.write_text(text, encoding="utf-8")
    return text


def make_resolver(cache: Path) -> object:
    """A `SourceResolver` over the package's own fetcher, cached on disk.

    **Uses `fetch.urllib_fetcher` and `fetch.raw_url` rather than a hand-written
    request.** The first version of this function wrote its own `urlopen` call
    and every one of eleven pins came back `source_unresolvable` --
    `CERTIFICATE_VERIFY_FAILED`, because Python's `urllib` does not consult the
    system trust store on macOS. That is the same defect the package fixed in
    `fetch.urllib_fetcher`, which builds its context from `certifi` and says so
    at length; writing a second fetcher reproduced a bug that had already been
    found, measured and documented one directory away.

    So the only thing this adds is the cache, which is what a harvest loop needs
    and a one-shot checkout does not.
    """
    directory = cache / "sources"
    directory.mkdir(parents=True, exist_ok=True)
    fetch = urllib_fetcher()
    misses: set[str] = set()

    def resolve(pin: SourcePin) -> str | None:
        if getattr(pin, "kind", None) != "commit":
            return None
        commit = getattr(pin, "commit", "")
        key = f"{pin.path.replace('/', '__')}--{commit[:12]}"
        held = directory / key
        if held.is_file():
            return held.read_text(encoding="utf-8")
        if key in misses:
            return None
        try:
            body = fetch(raw_url(pin))  # type: ignore[arg-type]
        except (OSError, ValueError):
            # An unresolvable pin is a counted loss with a cause; raising here
            # would abort a corpus build over one dead repository.
            misses.add(key)
            return None
        text = body.decode("utf-8", errors="replace")
        held.write_text(text, encoding="utf-8")
        return text

    return resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="Where records are written.")
    parser.add_argument("--cache", type=Path, default=Path(".harvest-cache"))
    parser.add_argument(
        "--split",
        default=CorpusSplit.PRIVATE_HOLDOUT.value,
        choices=[split.value for split in CorpusSplit],
    )
    parser.add_argument("--contest", action="append", default=None, help="Just these.")
    args = parser.parse_args(argv)

    wanted = (
        CONTESTS
        if args.contest is None
        else tuple(pair for pair in CONTESTS if pair[0] in set(args.contest))
    )
    if not wanted:
        print("no contest matched --contest", file=sys.stderr)
        return 2

    reports: list[RawReport] = []
    cited: dict[str, str] = {}
    per_contest: Counter[str] = Counter()
    print(f"{len(wanted)} contest(s)", file=sys.stderr)
    for contest, published in wanted:
        text = judging_readme(contest, args.cache)
        if text is None:
            continue
        repo_url = f"https://github.com/sherlock-audit/{contest}-judging"
        found = split_sherlock_judging(text, repo_url=repo_url, published=published)
        per_contest[contest] = len(found)
        reports.extend(found)
        # Per contest, because a commit that dominates one contest says nothing
        # about another and a merged count would let the largest contest decide
        # every other contest's pin.
        for repo, commit in dominant_commits([text]).items():
            cited.setdefault(repo, commit)
        print(f"  {contest:<34} {len(found):>3} finding(s)", file=sys.stderr)

    if not reports:
        print("nothing to harvest", file=sys.stderr)
        return 1
    print(f"\n{len(reports)} finding(s); {len(cited)} repository commit(s) recovered by count")

    adapter = SherlockAdapter(cited_commits=cited)
    harvested = harvest(adapter, reports)
    print(f"\n=== harvest: {len(harvested.drafts)} draft(s) of {harvested.candidates} ===")
    for cause, count in sorted(harvested.by_cause.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {cause.value}")
    print(f"\n{harvested.yield_statement()}")

    resolve = make_resolver(args.cache)
    normalized = normalize(
        harvested.drafts,
        resolve,  # type: ignore[arg-type]
        split=CorpusSplit(args.split),
        population=Population.AUDIT_REVIEW,
    )
    print(f"\n=== normalize: {len(normalized.records)} record(s) of {normalized.drafts} ===")
    for loss, count in sorted(normalized.by_cause.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {loss.value}")

    print("\n=== records by class ===")
    for cls, count in sorted(
        normalized.records_by_class.items(), key=lambda kv: (-kv[1], kv[0].value)
    ):
        print(f"  {count:>4}  {cls.value:<26} {'ELIGIBLE' if count >= 10 else ''}")
    print("\n=== records by locator provenance ===")
    for provenance, count in sorted(
        normalized.records_by_provenance.items(), key=lambda kv: -kv[1]
    ):
        print(f"  {count:>4}  {provenance.value}")

    args.out.mkdir(parents=True, exist_ok=True)
    for record in normalized.records:
        path = args.out / f"{record.record_id}.json"
        path.write_text(
            json.dumps(record.model_dump(mode="json", exclude_none=True), indent=2) + "\n",
            encoding="utf-8",
        )
    print(f"\nwrote {len(normalized.records)} record(s) to {args.out}")
    print(f"split: {args.split}")
    print(f"\n{normalized.statement()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
