#!/usr/bin/env python3
"""Harvest published Code4rena reports into corpus records.

The network half, as `tools/harvest_sherlock.py` is for the other platform and
for the same reason: `RawReport` says fetching does not belong in the package,
and keeping it out is what lets the harvest stage run in the offline gate.

    python tools/harvest_code4rena.py --out /tmp/c4 --cache /tmp/c4cache

Code4rena's last `-findings` repository was published 2024-11-29, so a report
since then exists only as a web page. `corpus/sources.code4rena_report` converts
that page back into the markdown skeleton `Code4renaAdapter` reads, which keeps
the adapter deciding what a finding is -- including its **external count check**:
the report states `# Medium Risk Findings (6)`, a number nothing here produced,
so a converter that silently dropped a finding is caught by comparing the
declared total against what the enumerator found. This prints both.

`CONTESTS` holds the Solidity-dominant reports published after the public
corpus's newest pinned contest. It was built by listing every `code-423n4`
repository created since, probing `code4rena.com/reports/<slug>` for each, and
keeping those whose repository is at least 60% Solidity by GitHub's own language
count -- 56 reports exist, 17 are Solidity-dominant, and the rest are Move,
Rust, Go, Cairo or TypeScript, which this benchmark cannot parse.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from contract_assay.corpus.adapters.code4rena import (
    Code4renaAdapter,
    Code4renaEnumerator,
)
from contract_assay.corpus.fetch import raw_url, urllib_fetcher
from contract_assay.corpus.harvest import RawReport, harvest
from contract_assay.corpus.normalize import normalize
from contract_assay.corpus.records import (
    CorpusSplit,
    Population,
    SourcePin,
)
from contract_assay.corpus.sources import code4rena_report

REPORT = "https://code4rena.com/reports/{slug}"

# Every published report after the public corpus's newest pinned contest, minus
# the three the corpus already pins -- `2024-08-basin`, `2024-08-phi` and
# `2024-08-chakra` -- because a holdout record must not share a source with the
# split participants develop against.
#
# **Not filtered by language.** An earlier version kept only repositories that
# GitHub's language count put at 60% Solidity or more, which was a threshold
# picked rather than measured and cost real records: it excluded
# `2024-10-ramses-exchange` at 52%, a Solidity DEX, and DEXes are where slippage
# findings live. The filter was also redundant -- both adapters accept only
# Solidity permalinks, so a Move or Rust contest yields nothing and costs one
# fetch.
CONTESTS: tuple[str, ...] = (
    "2024-08-axelar-network",
    "2024-08-superposition",
    "2024-08-wildcat",
    "2024-09-fenix-finance",
    "2024-09-kakarot",
    "2024-09-panoptic",
    "2024-10-coded-estate",
    "2024-10-kleidi",
    "2024-10-loopfi",
    "2024-10-ramses-exchange",
    "2024-10-ronin",
    "2024-10-superposition",
    "2024-11-ethena-labs",
    "2024-11-mantra-dex",
    "2024-11-nibiru",
    "2024-12-flex-perpetuals",
    "2024-12-lambowin",
    "2024-12-secondswap",
    "2025-01-initia-move",
    "2025-01-iq-ai",
    "2025-01-liquid-ron",
    "2025-01-next-generation",
    "2025-01-pump-science",
    "2025-02-initia-cosmos",
    "2025-02-recall",
    "2025-02-thorwallet",
    "2025-03-nudgexyz",
    "2025-03-silo-finance",
    "2025-04-bitvault",
    "2025-04-kinetiq",
    "2025-04-virtuals-protocol",
    "2025-05-blackhole",
    "2025-05-upside",
    "2025-07-lido-finance",
    "2025-08-morpheus",
    "2025-08-solana-foundation",
    "2025-09-monad",
    "2025-09-succinct",
    "2025-10-covenant",
    "2025-10-hybra-finance",
    "2025-10-sequence",
    "2025-11-brix-money",
    "2025-11-ekubo",
    "2025-11-garden",
    "2025-11-megapot",
    "2025-11-merkl",
    "2025-11-sukukfi",
    "2025-11-swafe",
    "2026-01-olas",
    "2026-02-jupiter-lend",
    "2026-03-intuition",
    "2026-04-k2",
    "2026-04-monetrix",
)


def report_page(slug: str, cache: Path, fetch: object) -> str | None:
    """The report page, from the cache or from the site."""
    held = cache / f"{slug}.html"
    if held.is_file():
        return held.read_text(encoding="utf-8")
    try:
        body: bytes = fetch(REPORT.format(slug=slug))  # type: ignore[operator]
    except OSError as failed:
        print(f"  {slug}: {failed}", file=sys.stderr)
        return None
    text = body.decode("utf-8", errors="replace")
    cache.mkdir(parents=True, exist_ok=True)
    held.write_text(text, encoding="utf-8")
    return text


def make_resolver(cache: Path) -> object:
    """A `SourceResolver` over the package's fetcher, cached. See the other tool."""
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
            misses.add(key)
            return None
        text = body.decode("utf-8", errors="replace")
        held.write_text(text, encoding="utf-8")
        return text

    return resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(".c4-cache"))
    parser.add_argument(
        "--split",
        default=CorpusSplit.PRIVATE_HOLDOUT.value,
        choices=[split.value for split in CorpusSplit],
    )
    parser.add_argument("--contest", action="append", default=None)
    args = parser.parse_args(argv)

    wanted = (
        CONTESTS if args.contest is None else tuple(s for s in CONTESTS if s in set(args.contest))
    )
    if not wanted:
        print("no contest matched --contest", file=sys.stderr)
        return 2

    fetch = urllib_fetcher()
    enumerator = Code4renaEnumerator()
    reports: list[RawReport] = []
    print(f"{len(wanted)} report(s)", file=sys.stderr)
    print(f"\n{'contest':<26}{'declared':>9}{'found':>7}  note")
    print("-" * 62)
    for slug in wanted:
        page = report_page(slug, args.cache, fetch)
        if page is None:
            print(f"{slug:<26}{'-':>9}{'-':>7}  page not fetched")
            continue
        markdown = code4rena_report(page)
        if markdown is None:
            print(f"{slug:<26}{'-':>9}{'-':>7}  no report in the page")
            continue
        declared = enumerator.declared_total(markdown)
        found = len(enumerator.findings(markdown))
        # The platform's own count against this converter's. A mismatch is
        # either a conversion that dropped a finding or a report whose own count
        # is wrong, and it is printed rather than raised because both happen:
        # `2025-11-merkl` declares 4 medium findings and publishes 3, in the
        # heading, the table of contents and the body alike. Checked by hand
        # once the check fired, which is what the check is for.
        note = ""
        if declared is None:
            note = "no declared count in the report"
        elif declared != found:
            note = f"MISMATCH: converter found {found}, report declares {declared}"
        print(f"{slug:<26}{declared or '-'!s:>9}{found:>7}  {note}")
        reports.append(
            RawReport(
                platform="code4rena",
                report_url=REPORT.format(slug=slug),
                body=markdown,
            )
        )

    if not reports:
        print("nothing to harvest", file=sys.stderr)
        return 1

    harvested = harvest(Code4renaAdapter(), reports)
    print(f"\n=== harvest: {len(harvested.drafts)} draft(s) of {harvested.candidates} ===")
    for cause, count in sorted(harvested.by_cause.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>4}  {cause.value}")
    print(f"\n{harvested.yield_statement()}")

    normalized = normalize(
        harvested.drafts,
        make_resolver(args.cache),  # type: ignore[arg-type]
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
        print(f"  {count:>4}  {cls.value}")
    print("\n=== records by locator provenance ===")
    for provenance, count in sorted(
        normalized.records_by_provenance.items(), key=lambda kv: -kv[1]
    ):
        print(f"  {count:>4}  {provenance.value}")

    args.out.mkdir(parents=True, exist_ok=True)
    for record in normalized.records:
        (args.out / f"{record.record_id}.json").write_text(
            json.dumps(record.model_dump(mode="json", exclude_none=True), indent=2) + "\n",
            encoding="utf-8",
        )
    print(f"\nwrote {len(normalized.records)} record(s) to {args.out}")
    print(f"split: {args.split}")
    print(f"\n{normalized.statement()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
