#!/usr/bin/env python3
"""Measure how many chain incidents can become corpus records, and record it.

    python tools/measure_incident_yield.py --archive ~/src/incident-archive \\
        --out docs/measurements/incident-yield.json

The network half, as the two harvest tools are and for the same reason:
`corpus/incidents.py` is the pure reader and runs in the offline gate, and the
verification-repository lookups are here.

## Why this exists before the resolver does

`fetch` refuses an `AddressPin` outright, so no incident record can be built
yet. The question that decides whether building the resolver is worth it is the
**yield**: of the incidents in an archive, for how many can a record actually be
made. Four things have to hold at once, and this measures the conjunction rather
than the parts:

1. the artefact states a chain this reader can name and a fork point it can
   resolve;
2. it annotates exactly one exploited contract;
3. that contract has verified source in a verification repository;
4. there is a write-up, which is the only route to a defect class.

Reported as an intersection because the parts do not compose. `docs/design.md`
§6.1 records a 82% source-availability figure being read as a yield, which it is
not: it was measured over *any* address a proof-of-concept touches, while a
record needs the **victim's**, and identifiability was measured separately over
a different denominator. Two marginals do not give a joint.

## Why the archive is a local checkout and its commit is recorded

The previous attempt sampled 34 incidents and **the sample was never written
down** -- no list, no seed, no selection rule -- so its figures cannot be
reproduced or corrected, only re-taken. This measurement instead runs over the
whole population and pins the commit it ran against, because the archive grows:
it held 849 incidents when that measurement was taken and 863 at the commit this
one names. A count without a commit is not a measurement of anything.

`--commit` is checked against the checkout and the run is refused on a
mismatch, rather than recording whatever happened to be checked out.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from contract_assay.corpus.fetch import urllib_fetcher
from contract_assay.corpus.incidents import IncidentPoC, parse_poc

SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}"
POPULATION = "src/test/*/*_exp*.sol"
ARCHIVE = "https://github.com/SunWeb3Sec/DeFiHackLabs"
"""The archive the recorded measurement ran over, named rather than described.

`docs/design.md` calls it "a maintained third-party archive", which is enough
for a claim about a route and not enough for a measurement: a commit SHA of an
unnamed repository cannot be checked out, so recording one is the same defect as
recording a figure whose sample was never written down. The checkout's own
`origin` is compared against this and a mismatch is refused, because otherwise
`--archive` can point anywhere and the pinned commit means nothing.
"""


EXACT = "exact_match"
"""The only match strength at which a line-span locator is sound.

The repository defines two. An **exact match** means the deployed bytecode is
byte-for-byte the recompilation of the given sources, metadata hash included,
and the metadata carries a keccak256 of each source file -- so the source is
guaranteed to be the source that was compiled. Adding a comment breaks it.

A plain **match** means the bytecode agrees *except the metadata hash*. The
repository's own words for what that permits: "there are differences in source
code comments, variable names, or other metadata fields such as source paths."

That difference decides what a record can claim. A locator here is a line span,
and a source that differs in comments and variable names is a source whose
lines have moved. So a plain match supports a **file-level** claim and nothing
narrower -- and `assay_arena`'s round config already refuses `strength_floor:
"file"` on a ranked round, which means a plain-match incident cannot feed one.

Measured rather than assumed: this is the majority outcome, not the exception,
which is why the two are counted apart instead of summed into "verified".
"""


@dataclass(frozen=True, slots=True)
class Verification:
    """What the verification repository said about one address."""

    match: str | None
    answered: bool

    @property
    def verified(self) -> bool:
        return self.match is not None

    @property
    def exact(self) -> bool:
        return self.match == EXACT


def _git(archive: Path, *arguments: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(archive), *arguments],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def head_commit(archive: Path) -> str | None:
    return _git(archive, "rev-parse", "HEAD")


def origin_url(archive: Path) -> str | None:
    """Where the checkout came from, normalised enough to compare.

    Trailing `.git` and a trailing slash are stripped so an https clone and a
    `.git` clone of one repository are not reported as two archives.
    """
    url = _git(archive, "remote", "get-url", "origin")
    return url.removesuffix("/").removesuffix(".git") if url else None


def read_population(archive: Path) -> list[IncidentPoC]:
    """Every proof-of-concept in the checkout, parsed. No network."""
    root = archive / "src" / "test"
    return [
        parse_poc(
            str(path.relative_to(archive)),
            path.read_text(encoding="utf-8", errors="replace"),
        )
        for path in sorted(root.glob("*/*_exp*.sol"))
    ]


def make_lookup(cache: Path, pause: float) -> Any:
    """A cached verification lookup over the package's own fetcher.

    **Distinguishes an answer from a failure.** The repository reports "no
    verified source here" as HTTP 404 with a body, which is a fact about the
    address; a timeout or a DNS failure is a fact about this run. Counting the
    second as the first under-reports availability and the shortfall looks like
    a property of the chain, so `Verification.answered` carries the difference
    and unanswered lookups are excluded from the denominator rather than
    counted as unverified.
    """
    cache.mkdir(parents=True, exist_ok=True)
    fetch = urllib_fetcher(timeout=20.0)

    def lookup(chain: int, address: str) -> Verification:
        held = cache / f"{chain}-{address}.json"
        if held.is_file():
            payload = json.loads(held.read_text(encoding="utf-8"))
            return Verification(match=payload.get("match"), answered=True)
        url = SOURCIFY.format(chain=chain, address=address)
        try:
            body = fetch(url)
        except OSError as failed:
            code = getattr(failed, "code", None)
            if code != 404:
                return Verification(match=None, answered=False)
            reader = getattr(failed, "read", None)
            body = reader() if reader is not None else b"{}"
        time.sleep(pause)
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return Verification(match=None, answered=False)
        held.write_text(json.dumps(payload), encoding="utf-8")
        return Verification(match=payload.get("match"), answered=True)

    return lookup


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="A checkout of the archive.")
    parser.add_argument("--commit", default=None, help="Refuse to run unless HEAD is this.")
    parser.add_argument(
        "--archive-url",
        default=ARCHIVE,
        help="The archive the checkout must be of. Pass a fork's URL to measure one.",
    )
    parser.add_argument("--out", type=Path, default=None, help="Where the measurement is written.")
    parser.add_argument("--cache", type=Path, default=Path(".incident-cache"))
    parser.add_argument("--pause", type=float, default=0.12, help="Seconds between lookups.")
    parser.add_argument("--limit", type=int, default=None, help="Cap the lookups, for a dry run.")
    args = parser.parse_args(argv)

    if not (args.archive / "src" / "test").is_dir():
        print(f"no src/test under {args.archive}", file=sys.stderr)
        return 2
    commit = head_commit(args.archive)
    if args.commit and commit != args.commit:
        print(f"checkout is at {commit}, --commit says {args.commit}", file=sys.stderr)
        return 2
    if commit is None:
        print("the archive checkout is not a git repository, so nothing pins it", file=sys.stderr)
        return 2
    origin = origin_url(args.archive)
    if origin != args.archive_url.removesuffix("/").removesuffix(".git"):
        print(
            f"the checkout's origin is {origin!r}, not {args.archive_url!r}. A commit of an "
            "unnamed repository pins nothing; pass --archive-url to measure a different one.",
            file=sys.stderr,
        )
        return 2

    pocs = read_population(args.archive)
    if not pocs:
        print(f"no files matched {POPULATION}", file=sys.stderr)
        return 1
    incidents = {poc.incident for poc in pocs}
    total = len(pocs)
    print(f"archive {origin} at {commit}")
    print(f"{total} proof-of-concept file(s), {len(incidents)} distinct incident(s)\n")

    # Leg 1 and 2, both offline.
    forms = Counter(poc.fork.form.value if poc.fork else "no_fork_call" for poc in pocs)
    pinnable = [poc for poc in pocs if poc.fork and poc.fork.pinnable]
    single = [poc for poc in pocs if poc.victim]
    candidates = [poc for poc in pinnable if poc.victim]
    print("=== leg 1: a chain and a fork point, from the artefact ===")
    for form, count in forms.most_common():
        print(f"  {count:>4}  {count / total:>5.0%}  {form}")
    print(f"\n  resolved: {len(pinnable)}/{total} ({len(pinnable) / total:.0%})")
    print("\n=== leg 2: exactly one annotated exploited contract ===")
    victims = Counter(len(poc.victims) for poc in pocs)
    for count, files in sorted(victims.items()):
        print(f"  {files:>4}  {files / total:>5.0%}  {count} annotated address(es)")
    print(f"\n  exactly one: {len(single)}/{total} ({len(single) / total:.0%})")
    print(
        f"\n=== legs 1 and 2 together: {len(candidates)}/{total} "
        f"({len(candidates) / total:.0%}) ==="
    )

    # Leg 3, the only one that reaches the network.
    asked = candidates if args.limit is None else candidates[: args.limit]
    print(f"\n=== leg 3: verified source for that contract ({len(asked)} lookup(s)) ===")
    statuses: Counter[str] = Counter()
    verified: list[IncidentPoC] = []
    exact: list[IncidentPoC] = []
    unanswered = 0
    # Built once. Inside the loop it would rebuild the SSL context per lookup,
    # which is the cost the fetcher's docstring exists to explain.
    lookup = make_lookup(args.cache, args.pause)
    for index, poc in enumerate(asked, start=1):
        assert poc.fork is not None and poc.victim is not None
        answer = lookup(poc.fork.chain_id, poc.victim)
        if not answer.answered:
            unanswered += 1
            statuses["lookup did not answer"] += 1
        else:
            statuses[answer.match or "no verified source"] += 1
            if answer.verified:
                verified.append(poc)
            if answer.exact:
                exact.append(poc)
        if index % 50 == 0:
            print(f"  {index}/{len(asked)}", file=sys.stderr)
    for status, count in statuses.most_common():
        print(f"  {count:>4}  {status}")
    answered = len(asked) - unanswered
    if answered:
        print(
            f"\n  any match : {len(verified)}/{answered} of answered "
            f"({len(verified) / answered:.0%})  -- supports a file-level claim"
        )
        print(
            f"  exact match: {len(exact)}/{answered} of answered "
            f"({len(exact) / answered:.0%})  -- the only strength a line span survives"
        )

    # Leg 4, offline, and a bound rather than a result: a write-up is where a
    # class could come from, not a class.
    with_write_up = [poc for poc in verified if poc.analysis]
    exact_with_write_up = [poc for poc in exact if poc.analysis]
    print("\n=== leg 4: a write-up exists, which bounds class mapping ===")
    print(
        f"  {len(with_write_up)}/{len(verified)} of any-match, "
        f"{len(exact_with_write_up)}/{len(exact)} of exact-match, link a write-up"
    )

    print("\n=== the intersection, which is the yield-relevant figure ===")
    print(f"  file-level record possible : {len(with_write_up)} of the {len(asked)} examined")
    print(f"  line-span record possible  : {len(exact_with_write_up)} of the {len(asked)} examined")
    if args.limit is None:
        print(
            f"  over the whole population of {total}: "
            f"{len(with_write_up) / total:.0%} file-level, "
            f"{len(exact_with_write_up) / total:.0%} line-span"
        )
    else:
        # A limited run measures a prefix of the candidate list, which is
        # ordered by date. Reporting it as a population share would project
        # from a prefix rather than from a sample, so it is not projected.
        print(
            f"  examined {len(asked)} of {len(candidates)} candidates; a prefix, "
            "not a sample, so no population share is stated"
        )

    measurement: dict[str, Any] = {
        "archive": origin,
        "archive_commit": commit,
        "population_glob": POPULATION,
        "files": total,
        "incidents": len(incidents),
        "fork_point_forms": dict(forms),
        "chain_and_fork_point_resolved": len(pinnable),
        "victims_annotated_per_file": {str(k): v for k, v in sorted(victims.items())},
        "exactly_one_victim": len(single),
        "legs_1_and_2": len(candidates),
        "lookups_made": len(asked),
        "lookup_statuses": dict(statuses),
        "verified_victim_source_any_match": len(verified),
        "verified_victim_source_exact_match": len(exact),
        "any_match_and_write_up": len(with_write_up),
        "exact_match_and_write_up": len(exact_with_write_up),
    }
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(measurement, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
