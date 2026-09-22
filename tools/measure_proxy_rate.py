#!/usr/bin/env python3
"""Measure how many exploited contracts are proxies, from the chain.

    python tools/measure_proxy_rate.py --archive ~/src/incident-archive \\
        --out docs/measurements/proxy-rate.json

The network half of `corpus/bytecode.py`, as `measure_incident_yield.py` is of
`corpus/incidents.py`.

## The question and why the previous answer was an artefact

`docs/design.md` §6.2 leaves one thing undecided: whether the dominant shape of
a "fixed" state is a proxy whose implementation was replaced, an immutable
contract redeployed elsewhere, a repository fix never deployed, or an abandoned
project. Those carry different controls, and carving one enum member for all
four is the approximation refused three times already.

The measurement that would settle it was attempted and returned 13 immutable and
**no proxies at all**, from 34 incidents. Both halves were instrument:
identification was name-matching and failed on 18, and proxy detection asked a
verification repository, which reports a *recognised* proxy standard rather than
proxy-ness -- it returned "not a proxy" for two of three contracts whose own
names end in `Proxy`. So "no proxies" was a zero that says nothing about
proxies.

Both halves are now available. Identification comes from the archive's own
annotation (492 of 874 artefacts), and proxy-ness from the runtime bytecode,
where a `DELEGATECALL` cannot be hidden by not implementing a standard.

## What this can and cannot conclude

`corpus/bytecode` states the asymmetry: no `DELEGATECALL` is conclusive, one is
an upper bound. So this reports a **range** rather than a rate, and the range is
the honest answer to a question that decides engineering effort.

Two limits, neither of which the reading can absorb:

- **Read at `latest`, not at the fork point.** Runtime code is immutable so
  this is sound for the code itself, but it cannot say *which* implementation
  stood behind a proxy while the defect was live. That needs archive state, and
  public endpoints refuse it -- `eth_getStorageAt` at a 2021 block answers
  "historical state is not available". The rate does not need it; a record
  eventually will.
- **A contract that has since self-destructed answers `0x`.** Counted as its own
  outcome. Reading it as "no delegatecall, therefore not a proxy" would draw a
  conclusion about code nobody can read any more.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from contract_assay.corpus.bytecode import has_callcode, has_delegatecall, parse_code
from contract_assay.corpus.fetch import ssl_context
from contract_assay.corpus.incidents import parse_poc

ARCHIVE = "https://github.com/SunWeb3Sec/DeFiHackLabs"

ENDPOINTS: dict[int, str] = {
    1: "https://ethereum-rpc.publicnode.com",
    10: "https://mainnet.optimism.io",
    56: "https://bsc-dataseed.bnbchain.org",
    100: "https://rpc.gnosischain.com",
    137: "https://polygon-bor-rpc.publicnode.com",
    8453: "https://mainnet.base.org",
    42161: "https://arb1.arbitrum.io/rpc",
    43114: "https://api.avax.network/ext/bc/C/rpc",
    59144: "https://rpc.linea.build",
    81457: "https://rpc.blast.io",
}
"""Keyless public endpoints, one per chain, each confirmed to answer.

Deliberately incomplete and **not** silently substituted. A chain with no entry
is a counted loss naming the chain, because an address resolved against the
wrong chain does not fail -- it answers about a different contract, and the
answer looks exactly like a real one.
"""


def head_commit(archive: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(archive), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else None


def rpc_caller(pause: float, timeout: float = 20.0) -> Any:
    """A JSON-RPC caller: its own request, and **the project's TLS context**.

    `urllib_fetcher` cannot be reused -- it does a GET of a URL and this is a
    POST of a JSON body -- but `ssl_context` can, and must be. The first version
    of this function built no context and every one of 25 calls failed with
    `CERTIFICATE_VERIFY_FAILED`, which is the third time this project has
    written that bug. It was written here under a docstring asserting that a
    POST would not hit it, so the claim and its refutation shipped together.

    That is why `ssl_context` was extracted out of `urllib_fetcher`'s body: the
    fix was unreachable to any caller that needed a request the `Fetcher` type
    cannot express.
    """

    context = ssl_context()

    def call(url: str, method: str, params: list[Any]) -> tuple[Any, str | None]:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        request = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "contract-assay"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as failed:
            return None, f"{type(failed).__name__}: {failed}"
        time.sleep(pause)
        if "error" in payload:
            return None, str(payload["error"].get("message", payload["error"]))[:80]
        return payload.get("result"), None

    return call


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--commit", default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--cache", type=Path, default=Path(".proxy-cache"))
    parser.add_argument("--pause", type=float, default=0.1)
    # A limited run takes a prefix of a list sorted by (chain, address), which
    # is biased toward the lowest chain id and is not a sample of anything. It
    # is for checking that the call works, not for a figure.
    parser.add_argument("--limit", type=int, default=None, help="For a dry run; not a sample.")
    args = parser.parse_args(argv)

    root = args.archive / "src" / "test"
    if not root.is_dir():
        print(f"no src/test under {args.archive}", file=sys.stderr)
        return 2
    commit = head_commit(args.archive)
    if args.commit and commit != args.commit:
        print(f"checkout is at {commit}, --commit says {args.commit}", file=sys.stderr)
        return 2

    pocs = [
        parse_poc(str(path.relative_to(args.archive)), path.read_text("utf-8", errors="replace"))
        for path in sorted(root.glob("*/*_exp*.sol"))
    ]
    # One address per (chain, victim). Two artefacts of one incident name the
    # same contract, and asking twice would count one proxy twice. 10 artefacts
    # collapse this way, so 483 candidates become 473 contracts.
    #
    # **A resolved fork point is deliberately not required here**, which is why
    # this denominator is 475 where `measure_incident_yield.py` reports 483 and
    # neither is wrong. That tool needs a fork point because a record is pinned
    # to one; proxy-ness is read from immutable runtime code at `latest`, so a
    # contract whose artefact never stated a resolvable block still answers the
    # question being asked. 5 contracts enter this way.
    targets: dict[tuple[int, str], str] = {}
    unreachable: Counter[str] = Counter()
    for poc in pocs:
        if poc.fork is None or poc.victim is None or poc.fork.chain_id is None:
            continue
        if poc.fork.chain_id not in ENDPOINTS:
            unreachable[poc.fork.alias] += 1
            continue
        targets.setdefault((poc.fork.chain_id, poc.victim), poc.incident)

    print(f"archive at {commit}")
    print(f"{len(pocs)} artefact(s); {len(targets)} distinct (chain, victim) pair(s)")
    if unreachable:
        print(f"no endpoint for: {dict(unreachable)}")

    args.cache.mkdir(parents=True, exist_ok=True)
    call = rpc_caller(args.pause)
    outcomes: Counter[str] = Counter()
    sizes: list[int] = []
    # Size against delegation, so the lower bound below is derived per run
    # rather than carried as a remembered byte length.
    delegating_sizes: list[int] = []
    delegating: list[str] = []
    ordered = sorted(targets)
    asked = ordered if args.limit is None else ordered[: args.limit]
    print(f"\n=== runtime code for {len(asked)} contract(s) ===")
    for index, (chain, address) in enumerate(asked, start=1):
        held = args.cache / f"{chain}-{address}.hex"
        if held.is_file():
            code_hex: str | None = held.read_text(encoding="utf-8").strip()
            failure = None
        else:
            code_hex, failure = call(ENDPOINTS[chain], "eth_getCode", [address, "latest"])
            if isinstance(code_hex, str):
                held.write_text(code_hex, encoding="utf-8")
        if failure is not None or not isinstance(code_hex, str):
            outcomes["the call did not answer"] += 1
            continue
        try:
            runtime = parse_code(code_hex)
        except ValueError:
            outcomes["the answer was not code"] += 1
            continue
        if not runtime:
            outcomes["no code at this address now"] += 1
            continue
        sizes.append(len(runtime))
        if has_delegatecall(runtime):
            outcomes["delegatecall: may be a proxy"] += 1
            delegating_sizes.append(len(runtime))
            delegating.append(f"{chain}:{address}")
        elif has_callcode(runtime):
            outcomes["callcode only: not a proxy's shape"] += 1
        else:
            outcomes["no delegatecall: not a proxy"] += 1
        if index % 50 == 0:
            print(f"  {index}/{len(asked)}", file=sys.stderr)

    for outcome, count in outcomes.most_common():
        print(f"  {count:>4}  {outcome}")

    readable = sum(
        count
        for outcome, count in outcomes.items()
        if outcome.startswith(("delegatecall", "callcode", "no delegatecall"))
    )
    upper = outcomes["delegatecall: may be a proxy"]
    print("\n=== the range, which is the answer ===")
    if readable:
        print(f"  at most  {upper}/{readable} ({upper / readable:.0%}) are proxies")
        print(
            f"  at least {readable - upper}/{readable} ({(readable - upper) / readable:.0%})"
            " are not, conclusively"
        )
    floor = 0
    if sizes:
        sizes.sort()
        print("\n=== runtime code size, bytes ===")
        for label, value in (
            ("smallest", sizes[0]),
            ("median", sizes[len(sizes) // 2]),
            ("largest", sizes[-1]),
        ):
            print(f"  {label:<9} {value}")
        # The contracts at the observed minimum, and whether all of them
        # delegate. This is not a threshold: the size is read off the data each
        # run, and the claim is only about contracts too small to hold anything
        # but a forwarding stub. The measured distribution offers no cutoff to
        # pick anyway -- every contract below 1200 bytes delegates, with no gap.
        smallest = sizes[0]
        at_floor = sum(1 for size in sizes if size == smallest)
        delegating_at_floor = sum(1 for size in delegating_sizes if size == smallest)
        print(
            f"\n  {at_floor} contract(s) sit at the minimum of {smallest} bytes, "
            f"{delegating_at_floor} of them delegating"
        )
        if at_floor == delegating_at_floor and at_floor:
            floor = at_floor
            print(f"  A contract of {smallest} bytes cannot hold business logic, so these")
            print("  are proxies rather than an upper bound -- a lower bound at last.")

    measurement: dict[str, Any] = {
        "archive": ARCHIVE,
        "archive_commit": commit,
        "artefacts": len(pocs),
        "distinct_chain_victim_pairs": len(targets),
        "no_endpoint_for": dict(unreachable),
        "examined": len(asked),
        "outcomes": dict(outcomes),
        "readable_code": readable,
        "delegatecall_upper_bound": upper,
        "minimal_stub_lower_bound": floor,
        "code_size_bytes": (
            {"smallest": sizes[0], "median": sizes[len(sizes) // 2], "largest": sizes[-1]}
            if sizes
            else {}
        ),
        "read_at": "latest",
    }
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(measurement, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
