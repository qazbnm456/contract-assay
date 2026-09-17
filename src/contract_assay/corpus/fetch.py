"""Obtaining the source a record pins, and refusing anything else.

A record pins its subject by repository, commit, path and digest. Without a way
to turn that into a file, `verify` and `score` both need a `--source-root` that
nobody outside this repository can build -- so the pins were a promise of
reproducibility that could not be collected. This is the collection.

The digest is the whole design
------------------------------
`CommitPin.sha256` is checked before anything is written, and a mismatch is
**refused rather than recorded**. A file whose digest differs from the pin is
not the file the record is about: its lines have moved, so every locator in
that record now points somewhere else, and a score computed over it would be a
real number about the wrong source. That failure has no symptom -- the run
completes, the quotes mostly still match, and the recall figure is simply
wrong.

A pin with no digest is written and **reported apart**, never counted as
verified. Absence of a check is not a passed check, and five of this corpus's
records have no digest to check.

What it does not fetch
----------------------
An `AddressPin` names a deployed contract, whose source of truth is a chain
explorer rather than a repository. It is reported as unavailable with that as
its reason instead of being guessed at from a repository that may not hold the
deployed bytecode's source.

Network access is injected
--------------------------
`fetch_records` takes a `Fetcher`, so the ordering, the digest check, the
idempotence and the reporting are all testable with no network. The default one
reads from the host's raw-content endpoint.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from contract_assay.corpus.records import AddressPin, CommitPin, CorpusRecord, SourcePin

__all__ = [
    "FetchOutcome",
    "FetchReport",
    "Fetcher",
    "fetch_records",
    "raw_url",
    "urllib_fetcher",
]

Fetcher = Callable[[str], bytes]
"""Takes a URL, returns its bytes, raises on anything else."""


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    """What happened to one pinned file."""

    source_id: str
    path: str
    state: str
    """What happened to the bytes: written, verified, present, unverified,
    mismatched, unavailable."""

    digest_checked: bool = False
    """Whether a recorded digest was compared against these bytes.

    Kept apart from `state`, because the two answer different questions and one
    field answering both is how the answer to the second gets lost: a freshly
    written file with no digest to check is `written`, which is not
    `unverified`, so a report reading trust off the state name reported nothing
    about it -- silently dropping the exact caveat this module says it keeps.
    """

    detail: str = ""

    @property
    def is_usable(self) -> bool:
        """Whether a scorer may read this file.

        `mismatched` is not usable and that is the point of the class: the bytes
        are there, they parse, and they are not the ones the record is about.
        """
        return self.state in {"written", "verified", "present", "unverified"}


@dataclass
class FetchReport:
    """Every pin's outcome, and the sentence that has to accompany a checkout."""

    outcomes: list[FetchOutcome] = field(default_factory=list)

    def by_state(self, state: str) -> list[FetchOutcome]:
        return [o for o in self.outcomes if o.state == state]

    @property
    def usable(self) -> int:
        return sum(1 for o in self.outcomes if o.is_usable)

    def statement(self) -> str:
        """What this checkout is, including what is missing from it.

        Printed rather than a count, because a checkout with nine files missing
        scores nine units' worth of recall as zero and looks exactly like a
        submission that missed them.
        """
        if not self.outcomes:
            return "No pins to fetch."
        parts = [f"{self.usable} of {len(self.outcomes)} pinned file(s) available."]
        checked = sum(1 for o in self.outcomes if o.digest_checked)
        if checked:
            parts.append(f"{checked} matched their recorded digest.")
        # Read off `digest_checked`, never off the state name: a file just
        # written with no digest to check is as unchecked as one already on disk.
        trusted = sum(1 for o in self.outcomes if o.is_usable and not o.digest_checked)
        if trusted:
            parts.append(
                f"{trusted} had no digest recorded and were taken on trust -- "
                "absence of a check is not a passed check."
            )
        mismatched = self.by_state("mismatched")
        if mismatched:
            named = ", ".join(sorted(o.path for o in mismatched)[:5])
            parts.append(
                f"{len(mismatched)} did NOT match their digest and were not written "
                f"({named}). Their records' locators point into source that has moved, so "
                "scoring against them would be a real number about the wrong file."
            )
        unavailable = self.by_state("unavailable")
        if unavailable:
            parts.append(
                f"{len(unavailable)} could not be fetched. A unit missing from a checkout "
                "scores as a submission that missed it, so a score over this checkout is "
                "over the subset that is here."
            )
        return " ".join(parts)


def raw_url(pin: CommitPin) -> str:
    """The host's raw-content URL for a pinned file.

    GitHub only, and refused by name otherwise. A guessed URL scheme for an
    unknown host either 404s -- which reads as a missing unit -- or returns an
    HTML error page, which would be written to disk as Solidity.
    """
    parsed = urlparse(pin.repo_url)
    if parsed.netloc not in {"github.com", "www.github.com"}:
        raise ValueError(
            f"{pin.repo_url!r} is not a host this knows how to read raw files from; "
            "add it here rather than guessing a URL scheme"
        )
    owner_repo = parsed.path.strip("/").removesuffix(".git")
    return f"https://raw.githubusercontent.com/{owner_repo}/{pin.commit}/{pin.path}"


def urllib_fetcher(timeout: float = 30.0) -> Fetcher:
    """The default fetcher. Separated so a caller can supply a cache or a mirror.

    The SSL context is built from `certifi`'s bundle when it is installed, and
    that is not incidental. Python's `urllib` does not consult the system trust
    store on macOS, so a default context fails to verify **every** host -- and
    the failure arrives as one `URLError` per file, which reads as "the host is
    unreachable" rather than "this machine has no CA bundle wired in". The first
    reading sends someone to check their network; the second is the fix. A cause
    recorded wrongly points investigation away from it.
    """
    import ssl
    import urllib.request

    context: ssl.SSLContext | None = None
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover - certifi ships with the usual stack
        context = None

    def fetch(url: str) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "contract-assay"})
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body: bytes = response.read()
        return body

    return fetch


def _pins(records: Iterable[CorpusRecord]) -> list[tuple[str, SourcePin]]:
    """One entry per distinct pinned file, in a stable order.

    Distinct, because a file holding six records is one download. Stable, so two
    runs report in the same order.
    """
    seen: dict[str, SourcePin] = {}
    for record in records:
        seen.setdefault(record.pin.source_id, record.pin)
    return sorted(seen.items())


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def fetch_records(
    records: Sequence[CorpusRecord],
    root: Path,
    *,
    fetch: Fetcher | None = None,
    workers: int = 8,
) -> FetchReport:
    """Build a source checkout under `root`, verifying every digest.

    Idempotent: a file already present with a matching digest is left alone, so
    an interrupted fetch resumes and a re-run costs nothing. A file present with
    the *wrong* digest is reported as mismatched and not replaced -- it may be a
    deliberate local edit, and silently overwriting somebody's edit is worse
    than telling them about it.
    """
    get = fetch or urllib_fetcher()
    report = FetchReport()

    def one(entry: tuple[str, SourcePin]) -> FetchOutcome:
        source_id, pin = entry
        if isinstance(pin, AddressPin):
            return FetchOutcome(
                source_id=source_id,
                path=pin.path,
                state="unavailable",
                detail="a deployed address's source of truth is a chain explorer, not a repository",
            )
        assert isinstance(pin, CommitPin)
        target = root / pin.path
        expected = pin.sha256

        if target.is_file():
            present = _digest(target.read_bytes())
            if expected is None:
                return FetchOutcome(source_id, pin.path, "unverified", detail="no digest recorded")
            if present == expected:
                return FetchOutcome(source_id, pin.path, "present", digest_checked=True)
            return FetchOutcome(
                source_id,
                pin.path,
                "mismatched",
                digest_checked=True,
                detail=f"on disk {present[:12]}, pinned {expected[:12]}; not replaced",
            )

        try:
            body = get(raw_url(pin))
        except Exception as failure:
            return FetchOutcome(
                source_id,
                pin.path,
                "unavailable",
                detail=f"{type(failure).__name__}: {failure}",
            )

        if expected is not None and _digest(body) != expected:
            # Refused, not written. The record's locators index lines that have
            # moved, and a score over this file would be a real number about the
            # wrong source -- a failure with no symptom.
            return FetchOutcome(
                source_id,
                pin.path,
                "mismatched",
                digest_checked=True,
                detail=f"fetched {_digest(body)[:12]}, pinned {expected[:12]}",
            )

        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_suffix(target.suffix + f".{os.getpid()}.partial")
        staging.write_bytes(body)
        staging.replace(target)
        return FetchOutcome(
            source_id,
            pin.path,
            "written" if expected is None else "verified",
            digest_checked=expected is not None,
            detail="" if expected is not None else "no digest recorded",
        )

    entries = _pins(records)
    with ThreadPoolExecutor(max_workers=max(workers, 1)) as pool:
        report.outcomes = list(pool.map(one, entries))
    return report
