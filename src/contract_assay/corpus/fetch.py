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
verified. Absence of a check is not a passed check, and six of this corpus's
records carry no digest -- over four pins, each of which also has a
digest-bearing record, so `_pins` keeps the digest and nothing is taken on
trust today.

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
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from contract_assay.corpus.records import AddressPin, CommitPin, CorpusRecord, SourcePin

__all__ = [
    "FetchOutcome",
    "FetchReport",
    "Fetcher",
    "checkout_file",
    "fetch_records",
    "raw_url",
    "revisioned_name",
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
    collisions: tuple[str, ...] = ()
    """Paths the corpus pins at more than one revision, so each got its own name."""

    unwritable: tuple[str, ...] = ()
    """Paths that are another pin's file on this filesystem, so were not written."""

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
        # `is_usable` as well: `mismatched` also compared a digest, so counting
        # `digest_checked` alone put "2 matched their recorded digest" in the
        # same paragraph as "1 did NOT match their digest".
        checked = sum(1 for o in self.outcomes if o.digest_checked and o.is_usable)
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
        if self.collisions:
            named = ", ".join(self.collisions[:3])
            parts.append(
                f"{len(self.collisions)} path(s) are pinned at more than one revision "
                f"({named}). Each revision was written under its own name -- "
                "`Pool@<commit>.sol` -- and the plain path holds whichever revision the "
                "most records pin, for a resolver that has not learned the names. Any "
                "write that did land on another's bytes is in the mismatch line below, "
                "which is read off the tree rather than off the writes."
            )
        if self.unwritable:
            named = ", ".join(self.unwritable[:3])
            parts.append(
                f"{len(self.unwritable)} path(s) are another pin's file on this filesystem "
                f"({named}) and were not written -- two spellings that differ only in case, or "
                "in Unicode normal form, are one file here. Fetch those pins into their own "
                "--source-root."
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


def _still_true(root: Path, pin: SourcePin, outcome: FetchOutcome) -> FetchOutcome:
    """Re-read what is on disk now and correct an outcome that has stopped holding."""
    if not outcome.is_usable or not outcome.digest_checked or pin.sha256 is None:
        return outcome
    target = root / outcome.path
    if not target.is_file():
        return replace(
            outcome, state="unavailable", detail="present when fetched, absent afterwards"
        )
    present = _digest(target.read_bytes())
    if present == pin.sha256:
        return outcome
    return replace(
        outcome,
        state="mismatched",
        detail=f"on disk {present[:12]}, pinned {pin.sha256[:12]} -- these bytes were "
        "replaced after they were verified, which one path pinned at two revisions does",
    )


def revisioned_name(pin: SourcePin) -> str | None:
    """Where a pin's bytes go when its path is pinned at more than one revision.

    `Pool@14a962c52a8f.sol` beside `Pool.sol`, because `source_id` carries the
    commit and a filesystem path does not: the corpus pins
    `plaza-evm/src/Pool.sol` at two commits whose bytes differ, and a checkout
    keyed on `pin.path` alone wrote both to one file. The second write won, its
    digest was checked *before* the first was clobbered, and `fetch` reported
    "140 matched their recorded digest" over a tree the scorer then refused 8
    records of -- measured, the whole-span ceiling read 0.9770 on a checkout
    built by this command and 0.9931 on one that happened to hold both.

    The commit is truncated to 12 characters, which is the width `describe`
    prints and long enough that two pins of one path colliding again is not a
    thing to plan for. `None` for a pin with no revision to name.
    """
    if not isinstance(pin, CommitPin):
        return None
    path = PurePosixPath(pin.path)
    if not path.name:
        # `_Pin` refuses such a path, so this is the second line of defence and
        # not the first. It is here because the first one did not exist: `"."`
        # made `with_name` raise `ValueError` out of `_local_resolver`, so the
        # gate that exists to refuse a bad record died on it, and so did the
        # scorer. A resolver must have an answer for every pin it is handed.
        return None
    return str(path.with_name(f"{path.stem}@{pin.commit[:12]}{path.suffix}"))


def checkout_file(root: Path, pin: SourcePin) -> Path | None:
    """The file under `root` holding this pin's bytes, or `None` if there is none.

    One function because there were three joins, and two of them did not know
    about the revision names this module writes: `harness.units_from` reported
    the minority revision of a collided path as a **missing unit**, so no
    submission driven by `contract-assay run` could see the file that
    `contract-assay fetch` had just written for it, while `score` still counted
    its record in the denominator.

    The revision name is preferred **only when its bytes match the digest**. A
    review planted 138 revision-named files into a checkout, and a resolver that
    preferred the name unconditionally read every one of them: 425 of 435
    records came back `unchecked`. Matching by digest makes a planted file
    invisible instead.

    The plain path is returned even when it mismatches, because `verify`
    distinguishes `digest_mismatch` from `source_unresolvable`, and a resolver
    that returned nothing for a mismatch would collapse the two -- a cause
    recorded wrongly points investigation away from the fix.
    """
    if not pin.is_filesystem_path:
        return None

    def inside(candidate: Path) -> Path | None:
        """The file, if it really is under `root`.

        `is_file()` follows symlinks, so a link inside a checkout reads whatever
        it points at -- and a checkout is built from paths third-party reports
        supplied. `_Pin` refuses a traversing path; a link is the same escape
        one indirection along, and the validator's docstring claims to refuse
        both. The root is resolved too, so a checkout that is *itself* reached
        through a link still works.
        """
        try:
            if not candidate.is_file():
                return None
            resolved_root = root.resolve()
            if candidate.resolve().is_relative_to(resolved_root):
                return candidate
        except OSError:
            return None
        return None

    revision = revisioned_name(pin)
    if revision is not None and pin.sha256 is not None:
        candidate = inside(root / revision)
        try:
            if candidate is not None and _digest(candidate.read_bytes()) == pin.sha256:
                return candidate
        except OSError:
            pass
    plain = inside(root / pin.path)
    if plain is not None:
        return plain
    if revision is not None and pin.sha256 is not None and inside(root / revision) is not None:
        # The plain path is absent and the revision file is all there is. Its
        # bytes did not match above, so this returns a file the digest gate will
        # then name as `digest_mismatch` -- which is the point: a cause recorded
        # wrongly points investigation away from the fix.
        #
        # **Only for a pin that has a digest.** Without one there is nothing to
        # check and nothing to name, so a review's planted `Ghost@<commit>.sol`
        # was read as the unit: the six digest-less records in this corpus are
        # all negatives whose pins also carry a digest-bearing record, so it was
        # unreachable here and reachable on any third-party checkout whose plain
        # file is absent.
        return root / revision
    return None


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
    pin_of = {record.pin.source_id: record.pin for record in records}

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
        shadowed = unwritable.get(pin.path)
        if shadowed is not None:
            return FetchOutcome(
                source_id=source_id,
                path=pin.path,
                state="unavailable",
                detail=f"{pin.path!r} and {shadowed!r} are one file on a case-insensitive or "
                "Unicode-normalising filesystem, so only the first was written; fetch this "
                "pin into its own --source-root",
            )
        # One name per revision when the path is pinned at several, so that no
        # write clobbers another's bytes. Every pin of a colliding path is
        # renamed, not just the losers: leaving one of them at the plain path
        # would make which revision a reader gets depend on which pin happened
        # to be primary.
        relative = (collisions.get(pin.path) and revisioned_name(pin)) or pin.path
        target = root / relative
        expected = pin.sha256

        if target.is_file():
            present = _digest(target.read_bytes())
            if expected is None:
                return FetchOutcome(source_id, relative, "unverified", detail="no digest recorded")
            if present == expected:
                return FetchOutcome(source_id, relative, "present", digest_checked=True)
            return FetchOutcome(
                source_id,
                relative,
                "mismatched",
                digest_checked=True,
                detail=f"on disk {present[:12]}, pinned {expected[:12]}; not replaced",
            )

        try:
            body = get(raw_url(pin))
        except Exception as failure:
            return FetchOutcome(
                source_id,
                relative,
                "unavailable",
                detail=f"{type(failure).__name__}: {failure}",
            )

        if expected is not None and _digest(body) != expected:
            # Refused, not written. The record's locators index lines that have
            # moved, and a score over this file would be a real number about the
            # wrong source -- a failure with no symptom.
            return FetchOutcome(
                source_id,
                relative,
                "mismatched",
                digest_checked=True,
                detail=f"fetched {_digest(body)[:12]}, pinned {expected[:12]}",
            )

        target.parent.mkdir(parents=True, exist_ok=True)
        # The digest of the *name* in the suffix, not only the pid: two targets
        # that are one file on a case-insensitive filesystem shared one staging
        # name, and the second thread's `replace` raised `FileNotFoundError`
        # after the first had already moved it.
        stamp = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:8]
        staging = target.with_suffix(target.suffix + f".{os.getpid()}.{stamp}.partial")
        staging.write_bytes(body)
        staging.replace(target)
        return FetchOutcome(
            source_id,
            relative,
            "written" if expected is None else "verified",
            digest_checked=expected is not None,
            detail="" if expected is not None else "no digest recorded",
        )

    entries = _pins(records)

    # Keyed on the path as a *filesystem* would see it, not as the record spells
    # it. Two pins differing only in case, or in Unicode normal form, land on one
    # file on the default macOS and Windows filesystems -- and the detector,
    # keyed on the raw string, did not fire: one file existed and the loser was
    # reported as a digest mismatch, which is the wrong cause for a name
    # collision. `_Pin` refuses `a/./b` for being a second spelling of one file;
    # these are the same class two spellings along.
    def filesystem_key(path: str) -> str:
        return unicodedata.normalize("NFC", path).casefold()

    spellings: dict[str, set[str]] = {}
    revisions: dict[str, set[str | None]] = {}
    for _, pin in entries:
        if isinstance(pin, CommitPin):
            spellings.setdefault(filesystem_key(pin.path), set()).add(pin.path)
            revisions.setdefault(pin.path, set()).add(pin.sha256)

    # Two *kinds* of collision, and they have different answers. One path
    # string pinned at several revisions is written once per revision, because
    # both sets of bytes can exist under different names. Two path *strings*
    # that are one file on this filesystem cannot both exist under any naming --
    # a revision name preserves the case that made them collide -- so the second
    # is reported unavailable, with that as its cause. It used to be reported as
    # a digest mismatch, which sent the reader looking for moved source.
    collisions = {path: True for path, seen in revisions.items() if len(seen) > 1}
    unwritable: dict[str, str] = {}
    for paths in spellings.values():
        if len(paths) > 1:
            first, *rest = sorted(paths)
            for path in rest:
                unwritable[path] = first

    with ThreadPoolExecutor(max_workers=max(workers, 1)) as pool:
        report.outcomes = list(pool.map(one, entries))

    # And the plain path as well, holding whichever revision the most records
    # pin. A third party's `--source-root` resolver is documented as joining
    # `pin.path` to a root, and this package's own does; one that has not
    # learned the revision names still finds a file, and the pins it is the
    # wrong revision for fail the digest gate and are reported `unchecked`
    # rather than scored against bytes their locators do not describe.
    for path in collisions:
        weight: Counter[str] = Counter()
        for record in records:
            if isinstance(record.pin, CommitPin) and record.pin.path == path:
                weight[record.pin.commit] += 1
        for commit, _ in sorted(weight.items(), key=lambda kv: (-kv[1], kv[0]))[:1]:
            for _, pin in entries:
                if isinstance(pin, CommitPin) and pin.path == path and pin.commit == commit:
                    name = revisioned_name(pin)
                    written = root / name if name else None
                    if written is not None and written.is_file():
                        (root / path).write_bytes(written.read_bytes())

    # **Verified against the tree, not against the writes.** Each outcome above
    # is true of the moment it was produced, and the statement is read as a
    # claim about the checkout that is there afterwards. Those were the same
    # sentence until two pins of one path made them different ones.
    report.outcomes = [_still_true(root, pin_of[o.source_id], o) for o in report.outcomes]
    report.collisions = tuple(sorted(collisions))
    report.unwritable = tuple(sorted(unwritable))
    return report
