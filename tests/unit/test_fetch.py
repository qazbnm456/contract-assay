"""Building a checkout, and refusing the one failure that has no symptom.

The fetcher is injected, so everything here runs with no network. What is being
tested is not HTTP -- it is the digest rule, because a file whose digest does not
match its pin is the one bad outcome that completes successfully: the run
finishes, most quotes still match, and the recall figure is a real number about
the wrong source.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import pytest

from contract_assay.corpus.fetch import checkout_file, fetch_records, raw_url, urllib_fetcher
from contract_assay.corpus.records import (
    AddressPin,
    CommitPin,
    CorpusRecord,
    CorpusSplit,
    Population,
    Provenance,
)
from contract_assay.models import Locator, VulnerabilityClass

pytestmark = pytest.mark.offline

BODY = b"contract Vault { address owner; }\n"
DIGEST = hashlib.sha256(BODY).hexdigest()
PATH = "src/Vault.sol"


def a_record(**over: Any) -> CorpusRecord:
    pin = over.pop(
        "pin",
        CommitPin(
            repo_url="https://github.com/example/vault",
            commit="a" * 40,
            path=PATH,
            sha256=DIGEST,
        ),
    )
    fields: dict[str, Any] = {
        "record_id": over.pop("record_id", "vault-access-control-1"),
        "population": Population.AUDIT_REVIEW,
        "split": CorpusSplit.PUBLIC,
        "pin": pin,
        "locator": Locator(
            file=PATH, contract="Vault", function="setOwner", start_line=1, end_line=1
        ),
        "locator_provenance": "stated",
        "classes": [VulnerabilityClass.ACCESS_CONTROL],
        "provenance": Provenance(platform="example", report_url="https://example.invalid/1"),
    }
    return CorpusRecord.model_validate({**fields, **over})


def a_fetcher(body: bytes = BODY):  # type: ignore[no-untyped-def]
    calls: list[str] = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        return body

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


class TestTheDigestDecides:
    def test_a_matching_file_is_written_and_called_verified(self, tmp_path: Path) -> None:
        report = fetch_records([a_record()], tmp_path, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["verified"]
        assert (tmp_path / PATH).read_bytes() == BODY

    def test_a_mismatch_is_refused_rather_than_written(self, tmp_path: Path) -> None:
        # The failure with no symptom: the record's locators index lines that
        # have moved, so a score over this file is a real number about the wrong
        # source.
        report = fetch_records([a_record()], tmp_path, fetch=a_fetcher(b"something else\n"))
        assert [o.state for o in report.outcomes] == ["mismatched"]
        assert not (tmp_path / PATH).exists()
        assert not report.outcomes[0].is_usable
        assert "wrong file" in report.statement()

    def test_no_recorded_digest_is_not_a_passed_check(self, tmp_path: Path) -> None:
        pin = CommitPin(repo_url="https://github.com/example/vault", commit="b" * 40, path=PATH)
        report = fetch_records([a_record(pin=pin)], tmp_path, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["written"]
        # Usable, and counted apart. Absence of a check is not a passed check --
        # and read off `digest_checked` rather than the state name, because
        # `written` is not `unverified` and a statement guessing from the state
        # dropped this caveat entirely.
        assert report.outcomes[0].is_usable
        assert report.outcomes[0].digest_checked is False
        assert "taken on trust" in report.statement()


class TestItIsIdempotent:
    def test_a_file_already_present_and_matching_is_not_refetched(self, tmp_path: Path) -> None:
        (tmp_path / PATH).parent.mkdir(parents=True)
        (tmp_path / PATH).write_bytes(BODY)
        fetcher = a_fetcher()
        report = fetch_records([a_record()], tmp_path, fetch=fetcher)
        assert [o.state for o in report.outcomes] == ["present"]
        assert fetcher.calls == []  # type: ignore[attr-defined]

    def test_a_local_edit_is_reported_rather_than_overwritten(self, tmp_path: Path) -> None:
        # It may be a deliberate edit, and silently replacing somebody's work is
        # worse than telling them about it.
        (tmp_path / PATH).parent.mkdir(parents=True)
        (tmp_path / PATH).write_bytes(b"// edited by hand\n")
        report = fetch_records([a_record()], tmp_path, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["mismatched"]
        assert (tmp_path / PATH).read_bytes() == b"// edited by hand\n"

    def test_one_file_holding_several_records_is_one_download(self, tmp_path: Path) -> None:
        fetcher = a_fetcher()
        records = [a_record(record_id=f"vault-access-control-{n}") for n in (1, 2, 3)]
        report = fetch_records(records, tmp_path, fetch=fetcher)
        assert len(report.outcomes) == 1
        assert len(fetcher.calls) == 1  # type: ignore[attr-defined]


class TestWhatItWillNotGuess:
    def test_one_path_at_two_revisions_gets_one_name_each(self, tmp_path: Path) -> None:
        # `source_id` carries the commit and a filesystem path does not. The
        # corpus pins `plaza-evm/src/Pool.sol` at two commits whose bytes
        # differ, and this wrote both to one file: the second write won, its
        # digest was checked before the first was clobbered, and the summary
        # said "140 matched their recorded digest" over a tree the scorer then
        # refused 8 records of. Measured end to end, the honest ceiling read
        # 0.9770 on a checkout this command built.
        other = b"contract Vault { address owner; uint256 total; }\n"
        records = [
            a_record(record_id="one"),
            a_record(
                record_id="two",
                pin=CommitPin(
                    repo_url="https://github.com/example/vault",
                    commit="b" * 40,
                    path=PATH,
                    sha256=hashlib.sha256(other).hexdigest(),
                ),
            ),
        ]

        def fetch(url: str) -> bytes:
            return other if "bbbb" in url else BODY

        report = fetch_records(records, tmp_path, fetch=fetch)
        assert sorted(o.state for o in report.outcomes) == ["verified", "verified"]
        assert report.collisions == (PATH,)
        assert (tmp_path / "src" / f"Vault@{'a' * 12}.sol").read_bytes() == BODY
        assert (tmp_path / "src" / f"Vault@{'b' * 12}.sol").read_bytes() == other
        # And the plain path, for a resolver that has not learned the names.
        assert (tmp_path / PATH).read_bytes() in {BODY, other}
        assert "pinned at more than one revision" in report.statement()

    def test_the_plain_path_gets_the_revision_the_most_records_pin(self, tmp_path: Path) -> None:
        # The tie-break, which nothing pinned: a resolver that has not learned
        # the revision names reads this file, so which revision lands here
        # decides how many records it gets right. Two records pin `a`, one pins
        # `b`.
        other = b"contract Vault { uint256 total; }\n"

        def pin_at(commit: str, digest: str) -> CommitPin:
            return CommitPin(
                repo_url="https://github.com/example/vault",
                commit=commit,
                path=PATH,
                sha256=digest,
            )

        minority = hashlib.sha256(other).hexdigest()
        records = [
            a_record(record_id="one", pin=pin_at("a" * 40, DIGEST)),
            a_record(record_id="two", pin=pin_at("a" * 40, DIGEST)),
            a_record(record_id="three", pin=pin_at("b" * 40, minority)),
        ]

        def fetch(url: str) -> bytes:
            return other if "bbbb" in url else BODY

        report = fetch_records(records, tmp_path, fetch=fetch)
        assert report.collisions == (PATH,)
        assert (tmp_path / PATH).read_bytes() == BODY

    def test_a_digest_less_outcome_is_not_counted_as_a_match(self, tmp_path: Path) -> None:
        # `mismatched` also compared a digest, so counting `digest_checked`
        # alone put "2 matched their recorded digest" in the same paragraph as
        # "1 did NOT match their digest".
        (tmp_path / "src").mkdir()
        (tmp_path / PATH).write_bytes(b"a local edit\n")
        report = fetch_records([a_record()], tmp_path, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["mismatched"]
        assert "matched their recorded digest" not in report.statement()

    def test_the_statement_is_true_of_the_tree_and_not_of_the_writes(self, tmp_path: Path) -> None:
        # Each outcome is true of the moment it was produced, and the statement
        # is read as a claim about the checkout afterwards. Those were the same
        # sentence until one path pinned at two revisions made them different
        # ones -- and the fix for that must not be the only thing keeping them
        # the same, so this makes a *second* fetch touch a file the first had
        # already verified.
        first, second = "src/A.sol", "src/B.sol"

        def pin_at(path: str) -> CommitPin:
            return CommitPin(
                repo_url="https://github.com/example/vault",
                commit="a" * 40,
                path=path,
                sha256=DIGEST,
            )

        def fetch(url: str) -> bytes:
            if url.endswith(second):
                (tmp_path / first).write_bytes(b"clobbered after verification\n")
            return BODY

        report = fetch_records(
            [
                a_record(
                    record_id="one",
                    pin=pin_at(first),
                    locator=Locator(
                        file=first, contract="A", function="f", start_line=1, end_line=1
                    ),
                ),
                a_record(
                    record_id="two",
                    pin=pin_at(second),
                    locator=Locator(
                        file=second, contract="B", function="f", start_line=1, end_line=1
                    ),
                ),
            ],
            tmp_path,
            fetch=fetch,
            workers=1,
        )
        assert {o.path: o.state for o in report.outcomes} == {
            first: "mismatched",
            second: "verified",
        }
        assert "replaced after they were verified" in report.by_state("mismatched")[0].detail

    def test_two_pins_of_one_file_are_one_download_and_no_race(self, tmp_path: Path) -> None:
        # Seven paths in the shipped corpus are pinned by two `source_id`s
        # carrying the *same* digest, so the collision detector -- which keys on
        # the set of distinct digests per path -- is false for them and both
        # entries target one file. At the default eight workers both wrote a
        # staging file and the second thread's `replace` raised
        # `FileNotFoundError` after the first had moved it: measured, 13 of 18
        # cold fetches of the shipped corpus crashed with a bare traceback out
        # of typer, on the command the README gives as step one.
        #
        # The fetcher is slow on purpose. Without the lock both threads are
        # inside it before either writes, so the download happens twice and the
        # race is live; with it the second finds the file present.
        calls: list[str] = []

        def fetch(url: str) -> bytes:
            calls.append(url)
            time.sleep(0.05)
            return BODY

        records = [
            a_record(
                record_id="one",
                pin=CommitPin(
                    repo_url="https://github.com/example/vault",
                    commit="a" * 40,
                    path=PATH,
                    sha256=DIGEST,
                ),
            ),
            a_record(
                record_id="two",
                pin=CommitPin(
                    repo_url="https://github.com/example/vault",
                    commit="b" * 40,
                    path=PATH,
                    sha256=DIGEST,
                ),
            ),
        ]
        report = fetch_records(records, tmp_path, fetch=fetch, workers=8)
        assert len(calls) == 1
        assert sorted(o.state for o in report.outcomes) == ["present", "verified"]
        assert report.collisions == ()
        assert list(tmp_path.rglob("*.partial")) == []

    def test_two_spellings_of_one_path_are_a_collision(self, tmp_path: Path) -> None:
        # The detector keyed on the raw string, so two pins differing only in
        # case -- one file on the default macOS and Windows filesystems -- did
        # not register: one file existed and the loser was reported as a digest
        # mismatch, which is the wrong cause for a name collision.
        other = b"contract Vault { uint256 total; }\n"

        def pin_at(path: str, digest: str) -> CommitPin:
            return CommitPin(
                repo_url="https://github.com/example/vault",
                commit="a" * 40,
                path=path,
                sha256=digest,
            )

        records = [
            a_record(
                record_id="one",
                pin=pin_at(PATH, DIGEST),
                locator=Locator(
                    file=PATH, contract="Vault", function="setOwner", start_line=1, end_line=1
                ),
            ),
            a_record(
                record_id="two",
                pin=pin_at("src/vault.sol", hashlib.sha256(other).hexdigest()),
                locator=Locator(
                    file="src/vault.sol",
                    contract="Vault",
                    function="setOwner",
                    start_line=1,
                    end_line=1,
                ),
            ),
        ]

        def fetch(url: str) -> bytes:
            return other if url.endswith("vault.sol") else BODY

        report = fetch_records(records, tmp_path, fetch=fetch)
        # Not a revision collision: two spellings of one file cannot both exist
        # under any naming, so the second is unavailable with that as its cause
        # -- it used to be reported as a digest mismatch, which sends a reader
        # looking for source that moved.
        assert report.collisions == ()
        assert report.unwritable == ("src/vault.sol",)
        assert sorted(o.state for o in report.outcomes) == ["unavailable", "verified"]
        assert "one file on a case-insensitive" in report.by_state("unavailable")[0].detail
        assert "are another pin's file on this filesystem" in report.statement()

    def test_a_file_outside_the_root_is_not_reported_as_present(self, tmp_path: Path) -> None:
        # The idempotence branch returned before containment was consulted, and
        # `is_file()`/`read_bytes()` follow links -- so a pre-existing symlink
        # out of the checkout was reported `present` with `digest_checked=True`
        # and the statement said the checkout was complete and verified, over
        # bytes this package's own reader refuses and `run` calls missing.
        outside = tmp_path / "outside.sol"
        outside.write_bytes(BODY)
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        (root / PATH).symlink_to(outside)
        report = fetch_records([a_record()], root, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["unavailable"]
        assert "resolves outside --source-root" in report.outcomes[0].detail
        assert "matched their recorded digest" not in report.statement()

    def test_a_first_fetch_into_a_directory_that_does_not_exist_works(self, tmp_path: Path) -> None:
        # The primary path, and it was invisible to the suite: without the root
        # created up front, `_writable_inside` walks past it to a directory
        # legitimately outside the checkout and refuses every write.
        root = tmp_path / "nested" / "checkout"
        report = fetch_records([a_record()], root, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["verified"]
        assert (root / PATH).read_bytes() == BODY

    def test_a_dangling_link_at_the_target_is_still_written(self, tmp_path: Path) -> None:
        # `replace` acts on the link, not on what it points at, so nothing
        # escapes -- and refusing it only lost a write that would have landed
        # inside the root. A clause whose only measured effect is a false
        # refusal is worse than no clause.
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        (root / PATH).symlink_to(tmp_path / "gone.sol")
        report = fetch_records([a_record()], root, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["verified"]
        assert (root / PATH).read_bytes() == BODY
        assert not (root / PATH).is_symlink()

    def test_the_plain_path_copy_does_not_clobber_a_neighbour(self, tmp_path: Path) -> None:
        # The case `_writable_inside` does not cover: a link at the plain path
        # pointing *inside* the root. `write_bytes` follows it and overwrites a
        # neighbouring unit; the copy unlinks first.
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        neighbour = root / "src" / "Neighbour.sol"
        neighbour.write_text("do not touch")
        (root / PATH).symlink_to(neighbour)
        other = b"contract Vault { uint256 total; }\n"

        def pin_at(commit: str, digest: str) -> CommitPin:
            return CommitPin(
                repo_url="https://github.com/example/vault",
                commit=commit,
                path=PATH,
                sha256=digest,
            )

        records = [
            a_record(record_id="one", pin=pin_at("a" * 40, DIGEST)),
            a_record(record_id="two", pin=pin_at("b" * 40, hashlib.sha256(other).hexdigest())),
        ]

        def fetch(url: str) -> bytes:
            return other if "bbbb" in url else BODY

        fetch_records(records, root, fetch=fetch)
        assert neighbour.read_text() == "do not touch"

    def test_a_write_that_would_land_outside_the_root_is_refused(self, tmp_path: Path) -> None:
        # `check_unit_path` refuses a traversing string; this refuses a
        # traversing tree. Measured: a directory component that is a
        # pre-existing symlink out of the root let `mkdir(exist_ok=True)`
        # succeed, the write land outside, and the outcome say `written`.
        outside = tmp_path / "outside"
        outside.mkdir()
        root = tmp_path / "root"
        root.mkdir()
        (root / "src").symlink_to(outside)
        report = fetch_records([a_record()], root, fetch=a_fetcher())
        assert [o.state for o in report.outcomes] == ["unavailable"]
        assert "resolves outside --source-root" in report.outcomes[0].detail
        assert not (outside / "Vault.sol").exists()

    def test_the_plain_path_copy_does_not_write_through_a_link(self, tmp_path: Path) -> None:
        # `write_bytes` follows an existing symlink, which is how the copy for a
        # collided path clobbered a file outside the root.
        victim = tmp_path / "victim.sol"
        victim.write_text("do not touch")
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        (root / PATH).symlink_to(victim)
        other = b"contract Vault { uint256 total; }\n"

        def pin_at(commit: str, digest: str) -> CommitPin:
            return CommitPin(
                repo_url="https://github.com/example/vault",
                commit=commit,
                path=PATH,
                sha256=digest,
            )

        records = [
            a_record(record_id="one", pin=pin_at("a" * 40, DIGEST)),
            a_record(record_id="two", pin=pin_at("b" * 40, hashlib.sha256(other).hexdigest())),
        ]

        def fetch(url: str) -> bytes:
            return other if "bbbb" in url else BODY

        fetch_records(records, root, fetch=fetch)
        assert victim.read_text() == "do not touch"

    def test_a_digest_less_pin_does_not_read_a_planted_revision_file(self, tmp_path: Path) -> None:
        # The revision branch is skipped when there is no digest, and the
        # fallback used to return the revision file unconditionally -- so a
        # planted `Ghost@<commit>.sol` was read as the unit. Nothing to check
        # means nothing to name, so there is nothing to return.
        pin = CommitPin(
            repo_url="https://github.com/example/vault", commit="a" * 40, path="src/Ghost.sol"
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / f"Ghost@{'a' * 12}.sol").write_text("contract Planted {}")
        assert checkout_file(tmp_path, pin) is None

    def test_a_symlink_out_of_the_checkout_is_not_the_unit(self, tmp_path: Path) -> None:
        # `is_file()` follows links, and a checkout is built from paths that
        # third-party reports supplied. `_Pin` refuses a traversing path; a link
        # is the same escape one indirection along.
        outside = tmp_path / "outside.txt"
        outside.write_text("not in the checkout")
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        (root / "src" / "Vault.sol").symlink_to(outside)
        pin = CommitPin(
            repo_url="https://github.com/example/vault", commit="a" * 40, path="src/Vault.sol"
        )
        assert checkout_file(root, pin) is None

    def test_a_checkout_reached_through_a_symlink_still_works(self, tmp_path: Path) -> None:
        # The root is resolved before the comparison, so a checkout that is
        # itself a link -- which is how a shared cache gets mounted -- is not
        # mistaken for an escape from itself. Nothing pinned this.
        real = tmp_path / "real"
        (real / "src").mkdir(parents=True)
        (real / "src" / "Vault.sol").write_text("contract Vault {}")
        link = tmp_path / "link"
        link.symlink_to(real)
        pin = CommitPin(
            repo_url="https://github.com/example/vault", commit="a" * 40, path="src/Vault.sol"
        )
        got = checkout_file(link, pin)
        assert got is not None
        assert got.read_text() == "contract Vault {}"

    def test_a_revision_file_that_escapes_is_not_the_unit(self, tmp_path: Path) -> None:
        # Both branches that can return a revision-named file are contained,
        # not just the plain one: with the digest matching, and with the plain
        # path absent so the mismatch fallback fires.
        outside = tmp_path / "outside.sol"
        outside.write_text("contract Secret {}")
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        (root / "src" / f"Vault@{'a' * 12}.sol").symlink_to(outside)
        matching = CommitPin(
            repo_url="https://github.com/example/vault",
            commit="a" * 40,
            path="src/Vault.sol",
            sha256=hashlib.sha256(b"contract Secret {}").hexdigest(),
        )
        assert checkout_file(root, matching) is None
        mismatching = matching.model_copy(update={"sha256": "0" * 64})
        assert checkout_file(root, mismatching) is None

    def test_a_symlink_inside_the_checkout_still_resolves(self, tmp_path: Path) -> None:
        # Containment, not a ban on links: a checkout reached through one, or
        # arranged with one internally, still works.
        root = tmp_path / "root"
        (root / "src").mkdir(parents=True)
        (root / "real.sol").write_text("contract Vault {}")
        (root / "src" / "Vault.sol").symlink_to(root / "real.sol")
        pin = CommitPin(
            repo_url="https://github.com/example/vault", commit="a" * 40, path="src/Vault.sol"
        )
        got = checkout_file(root, pin)
        assert got is not None
        assert got.read_text() == "contract Vault {}"

    def test_a_deployed_address_is_unavailable_with_its_reason(self, tmp_path: Path) -> None:
        # Its source of truth is a chain explorer. Guessing at a repository that
        # may not hold the deployed bytecode's source would produce a file that
        # parses and is not the subject.
        pin = AddressPin(
            chain_id=1,
            address="0x" + "a" * 40,
            fork_point="19000000",
            # The same path as the locator's: the record validator requires it,
            # which is itself the corpus refusing a record whose subject and
            # whose cited file are different files.
            path=PATH,
        )
        report = fetch_records([a_record(pin=pin)], tmp_path, fetch=a_fetcher())
        assert report.outcomes[0].state == "unavailable"
        assert "chain explorer" in report.outcomes[0].detail

    def test_an_unknown_host_is_refused_by_name(self) -> None:
        # A guessed URL scheme either 404s -- which reads as a missing unit --
        # or returns an HTML error page, which lands on disk as Solidity.
        pin = CommitPin(
            repo_url="https://git.example.org/x/y", commit="c" * 40, path=PATH, sha256=DIGEST
        )
        with pytest.raises(ValueError, match="not a host this knows"):
            raw_url(pin)

    def test_a_fetch_failure_is_reported_per_file(self, tmp_path: Path) -> None:
        def broken(url: str) -> bytes:
            raise TimeoutError("the host did not answer")

        report = fetch_records([a_record()], tmp_path, fetch=broken)
        assert report.outcomes[0].state == "unavailable"
        assert "TimeoutError" in report.outcomes[0].detail
        # Said out loud: a unit missing from a checkout scores as a submission
        # that missed it.
        assert "scores as a submission that missed it" in report.statement()


class TestTheDefaultFetcherTrustsTheRightStore:
    def test_it_builds_a_context_from_certifi(self) -> None:
        # Python's urllib does not consult the system trust store on macOS, so a
        # default context fails to verify every host -- arriving as one URLError
        # per file, which reads as an unreachable host rather than a missing CA
        # bundle. This ran against 141 real pins and reported 141 failures once,
        # for exactly that reason.
        # Not `importorskip`: certifi is a declared dependency now, and the
        # skip was in the environment where its absence bites -- so the suite
        # reported a pass on the machine where `fetch` failed 141 of 141 pins.
        import certifi

        assert Path(certifi.where()).is_file()
        assert callable(urllib_fetcher())

    def test_certifi_is_declared_rather_than_hoped_for(self) -> None:
        # Two reviews found the missing declaration and fixed the mypy
        # consequence of it. This is the declaration.
        import tomllib

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        assert any(
            requirement.startswith("certifi") for requirement in declared["project"]["dependencies"]
        )
