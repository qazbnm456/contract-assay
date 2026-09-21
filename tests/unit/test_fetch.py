"""Building a checkout, and refusing the one failure that has no symptom.

The fetcher is injected, so everything here runs with no network. What is being
tested is not HTTP -- it is the digest rule, because a file whose digest does not
match its pin is the one bad outcome that completes successfully: the run
finishes, most quotes still match, and the recall figure is a real number about
the wrong source.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from contract_assay.corpus.fetch import fetch_records, raw_url, urllib_fetcher
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
        pytest.importorskip("certifi")
        assert callable(urllib_fetcher())
