"""CLI behaviour.

A CLI is the only part of a library that users meet before reading anything, so
its failures have to be legible: a rejected record must say which record, which
check, and against what. These tests assert on that reporting, not just on exit
codes -- an exit code tells an author that something is wrong, and nothing else.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from contract_assay.cli import _local_resolver, app
from contract_assay.corpus.records import AddressPin, CommitPin
from contract_assay.models import DEFAULT_PREDICTIONS_PER_UNIT

pytestmark = pytest.mark.offline

runner = CliRunner()

VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function swapAndWithdraw(uint256 amountIn, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, 0, path, address(this), block.timestamp);
    }
}
"""

COMMIT = "a" * 40


def a_record(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "record_id": "vault-slippage-1",
        "split": "public",
        "pin": {
            "kind": "commit",
            "repo_url": "https://github.com/example/vault",
            "commit": COMMIT,
            "path": "src/Vault.sol",
        },
        "locator": {
            "file": "src/Vault.sol",
            "contract": "Vault",
            "function": "swapAndWithdraw",
            "start_line": 11,
            "end_line": 13,
        },
        "population": "audit_review",
        "locator_provenance": "stated",
        "classes": ["slippage"],
        "provenance": {
            "platform": "example-platform",
            "report_url": "https://example.invalid/report/1",
        },
    }
    return {**base, **over}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(VAULT, encoding="utf-8")
    (tmp_path / "records").mkdir()
    return tmp_path


def _cap_default(application: typer.Typer, command: str) -> object:
    """The default `--predictions-per-unit` a command was declared with."""
    import inspect

    for info in application.registered_commands:
        if (info.name or info.callback.__name__.replace("_", "-")) == command:
            return inspect.signature(info.callback).parameters["predictions_per_unit"].default
    raise AssertionError(f"no command named {command!r}")


def write_record(workspace: Path, record: dict[str, object], name: str = "record.json") -> Path:
    path = workspace / "records" / name
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path


class TestTopLevel:
    def test_version_is_reported(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "contract-assay" in result.stdout

    def test_bare_invocation_shows_help_rather_than_doing_nothing(self) -> None:
        result = runner.invoke(app, [])
        assert "verify" in result.stdout
        assert "declarations" in result.stdout


class TestDeclarations:
    def test_it_lists_what_a_file_declares(self, workspace: Path) -> None:
        result = runner.invoke(app, ["declarations", str(workspace / "src" / "Vault.sol")])
        assert result.exit_code == 0
        assert "Vault" in result.stdout
        assert "swapAndWithdraw" in result.stdout
        # Constructors are declarations, and a text matcher would miss this one.
        assert "constructor" in result.stdout

    def test_it_shows_parameter_types_so_overloads_can_be_told_apart(self, workspace: Path) -> None:
        # Diagnosing a record rejected as ambiguous is what this command is for,
        # and a bare name cannot distinguish one overload from another.
        result = runner.invoke(app, ["declarations", str(workspace / "src" / "Vault.sol")])
        assert "swapAndWithdraw(uint256,address[])" in result.stdout
        assert "constructor(address)" in result.stdout

    def test_an_unreadable_file_exits_nonzero(self, workspace: Path) -> None:
        junk = workspace / "src" / "Junk.sol"
        junk.write_text("}{ not solidity ][", encoding="utf-8")
        result = runner.invoke(app, ["declarations", str(junk)])
        assert result.exit_code == 1
        assert "no declarations" in result.stdout

    def test_a_missing_file_is_rejected_by_the_argument_parser(self, workspace: Path) -> None:
        result = runner.invoke(app, ["declarations", str(workspace / "nope.sol")])
        assert result.exit_code != 0


class TestVerify:
    def test_a_sound_record_is_admitted(self, workspace: Path) -> None:
        write_record(workspace, a_record())
        result = runner.invoke(
            app, ["verify", str(workspace / "records"), "--source-root", str(workspace)]
        )
        assert result.exit_code == 0, result.stdout
        assert "admitted" in result.stdout
        assert "1 record admitted" in result.stdout
        assert "no candidates were rejected" in result.stdout

    def test_a_rejected_record_names_the_check_that_failed(self, workspace: Path) -> None:
        # Pointing at the constructor's lines while naming swapAndWithdraw.
        record = a_record()
        record["locator"] = {**record["locator"], "start_line": 7, "end_line": 9}  # type: ignore[dict-item]
        write_record(workspace, record)

        result = runner.invoke(
            app, ["verify", str(workspace / "records"), "--source-root", str(workspace)]
        )
        assert result.exit_code == 1
        assert "rejected" in result.stdout
        assert "function_not_in_span" in result.stdout

    def test_a_malformed_record_reports_the_problem_rather_than_a_traceback(
        self, workspace: Path
    ) -> None:
        # A positive with no function: valid JSON, invalid ground truth.
        record = a_record()
        record["locator"] = {k: v for k, v in record["locator"].items() if k != "function"}  # type: ignore[union-attr]
        write_record(workspace, record)

        result = runner.invoke(
            app, ["verify", str(workspace / "records"), "--source-root", str(workspace)]
        )
        assert result.exit_code == 1
        assert "malformed record" in result.stdout
        assert "must name the function" in result.stdout

    def test_a_single_file_target_works_as_well_as_a_directory(self, workspace: Path) -> None:
        path = write_record(workspace, a_record())
        result = runner.invoke(app, ["verify", str(path), "--source-root", str(workspace)])
        assert result.exit_code == 0

    def test_an_empty_directory_is_an_error_not_a_silent_success(self, workspace: Path) -> None:
        # Reporting "0 admitted, 0 rejected" for a mistyped path would read as a
        # clean run and quietly verify nothing.
        result = runner.invoke(
            app, ["verify", str(workspace / "records"), "--source-root", str(workspace)]
        )
        assert result.exit_code == 1
        assert "no record files" in result.stdout

    def test_unresolvable_source_is_reported_with_the_pin(self, workspace: Path) -> None:
        record = a_record()
        record["pin"] = {**record["pin"], "path": "src/Missing.sol"}  # type: ignore[dict-item]
        record["locator"] = {**record["locator"], "file": "src/Missing.sol"}  # type: ignore[dict-item]
        write_record(workspace, record)

        result = runner.invoke(
            app, ["verify", str(workspace / "records"), "--source-root", str(workspace)]
        )
        assert result.exit_code == 1
        assert "source_unresolvable" in result.stdout

    def test_write_digests_records_the_verified_bytes(self, workspace: Path) -> None:
        path = write_record(workspace, a_record())
        assert "sha256" not in json.loads(path.read_text())["pin"]

        result = runner.invoke(
            app,
            [
                "verify",
                str(workspace / "records"),
                "--source-root",
                str(workspace),
                "--write-digests",
            ],
        )
        assert result.exit_code == 0

        digest = json.loads(path.read_text())["pin"]["sha256"]
        assert digest and len(digest) == 64

    def test_without_write_digests_the_record_is_left_alone(self, workspace: Path) -> None:
        path = write_record(workspace, a_record())
        before = path.read_text()

        runner.invoke(app, ["verify", str(workspace / "records"), "--source-root", str(workspace)])
        assert path.read_text() == before

    def test_a_pinned_digest_that_no_longer_matches_is_rejected(self, workspace: Path) -> None:
        path = write_record(workspace, a_record())
        runner.invoke(
            app,
            [
                "verify",
                str(workspace / "records"),
                "--source-root",
                str(workspace),
                "--write-digests",
            ],
        )

        # The source changes after the record was pinned.
        (workspace / "src" / "Vault.sol").write_text(
            VAULT.replace("amountIn, 0,", "amountIn, minOut,"), encoding="utf-8"
        )
        result = runner.invoke(
            app, ["verify", str(workspace / "records"), "--source-root", str(workspace)]
        )
        assert result.exit_code == 1
        assert "digest_mismatch" in result.stdout
        assert path.exists()


class TestResolvingAnAddressPin:
    """Verified source is a map of names to contents, not a directory tree.

    So the local form is a manifest per (chain, address), and `path` is looked
    up in it rather than joined to anything. Writing those keys into
    directories would make `path` joinable by accident and lose the distinction
    the pin exists to carry -- and the keys are import specifiers
    (`@openzeppelin/contracts/...`), which is what makes joining wrong rather
    than merely unusual.
    """

    ADDRESS = "0x" + "c" * 40

    def _manifest(self, root: Path, sources: dict[str, object]) -> None:
        chain = root / "1"
        chain.mkdir(parents=True, exist_ok=True)
        (chain / f"{self.ADDRESS}.json").write_text(json.dumps({"sources": sources}))

    def _pin(self, path: str = "contracts/Vault.sol") -> AddressPin:
        return AddressPin(chain_id=1, address=self.ADDRESS, fork_point="13849006", path=path)

    def test_a_key_is_looked_up_not_joined(self, tmp_path: Path) -> None:
        self._manifest(tmp_path, {"contracts/Vault.sol": {"content": "contract Vault {}"}})
        assert _local_resolver(tmp_path)(self._pin()) == "contract Vault {}"

    def test_an_import_specifier_resolves(self, tmp_path: Path) -> None:
        key = "@openzeppelin/contracts/token/ERC20/ERC20.sol"
        self._manifest(tmp_path, {key: {"content": "contract ERC20 {}"}})
        assert _local_resolver(tmp_path)(self._pin(key)) == "contract ERC20 {}"

    def test_a_plain_string_entry_is_accepted(self, tmp_path: Path) -> None:
        self._manifest(tmp_path, {"contracts/Vault.sol": "contract Vault {}"})
        assert _local_resolver(tmp_path)(self._pin()) == "contract Vault {}"

    def test_a_missing_manifest_resolves_to_nothing(self, tmp_path: Path) -> None:
        assert _local_resolver(tmp_path)(self._pin()) is None

    def test_a_missing_key_resolves_to_nothing(self, tmp_path: Path) -> None:
        self._manifest(tmp_path, {"contracts/Other.sol": "contract Other {}"})
        assert _local_resolver(tmp_path)(self._pin()) is None

    def test_a_corrupt_manifest_is_not_a_traceback(self, tmp_path: Path) -> None:
        chain = tmp_path / "1"
        chain.mkdir(parents=True)
        (chain / f"{self.ADDRESS}.json").write_text("{not json")
        assert _local_resolver(tmp_path)(self._pin()) is None

    def test_a_commit_pin_does_not_read_the_manifest(self, tmp_path: Path) -> None:
        # The two kinds are read from the two shapes they actually have, and
        # neither falls back to the other: a silent fallback would resolve a
        # commit pin against whatever manifest happened to be there.
        self._manifest(tmp_path, {"src/Vault.sol": "contract Vault {}"})
        pin = CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path="src/Vault.sol")
        assert _local_resolver(tmp_path)(pin) is None


class TestTheResolverReadsARevisionedCheckout:
    """`fetch` writes one name per revision, so the resolver looks for it."""

    def test_the_revisioned_name_is_preferred_when_its_digest_matches(self, tmp_path: Path) -> None:
        mine = "this revision"
        pin = CommitPin(
            repo_url="https://github.com/x/y",
            commit="a" * 40,
            path="src/Vault.sol",
            sha256=hashlib.sha256(mine.encode()).hexdigest(),
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "Vault.sol").write_text("the other revision")
        (tmp_path / "src" / f"Vault@{'a' * 12}.sol").write_text(mine)
        assert _local_resolver(tmp_path)(pin) == mine

    def test_a_planted_revision_file_does_not_shadow_the_real_one(self, tmp_path: Path) -> None:
        # A review dropped 138 revision-named files into a checkout: a resolver
        # preferring the name unconditionally read every one of them and 425 of
        # 435 records came back `unchecked`. Containment held -- the digest gate
        # turns it into a denial, never a forgery -- and the resolver should not
        # need the gate to save it.
        real = "contract Vault {}"
        pin = CommitPin(
            repo_url="https://github.com/x/y",
            commit="a" * 40,
            path="src/Vault.sol",
            sha256=hashlib.sha256(real.encode()).hexdigest(),
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "Vault.sol").write_text(real)
        (tmp_path / "src" / f"Vault@{'a' * 12}.sol").write_text("planted")
        assert _local_resolver(tmp_path)(pin) == real

    def test_a_mismatch_still_resolves_so_verify_can_name_it(self, tmp_path: Path) -> None:
        # `verify` distinguishes `digest_mismatch` from `source_unresolvable`,
        # and a resolver that returned nothing for a mismatch would collapse
        # the two.
        pin = CommitPin(
            repo_url="https://github.com/x/y",
            commit="a" * 40,
            path="src/Vault.sol",
            sha256="0" * 64,
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "Vault.sol").write_text("whatever is here")
        assert _local_resolver(tmp_path)(pin) == "whatever is here"

    def test_the_plain_path_still_resolves(self, tmp_path: Path) -> None:
        # Every checkout that is not this corpus's one colliding path, and every
        # checkout built by hand, has only the plain name.
        pin = CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path="src/Vault.sol")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "Vault.sol").write_text("contract Vault {}")
        assert _local_resolver(tmp_path)(pin) == "contract Vault {}"


class TestTheCapIsTheSameOnBothSurfaces:
    """The number `score` counts, the number `run` hands over, and one test each.

    A review reverted both defaults to `None` and the whole suite stayed green:
    `DEFAULT_PREDICTIONS_PER_UNIT` was asserted only where the scorer enforces
    it, never where either command chooses it. That is the same failure the
    sibling repository's round cap had -- a value justified in one place and
    relied on in another.
    """

    def _runs(self, workspace: Path, count: int) -> Path:
        run = {
            "detector_id": "d",
            "class_id": "slippage",
            "source_id": CommitPin(
                repo_url="https://github.com/example/vault", commit=COMMIT, path="src/Vault.sol"
            ).source_id,
            "outcome": "vulnerable",
            "evidence_tier": "syntactic",
            "produced_without_a_model": True,
            "findings": [
                {
                    "finding": {
                        "detector_id": "d",
                        "locator": {
                            "file": "src/Vault.sol",
                            "start_line": 11,
                            "end_line": 13,
                        },
                        "quote": VAULT.split("\n")[11],
                        "reasoning": f"claim {index}",
                    },
                    "status": "verified",
                }
                for index in range(count)
            ],
        }
        path = workspace / "runs.jsonl"
        path.write_text(json.dumps(run) + "\n", encoding="utf-8")
        return path

    def test_run_caps_without_being_asked(self, workspace: Path) -> None:
        # The third place that chooses this number, and the one on the path a
        # submitter uses. It was `None` while `run_submission`'s own default was
        # nine and its docstring said "what a submission hands over is what gets
        # scored" -- so the default was dead through the command, and a review
        # reverted it in the other direction with the suite still green.
        assert _cap_default(app, "run") == DEFAULT_PREDICTIONS_PER_UNIT, (
            "contract-assay run must hand over what score will count"
        )

    def test_score_caps_without_being_asked(self, workspace: Path) -> None:
        write_record(workspace, a_record())
        result = runner.invoke(
            app,
            [
                "score",
                str(self._runs(workspace, DEFAULT_PREDICTIONS_PER_UNIT + 3)),
                "--records",
                str(workspace / "records"),
                "--source-root",
                str(workspace),
                "--submission-id",
                "s",
            ],
        )
        assert result.exit_code == 0, result.output
        document = json.loads(result.output)
        assert document["predictions_per_unit"] == DEFAULT_PREDICTIONS_PER_UNIT
        [cls] = document["classes"]
        assert (cls["predictions"], cls["capped_predictions"]) == (
            DEFAULT_PREDICTIONS_PER_UNIT,
            3,
        )
