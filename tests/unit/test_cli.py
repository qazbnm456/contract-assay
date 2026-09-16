"""CLI behaviour.

A CLI is the only part of a library that users meet before reading anything, so
its failures have to be legible: a rejected record must say which record, which
check, and against what. These tests assert on that reporting, not just on exit
codes -- an exit code tells an author that something is wrong, and nothing else.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from contract_assay.cli import app

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
