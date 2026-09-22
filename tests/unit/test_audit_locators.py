"""The pure half of `tools/audit_locators.py`: which paths a finding links to.

Tested because this tool's job is to accuse a record of pointing at the wrong
file, and a false accusation is the costly way for it to be wrong -- it sends a
curator to "fix" a record that was right.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.offline

_TOOL = Path(__file__).resolve().parents[2] / "tools" / "audit_locators.py"
_spec = importlib.util.spec_from_file_location("audit_locators", _TOOL)
assert _spec is not None and _spec.loader is not None
audit = importlib.util.module_from_spec(_spec)
sys.modules["audit_locators"] = audit
_spec.loader.exec_module(audit)

BLOB = "https://github.com/sherlock-audit/2025-05-x/blob/main/repo/src/Stake.sol"


class TestWhichPathsAFindingCites:
    def test_a_query_string_is_not_part_of_the_path(self) -> None:
        """The regression. `?plain=1` is how Sherlock submissions usually link,
        and keeping it in the path made four records whose own report cites
        their own file read as "never linked"."""
        _, everywhere = audit.cited_paths(f"see {BLOB}?plain=1#L42 for it")
        assert everywhere == ["repo/src/Stake.sol"]

    def test_a_bare_question_mark_is_not_part_of_the_path(self) -> None:
        _, everywhere = audit.cited_paths(f"see {BLOB}?#L42")
        assert everywhere == ["repo/src/Stake.sol"]

    def test_a_line_anchor_is_not_part_of_the_path(self) -> None:
        _, everywhere = audit.cited_paths(f"{BLOB}#L10-L20")
        assert everywhere == ["repo/src/Stake.sol"]

    def test_the_nomination_is_only_what_sits_under_the_heading(self) -> None:
        """A body quotes other files while arguing; agreeing with one of those is
        not agreeing with the file the finding nominated."""
        other = "https://github.com/sherlock-audit/2025-05-x/blob/main/repo/src/Other.sol"
        body = f"# Lines of code\n\n{BLOB}#L1\n\n# Vulnerability details\n\nsee {other}#L9\n"
        under, everywhere = audit.cited_paths(body)
        assert under == ["repo/src/Stake.sol"]
        assert everywhere == ["repo/src/Stake.sol", "repo/src/Other.sol"]

    def test_a_body_without_the_heading_nominates_nothing(self) -> None:
        under, everywhere = audit.cited_paths(f"text {BLOB}#L3")
        assert under == []
        assert everywhere == ["repo/src/Stake.sol"]
