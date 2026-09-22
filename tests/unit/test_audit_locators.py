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


class TestClassifying:
    """The outcome order, pinned because it was wrong once."""

    def test_a_pin_the_finding_nominated_is_a_match(self) -> None:
        assert audit.classify("a.sol", "", ["a.sol"], ["a.sol"]) == (
            "the pin is what the finding nominated",
            None,
        )

    def test_a_repinned_record_counts_as_a_match_not_as_dismissed(self) -> None:
        """The regression. A record this audit repinned carries the marker and
        now matches; checking the marker first counted it as dismissed."""
        notes = f"{audit.ADJUDICATED} ... repinned"
        outcome, flag = audit.classify("a.sol", notes, ["a.sol"], ["a.sol"])
        assert outcome == "the pin is what the finding nominated"
        assert flag is None

    def test_an_adjudicated_mismatch_is_not_flagged_again(self) -> None:
        notes = f"{audit.ADJUDICATED} ... kept where it is"
        outcome, flag = audit.classify("a.sol", notes, ["b.sol"], ["b.sol"])
        assert outcome == "mismatch already adjudicated; reasoning in notes"
        assert flag is None

    def test_an_unadjudicated_mismatch_is_flagged(self) -> None:
        assert audit.classify("a.sol", "", ["b.sol"], ["b.sol"])[1] == "never linked"
        assert audit.classify("a.sol", "", ["b.sol"], ["b.sol", "a.sol"])[1] == (
            "linked elsewhere in the body"
        )

    def test_other_notes_do_not_dismiss_a_mismatch(self) -> None:
        """Only this audit's marker counts; a record's unrelated notes do not
        silence it."""
        _, flag = audit.classify("a.sol", "Adjudicated by reading.", ["b.sol"], ["b.sol"])
        assert flag == "never linked"
