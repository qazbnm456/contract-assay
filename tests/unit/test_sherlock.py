"""The Sherlock adapter.

Fixtures are written by hand and mirror the platform's submission template; no
report text is vendored, for the reason `adapters/__init__` gives.

What this platform tests that Code4rena does not is a template. Severity is a
structured field and `### Root Cause` exists to say where the defect is, so the
adapter can read a location from the section that means one rather than from any
link it happens to find. The cases below are mostly about honouring that
boundary and about references that name a moving target.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.adapters.sherlock import SherlockAdapter, SherlockEnumerator
from contract_assay.corpus.harvest import RawReport, Skip, SkipCause, harvest
from contract_assay.models import VulnerabilityClass

pytestmark = pytest.mark.offline

SHA = "c" * 40
REPO = "https://github.com/sherlock-audit/2099-01-example"


def a_report(body: str, url: str = "https://github.com/sherlock-audit/x-judging/001/001.md"):
    return RawReport(platform="sherlock", report_url=url, body=body)


WELL_FORMED = a_report(
    f"""\
Some Warden Handle

High

# Reentrancy lets a caller drain the vault

### Summary

The balance is written after the external call.

### Root Cause

In `withdraw` {REPO}/blob/{SHA}/src/Vault.sol#L20-L28

```solidity
    function withdraw(uint256 amount) external {{
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }}
```

### Impact

Funds can be drained.

### PoC

```solidity
    function test_drain() public {{
        vm.prank(attacker);
    }}
```

### Mitigation

Write state first.
"""
)


class TestTheTemplate:
    def test_severity_and_title_are_read_as_structured_fields(self) -> None:
        issue = SherlockEnumerator().issue(WELL_FORMED.body)
        assert issue is not None
        assert issue.severity == "high"
        assert issue.title == "Reentrancy lets a caller drain the vault"

    def test_the_root_cause_section_is_isolated_from_the_rest(self) -> None:
        # The whole point: a link in a proof of concept cites what the exploit
        # touched, which is not where the defect is.
        issue = SherlockEnumerator().issue(WELL_FORMED.body)
        assert issue is not None
        root = issue.root_cause
        assert root is not None
        assert "Vault.sol#L20-L28" in root
        assert "test_drain" not in root

    def test_a_document_outside_the_template_is_reported_as_unrecognised(self) -> None:
        basis = SherlockEnumerator().enumeration_basis("just some prose")
        assert basis.startswith("unrecognised")

    def test_a_missing_root_cause_section_is_reported_as_partial(self) -> None:
        body = WELL_FORMED.body.replace("### Root Cause", "### Details")
        assert SherlockEnumerator().enumeration_basis(body).startswith("partial")

    def test_a_full_template_is_reported_as_externally_confirmed(self) -> None:
        # The denominator is the platform's directory-per-issue layout, not
        # anything this adapter counts.
        basis = SherlockEnumerator().enumeration_basis(WELL_FORMED.body)
        assert basis.startswith("externally confirmed")
        assert "one issue per directory" in basis


class TestExtraction:
    def test_a_pinned_range_in_the_root_cause_becomes_a_stated_span(self) -> None:
        [draft] = harvest(SherlockAdapter(), [WELL_FORMED]).drafts
        assert (draft.start_line, draft.end_line) == (20, 28)
        assert draft.commit == SHA
        assert draft.path == "src/Vault.sol"
        assert draft.classes == (VulnerabilityClass.REENTRANCY,)

    def test_severity_is_provenance_not_a_class(self) -> None:
        [draft] = harvest(SherlockAdapter(), [WELL_FORMED]).drafts
        assert draft.provenance.reported_severity == "high"

    def test_the_root_cause_excerpt_is_carried_and_the_harness_is_not(self) -> None:
        [draft] = harvest(SherlockAdapter(), [WELL_FORMED]).drafts
        assert draft.quoted_source is not None
        assert "test_drain" not in draft.quoted_source

    def test_a_single_line_citation_becomes_an_anchor(self) -> None:
        body = WELL_FORMED.body.replace("#L20-L28", "#L24")
        [draft] = harvest(SherlockAdapter(), [a_report(body)]).drafts
        assert draft.anchor_line == 24
        assert not draft.has_stated_span

    def test_a_branch_reference_is_refused_and_counted(self) -> None:
        # `main` names whatever it currently points at, so the location is not
        # reproducible. Counted rather than resolved: resolving today gives
        # today's target, and whether that is the audited state is a separate
        # question with its own uncertainty.
        body = WELL_FORMED.body.replace(f"/blob/{SHA}/", "/blob/main/")
        result = harvest(SherlockAdapter(), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_COMMIT: 1}

    def test_a_low_severity_submission_is_out_of_scope(self) -> None:
        body = WELL_FORMED.body.replace("\nHigh\n", "\nLow\n", 1)
        result = harvest(SherlockAdapter(), [a_report(body)])
        assert result.by_cause == {SkipCause.NOT_A_FINDING: 1}

    def test_a_protocol_logic_title_maps_to_nothing(self) -> None:
        body = WELL_FORMED.body.replace(
            "# Reentrancy lets a caller drain the vault",
            "# Queued withdrawal accounting deflates the reported total",
        )
        result = harvest(SherlockAdapter(), [a_report(body)])
        assert result.by_cause == {SkipCause.UNMAPPED_CLASS: 1}
        assert result.unclassified_skips == 1

    def test_several_distinct_pinned_locations_state_none(self) -> None:
        body = WELL_FORMED.body.replace(
            "#L20-L28",
            f"#L20-L28 and {REPO}/blob/{SHA}/src/Token.sol#L4-L9",
        )
        result = harvest(SherlockAdapter(), [a_report(body)])
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}

    def test_a_root_cause_with_no_solidity_link_falls_back_to_the_body(self) -> None:
        body = WELL_FORMED.body.replace(
            f"In `withdraw` {REPO}/blob/{SHA}/src/Vault.sol#L20-L28",
            "In `withdraw`, state is written late.",
        ).replace("### Impact", f"See {REPO}/blob/{SHA}/src/Vault.sol#L20-L28\n\n### Impact")
        [draft] = harvest(SherlockAdapter(), [a_report(body)]).drafts
        assert (draft.start_line, draft.end_line) == (20, 28)

    def test_a_submission_citing_no_solidity_is_a_counted_loss(self) -> None:
        body = WELL_FORMED.body.replace(f"{REPO}/blob/{SHA}/src/Vault.sol#L20-L28", "somewhere")
        result = harvest(SherlockAdapter(), [a_report(body)])
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}


class TestTheAdapterSurvivesOddDocuments:
    @pytest.mark.parametrize(
        "body",
        ["", "High", "# Title only", "Handle\n\nHigh\n", "###Root Cause\n", "# T\n\nHigh\n"],
    )
    def test_nothing_raises_and_every_candidate_is_accounted_for(self, body: str) -> None:
        adapter = SherlockAdapter()
        report = a_report(body)
        enumerated = len(adapter.candidates(report))
        result = harvest(adapter, [report])
        assert result.candidates == enumerated
        assert len(result.drafts) + len(result.skipped) == enumerated

    def test_an_unrecognised_document_is_still_counted_as_a_candidate(self) -> None:
        # A document the template did not match is a measured loss; one silently
        # ignored is an invisible one.
        result = harvest(SherlockAdapter(), [a_report("just prose")])
        assert result.candidates == 1
        assert result.by_cause == {SkipCause.MALFORMED_REPORT: 1}

    def test_extract_on_an_unrecognised_document_returns_a_skip(self) -> None:
        outcome = SherlockAdapter().extract(
            a_report("just prose"), SherlockAdapter().candidates(a_report("just prose"))[0]
        )
        assert isinstance(outcome, Skip)
        assert outcome.cause is SkipCause.MALFORMED_REPORT
