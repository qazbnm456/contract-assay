"""The Immunefi adapter, and recovering a commit a report never stated.

Fixtures are written by hand and mirror the platform's metadata block; no report
text is vendored.

What this platform tests that the others do not is the commit. Every observed
target names a branch, so nothing is pinned as written, and the submission date
is what makes a bounded inference available instead of unbounded drift.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.adapters.immunefi import ImmunefiAdapter, ImmunefiEnumerator
from contract_assay.corpus.harvest import RawReport, SkipCause, harvest

pytestmark = pytest.mark.offline

SHA = "d" * 40
REPO = "https://github.com/example/protocol"
RESOLVED = "e" * 40


def a_report(body: str, url: str = "https://immunefi.com/r/1") -> RawReport:
    return RawReport(platform="immunefi", report_url=url, body=body)


def resolver(repo_url: str, iso_date: str) -> str | None:
    return RESOLVED if (repo_url, iso_date) == (REPO, "2024-05-02") else None


WELL_FORMED = a_report(
    f"""\
# Reentrancy allows draining the vault

Submitted on May 2nd 2024 at 16:22:35 UTC by @someone for [Boost | Example](https://immunefi.com/x)

Report ID: #30634

Report type: Smart Contract

Report severity: Critical

Target: {REPO}/blob/main/src/Vault.sol

Impacts:
- Direct theft of any user funds

## Brief/Intro

The withdrawal path calls out before writing state.

## Vulnerability Details

See {REPO}/blob/main/src/Vault.sol?plain=1#L195

## Proof of Concept

```solidity
    function test_drain() public {{
        vm.prank(attacker);
    }}
```
"""
)


class TestTheMetadataBlock:
    def test_the_platform_fields_are_read_as_fields(self) -> None:
        report = ImmunefiEnumerator().report(WELL_FORMED.body)
        assert report is not None
        assert report.report_type == "Smart Contract"
        assert report.severity == "critical"
        assert report.submitted == "2024-05-02"
        assert report.is_smart_contract

    def test_the_date_is_read_in_either_word_order(self) -> None:
        enum = ImmunefiEnumerator()
        other = WELL_FORMED.body.replace("Submitted on May 2nd 2024", "Submitted on 2nd May 2024")
        parsed = enum.report(other)
        assert parsed is not None and parsed.submitted == "2024-05-02"

    def test_an_unreadable_date_is_empty_rather_than_guessed(self) -> None:
        body = WELL_FORMED.body.replace("Submitted on May 2nd 2024", "Submitted sometime in 2024")
        parsed = ImmunefiEnumerator().report(body)
        assert parsed is not None and parsed.submitted == ""

    def test_a_complete_block_is_externally_confirmed(self) -> None:
        basis = ImmunefiEnumerator().enumeration_basis(WELL_FORMED.body)
        assert basis.startswith("externally confirmed")

    def test_a_missing_field_is_named_rather_than_glossed(self) -> None:
        body = WELL_FORMED.body.replace("Report severity: Critical", "")
        basis = ImmunefiEnumerator().enumeration_basis(body)
        assert basis.startswith("partial")
        assert "Report severity" in basis

    def test_a_document_with_no_title_contributes_nothing(self) -> None:
        assert ImmunefiEnumerator().enumeration_basis("prose").startswith("unrecognised")


class TestRecoveringTheCommit:
    def test_a_branch_target_without_a_resolver_is_a_counted_loss(self) -> None:
        # What the other adapters do unconditionally: a branch names whatever it
        # currently points at, so nothing can be pinned.
        result = harvest(ImmunefiAdapter(), [WELL_FORMED])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_COMMIT: 1}

    def test_a_resolver_pins_it_and_the_assumption_travels(self) -> None:
        [draft] = harvest(ImmunefiAdapter(resolve_commit=resolver), [WELL_FORMED]).drafts
        assert draft.commit == RESOLVED
        assert draft.commit_resolved_from is not None
        assert "date, 2024-05-02" in draft.commit_resolved_from

    def test_a_target_already_pinned_records_no_assumption(self) -> None:
        body = WELL_FORMED.body.replace(
            f"{REPO}/blob/main/src/Vault.sol\n", f"{REPO}/blob/{SHA}/src/Vault.sol\n"
        )
        [draft] = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)]).drafts
        assert draft.commit == SHA
        assert draft.commit_resolved_from is None

    def test_a_resolver_that_cannot_answer_is_a_counted_loss(self) -> None:
        body = WELL_FORMED.body.replace("May 2nd 2024", "June 9th 2024")
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.by_cause == {SkipCause.NO_COMMIT: 1}

    def test_no_date_means_no_resolution_rather_than_a_substitute(self) -> None:
        body = WELL_FORMED.body.replace("Submitted on May 2nd 2024", "Submitted recently")
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.by_cause == {SkipCause.NO_COMMIT: 1}


class TestBorrowingALineFromTheBody:
    def test_the_metadata_names_the_file_and_the_body_the_line(self) -> None:
        [draft] = harvest(ImmunefiAdapter(resolve_commit=resolver), [WELL_FORMED]).drafts
        assert draft.path == "src/Vault.sol"
        assert draft.anchor_line == 195

    def test_a_query_string_does_not_stop_a_file_being_solidity(self) -> None:
        # `?plain=1` left in the path makes a .sol file look like it has an
        # unrecognised extension, for a reason nothing to do with the file.
        [draft] = harvest(ImmunefiAdapter(resolve_commit=resolver), [WELL_FORMED]).drafts
        assert draft.anchor_line == 195

    def test_two_candidate_lines_state_no_single_location(self) -> None:
        body = WELL_FORMED.body.replace(
            "?plain=1#L195", "?plain=1#L195 and also " + REPO + "/blob/main/src/Vault.sol#L400"
        )
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}

    def test_a_line_for_a_different_file_is_not_borrowed(self) -> None:
        body = WELL_FORMED.body.replace("src/Vault.sol?plain=1#L195", "src/Other.sol#L195")
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}


class TestWhatIsOutOfScope:
    def test_a_non_contract_report_is_out_of_language_scope(self) -> None:
        # The platform runs competitions for other targets, and those are not a
        # loss this corpus could ever have recovered.
        body = WELL_FORMED.body.replace(
            "Report type: Smart Contract", "Report type: Blockchain/DLT"
        )
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.by_cause == {SkipCause.NOT_A_FINDING: 1}

    def test_an_insight_severity_is_out_of_scope(self) -> None:
        body = WELL_FORMED.body.replace("Report severity: Critical", "Report severity: Insight")
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.by_cause == {SkipCause.NOT_A_FINDING: 1}

    def test_a_protocol_logic_title_maps_to_nothing(self) -> None:
        body = WELL_FORMED.body.replace(
            "# Reentrancy allows draining the vault",
            "# Queued withdrawal accounting deflates the reported total",
        )
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.by_cause == {SkipCause.UNMAPPED_CLASS: 1}

    def test_a_non_solidity_target_is_refused(self) -> None:
        body = WELL_FORMED.body.replace("src/Vault.sol\n", "README.md\n")
        result = harvest(ImmunefiAdapter(resolve_commit=resolver), [a_report(body)])
        assert result.by_cause == {SkipCause.NO_FILE_PATH: 1}


class TestTheAdapterSurvivesOddDocuments:
    @pytest.mark.parametrize(
        "body", ["", "# Title only", "Report type: Smart Contract", "# T\n\nTarget: nonsense"]
    )
    def test_nothing_raises_and_every_candidate_is_accounted_for(self, body: str) -> None:
        adapter = ImmunefiAdapter(resolve_commit=resolver)
        report = a_report(body)
        enumerated = len(adapter.candidates(report))
        result = harvest(adapter, [report])
        assert result.candidates == enumerated
        assert len(result.drafts) + len(result.skipped) == enumerated

    def test_the_proof_of_concept_is_never_taken_as_the_defect(self) -> None:
        # A PoC exercises the defect rather than containing it, so quoting it
        # would locate the test.
        [draft] = harvest(ImmunefiAdapter(resolve_commit=resolver), [WELL_FORMED]).drafts
        assert draft.quoted_source is None or "test_drain" not in draft.quoted_source
