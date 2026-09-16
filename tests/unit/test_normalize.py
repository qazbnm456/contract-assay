"""Resolving a draft's location, and pinning the bytes it was resolved against.

Two things here carry most of the weight. Span derivation, which converts the
prose-located category from unusable to usable and is the reason the corpus is
not biased by era. And the digest, pinned at this stage rather than left to
`verify`, because for a derived span it is the only check that survives -- and it
only survives if it witnesses the bytes the derivation actually ran against.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.harvest import DraftRecord
from contract_assay.corpus.normalize import NormalizeCause, normalize
from contract_assay.corpus.records import CorpusSplit, LocatorProvenance, Provenance
from contract_assay.corpus.verify import CheckFailure, SourceResolver, verify_all
from contract_assay.models import VulnerabilityClass

pytestmark = pytest.mark.offline

SHA = "a" * 40

VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address owner;

    function setOwner(address o) external {
        owner = o;
    }

    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
    }
}

contract Treasury {
    function setOwner(address o) external {}
}
"""

OVERLOADED = """\
contract Router {
    function swap(uint256 a) external {}

    function swap(uint256 a, address to) external {}
}
"""


def resolver(source: str | None = VAULT) -> SourceResolver:
    def _resolve(repo_url: str, commit: str, path: str) -> str | None:
        return source

    return _resolve


def a_draft(**over: object) -> DraftRecord:
    base: dict[str, object] = {
        "candidate_id": "H-01",
        "repo_url": "https://github.com/example/vault",
        "commit": SHA,
        "path": "src/Vault.sol",
        "contract": "Vault",
        "function": "setOwner",
        "classes": (VulnerabilityClass.ACCESS_CONTROL,),
        "provenance": Provenance(platform="example", report_url="https://example.invalid/1"),
    }
    return DraftRecord(**{**base, **over})  # type: ignore[arg-type]


def run(*drafts: DraftRecord, source: str | None = VAULT):  # type: ignore[no-untyped-def]
    return normalize(drafts, resolver(source), split=CorpusSplit.PUBLIC)


class TestAStatedSpanIsKept:
    def test_the_report_span_is_used_verbatim(self) -> None:
        report = run(a_draft(start_line=7, end_line=9))
        [record] = report.records
        assert (record.locator.start_line, record.locator.end_line) == (7, 9)
        assert record.locator_provenance is LocatorProvenance.STATED

    def test_a_span_past_the_end_of_the_file_is_lost(self) -> None:
        report = run(a_draft(start_line=900, end_line=901))
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.SPAN_OUT_OF_RANGE: 1}


class TestSpanDerivation:
    def test_a_function_named_in_prose_gets_a_span(self) -> None:
        # The whole prose-located category, converted from unusable to usable.
        report = run(a_draft())
        [record] = report.records
        assert record.locator_provenance is LocatorProvenance.DERIVED
        assert (record.locator.start_line, record.locator.end_line) == (7, 9)

    def test_the_enclosing_contract_is_recovered_when_the_report_omits_it(self) -> None:
        report = run(a_draft(contract=None, function="withdraw"))
        [record] = report.records
        assert record.locator.contract == "Vault"

    def test_derived_records_are_counted_as_such(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02", start_line=7, end_line=9))
        assert report.records_by_provenance == {
            LocatorProvenance.DERIVED: 1,
            LocatorProvenance.STATED: 1,
        }

    def test_an_overloaded_name_is_refused(self) -> None:
        # Choosing one would produce a record describing a function nobody
        # selected -- the same call `verify` already makes for stated spans.
        report = run(
            a_draft(contract="Router", function="swap", path="src/Router.sol"),
            source=OVERLOADED,
        )
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.FUNCTION_AMBIGUOUS: 1}

    def test_a_name_shared_by_two_contracts_needs_the_contract(self) -> None:
        # `setOwner` exists in both Vault and Treasury.
        assert run(a_draft(contract=None)).by_cause == {NormalizeCause.FUNCTION_AMBIGUOUS: 1}
        assert len(run(a_draft(contract="Treasury")).records) == 1

    def test_a_function_that_is_not_there_is_lost(self) -> None:
        report = run(a_draft(function="nonexistent"))
        assert report.by_cause == {NormalizeCause.FUNCTION_NOT_FOUND: 1}

    def test_a_contract_that_is_not_there_is_lost(self) -> None:
        report = run(a_draft(contract="Absent"))
        assert report.by_cause == {NormalizeCause.CONTRACT_NOT_FOUND: 1}

    def test_an_unreadable_file_is_lost(self) -> None:
        report = run(a_draft(), source="}{ not solidity ][")
        assert report.by_cause == {NormalizeCause.UNPARSEABLE_SOURCE: 1}

    @pytest.mark.parametrize("source", [None, "   \n "])
    def test_an_unresolvable_source_is_lost(self, source: str | None) -> None:
        report = run(a_draft(), source=source)
        assert report.by_cause == {NormalizeCause.SOURCE_UNRESOLVABLE: 1}


class TestTheDigestWitnessesTheDerivation:
    """The only check that survives for a derived span, and why it has to be here.

    A derived span is not cross-checked by verification: asking the declaration
    index whether a function sits inside a span that index produced is a
    tautology. What remains is that the file has not changed since the derivation
    ran -- and that guarantee exists only because the digest is recorded at this
    stage. Left blank for `verify` to fill in, verification would be comparing
    the file to itself.
    """

    def test_the_digest_is_pinned_at_normalize_time(self) -> None:
        [record] = run(a_draft()).records
        assert record.pin.sha256 is not None

    def test_a_file_changed_after_derivation_is_rejected(self) -> None:
        [record] = run(a_draft()).records
        moved = VAULT.replace("address owner;", "address owner;\n    uint256 extra;")
        report = verify_all([record], resolver(moved))
        assert report.admitted == ()
        assert CheckFailure.DIGEST_MISMATCH in report.rejected[0].failures

    def test_the_same_bytes_still_verify(self) -> None:
        [record] = run(a_draft()).records
        assert len(verify_all([record], resolver()).admitted) == 1


class TestRecordIdentity:
    def test_ids_are_stable_across_runs(self) -> None:
        # Derived from the draft rather than from position, so a record's
        # identity does not depend on how many other reports were in the batch.
        first = run(a_draft()).records[0].record_id
        second = run(a_draft(), a_draft(candidate_id="H-99")).records[0].record_id
        assert first == second

    def test_ids_differ_for_different_findings_in_one_file(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02", function="withdraw"))
        assert len({record.record_id for record in report.records}) == 2

    def test_an_id_is_readable_and_names_the_class(self) -> None:
        [record] = run(a_draft()).records
        assert record.record_id.startswith("vault-access-control-")


class TestAccounting:
    def test_losses_are_tallied_by_class(self) -> None:
        report = run(
            a_draft(function="nonexistent"),
            a_draft(
                candidate_id="H-02",
                function="missing",
                classes=(VulnerabilityClass.REENTRANCY,),
            ),
        )
        assert report.skipped_by_class == {
            VulnerabilityClass.ACCESS_CONTROL: 1,
            VulnerabilityClass.REENTRANCY: 1,
        }

    def test_a_per_class_loss_rate_is_available(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02", function="nonexistent"))
        assert report.loss_rate_for(VulnerabilityClass.ACCESS_CONTROL) == 0.5
        assert report.loss_rate_for(VulnerabilityClass.REENTRANCY) == 0.0

    def test_the_statement_names_derivation_and_losses(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02", function="nonexistent"))
        statement = report.statement()
        assert "function_not_found 1" in statement
        assert "had its span derived" in statement
        assert "cannot cross-check" in statement

    def test_a_clean_run_still_mentions_derivation(self) -> None:
        statement = run(a_draft()).statement()
        assert "none were lost" in statement
        assert "had its span derived" in statement

    def test_an_all_stated_run_says_nothing_about_derivation(self) -> None:
        statement = run(a_draft(start_line=7, end_line=9)).statement()
        assert "derived" not in statement

    def test_an_empty_run_says_so(self) -> None:
        report = run()
        assert report.drafts == 0
        assert report.loss_rate == 0.0
        assert report.statement() == "No drafts were normalized."

    def test_plural_derivations_read_correctly(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02", function="withdraw"))
        assert "2 had their span derived" in report.statement()


class TestSplitIsAPolicyDecision:
    def test_the_split_must_be_supplied(self) -> None:
        # No default: a forgotten split would publish a record meant to be
        # withheld, and it is not a fact recoverable from a report.
        with pytest.raises(TypeError):
            normalize([a_draft()], resolver())  # type: ignore[call-arg]

    @pytest.mark.parametrize("split", [CorpusSplit.PUBLIC, CorpusSplit.PRIVATE_HOLDOUT])
    def test_the_split_reaches_the_record(self, split: CorpusSplit) -> None:
        report = normalize([a_draft()], resolver(), split=split)
        assert report.records[0].split is split
