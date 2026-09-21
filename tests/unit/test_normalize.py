"""Resolving a draft's location, and pinning the bytes it was resolved against.

Two things here carry most of the weight. Span derivation, which converts the
prose-located category from unusable to usable and is the reason the corpus is
not biased by era. And the digest, pinned at this stage rather than left to
`verify`, because for a derived span it is the only check that survives -- and it
only survives if it witnesses the bytes the derivation actually ran against.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contract_assay.corpus.harvest import DraftRecord
from contract_assay.corpus.normalize import NormalizeCause, normalize
from contract_assay.corpus.records import (
    CorpusSplit,
    LocatorLabel,
    LocatorProvenance,
    Population,
    Provenance,
    SourcePin,
)
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
    def _resolve(pin: SourcePin) -> str | None:
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
    return normalize(
        drafts,
        resolver(source),
        split=CorpusSplit.PUBLIC,
        population=Population.AUDIT_REVIEW,
    )


class TestADraftThatCannotBecomeARecordIsCounted:
    """One malformed permalink used to abort the whole corpus build.

    `DraftRecord` refuses such a path where the draft is built. This is the
    second line of defence: `normalize` constructs a `CommitPin` from a draft's
    path at two sites and had no `try` around either, so a `ValidationError`
    escaped the run. A draft that cannot become a record is one counted
    rejection.
    """

    def test_an_unusable_path_is_refused_at_the_draft(self) -> None:
        # `adapters.markdown` takes the path from a GitHub blob URL with nothing
        # but `lstrip("/")`, so `../../etc/passwd.sol` is a shape a real report
        # can produce. Refused where the adapter that built it is identifiable.
        with pytest.raises(ValidationError, match="path must"):
            a_draft(path="../../etc/passwd.sol")

    def test_normalize_counts_one_rather_than_raising(self) -> None:
        # Reached by a draft built any way other than through the model -- a
        # script, a fixture, a future adapter that bypasses it.
        draft = a_draft().model_construct(**{**a_draft().__dict__, "path": "../../etc/passwd.sol"})
        outcome = run(draft)
        assert outcome.records == ()
        assert outcome.by_cause[NormalizeCause.UNUSABLE_PATH] == 1
        assert len(outcome.skipped) == 1

    def test_an_unusable_primary_falls_through_to_a_usable_candidate(self) -> None:
        # `_file_the_quote_names` says which file the adapter put in `path` is
        # not load-bearing: every candidate is resolved and the quote decides.
        # That was false whenever the *primary's spelling* was the broken part,
        # because the pin was built from it before any candidate was tried.
        draft = a_draft().model_construct(
            **{
                **a_draft().__dict__,
                "path": "../../etc/passwd.sol",
                "alternative_paths": ("src/Vault.sol",),
            }
        )
        outcome = run(draft)
        assert NormalizeCause.UNUSABLE_PATH not in outcome.by_cause
        assert [record.pin.path for record in outcome.records] == ["src/Vault.sol"]

    def test_the_recorded_reason_is_the_reason(self) -> None:
        # `str(ValidationError).splitlines()[-1]` is pydantic's documentation
        # URL, so every skip recorded "For further information visit
        # https://errors.pydantic.dev/..." where the cause should be. This file
        # says three times that a cause recorded wrongly points investigation
        # away from the fix.
        draft = a_draft().model_construct(**{**a_draft().__dict__, "path": "."})
        [skip] = run(draft).skipped
        assert skip.cause is NormalizeCause.UNUSABLE_PATH
        assert "pydantic.dev" not in skip.detail
        assert "path must name a file" in skip.detail

    def test_one_unusable_alternative_does_not_lose_the_draft(self) -> None:
        # The quote may still name one of the others, so an unusable candidate
        # is skipped rather than fatal.
        draft = a_draft().model_construct(
            **{
                **a_draft().__dict__,
                "path": "src/Vault.sol",
                "alternative_paths": ("..",),
                "quoted_source": "owner = who;",
                "contract": None,
                "function": None,
            }
        )
        outcome = run(draft)
        # Whatever becomes of the draft, the unusable candidate is not why.
        assert NormalizeCause.UNUSABLE_PATH not in outcome.by_cause


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
        report = run(
            a_draft(), a_draft(candidate_id="H-02", function="withdraw", start_line=11, end_line=13)
        )
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


class TestOneDefectReportedTwice:
    """Some platforms publish every submission, so one defect arrives repeatedly.

    Kept apart they inflate recall silently: a detector finding the defect once
    matches every copy. Folded, the count is right and the fold is disclosed.
    """

    def test_two_reports_of_one_defect_become_one_record(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02"))
        assert len(report.records) == 1
        assert report.duplicates == 1
        assert report.drafts == 2

    def test_a_fold_is_not_a_loss(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02"))
        assert report.skipped == ()
        assert report.loss_rate == 0.0
        assert "described a defect already recorded" in report.statement()

    def test_the_better_supported_record_survives(self) -> None:
        confirmed_id = run(a_draft(candidate_id="H-01", function="withdraw")).records[0].record_id
        # The confirmed one, whatever order the drafts arrive in.
        # Both name `withdraw`; only one also named the contract, so only one
        # made a second claim for the index to adjudicate.
        confirmed = a_draft(candidate_id="H-01", function="withdraw")
        alone = a_draft(candidate_id="H-02", function="withdraw", contract=None)
        for drafts in ((alone, confirmed), (confirmed, alone)):
            [record] = run(*drafts).records
            assert record.is_cross_checked
            assert record.record_id == confirmed_id

    def test_a_different_class_in_one_function_is_a_different_defect(self) -> None:
        report = run(
            a_draft(),
            a_draft(candidate_id="H-02", classes=(VulnerabilityClass.REENTRANCY,)),
        )
        assert len(report.records) == 2
        assert report.duplicates == 0

    def test_the_same_function_in_another_file_is_a_different_defect(self) -> None:
        report = run(a_draft(), a_draft(candidate_id="H-02", path="src/Other.sol"))
        assert len(report.records) == 2
        assert report.duplicates == 0


class TestRecordIdentity:
    def test_ids_are_stable_across_runs(self) -> None:
        # Derived from the draft rather than from position, so a record's
        # identity does not depend on how many other reports were in the batch.
        first = run(a_draft()).records[0].record_id
        batch = run(a_draft(), a_draft(candidate_id="H-99", function="withdraw"))
        assert first in {record.record_id for record in batch.records}

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
        assert "had its span inferred from a function named in prose" in statement
        assert "supports no exact-location match" in statement

    def test_a_clean_run_still_mentions_derivation(self) -> None:
        statement = run(a_draft()).statement()
        assert "none were lost" in statement
        assert "had its span inferred" in statement

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
        assert "2 had their span inferred" in report.statement()


class TestSplitIsAPolicyDecision:
    def test_the_split_must_be_supplied(self) -> None:
        # No default: a forgotten split would publish a record meant to be
        # withheld, and it is not a fact recoverable from a report.
        with pytest.raises(TypeError):
            normalize([a_draft()], resolver())  # type: ignore[call-arg]

    @pytest.mark.parametrize("split", [CorpusSplit.PUBLIC, CorpusSplit.PRIVATE_HOLDOUT])
    def test_the_split_reaches_the_record(self, split: CorpusSplit) -> None:
        report = normalize([a_draft()], resolver(), split=split, population=Population.AUDIT_REVIEW)
        assert report.records[0].split is split


class TestAnchoring:
    """A stated line, widened to the declaration containing it."""

    def test_a_stated_line_is_widened_to_its_declaration(self) -> None:
        # `setOwner` spans 7-9 and the report pointed at line 8.
        [record] = run(a_draft(anchor_line=8, contract=None, function=None)).records
        assert record.locator_provenance is LocatorProvenance.ANCHORED
        assert (record.locator.start_line, record.locator.end_line) == (7, 9)
        assert record.anchor_line == 8
        assert record.locator.function == "setOwner"
        assert record.locator.contract == "Vault"

    def test_the_anchor_survives_onto_the_record(self) -> None:
        # It is the finest thing the report asserted, and what §7 scores against.
        [record] = run(a_draft(anchor_line=8, contract=None, function=None)).records
        assert record.anchor_line == 8
        assert record.locator_provenance.supports_exact_match

    def test_an_anchor_in_no_declaration_is_a_loss_not_a_guess(self) -> None:
        # Line 5 is a state variable, not inside any function. The report
        # pointed somewhere real and this stage cannot name a function for it.
        report = run(a_draft(anchor_line=5, contract=None, function=None))
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.NO_DECLARATION_AT_ANCHOR: 1}

    def test_an_anchor_past_the_end_of_the_file_is_lost(self) -> None:
        report = run(a_draft(anchor_line=900, contract=None, function=None))
        assert report.by_cause == {NormalizeCause.SPAN_OUT_OF_RANGE: 1}

    def test_a_named_contract_disagreeing_with_the_anchor_is_refused(self) -> None:
        # The one genuine cross-check an anchored locator has: neither the
        # contract name nor the line came from the declaration index, so their
        # disagreement means the record does not describe what it claims.
        report = run(a_draft(anchor_line=8, contract="Treasury", function=None))
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.ANCHOR_CONTRADICTS_CONTRACT: 1}

    def test_a_named_contract_agreeing_with_the_anchor_is_evidence(self) -> None:
        [record] = run(a_draft(anchor_line=8, contract="Vault", function=None)).records
        assert record.locator.contract == "Vault"

    def test_an_anchor_beats_a_prose_function_name(self) -> None:
        # Both are present; the anchor is what the report pointed at, so it wins
        # and the record is anchored rather than derived.
        [record] = run(a_draft(anchor_line=8, function="withdraw")).records
        assert record.locator_provenance is LocatorProvenance.ANCHORED
        assert record.locator.function == "setOwner"

    def test_a_stated_span_beats_an_anchor(self) -> None:
        # DraftRecord forbids both, so this is about ordering within `_locate`
        # rather than about a reachable draft.
        [record] = run(a_draft(start_line=7, end_line=9)).records
        assert record.locator_provenance is LocatorProvenance.STATED

    def test_the_three_provenances_are_counted_apart(self) -> None:
        report = run(
            a_draft(candidate_id="A", start_line=7, end_line=9),
            a_draft(candidate_id="B", anchor_line=12, contract=None, function=None),
            a_draft(candidate_id="C", classes=(VulnerabilityClass.REENTRANCY,)),
        )
        assert report.records_by_provenance == {
            LocatorProvenance.STATED: 1,
            LocatorProvenance.ANCHORED: 1,
            LocatorProvenance.DERIVED: 1,
        }

    def test_the_statement_distinguishes_anchored_from_inferred(self) -> None:
        report = run(
            a_draft(candidate_id="B", anchor_line=12, contract=None, function=None),
            a_draft(candidate_id="C"),
        )
        statement = report.statement()
        assert "1 is anchored to a stated line" in statement
        assert "1 had its span inferred" in statement


class TestADraftStatesOneKindOfLocation:
    def _draft(self, **over: object) -> DraftRecord:
        return a_draft(**over)

    def test_a_span_and_an_anchor_together_are_refused(self) -> None:
        # A report that gave a range stated its span; one that gave a line did
        # not. Carrying both would leave which of them was asserted unclear.
        with pytest.raises(ValidationError, match="either a span or a single anchor"):
            self._draft(start_line=7, end_line=9, anchor_line=8)

    def test_none_of_the_three_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="should have been skipped"):
            self._draft(start_line=None, end_line=None, anchor_line=None, function=None)

    def test_an_anchor_alone_is_a_valid_draft(self) -> None:
        draft = self._draft(function=None, contract=None, anchor_line=8)
        assert draft.has_anchor and not draft.has_stated_span


class TestQuoteMatching:
    """Locating a report's own excerpt in the pinned file.

    The strongest confirmation available and the only one produced by two
    sources neither of which derived from the other: the text came from the
    report, the bytes from the repository, and the span is where they agree.
    """

    TWICE = """\
contract Vault {
    address owner;

    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }

    function rescue(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}
"""

    UNIQUE = """
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
"""

    REPEATED = """
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
"""

    def test_a_unique_excerpt_locates_and_is_cross_checked(self) -> None:
        [record] = run(
            a_draft(quoted_source=self.UNIQUE, contract=None, function=None), source=self.TWICE
        ).records
        assert record.locator_provenance is LocatorProvenance.QUOTED
        assert (record.locator.start_line, record.locator.end_line) == (4, 7)
        assert record.is_cross_checked
        assert record.locator_provenance.supports_exact_match

    def test_the_host_is_recovered_from_the_matched_span(self) -> None:
        [record] = run(
            a_draft(quoted_source=self.UNIQUE, contract=None, function=None), source=self.TWICE
        ).records
        assert (record.locator.contract, record.locator.function) == ("Vault", "withdraw")

    def test_an_excerpt_occurring_twice_locates_nothing(self) -> None:
        # Taking the first would be a wrong record that no contiguity test
        # catches, because a wrong match can be perfectly contiguous.
        report = run(
            a_draft(quoted_source=self.REPEATED, contract=None, function=None), source=self.TWICE
        )
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.QUOTE_AMBIGUOUS: 1}

    def test_an_excerpt_that_is_not_there_is_a_counted_loss(self) -> None:
        report = run(
            a_draft(
                quoted_source="function absent() external {\n  revert();\n  return;\n}",
                contract=None,
                function=None,
            ),
            source=self.TWICE,
        )
        assert report.by_cause == {NormalizeCause.QUOTE_NOT_FOUND: 1}

    def test_comments_and_elisions_in_an_excerpt_are_ignored(self) -> None:
        # Reviewers annotate the code they quote, and excerpt it with ellipses.
        annotated = """
    function withdraw(uint256 amount) external {   // <-- entry point
        payable(msg.sender).transfer(amount);      // external call first
        ...
        balances[msg.sender] -= amount;
    }
"""
        [record] = run(
            a_draft(quoted_source=annotated, contract=None, function=None), source=self.TWICE
        ).records
        assert (record.locator.start_line, record.locator.end_line) == (4, 7)

    def test_line_number_prefixes_are_ignored(self) -> None:
        numbered = """
    4:    function withdraw(uint256 amount) external {
    5:        payable(msg.sender).transfer(amount);
    6:        balances[msg.sender] -= amount;
    7:    }
"""
        [record] = run(
            a_draft(quoted_source=numbered, contract=None, function=None), source=self.TWICE
        ).records
        assert record.locator_provenance is LocatorProvenance.QUOTED

    def test_an_excerpt_too_short_to_locate_falls_through(self) -> None:
        # One or two lines duplicate too easily, and a match unique by accident
        # is a wrong record waiting to happen. It falls through to a weaker
        # route rather than being recorded as a loss.
        [record] = run(
            a_draft(quoted_source="    }", function="withdraw", contract="Vault"),
            source=self.TWICE,
        ).records
        assert record.locator_provenance is LocatorProvenance.DERIVED

    def test_a_stated_span_the_excerpt_agrees_with_stays_stated(self) -> None:
        [record] = run(
            a_draft(
                quoted_source=self.UNIQUE, start_line=4, end_line=7, function=None, contract=None
            ),
            source=self.TWICE,
        ).records
        assert record.locator_provenance is LocatorProvenance.STATED

    def test_a_stated_span_the_excerpt_contradicts_is_refused(self) -> None:
        # Two assertions from the report, adjudicated by the repository's bytes,
        # disagreeing about where the defect is. Neither is obviously wrong, so
        # the record is refused rather than decided by preference.
        report = run(
            a_draft(
                quoted_source=self.UNIQUE, start_line=9, end_line=12, function=None, contract=None
            ),
            source=self.TWICE,
        )
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.QUOTE_CONTRADICTS_SPAN: 1}

    def test_quoted_records_are_counted_by_provenance(self) -> None:
        report = run(
            a_draft(quoted_source=self.UNIQUE, contract=None, function=None), source=self.TWICE
        )
        assert report.records_by_provenance == {LocatorProvenance.QUOTED: 1}


class TestPopulationIsRecorded:
    def test_the_population_must_be_supplied(self) -> None:
        # Not recoverable from a report, and the two bodies of work skew in
        # opposite directions, so a mixture counted as one describes neither.
        with pytest.raises(TypeError):
            normalize([a_draft()], resolver(), split=CorpusSplit.PUBLIC)  # type: ignore[call-arg]

    @pytest.mark.parametrize("population", [Population.AUDIT_REVIEW, Population.EXPLOITED_INCIDENT])
    def test_the_population_reaches_the_record(self, population: Population) -> None:
        report = normalize([a_draft()], resolver(), split=CorpusSplit.PUBLIC, population=population)
        assert report.records[0].population is population


class TestAStatedSpanGetsItsLabels:
    """A report giving a range but no function name is common, and usable."""

    def test_the_function_is_read_off_the_span(self) -> None:
        # The span stays the report's; only the labels are filled in. Without
        # this the record has no function, cannot be scored at function
        # granularity, and is lost for the sake of a name the index can read
        # off the span it was already handed.
        [record] = run(a_draft(start_line=7, end_line=9, contract=None, function=None)).records
        assert record.locator_provenance is LocatorProvenance.STATED
        assert (record.locator.contract, record.locator.function) == ("Vault", "setOwner")
        assert (record.locator.start_line, record.locator.end_line) == (7, 9)

    def test_a_name_the_report_gave_is_not_overwritten(self) -> None:
        [record] = run(
            a_draft(start_line=7, end_line=9, contract="Vault", function="setOwner")
        ).records
        assert record.locator.function == "setOwner"


class TestWhatTheReportActuallyAsserted:
    """Confirmation depends on the report having made two claims, not on the label.

    A span whose function name the index filled in is not corroborated by that
    name: `verify` asks whether the function lies in the span it was read out
    of, and the answer is certain. Recording which labels came from the report
    is what keeps that distinguishable, because a finished record cannot tell an
    index-supplied label from a stated one.
    """

    def test_a_stated_span_alone_is_not_cross_checked(self) -> None:
        [record] = run(a_draft(start_line=7, end_line=9, contract=None, function=None)).records
        assert record.locator.function == "setOwner"  # supplied by the index
        assert record.asserted_labels == []
        assert not record.is_cross_checked

    def test_a_stated_span_with_a_stated_name_is_cross_checked(self) -> None:
        [record] = run(
            a_draft(start_line=7, end_line=9, contract="Vault", function="setOwner")
        ).records
        assert set(record.asserted_labels) == {LocatorLabel.CONTRACT, LocatorLabel.FUNCTION}
        assert record.is_cross_checked

    def test_an_anchored_records_function_is_never_the_reports(self) -> None:
        # It came from the declaration the anchor landed in, even when the draft
        # happened to carry a name as well.
        [record] = run(a_draft(anchor_line=8, function="withdraw", contract="Vault")).records
        assert record.locator.function == "setOwner"
        assert record.asserted_labels == [LocatorLabel.CONTRACT]
        assert record.is_cross_checked

    def test_a_prose_derived_record_keeps_both_stated_labels(self) -> None:
        [record] = run(a_draft(contract="Vault", function="setOwner")).records
        assert set(record.asserted_labels) == {LocatorLabel.CONTRACT, LocatorLabel.FUNCTION}
        assert record.is_cross_checked

    def test_a_prose_derived_record_with_only_a_function_is_not(self) -> None:
        [record] = run(a_draft(contract=None, function="withdraw")).records
        assert record.asserted_labels == [LocatorLabel.FUNCTION]
        assert not record.is_cross_checked


STATE_BLOCK = """\
contract Bank {
    address owner;
    uint256 total;
    mapping(address => uint256) balances;

    function deposit() external {
        total += 1;
    }
}
"""


class TestASpanInNoFunction:
    """A location that may well be right, and still cannot be scored.

    Scoring is at function granularity, so a span covering a state variable
    block or a whole contract has nothing to be scored against. It is counted
    apart from an anchor that hit no declaration, because that is about a line
    the report pointed at and this is about a span the report gave outright.
    """

    def test_a_stated_span_outside_any_function_is_lost(self) -> None:
        report = run(a_draft(contract=None, function=None, start_line=5, end_line=5))
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.NO_ENCLOSING_FUNCTION: 1}

    def test_a_quoted_span_outside_any_function_is_lost(self) -> None:
        report = run(
            a_draft(
                contract=None,
                function=None,
                quoted_source=(
                    "    address owner;\n    uint256 total;\n"
                    "    mapping(address => uint256) balances;"
                ),
            ),
            source=STATE_BLOCK,
        )
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.NO_ENCLOSING_FUNCTION: 1}

    def test_a_function_named_elsewhere_does_not_rescue_the_span(self) -> None:
        # It used to. The record it produced -- lines 5-5, function `setOwner`,
        # which is declared nowhere near line 5 -- is one `verify` is documented
        # to reject, and did: the two stages disagreed about what a record is,
        # and this test pinned the wrong side of it. The refusal now happens
        # where both signals are still in hand, under a cause that says the
        # finding pointed at two places.
        report = run(a_draft(function="setOwner", start_line=5, end_line=5))
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.LOCATION_CONTRADICTS_NAME: 1}


class TestTheExcerptChoosesTheFile:
    """A finding citing several files has not stated one; its excerpt may have.

    The adapter hands over the whole cited set rather than guessing, because
    only this stage holds the bytes. Six of eleven losses over one sample were
    exactly this shape: a usable excerpt discarded because the *file* was not
    unique.
    """

    OTHER = """\
contract Other {
    function untouched(uint256 a) external {
        total = a;
    }
}
"""

    QUOTE = "    function setOwner(address o) external {\n        owner = o;\n    }"

    def _run(self, sources: dict[str, str], **over: object):  # type: ignore[no-untyped-def]
        def resolve(pin) -> str | None:  # type: ignore[no-untyped-def]
            return sources.get(pin.path)

        draft = a_draft(
            contract=None,
            function=None,
            quoted_source=self.QUOTE,
            alternative_paths=("src/Other.sol",),
            **over,
        )
        return normalize(
            [draft], resolve, split=CorpusSplit.PUBLIC, population=Population.AUDIT_REVIEW
        )

    def test_the_file_holding_the_excerpt_is_chosen(self) -> None:
        report = self._run({"src/Vault.sol": VAULT, "src/Other.sol": self.OTHER})
        [record] = report.records
        assert record.pin.path == "src/Vault.sol"
        assert record.locator_provenance is LocatorProvenance.QUOTED

    def test_the_order_the_adapter_happened_to_use_is_not_load_bearing(self) -> None:
        # The excerpt is in the *alternative*, and the record still resolves to
        # it -- which is what makes handing over a set rather than a guess sound.
        report = self._run(
            {"src/Vault.sol": self.OTHER, "src/Other.sol": VAULT},
        )
        [record] = report.records
        assert record.pin.path == "src/Other.sol"

    def test_an_excerpt_in_two_of_them_identifies_neither(self) -> None:
        # The same failure as an excerpt occurring twice in one file, and
        # counted under the same cause.
        report = self._run({"src/Vault.sol": VAULT, "src/Other.sol": VAULT})
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.QUOTE_AMBIGUOUS: 1}

    def test_an_excerpt_in_none_of_them_is_its_own_loss(self) -> None:
        # Counted apart from `quote_not_found`, which is about one stated file:
        # here the file was never stated and the excerpt was to choose it, so
        # what failed is the choosing.
        report = self._run({"src/Vault.sol": self.OTHER, "src/Other.sol": self.OTHER})
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.FILE_NOT_DETERMINED: 1}

    def test_a_file_that_cannot_be_fetched_is_skipped_not_matched(self) -> None:
        report = self._run({"src/Vault.sol": VAULT})
        [record] = report.records
        assert record.pin.path == "src/Vault.sol"


class TestRemovingCommentsMustNotMoveALine:
    """A unique match at the wrong span is the worst thing a matcher can do.

    Comments are stripped before matching so that a report quoting code without
    its comments still locates. Substituting the empty string for a block
    comment removes its newlines and shifts the number of every line after it,
    and one real file's banner comments shifted a match by 28 lines. The match
    was *unique*, so nothing in the matcher noticed.

    What noticed was `verify`, whose declaration check found the named function
    absent from the matched span -- which is the whole reason a record is checked
    against the source after being built rather than trusted from the stage that
    built it.
    """

    SOURCE = """\
contract Banner {
    /*//////////////////////////////////////////////////////////////
                              A SECTION
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                            ANOTHER SECTION
    //////////////////////////////////////////////////////////////*/

    function target(uint256 a) external {
        total = a;
        emit Changed(a);
    }
}
"""

    QUOTE = (
        "    function target(uint256 a) external {\n        total = a;\n        emit Changed(a);"
    )

    def test_the_span_is_where_the_code_actually_is(self) -> None:
        report = run(
            a_draft(contract="Banner", function="target", quoted_source=self.QUOTE),
            source=self.SOURCE,
        )
        [record] = report.records
        assert record.locator_provenance is LocatorProvenance.QUOTED
        # `function target` is on line 10 of the source above. A collapsing
        # comment stripper reports it near line 4.
        assert record.locator.start_line == 10

    def test_a_line_comment_does_not_shift_anything_either(self) -> None:
        source = self.SOURCE.replace("contract Banner {", "// a leading note\ncontract Banner {")
        report = run(
            a_draft(contract="Banner", function="target", quoted_source=self.QUOTE),
            source=source,
        )
        [record] = report.records
        assert record.locator.start_line == 11


class TestTwoPlacesAndNoWordOnWhich:
    """A quote showing a caller and prose naming a callee point at two functions.

    Six drafts over one sample, identical in shape every time: the prose named
    a function declared in *another file* -- a library's validator called from
    the quoted lines, `nuke` where the quote shows `burn`, a hook's
    `onQueueWithdrawal` where the quote shows `closeMarket`. §7.3's rule
    arriving in curation: a call edge is not the same function.

    The route used to let the prose name override the declaration the quote
    landed in, which pinned the callee's name to the caller's lines. Preferring
    the quote instead would have pinned three of the six to code the finding was
    not about. Both signals are the report's, neither is obviously wrong, and
    the record is refused.
    """

    CALLER = """\
contract Market {
    function closeMarket() external {
        MarketState memory state = _getUpdatedState();
        hooks.onQueueWithdrawal(state);
    }
}
"""

    def test_a_name_from_another_file_refuses_the_quoted_span(self) -> None:
        report = run(
            a_draft(
                contract=None,
                function="onQueueWithdrawal",
                quoted_source=(
                    "    function closeMarket() external {\n"
                    "        MarketState memory state = _getUpdatedState();\n"
                    "        hooks.onQueueWithdrawal(state);\n"
                    "    }"
                ),
            ),
            source=self.CALLER,
        )
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.LOCATION_CONTRADICTS_NAME: 1}

    def test_the_name_the_quote_does_contain_is_kept(self) -> None:
        [record] = run(
            a_draft(
                function="setOwner",
                quoted_source=(
                    "    function setOwner(address o) external {\n        owner = o;\n    }"
                ),
            )
        ).records
        assert record.locator.function == "setOwner"
        assert record.locator_provenance is LocatorProvenance.QUOTED


class TestAReviewersMarkerIsNotCode:
    """`@> return x;` and `|>  require(...)` point at the line that matters.

    They were costing whole records rather than one line each: the marked line
    failed to match, which broke contiguity, so an excerpt whose every other
    line was present matched nothing at all. Two published conventions, two
    findings each in one sample.
    """

    @pytest.mark.parametrize("marker", ["@>", "|>", "=>"])
    def test_a_marked_line_still_matches(self, marker: str) -> None:
        [record] = run(
            a_draft(
                function=None,
                contract=None,
                quoted_source=(
                    "    function setOwner(address o) external {\n"
                    f"{marker}      owner = o;\n"
                    "    }"
                ),
            )
        ).records
        assert record.locator.function == "setOwner"

    def test_a_marker_after_a_line_number_is_also_removed(self) -> None:
        # Both conventions at once, which is how one report writes it.
        [record] = run(
            a_draft(
                function=None,
                contract=None,
                quoted_source=(
                    "7:    function setOwner(address o) external {\n8: @>      owner = o;\n9:    }"
                ),
            )
        ).records
        assert record.locator.function == "setOwner"


class TestSpacingIsNotEvidence:
    """`if(a>b){` and `if (a > b) {` are the same code.

    The matcher already collapsed *runs* of whitespace, so `a  =  b` matched
    `a = b` and `a=b` did not -- an inconsistency in a tolerance rather than a
    tolerance withheld. Worth saying plainly: closing it recovered **no** draft
    in the sample that prompted the look. The excerpt that seemed to need it
    turned out to quote genuinely different code, a ternary the report had
    rewritten as an `if`, which is an absence the source confirms.
    """

    TIGHT = """\
contract Vault {
    function claim(uint256 id) external {
        if(balances[id]>0){
            payable(msg.sender).transfer(balances[id]);
        }
    }
}
"""

    def test_a_quote_spaced_differently_still_matches(self) -> None:
        [record] = run(
            a_draft(
                contract=None,
                function=None,
                quoted_source=(
                    "    function claim(uint256 id) external {\n"
                    "        if (balances[id] > 0) {\n"
                    "            payable(msg.sender).transfer(balances[id]);\n"
                    "        }\n"
                    "    }"
                ),
            ),
            source=self.TIGHT,
        ).records
        assert record.locator.function == "claim"
        assert (record.locator.start_line, record.locator.end_line) == (2, 6)


class TestASpanCoveringTwoFunctionsNamesNeither:
    """Found in a published record, not in a test.

    An excerpt matched a region beginning on `claimFlux`'s closing brace and
    running into the next function's body. The enclosing declaration was read
    off the span's *first* line, so the record named `claimFlux` while the
    report's own title named `getClaimableFlux`. Every check passed: the span
    was inside the file, and the report asserted no function name for `verify`
    to cross-check, so there was nothing to contradict.
    """

    TWO = """\
contract V {
    function first(uint256 a) external {
        total = a;
    }

    function second(uint256 b) external {
        total = b;
    }
}
"""

    def test_a_quote_straddling_a_boundary_is_refused(self) -> None:
        report = run(
            a_draft(
                contract=None,
                function=None,
                quoted_source=(
                    "    }\n\n    function second(uint256 b) external {\n        total = b;"
                ),
            ),
            source=self.TWO,
        )
        assert report.records == ()
        assert report.by_cause == {NormalizeCause.SPAN_STRADDLES_DECLARATIONS: 1}

    def test_a_quote_inside_one_function_is_kept(self) -> None:
        [record] = run(
            a_draft(
                contract=None,
                function=None,
                quoted_source=(
                    "    function second(uint256 b) external {\n        total = b;\n    }"
                ),
            ),
            source=self.TWO,
        ).records
        assert record.locator.function == "second"
