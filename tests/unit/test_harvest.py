"""Harvest, and the losses it has to account for.

The fixture set deliberately over-represents awkward reports relative to their
real frequency. Building an adapter against clean, permalinked reports exercises
the path that was never in danger, while the prose-located path -- the whole
reason span derivation exists -- goes under-tested, and the bias fix ships
untested against the cases it was built for. So two of the reports below are
well-formed and the rest are not.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from pydantic import ValidationError

from contract_assay.corpus.harvest import (
    Candidate,
    DraftRecord,
    RawReport,
    Skip,
    SkipCause,
    harvest,
)
from contract_assay.corpus.records import Provenance
from contract_assay.models import VulnerabilityClass

pytestmark = pytest.mark.offline

SHA = "a" * 40
LABELS = {
    "reentrancy": VulnerabilityClass.REENTRANCY,
    "access control": VulnerabilityClass.ACCESS_CONTROL,
    "unchecked return": VulnerabilityClass.UNCHECKED_EXTERNAL_CALL,
    "arithmetic": VulnerabilityClass.ARITHMETIC_ROUNDING,
    "oracle": VulnerabilityClass.ORACLE_INTEGRITY,
}


class ExampleAdapter:
    """A whole-cloth report format, parsed the way a real adapter would be.

    Each finding is a `## [ID] Title` heading followed by `Key: value` lines.
    Missing keys are the point: every skip cause below is reachable by leaving
    something out, which is how real reports differ from each other.
    """

    platform = "example"

    def candidates(self, report: RawReport) -> Sequence[Candidate]:
        found: list[Candidate] = []
        for block in report.body.split("## ")[1:]:
            fields = self._fields(block)
            label = fields.get("class", "").strip().lower()
            mapped = LABELS.get(label)
            found.append(
                Candidate(
                    candidate_id=block.splitlines()[0].strip(),
                    classes=(mapped,) if mapped else (),
                    raw_labels=(label,) if label else (),
                    title=block.splitlines()[0].strip(),
                )
            )
        return found

    def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
        block = next(
            b
            for b in report.body.split("## ")[1:]
            if b.splitlines()[0].strip() == candidate.candidate_id
        )
        fields = self._fields(block)

        if fields.get("kind") == "informational":
            return Skip(SkipCause.NOT_A_FINDING, "marked informational by the auditors")
        if not candidate.raw_labels:
            return Skip(SkipCause.NO_CLASS, "no class stated")
        if not candidate.classes:
            return Skip(SkipCause.UNMAPPED_CLASS, f"label {candidate.raw_labels[0]!r}")
        if "repo" not in fields:
            return Skip(SkipCause.NO_REPOSITORY)
        if len(fields.get("commit", "")) != 40:
            return Skip(SkipCause.NO_COMMIT, fields.get("commit", "absent"))
        if "file" not in fields:
            return Skip(SkipCause.NO_FILE_PATH)

        lines = fields.get("lines")
        span = tuple(int(part) for part in lines.split("-")) if lines else (None, None)
        if span == (None, None) and "function" not in fields:
            return Skip(SkipCause.NO_LOCATION, "neither a span nor a function name")

        return DraftRecord(
            candidate_id=candidate.candidate_id,
            repo_url=fields["repo"],
            commit=fields["commit"],
            path=fields["file"],
            contract=fields.get("contract"),
            function=fields.get("function"),
            start_line=span[0],
            end_line=span[1],
            classes=candidate.classes,
            provenance=Provenance(
                platform=report.platform,
                report_url=report.report_url,
                reported_severity=fields.get("severity"),
            ),
        )

    @staticmethod
    def _fields(block: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for line in block.splitlines()[1:]:
            key, _, value = line.partition(":")
            if value.strip():
                fields[key.strip().lower().lstrip("*").strip()] = value.strip().strip("*").strip()
        return fields


def report(body: str, url: str = "https://example.invalid/r/1") -> RawReport:
    return RawReport(platform="example", report_url=url, body=body)


# --- Two well-formed reports ------------------------------------------------

PERMALINKED = report(
    f"""\
# Audit
## [H-01] Reentrancy in withdraw
Class: reentrancy
Repo: https://github.com/example/vault
Commit: {SHA}
File: src/Vault.sol
Contract: Vault
Function: withdraw
Lines: 20-24
Severity: high
"""
)

PERMALINKED_TWO = report(
    f"""\
# Audit
## [M-01] Unchecked return in payout
Class: unchecked return
Repo: https://github.com/example/vault
Commit: {SHA}
File: src/Vault.sol
Function: payout
Lines: 30-31
Severity: medium
"""
)

# --- The awkward majority ---------------------------------------------------

PROSE_LOCATION = report(
    f"""\
# Audit
## [H-02] Access control on setOwner
Class: access control
Repo: https://github.com/example/vault
Commit: {SHA}
File: src/Vault.sol
Contract: Vault
Function: setOwner
Severity: high
"""
)
"""A function named in prose, no line numbers. Recoverable by derivation."""

NO_LOCATION_AT_ALL = report(
    f"""\
# Audit
## [H-03] Arithmetic underflow somewhere in the accounting
Class: arithmetic
Repo: https://github.com/example/vault
Commit: {SHA}
File: src/Vault.sol
Severity: high
"""
)
"""Class perfectly clear, location absent. The loss that must stay class-resolved."""

NO_COMMIT = report(
    f"""\
# Audit
## [H-04] Arithmetic rounding in shares
Class: arithmetic
Repo: https://github.com/example/vault
Commit: main
File: src/Vault.sol
Function: shares
Severity: high

## [H-05] Arithmetic overflow in fees
Class: arithmetic
Repo: https://github.com/example/vault
Commit: {SHA[:7]}
File: src/Vault.sol
Function: fees
Severity: high
"""
)
"""A branch name and a short SHA. Neither is reproducible."""

UNMAPPED_AND_UNLABELLED = report(
    """\
# Audit
## [L-01] Gas optimisation in the loop
Class: gas
Repo: https://github.com/example/vault
Commit: bbbb
File: src/Vault.sol

## [L-02] Something odd here
Repo: https://github.com/example/vault
File: src/Vault.sol
"""
)
"""One label outside the nine, one finding with no label at all."""

INFORMATIONAL = report(
    """\
# Audit
## [I-01] Consider adding documentation
Class: access control
Kind: informational
Repo: https://github.com/example/vault
File: src/Vault.sol
"""
)
"""Identified as a candidate, then correctly refused as not a finding."""

NO_REPO = report(
    f"""\
# Audit
## [H-06] Oracle staleness
Class: oracle
Commit: {SHA}
File: src/Oracle.sol
Function: latestPrice
Severity: high
"""
)

AWKWARD_HEAVY = (
    PERMALINKED,
    PERMALINKED_TWO,
    PROSE_LOCATION,
    NO_LOCATION_AT_ALL,
    NO_COMMIT,
    UNMAPPED_AND_UNLABELLED,
    INFORMATIONAL,
    NO_REPO,
)


class TestAccountingIsComplete:
    def test_every_candidate_gets_exactly_one_outcome(self) -> None:
        # The property the two-phase protocol exists for: an adapter cannot drop
        # a candidate without also not enumerating it, which changes a number it
        # does not control.
        adapter = ExampleAdapter()
        enumerated = sum(len(adapter.candidates(r)) for r in AWKWARD_HEAVY)
        result = harvest(adapter, AWKWARD_HEAVY)
        assert result.candidates == enumerated
        assert len(result.drafts) + len(result.skipped) == enumerated

    def test_hiding_a_loss_requires_hiding_the_candidate(self) -> None:
        class Reticent(ExampleAdapter):
            def candidates(self, report: RawReport) -> Sequence[Candidate]:
                # Enumerate only what will succeed.
                return [c for c in super().candidates(report) if c.classes]

        full = harvest(ExampleAdapter(), AWKWARD_HEAVY)
        reticent = harvest(Reticent(), AWKWARD_HEAVY)
        assert reticent.candidates < full.candidates
        assert reticent.yield_rate > full.yield_rate

    def test_the_well_formed_reports_are_extracted(self) -> None:
        result = harvest(ExampleAdapter(), [PERMALINKED, PERMALINKED_TWO])
        assert len(result.drafts) == 2
        assert result.skipped == ()
        assert result.yield_rate == 1.0


class TestLossesAreClassResolved:
    def test_a_class_survives_a_lost_location(self) -> None:
        # The point of separating identification from extraction: the location is
        # unrecoverable and the vulnerability type is perfectly clear.
        result = harvest(ExampleAdapter(), [NO_LOCATION_AT_ALL])
        assert result.drafts == ()
        assert result.skipped_by_class == {VulnerabilityClass.ARITHMETIC_ROUNDING: 1}
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}

    def test_an_unmappable_label_is_counted_apart_from_the_classes(self) -> None:
        # Not a class under-sampled but a candidate whose class is unknown, so it
        # must not be distributed across the classes that are known.
        result = harvest(ExampleAdapter(), [UNMAPPED_AND_UNLABELLED])
        assert result.unclassified_skips == 2
        assert result.skipped_by_class == {}
        assert set(result.by_cause) == {SkipCause.UNMAPPED_CLASS, SkipCause.NO_CLASS}

    def test_per_class_loss_shows_what_an_aggregate_hides(self) -> None:
        # Arithmetic loses everything, unchecked-return loses nothing, and the
        # overall yield says neither.
        result = harvest(ExampleAdapter(), AWKWARD_HEAVY)
        assert result.skip_rate_for(VulnerabilityClass.ARITHMETIC_ROUNDING) == 1.0
        assert result.skip_rate_for(VulnerabilityClass.UNCHECKED_EXTERNAL_CALL) == 0.0
        assert 0.0 < result.yield_rate < 1.0

    def test_a_class_never_seen_has_no_loss_rate(self) -> None:
        result = harvest(ExampleAdapter(), [PERMALINKED])
        assert result.skip_rate_for(VulnerabilityClass.DENIAL_OF_SERVICE) == 0.0

    def test_causes_are_named_individually_not_aggregated(self) -> None:
        # "Could not extract" across seven causes tells an adapter author nothing
        # about what to fix, and a reader nothing about which shapes are lost.
        result = harvest(ExampleAdapter(), AWKWARD_HEAVY)
        assert set(result.by_cause) == {
            SkipCause.NO_LOCATION,
            SkipCause.NO_COMMIT,
            SkipCause.UNMAPPED_CLASS,
            SkipCause.NO_CLASS,
            SkipCause.NOT_A_FINDING,
            SkipCause.NO_REPOSITORY,
        }

    def test_platform_counts_are_kept_alongside_class_counts(self) -> None:
        result = harvest(ExampleAdapter(), AWKWARD_HEAVY)
        assert result.candidates_by_platform == {"example": result.candidates}
        assert result.skipped_by_platform == {"example": len(result.skipped)}


class TestDerivationIsFlaggedUpFront:
    def test_a_prose_located_draft_is_counted_as_needing_derivation(self) -> None:
        result = harvest(ExampleAdapter(), [PROSE_LOCATION])
        [draft] = result.drafts
        assert not draft.has_stated_span
        assert draft.function == "setOwner"
        assert result.derived_span_drafts == 1

    def test_a_permalinked_draft_needs_no_derivation(self) -> None:
        result = harvest(ExampleAdapter(), [PERMALINKED])
        [draft] = result.drafts
        assert draft.has_stated_span
        assert result.derived_span_drafts == 0


class TestTheStatementSaysWhatWasLost:
    def test_it_names_causes_and_the_heaviest_class_losses(self) -> None:
        statement = harvest(ExampleAdapter(), AWKWARD_HEAVY).yield_statement()
        assert "candidates extracted" in statement
        assert "no_commit 2" in statement
        assert "arithmetic_rounding 100%" in statement

    def test_it_names_the_floor_on_its_own_accuracy(self) -> None:
        # An adapter can only count what it recognised as a finding, so a section
        # it never identified is absent from every number. A statement omitting
        # that would overstate its own completeness.
        for reports in (AWKWARD_HEAVY, [PERMALINKED], []):
            statement = harvest(ExampleAdapter(), reports).yield_statement()
            assert "never recognised as a finding is absent" in statement

    def test_it_reports_unattributable_skips_separately(self) -> None:
        statement = harvest(ExampleAdapter(), [UNMAPPED_AND_UNLABELLED]).yield_statement()
        assert "could not be attributed to a class" in statement

    def test_an_empty_run_says_so_rather_than_dividing_by_zero(self) -> None:
        result = harvest(ExampleAdapter(), [])
        assert result.candidates == 0
        assert result.yield_rate == 0.0
        assert result.yield_statement().startswith("No candidates were identified.")


class TestOneBadReportDoesNotLoseTheBatch:
    def test_an_adapter_raising_is_recorded_as_a_skip(self) -> None:
        class Brittle(ExampleAdapter):
            def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
                if "H-01" in candidate.candidate_id:
                    raise ValueError("ran off the end of the table")
                return super().extract(report, candidate)

        result = harvest(Brittle(), [PERMALINKED, PERMALINKED_TWO])
        assert len(result.drafts) == 1
        assert result.by_cause == {SkipCause.MALFORMED_REPORT: 1}
        assert "ran off the end" in result.skipped[0].skip.detail

    def test_the_rest_of_the_batch_still_accounts_for_itself(self) -> None:
        # Letting the exception through would lose the accounting for every other
        # candidate in the batch, which is a larger and less visible loss than
        # one malformed report.
        class AlwaysBroken(ExampleAdapter):
            def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
                raise RuntimeError("nope")

        result = harvest(AlwaysBroken(), AWKWARD_HEAVY)
        assert result.candidates == harvest(ExampleAdapter(), AWKWARD_HEAVY).candidates
        assert len(result.skipped) == result.candidates


class TestADraftMustBeAbleToBecomeARecord:
    def _draft(self, **over: object) -> DraftRecord:
        base: dict[str, object] = {
            "candidate_id": "H-01",
            "repo_url": "https://github.com/example/vault",
            "commit": SHA,
            "path": "src/Vault.sol",
            "function": "withdraw",
            "start_line": 20,
            "end_line": 24,
            "classes": (VulnerabilityClass.REENTRANCY,),
            "provenance": Provenance(platform="example", report_url="https://example.invalid/r/1"),
        }
        return DraftRecord(**{**base, **over})  # type: ignore[arg-type]

    @pytest.mark.parametrize("commit", ["main", "a" * 7, "A" * 40, ""])
    def test_a_commit_that_is_not_a_full_sha_is_refused(self, commit: str) -> None:
        with pytest.raises(ValidationError, match="full 40-character"):
            self._draft(commit=commit)

    def test_a_draft_with_no_span_and_no_function_is_refused(self) -> None:
        # Such a candidate should have been skipped as no_location, where it
        # would have been counted under its class.
        with pytest.raises(ValidationError, match="should have been skipped"):
            self._draft(start_line=None, end_line=None, function=None)

    def test_half_a_span_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="both ends or neither"):
            self._draft(end_line=None)

    def test_a_reversed_span_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="precedes"):
            self._draft(start_line=24, end_line=20)

    def test_a_draft_must_carry_at_least_one_class(self) -> None:
        with pytest.raises(ValidationError):
            self._draft(classes=())

    def test_a_function_without_a_span_is_a_valid_draft(self) -> None:
        draft = self._draft(start_line=None, end_line=None)
        assert draft.function == "withdraw"
        assert not draft.has_stated_span
