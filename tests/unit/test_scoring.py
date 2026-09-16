"""Scoring located findings against pinned ground truth.

Most of this file is about what the scorer refuses to claim. A scorer that
overstates is worse than one that reports less, because the figure it produces
looks exactly like a figure that does not have the problem.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.records import (
    CorpusRecord,
    CorpusSplit,
    LocatorLabel,
    LocatorProvenance,
    Population,
    Provenance,
    SourcePin,
)
from contract_assay.models import (
    CitationStatus,
    DetectorRun,
    EvidenceTier,
    FailedCheck,
    Finding,
    InvalidReason,
    Locator,
    Outcome,
    RejectionKind,
    SkipReason,
    VerifiedFinding,
    VulnerabilityClass,
)
from contract_assay.report.scoring import (
    MINIMUM_RECORDS_PER_CLASS,
    MatchStrength,
    score,
)

pytestmark = pytest.mark.offline

PATH = "src/Vault.sol"
CLS = VulnerabilityClass.REENTRANCY

SOURCE = """\
contract Vault {
    uint256 total;

    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        total -= amount;
    }

    function withdraw(uint256 amount, address to) external {
        payable(to).transfer(amount);
        total -= amount;
    }

    function unrelated() external {
        total = 0;
    }
}
"""


def resolver(source: str | None = SOURCE):  # type: ignore[no-untyped-def]
    def _resolve(repo_url: str, commit: str, path: str) -> str | None:
        return source if path == PATH else None

    return _resolve


def a_record(
    *,
    record_id: str = "vault-reentrancy-1",
    start: int = 4,
    end: int = 7,
    function: str = "withdraw",
    provenance: LocatorProvenance = LocatorProvenance.STATED,
    anchor: int | None = None,
    cls: VulnerabilityClass = CLS,
) -> CorpusRecord:
    return CorpusRecord(
        record_id=record_id,
        population=Population.AUDIT_REVIEW,
        split=CorpusSplit.PUBLIC,
        pin=SourcePin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
        locator=Locator(
            file=PATH, contract="Vault", function=function, start_line=start, end_line=end
        ),
        locator_provenance=provenance,
        anchor_line=anchor,
        asserted_labels=[LocatorLabel.CONTRACT, LocatorLabel.FUNCTION],
        classes=[cls],
        provenance=Provenance(platform="p", report_url="https://x/1"),
    )


def a_run(
    spans: list[tuple[int, int]],
    *,
    cls: VulnerabilityClass = CLS,
    outcome: Outcome | None = None,
    unverifiable: int = 0,
    file: str = PATH,
) -> DetectorRun:
    # `vulnerable` requires a verified finding and `clean` forbids one, so the
    # outcome follows from the spans unless a test is specifically about an
    # outcome that is not a measurement.
    if outcome is None:
        outcome = Outcome.VULNERABLE if spans else Outcome.CLEAN
    findings = [
        VerifiedFinding(
            finding=Finding(
                detector_id="d",
                quote="x",
                reasoning="r",
                locator=Locator(file=file, start_line=a, end_line=b),
            ),
            status=CitationStatus.VERIFIED,
        )
        for a, b in spans
    ]
    findings += [
        VerifiedFinding(
            finding=Finding(
                detector_id="d",
                quote="x",
                reasoning="r",
                locator=Locator(file=PATH, start_line=1, end_line=1),
            ),
            status=CitationStatus.UNVERIFIED,
            failed_checks=[
                FailedCheck(check="citation_quote_absent_from_source", kind=RejectionKind.CITATION)
            ],
        )
        for _ in range(unverifiable)
    ]
    return DetectorRun(
        detector_id="d",
        class_id=cls,
        source_id="s",
        outcome=outcome,
        evidence_tier=None if outcome is Outcome.SKIPPED else EvidenceTier.SYNTACTIC,
        findings=[] if outcome is Outcome.SKIPPED else findings,
        invalid_reason=InvalidReason.SCHEMA_VIOLATION if outcome is Outcome.INVALID else None,
        skip_reason=SkipReason.UNPARSEABLE if outcome is Outcome.SKIPPED else None,
    )


def only(report, cls: VulnerabilityClass = CLS):  # type: ignore[no-untyped-def]
    return report.by_class[cls]


class TestMatchStrength:
    def test_a_prediction_in_the_right_function_matches_at_exact(self) -> None:
        got = only(score([a_run([(5, 6)])], [a_record()], resolver()))
        assert got.by_strength == {MatchStrength.EXACT: 1}

    def test_the_same_function_without_overlap_matches_at_function(self) -> None:
        # The detector named the right function and pointed at a different line
        # in it. A weaker claim, and a real one.
        got = only(score([a_run([(4, 4)])], [a_record(start=6, end=6)], resolver()))
        assert got.by_strength == {MatchStrength.FUNCTION: 1}

    def test_a_different_function_in_the_same_file_matches_at_file_only(self) -> None:
        got = only(score([a_run([(15, 16)])], [a_record()], resolver()))
        assert got.by_strength == {MatchStrength.FILE: 1}

    def test_a_different_file_matches_nothing(self) -> None:
        got = only(score([a_run([(5, 6)], file="src/Other.sol")], [a_record()], resolver()))
        assert got.matched == 0
        assert got.false_negatives == 1


class TestOverloadsAreNotTheSameFunction:
    """Names are shared; signatures are not."""

    def test_the_wrong_overload_does_not_reach_function_strength(self) -> None:
        # `withdraw(uint256)` spans 4-7 and `withdraw(uint256,address)` spans
        # 9-12. A prediction in the second names the right *name*.
        got = only(score([a_run([(10, 11)])], [a_record(start=4, end=7)], resolver()))
        assert got.by_strength == {MatchStrength.FILE: 1}

    def test_the_right_overload_does(self) -> None:
        got = only(score([a_run([(10, 11)])], [a_record(start=9, end=12)], resolver()))
        assert got.by_strength == {MatchStrength.EXACT: 1}


class TestWhatTheScorerRefusesToClaim:
    def test_a_prose_derived_record_cannot_support_exact(self) -> None:
        # Its span is the whole function, so any prediction inside overlaps and
        # `exact` would be satisfied trivially.
        record = a_record(provenance=LocatorProvenance.DERIVED)
        got = only(score([a_run([(5, 6)])], [record], resolver()))
        assert got.by_strength == {MatchStrength.FUNCTION: 1}
        assert got.exact_unavailable == 1

    def test_without_source_function_strength_is_unavailable_not_guessed(self) -> None:
        # Comparing names instead would let the wrong overload score as right.
        got = only(score([a_run([(5, 6)])], [a_record()], None))
        assert got.by_strength == {MatchStrength.FILE: 1}
        assert got.function_unavailable == 1

    def test_unresolvable_source_degrades_the_same_way(self) -> None:
        got = only(score([a_run([(5, 6)])], [a_record()], resolver(None)))
        assert got.function_unavailable == 1

    def test_an_anchored_record_is_scored_against_its_anchor(self) -> None:
        # The span was widened from the anchor, so requiring overlap with the
        # span would accept a prediction anywhere in the function.
        record = a_record(provenance=LocatorProvenance.ANCHORED, anchor=5, start=4, end=7)
        covering = only(score([a_run([(5, 5)])], [record], resolver()))
        missing = only(score([a_run([(7, 7)])], [record], resolver()))
        assert covering.by_strength == {MatchStrength.EXACT: 1}
        assert missing.by_strength == {MatchStrength.FUNCTION: 1}


class TestErrorsStayOutOfTheMatrix:
    def test_invalid_and_skipped_runs_are_counted_beside_it(self) -> None:
        runs = [
            a_run([(5, 6)]),
            a_run([], outcome=Outcome.INVALID),
            a_run([], outcome=Outcome.SKIPPED),
        ]
        got = only(score(runs, [a_record()], resolver()))
        assert (got.invalid_runs, got.skipped_runs, got.measured_runs) == (1, 1, 1)
        assert got.matched == 1

    def test_completion_rate_excludes_skips_and_counts_invalids(self) -> None:
        runs = [a_run([(5, 6)]), a_run([], outcome=Outcome.INVALID)]
        got = only(score(runs, [a_record()], resolver()))
        assert got.completion_rate == 0.5

    def test_an_unverifiable_claim_costs_precision(self) -> None:
        # Output that costs nothing to produce must not be free to produce.
        clean = only(score([a_run([(5, 6)])], [a_record()], resolver()))
        sprayed = only(score([a_run([(5, 6)], unverifiable=3)], [a_record()], resolver()))
        assert clean.precision() == 1.0
        assert sprayed.precision() == 0.25


class TestPrecisionCountsEveryPrediction:
    def test_a_weaker_match_is_a_miss_at_a_higher_floor(self) -> None:
        # The denominator is every prediction. One prediction lands in the right
        # function and one only in the right file, so at the `function` floor the
        # second is a miss -- and it is neither a hit there nor an unmatched
        # false positive, so leaving it out of the total would raise the figure
        # by discarding the evidence against it.
        records = [
            a_record(record_id="vault-reentrancy-1", start=4, end=7),
            a_record(record_id="vault-reentrancy-2", start=9, end=12),
        ]
        got = only(score([a_run([(5, 6), (15, 16)])], records, resolver()))
        assert got.predictions == 2
        assert got.by_strength == {MatchStrength.EXACT: 1, MatchStrength.FILE: 1}
        assert got.precision(MatchStrength.FUNCTION) == 0.5
        assert got.precision(MatchStrength.FILE) == 1.0

    def test_an_extra_prediction_is_a_false_positive_at_every_floor(self) -> None:
        # With one record, a second prediction cannot be assigned however close
        # it is, so it counts against precision at the weakest floor too.
        got = only(score([a_run([(5, 6), (15, 16)])], [a_record()], resolver()))
        assert got.predictions == 2
        assert got.precision(MatchStrength.FILE) == 0.5

    def test_spraying_claims_lowers_precision(self) -> None:
        got = only(score([a_run([(5, 6), (15, 16), (2, 2), (16, 16)])], [a_record()], resolver()))
        assert got.predictions == 4
        assert got.precision() == 0.25

    def test_precision_is_none_when_nothing_was_claimed(self) -> None:
        got = only(score([a_run([])], [a_record()], resolver()))
        assert got.precision() is None
        assert got.recall() == 0.0


class TestAssignmentIsOneToOne:
    def test_two_predictions_cannot_both_claim_one_record(self) -> None:
        got = only(score([a_run([(5, 6), (5, 7)])], [a_record()], resolver()))
        assert got.matched == 1
        assert got.false_positives == 1

    def test_maximum_matching_beats_greedy(self) -> None:
        # Two records; one prediction can reach either at exact strength and the
        # other can reach only the second. Greedy taking the first pairing
        # leaves a record unmatched; maximum matching does not.
        records = [
            a_record(record_id="vault-reentrancy-1", start=4, end=7),
            a_record(record_id="vault-reentrancy-2", start=9, end=12, function="withdraw"),
        ]
        got = only(score([a_run([(5, 6), (10, 11)])], records, resolver()))
        assert got.matched == 2
        assert got.false_negatives == 0


class TestStratification:
    def test_records_are_counted_by_provenance_and_population(self) -> None:
        records = [
            a_record(record_id="vault-reentrancy-1"),
            a_record(record_id="vault-reentrancy-2", provenance=LocatorProvenance.DERIVED),
        ]
        report = score([a_run([(5, 6)])], records, resolver())
        assert report.by_provenance == {
            LocatorProvenance.STATED: 1,
            LocatorProvenance.DERIVED: 1,
        }
        assert report.by_population == {Population.AUDIT_REVIEW: 2}

    def test_runs_are_counted_by_level_and_tier(self) -> None:
        report = score([a_run([(5, 6)])], [a_record()], resolver())
        assert report.by_tier == {EvidenceTier.SYNTACTIC: 1}
        assert sum(report.by_level.values()) == 1


class TestTheStatementNamesWhatIsThin:
    def test_a_class_below_the_minimum_is_named(self) -> None:
        report = score([a_run([(5, 6)])], [a_record()], resolver())
        statement = report.statement()
        assert f"minimum of {MINIMUM_RECORDS_PER_CLASS}" in statement
        assert "reentrancy (1)" in statement
        assert report.thin_classes == (CLS,)

    def test_the_assignment_rule_is_always_stated(self) -> None:
        # §7.1 requires it: greedy and optimal give different numbers, so which
        # is in use has to be said where it is used.
        report = score([a_run([(5, 6)])], [a_record()], resolver())
        assert "maximum matching per strength tier" in report.statement()

    def test_an_empty_corpus_says_so(self) -> None:
        assert score([], [], resolver()).statement().startswith("No ground-truth records")

    def test_a_negative_record_is_not_scored_as_a_positive(self) -> None:
        negative = CorpusRecord(
            record_id="vault-clean-1",
            population=Population.AUDIT_REVIEW,
            split=CorpusSplit.PUBLIC,
            pin=SourcePin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
            classes=[],
            negative_for=[CLS],
            vulnerable_to=[VulnerabilityClass.SLIPPAGE],
            negative_kind=__import__(
                "contract_assay.corpus.records", fromlist=["NegativeKind"]
            ).NegativeKind.CROSS_CLASS,
            provenance=Provenance(platform="p", report_url="https://x/1"),
        )
        report = score([a_run([(5, 6)])], [negative], resolver())
        assert report.by_class == {}


class TestOneFindingSatisfiesOneRecord:
    """Matching is one-to-one, and the direction that fact moves a score.

    Recorded as tests because the design once asserted the opposite -- that a
    duplicated ground-truth record would inflate recall, on the assumption that
    one finding matches every copy. Nothing failed when that was written, which
    is the problem: a claim about the scorer with no test behind it is a claim
    about what somebody believed the scorer did.
    """

    def _score(self, records: int):  # type: ignore[no-untyped-def]
        truths = [a_record(record_id=f"dup-record-{i}") for i in range(records)]
        return score([a_run([(4, 7)])], truths, resolver()).by_class[CLS]

    def test_one_finding_cannot_satisfy_two_records(self) -> None:
        assert sum(self._score(2).by_strength.values()) == 1

    def test_the_unmatched_copies_are_counted_as_misses(self) -> None:
        assert self._score(4).false_negatives == 3

    def test_duplication_understates_recall(self) -> None:
        # Not overstates. The factor is the number of reviewers who submitted
        # the same defect, which is why `normalize` folds them (§6.7).
        assert self._score(1).recall(MatchStrength.EXACT) == 1.0
        assert self._score(2).recall(MatchStrength.EXACT) == 0.5
        assert self._score(4).recall(MatchStrength.EXACT) == 0.25

    def test_duplication_leaves_precision_alone(self) -> None:
        # The prediction is matched either way, so only the recall denominator
        # moves. Stated because "duplicates distort the score" is too vague to
        # act on -- it distorts one side of it.
        for records in (1, 2, 4):
            assert self._score(records).precision(MatchStrength.EXACT) == 1.0
