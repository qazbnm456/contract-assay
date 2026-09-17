"""Scoring located findings against pinned ground truth.

Most of this file is about what the scorer refuses to claim. A scorer that
overstates is worse than one that reports less, because the figure it produces
looks exactly like a figure that does not have the problem.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contract_assay.corpus.records import (
    CommitPin,
    CorpusRecord,
    CorpusSplit,
    LocatorLabel,
    LocatorProvenance,
    NegativeKind,
    NegativeScope,
    Population,
    Provenance,
    SourcePin,
)
from contract_assay.models import (
    CitationStatus,
    DeclaredLimit,
    DetectorRun,
    EvidenceTier,
    FailedCheck,
    Finding,
    InvalidReason,
    LimitKind,
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
    def _resolve(pin: SourcePin) -> str | None:
        return source if pin.path == PATH else None

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
        pin=CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
        locator=Locator(
            file=PATH, contract="Vault", function=function, start_line=start, end_line=end
        ),
        locator_provenance=provenance,
        anchor_line=anchor,
        asserted_labels=[LocatorLabel.CONTRACT, LocatorLabel.FUNCTION],
        classes=[cls],
        provenance=Provenance(platform="p", report_url="https://x/1"),
    )


def a_negative(
    *, cls: VulnerabilityClass = CLS, record_id: str = "vault-clean-for-reentrancy"
) -> CorpusRecord:
    """A record asserting the pinned file holds no instance of `cls`.

    The only thing that licenses a precision figure: a positive record asserts
    an instance exists at one location and says nothing about the rest of its
    file, so an unmatched prediction there is unjudged rather than wrong.
    """
    return CorpusRecord(
        record_id=record_id,
        population=Population.AUDIT_REVIEW,
        split=CorpusSplit.PUBLIC,
        pin=CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
        classes=[],
        negative_for=[cls],
        negative_kind=NegativeKind.CONFIRMED_CLEAN,
        notes="Read every function in the file against the class definition.",
        provenance=Provenance(platform="p", report_url="https://x/2"),
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
        judged = [a_record(), a_negative()]
        clean = only(score([a_run([(5, 6)])], judged, resolver()))
        sprayed = only(score([a_run([(5, 6)], unverifiable=3)], judged, resolver()))
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
            a_negative(),
        ]
        got = only(score([a_run([(5, 6), (15, 16)])], records, resolver()))
        assert got.predictions == 2
        assert got.by_strength == {MatchStrength.EXACT: 1, MatchStrength.FILE: 1}
        assert got.precision(MatchStrength.FUNCTION) == 0.5
        assert got.precision(MatchStrength.FILE) == 1.0

    def test_an_extra_prediction_is_a_false_positive_at_every_floor(self) -> None:
        # With one record, a second prediction cannot be assigned however close
        # it is, so it counts against precision at the weakest floor too.
        got = only(score([a_run([(5, 6), (15, 16)])], [a_record(), a_negative()], resolver()))
        assert got.predictions == 2
        assert got.precision(MatchStrength.FILE) == 0.5

    def test_spraying_claims_lowers_precision(self) -> None:
        got = only(
            score(
                [a_run([(5, 6), (15, 16), (2, 2), (16, 16)])],
                [a_record(), a_negative()],
                resolver(),
            )
        )
        assert got.predictions == 4
        assert got.precision() == 0.25

    def test_precision_is_none_when_nothing_was_claimed(self) -> None:
        got = only(score([a_run([])], [a_record(), a_negative()], resolver()))
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
            pin=CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
            classes=[],
            negative_for=[CLS],
            vulnerable_to=[VulnerabilityClass.SLIPPAGE],
            negative_kind=__import__(
                "contract_assay.corpus.records", fromlist=["NegativeKind"]
            ).NegativeKind.CROSS_CLASS,
            provenance=Provenance(platform="p", report_url="https://x/1"),
        )
        report = score([a_run([(5, 6)])], [negative], resolver())
        # The class is in the matrix, because a negative speaking to it licenses
        # a precision figure. What it must not do is contribute a *record* to be
        # recalled -- so `records` stays zero and recall stays unavailable,
        # which is the thing this test is about.
        [got] = report.by_class.values()
        assert got.records == 0
        assert got.recall() is None
        assert got.false_negatives == 0


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
        return score([a_run([(4, 7)])], [*truths, a_negative()], resolver()).by_class[CLS]

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


class TestAClassTheCorpusDoesNotCover:
    """Findings the corpus cannot adjudicate are counted, not dropped.

    Found by running three detectors against eleven real records: 90 verified
    findings went in and 2 came out. The class-keyed loop visited only the
    classes the records carried, so 88 findings were emitted, verified against
    source, and tidied away -- §7.2's failure mode on §7.2's own metric. Nothing
    failed when that was the behaviour, which is why these tests exist.
    """

    OTHER = VulnerabilityClass.INSECURE_RANDOMNESS

    def _report(self):  # type: ignore[no-untyped-def]
        return score(
            [a_run([(4, 7)]), a_run([(4, 7), (9, 12), (14, 16)], cls=self.OTHER)],
            [a_record(), a_negative()],
            resolver(),
        )

    def test_the_claims_are_counted(self) -> None:
        assert self._report().unscoreable_claims == {self.OTHER: 3}

    def test_the_runs_are_counted(self) -> None:
        assert self._report().unscoreable_runs == {self.OTHER: 1}

    def test_they_enter_no_confusion_matrix(self) -> None:
        # Scoring them as false positives is the opposite overclaim: with no
        # record of that class the corpus has no standing to call them wrong.
        report = self._report()
        assert self.OTHER not in report.by_class
        assert report.by_class[CLS].precision(MatchStrength.EXACT) == 1.0

    def test_the_statement_says_so(self) -> None:
        statement = self._report().statement()
        assert "3 verified findings could not be adjudicated" in statement
        assert "insecure_randomness (3)" in statement

    def test_every_measured_run_is_stratified(self) -> None:
        # These tables describe the submission. Restricted to scoreable classes
        # they described the corpus's coverage instead, while looking the same.
        assert sum(self._report().by_level.values()) == 2
        assert sum(self._report().by_tier.values()) == 2

    def test_a_clean_run_in_an_uncovered_class_adds_no_claims(self) -> None:
        report = score([a_run([], cls=self.OTHER)], [a_record()], resolver())
        assert report.unscoreable_claims == {}
        assert report.unscoreable_runs == {self.OTHER: 1}


class TestADeclaredLimit:
    """A fact about the instrument, reported apart from an estimate from a sample.

    A score moves as records are added; a demonstrated blindness does not, which
    is why it is certain at one record where no score ever is. Reporting it
    beside the score as a caveat would lose the certain half and make both read
    as provisional.
    """

    ENTRY = DeclaredLimit(
        kind=LimitKind.BLINDNESS,
        shape="a guard that is present and unsound",
        demonstrated_by="vault-reentrancy-1",
        unpatched_because="soundness needs caller-taint, which is the semantic tier",
        closed_when="the semantic tier lands",
    )

    def _report(self, *, closed: bool = False, extra_record: bool = False):  # type: ignore[no-untyped-def]
        entry = self.ENTRY.model_copy(update={"closed_by": "abc1234"}) if closed else self.ENTRY
        run = a_run([]).model_copy(update={"declared_limits": [entry]})
        records = [a_record()]
        if extra_record:
            records.append(
                a_record(record_id="vault-reentrancy-2", start=10, end=13, function="withdraw")
            )
        return score([run], records, resolver())

    def test_it_travels_on_the_report(self) -> None:
        assert self._report().declared_limits == {CLS: (self.ENTRY,)}

    def test_it_gets_its_own_sentence(self) -> None:
        statement = self._report().statement()
        assert "Declared and open limits" in statement
        assert "a guard that is present and unsound" in statement
        assert "vault-reentrancy-1" in statement
        assert "a score moves as records are added and a declared limit does not" in statement

    def test_a_miss_it_names_is_accounted_for(self) -> None:
        assert self._report().unexplained_misses == {CLS: 0}

    def test_a_miss_it_does_not_name_is_not(self) -> None:
        # The one thing self-declaration cannot supply: nothing forces a
        # detector to declare a blindness it would rather not, so an undeclared
        # miss costs visibility rather than nothing.
        assert self._report(extra_record=True).unexplained_misses == {CLS: 1}

    def test_a_closed_entry_stops_accounting_for_anything(self) -> None:
        # The register is a work list, not a graveyard: a closed entry no longer
        # excuses a miss, so a regression shows up as an unexplained one.
        assert self._report(closed=True).unexplained_misses == {CLS: 1}
        assert "known blindness declared and unpatched" not in self._report(closed=True).statement()

    def test_a_class_nothing_ran_against_has_no_unexplained_misses(self) -> None:
        # Its records are unmeasured rather than missed. Counting them would
        # merge "the detector did not see it" with "there is no detector".
        report = score([], [a_record()], resolver())
        assert report.by_class[CLS].false_negatives == 1
        assert report.unexplained_misses == {}


class TestDeclaringReadsBetterThanNotDeclaring:
    """The incentive, pinned rather than left emergent.

    This is the first mechanism here whose adversary is a stranger rather than a
    mistake. If a reader took "three declared blindnesses" as weakness, a
    submission wanting to look good would declare nothing, its misses would land
    in the unaccounted count, and the mechanism would produce exactly the silence
    it exists to prevent. So declaring must move a number that reads badly and
    must not add one that grows -- and an incentive that is correct by accident
    stops being correct the first time somebody reformats the output.
    """

    ENTRY = DeclaredLimit(
        kind=LimitKind.BLINDNESS,
        shape="a guard that is present and unsound",
        demonstrated_by="vault-reentrancy-1",
        unpatched_because="soundness needs caller-taint",
        closed_when="the semantic tier lands",
    )

    def _report(self, *, declaring: bool):  # type: ignore[no-untyped-def]
        run = a_run([])
        if declaring:
            run = run.model_copy(update={"declared_limits": [self.ENTRY]})
        return score([run], [a_record()], resolver())

    def test_declaring_reduces_the_unaccounted_misses(self) -> None:
        assert self._report(declaring=False).unexplained_misses == {CLS: 1}
        assert self._report(declaring=True).unexplained_misses == {CLS: 0}

    def test_declaring_adds_no_count_that_grows(self) -> None:
        # The entries are named, never totalled. A total would be the figure a
        # submission is punished for, and it would also be arithmetic that does
        # not hold, since entries are not units of work.
        statement = self._report(declaring=True).statement()
        assert "1 declared limit" not in statement
        assert "limits declared" not in statement
        assert "Declared and open limits" in statement

    def test_the_statement_says_which_figure_is_the_weakness(self) -> None:
        # In the report's own text, so a later reader does not have to infer the
        # sign from the structure.
        statement = self._report(declaring=True).statement()
        assert "the figure to read as a weakness" in statement
        assert "moves a miss out of it" in statement

    def test_not_declaring_leaves_the_miss_visible_as_unaccounted(self) -> None:
        # The silence still costs something, which is the whole point: it is not
        # punished less than honesty, it is punished more.
        assert sum(self._report(declaring=False).unexplained_misses.values()) == 1


class TestTheRegisterCannotBeSummed:
    """A record can trip several independently sufficient blindnesses.

    Close any one and the record stays invisible, so a count of open entries is
    not a count of remaining work. The relation is recorded and the consumer
    decides the policy -- the same ruling the caller/callee duplicates got
    (§6.7), for the same reason: collapsing or summing encodes a policy in a
    number whose arithmetic then fails.
    """

    def _two_entries(self):  # type: ignore[no-untyped-def]
        shapes = ("a guard that is present and unsound", "a state change through a call")
        entries = [
            DeclaredLimit(
                kind=LimitKind.BLINDNESS,
                shape=shape,
                demonstrated_by="vault-reentrancy-1",
                unpatched_because="needs the semantic tier",
                closed_when="the semantic tier lands",
                isolated=False,
            )
            for shape in shapes
        ]
        run = a_run([]).model_copy(update={"declared_limits": entries})
        return score([run], [a_record()], resolver())

    def test_the_relation_is_recorded(self) -> None:
        report = self._two_entries()
        assert len(report.limits_by_record["vault-reentrancy-1"]) == 2

    def test_the_statement_says_the_entries_do_not_add_up(self) -> None:
        statement = self._two_entries().statement()
        assert "Entries are not units of work" in statement
        assert "1 record above is named by more than one" in statement

    def test_one_record_is_still_accounted_for_once(self) -> None:
        # Two entries naming one record do not excuse two misses.
        assert self._two_entries().unexplained_misses == {CLS: 0}

    def test_a_closed_entry_leaves_the_relation(self) -> None:
        # Only open entries are work; a closed one stops accounting and stops
        # appearing, so a record whose other entry is still open is not silently
        # promoted to visible.
        entries = [
            DeclaredLimit(
                kind=LimitKind.BLINDNESS,
                shape="a",
                demonstrated_by="vault-reentrancy-1",
                unpatched_because="r",
                closed_when="the semantic tier lands",
                isolated=False,
                closed_by="abc1234",
            ),
            DeclaredLimit(
                kind=LimitKind.BLINDNESS,
                shape="b",
                demonstrated_by="vault-reentrancy-1",
                unpatched_because="r",
                closed_when="the semantic tier lands",
                isolated=False,
            ),
        ]
        run = a_run([]).model_copy(update={"declared_limits": entries})
        report = score([run], [a_record()], resolver())
        assert len(report.limits_by_record["vault-reentrancy-1"]) == 1
        assert report.unexplained_misses == {CLS: 0}


class TestTheTwoKindsOfLimitStayApart:
    """An indeterminacy correctly reported is the instrument working.

    So it must not read as a defect. Merging the kinds would make an honest
    submission look worse than one that silently guessed, which is the same
    incentive the missing total fixed, one level in -- between two kinds of
    declaration rather than between declaring and not.
    """

    def _report(self, kind: LimitKind):  # type: ignore[no-untyped-def]
        limit = DeclaredLimit(
            kind=kind,
            shape="a state change through an external call",
            demonstrated_by="vault-reentrancy-1",
            unpatched_because="the callee is not in the unit",
            closed_when="the callee's bytes come into scope",
        )
        run = a_run([]).model_copy(update={"declared_limits": [limit]})
        return score([run], [a_record()], resolver())

    def test_the_kind_is_named_in_the_statement(self) -> None:
        assert "[indeterminacy]" in self._report(LimitKind.INDETERMINACY).statement()
        assert "[blindness]" in self._report(LimitKind.BLINDNESS).statement()

    def test_the_statement_says_what_each_kind_means(self) -> None:
        statement = self._report(LimitKind.INDETERMINACY).statement()
        assert "the instrument correctly reporting that something is unknowable" in statement
        assert "something the instrument should see and does not" in statement

    def test_both_kinds_account_for_a_miss_equally(self) -> None:
        # Declaring either is the honest act, so neither is punished relative to
        # the other. What is punished is silence.
        for kind in (LimitKind.BLINDNESS, LimitKind.INDETERMINACY):
            assert self._report(kind).unexplained_misses == {CLS: 0}

    def test_what_closes_it_is_stated_not_derived(self) -> None:
        # Deriving it from the kind would encode a general claim -- better
        # analysis closes blindnesses, more scope closes indeterminacies -- of
        # exactly the sort that has already been wrong here once.
        assert "closed when the callee's bytes come into scope" in (
            self._report(LimitKind.INDETERMINACY).statement()
        )

    def test_a_limit_must_state_its_kind(self) -> None:
        with pytest.raises(ValidationError):
            DeclaredLimit(  # type: ignore[call-arg]
                shape="x",
                demonstrated_by="vault-reentrancy-1",
                unpatched_because="y",
                closed_when="z",
            )

    def test_a_limit_must_say_what_would_close_it(self) -> None:
        with pytest.raises(ValidationError):
            DeclaredLimit(  # type: ignore[call-arg]
                kind=LimitKind.BLINDNESS,
                shape="x",
                demonstrated_by="vault-reentrancy-1",
                unpatched_because="y",
            )


class TestWhatTheCorpusHasStandingToJudge:
    """A positive record does not establish completeness.

    It asserts an instance exists at a location and says nothing about whether
    others exist elsewhere in the same file. So an unmatched prediction there is
    unjudged, not wrong -- the same standing argument that keeps an uncovered
    class's findings out of the matrix, which had not been applied here because
    this class happened to have records.

    Reporting a figure anyway understates precision by an amount that varies
    with how thoroughly each unit was annotated, and understates it most for the
    most productive predicates.
    """

    def test_a_positive_only_corpus_licenses_no_precision(self) -> None:
        got = only(score([a_run([(5, 6), (15, 16)])], [a_record()], resolver()))
        assert got.predictions == 2
        assert got.precision(MatchStrength.FILE) is None

    def test_the_unjudged_predictions_are_counted(self) -> None:
        # The matched one is judged: the record it matched asserts an instance
        # is there. The other is not, and precision needs both.
        got = only(score([a_run([(5, 6), (15, 16)])], [a_record()], resolver()))
        assert got.unjudged_predictions == 1
        assert got.judged_predictions == 1
        assert got.pool_is_fully_judged is False

    def test_a_negative_record_licenses_it(self) -> None:
        got = only(score([a_run([(5, 6), (15, 16)])], [a_record(), a_negative()], resolver()))
        assert got.judged_predictions == 2
        assert got.unjudged_predictions == 0
        assert got.precision(MatchStrength.FILE) == 0.5

    def test_a_negative_for_another_class_licenses_nothing(self) -> None:
        other = a_negative(
            cls=VulnerabilityClass.INSECURE_RANDOMNESS, record_id="vault-clean-for-randomness"
        )
        got = only(score([a_run([(5, 6), (15, 16)])], [a_record(), other], resolver()))
        assert got.precision(MatchStrength.FILE) is None
        assert got.completeness_records == 0

    def test_no_negative_is_distinguishable_from_an_uncovered_unit(self) -> None:
        # Two states that would otherwise share the single appearance of n/a.
        # Judged units counts where something was judged, so a prediction in
        # the record's own file lands in one at file strength -- which is the
        # known weakness of that floor (§7) rather than a surprise here.
        absent = only(score([a_run([(5, 6)], file="src/Other.sol")], [a_record()], resolver()))
        assert absent.completeness_records == 0 and absent.judged_units == 0
        elsewhere = only(
            score(
                [a_run([(15, 16)], file="src/Other.sol")],
                [a_record(), a_negative()],
                resolver(),
            )
        )
        assert elsewhere.completeness_records == 1 and elsewhere.judged_units == 0

    def test_the_statement_says_the_corpus_cannot_judge_them(self) -> None:
        statement = score([a_run([(5, 6), (15, 16)])], [a_record()], resolver()).statement()
        assert "1 prediction is not yet adjudicated" in statement
        assert "no standing to call it right or wrong" in statement
        # Named per class with a count, because the number is the work
        # outstanding rather than a property of the source.
        assert "reentrancy 1" in statement
        assert "driven by what was predicted" in statement


class TestOnlySomeNegativesLicenseCompleteness:
    """ "Cheap to verify" and "sufficient for the purpose" are different properties.

    A post-fix negative needs no human judgement to verify -- the same file at
    the fix commit, and the verifier confirms it -- and what it verifies is that
    one reported defect is gone. Other instances of the class may remain.
    Bridging that to completeness needs the assumption that the audit found
    every instance in the file, which is the corpus-completeness assumption
    §7.3 refuses one level down.

    Found by trying to file one and reading what the field claims, not by
    reasoning about the kinds.
    """

    def _negative(self, kind: NegativeKind) -> CorpusRecord:
        extra: dict[str, object] = {}
        if kind is NegativeKind.POST_FIX:
            extra = {
                "pin": CommitPin(repo_url="https://github.com/x/y", commit="b" * 40, path=PATH),
                "provenance": Provenance(
                    platform="p", report_url="https://x/3", fix_commit="b" * 40
                ),
            }
        elif kind is NegativeKind.CROSS_CLASS:
            extra = {"vulnerable_to": [VulnerabilityClass.INSECURE_RANDOMNESS]}
        return a_negative().model_copy(update={"negative_kind": kind, **extra})

    def test_a_post_fix_negative_licenses_nothing(self) -> None:
        got = only(
            score(
                [a_run([(5, 6), (15, 16)])],
                [a_record(), self._negative(NegativeKind.POST_FIX)],
                resolver(),
            )
        )
        assert got.completeness_records == 0
        assert got.precision(MatchStrength.FILE) is None
        # One prediction is assigned to the single record and judged by it.
        # Matching is one-to-one, so the second cannot be, and the post-fix
        # negative speaks for no region -- the pool is not fully judged and
        # precision stays absent.
        assert got.unjudged_predictions == 1
        assert got.pool_is_fully_judged is False

    def test_a_confirmed_clean_negative_licenses_it(self) -> None:
        got = only(
            score(
                [a_run([(5, 6), (15, 16)])],
                [a_record(), self._negative(NegativeKind.CONFIRMED_CLEAN)],
                resolver(),
            )
        )
        assert got.completeness_records == 1
        assert got.precision(MatchStrength.FILE) == 0.5

    def test_a_cross_class_negative_licenses_it(self) -> None:
        # The human had to name what the file *is* vulnerable to, so the
        # assertion is reviewable and covers the whole file.
        got = only(
            score(
                [a_run([(5, 6), (15, 16)])],
                [a_record(), self._negative(NegativeKind.CROSS_CLASS)],
                resolver(),
            )
        )
        assert got.completeness_records == 1
        assert got.precision(MatchStrength.FILE) == 0.5

    def test_the_kind_carries_the_distinction(self) -> None:
        # A property of the kind, not of negatives in general, which is the
        # error it exists to prevent.
        assert NegativeKind.POST_FIX.licenses_completeness is False
        assert NegativeKind.CROSS_CLASS.licenses_completeness is True
        assert NegativeKind.CONFIRMED_CLEAN.licenses_completeness is True


class TestJudgingWhatWasPredicted:
    """Precision without a completeness claim anywhere.

    If what gets judged is the set of locations something predicted, then every
    prediction is judged by construction and precision is defined over them --
    while no record asserts what a file does not contain. Judging is driven by
    what was claimed rather than by the size of the corpus, which is the
    standard treatment of incomplete relevance judgements.

    It is also the only hand review worth doing here: a confirmation resting on
    a structural absence licenses nothing, because the absence that makes it
    cheap is the absence the predicate looks for.
    """

    def _adjudication(self, start: int, end: int, record_id: str) -> CorpusRecord:
        return a_negative(record_id=record_id).model_copy(
            update={
                "negative_kind": NegativeKind.ADJUDICATED,
                "locator": Locator(
                    file=PATH,
                    contract="Vault",
                    function="unrelated",
                    start_line=start,
                    end_line=end,
                ),
                "locator_provenance": LocatorProvenance.STATED,
                "notes": "The read here sets a deadline; nothing treats it as unpredictable.",
            }
        )

    def test_an_adjudication_judges_the_prediction_it_overlaps(self) -> None:
        got = only(
            score(
                [a_run([(5, 6), (15, 16)])],
                [a_record(), self._adjudication(15, 16, "vault-adjudicated-1")],
                resolver(),
            )
        )
        # Two judged: the one that matched a record, and the one adjudicated as
        # not an instance. Which is the whole pool, so precision is available.
        assert got.judged_predictions == 2
        assert got.unjudged_predictions == 0
        assert got.adjudications == 1
        assert got.pool_is_fully_judged is True

    def test_judging_every_prediction_defines_precision(self) -> None:
        # The whole point: two predictions, one matched, one adjudicated as not
        # an instance, and precision is 50% with no file-wide claim made.
        got = only(
            score(
                [a_run([(5, 6), (15, 16)])],
                [a_record(), self._adjudication(15, 16, "vault-adjudicated-1")],
                resolver(),
            )
        )
        assert got.completeness_records == 0
        assert got.precision(MatchStrength.FILE) == 0.5

    def test_an_adjudication_licenses_no_completeness(self) -> None:
        # It speaks for a location, so it must not be counted among the records
        # that speak for a file.
        assert NegativeKind.ADJUDICATED.licenses_completeness is False
        assert NegativeKind.ADJUDICATED.scope is NegativeScope.LOCATION
        assert NegativeKind.CONFIRMED_CLEAN.scope is NegativeScope.FILE
        assert NegativeKind.POST_FIX.scope is NegativeScope.NOTHING

    def test_an_adjudication_elsewhere_judges_nothing(self) -> None:
        got = only(
            score(
                [a_run([(15, 16)], file="src/Other.sol")],
                [a_record(), self._adjudication(30, 31, "vault-adjudicated-2")],
                resolver(),
            )
        )
        assert got.adjudications == 1
        assert got.judged_predictions == 0
        assert got.precision(MatchStrength.FILE) is None

    def test_an_adjudication_must_say_where(self) -> None:
        # Without a location it is a file-wide claim wearing a narrower name.
        payload = a_negative().model_dump(mode="json") | {
            "negative_kind": "adjudicated",
            "locator": None,
        }
        with pytest.raises(ValidationError, match="must say which location"):
            CorpusRecord.model_validate(payload)

    def test_an_adjudication_must_say_what_was_found(self) -> None:
        # The judgement is the record's whole content, and "examined" is not
        # reviewable.
        payload = self._adjudication(15, 16, "vault-adjudicated-1").model_dump(mode="json")
        payload["notes"] = "   "
        payload["locator_provenance"] = LocatorProvenance.STATED.value
        with pytest.raises(ValidationError, match="must record what was found"):
            CorpusRecord.model_validate(payload)


class TestACallEdgeIsNotTheSameFunction:
    """One rule settles the locator question, and this is its scoring surface.

    **Nothing weaker than the same function counts as the same location, and
    everything weaker is reported as its own named strength.** So a prediction
    in a callee of a record's function is not a function match; it is
    `call_adjacent`, which has its own figure and is never folded into the
    function one.

    No corpus record exercises this tier yet, which is stated rather than
    implied: the two cases that motivated it are not resolved by it, and §4.2
    records why.
    """

    ADJACENT = """\
contract Vault {
    uint256 total;

    function entry(uint256 amount) external {
        _work(amount);
    }

    function _work(uint256 amount) internal {
        total += amount;
    }

    function unrelated(uint256 amount) external {
        total -= amount;
    }

    function _twice(uint256 a) internal {}

    function _twice(uint256 a, uint256 b) internal {}

    function overloadCaller() external {
        _twice(1);
    }
}
"""

    def _record(self, start: int, end: int, function: str) -> CorpusRecord:
        return a_record(start=start, end=end, function=function)

    def _strength_of(self, prediction: tuple[int, int], record: CorpusRecord) -> str:
        report = score([a_run([prediction])], [record], resolver(self.ADJACENT))
        [match] = report.matches
        return match.strength.value

    def test_a_callee_of_the_records_function_is_call_adjacent(self) -> None:
        # The record is at the entry point and the prediction is in the callee.
        assert self._strength_of((9, 10), self._record(4, 6, "entry")) == "call_adjacent"

    def test_the_caller_direction_counts_too(self) -> None:
        assert self._strength_of((4, 6), self._record(8, 10, "_work")) == "call_adjacent"

    def test_an_unrelated_function_is_only_a_file_match(self) -> None:
        assert self._strength_of((12, 14), self._record(4, 6, "entry")) == "file"

    def test_the_same_function_is_still_stronger(self) -> None:
        # The tier sits below `function`, so it must never capture what the
        # stricter tiers would.
        assert self._strength_of((5, 5), self._record(4, 6, "entry")) == "exact"

    def test_an_overloaded_name_is_refused_rather_than_resolved(self) -> None:
        # An overload would make two unrelated functions look adjacent, and
        # refusing is the rule the declaration index applies everywhere else.
        assert self._strength_of((20, 20), self._record(16, 16, "_twice")) == "file"

    def test_it_ranks_between_file_and_function(self) -> None:
        assert (
            MatchStrength.FILE.rank < MatchStrength.CALL_ADJACENT.rank < MatchStrength.FUNCTION.rank
        )

    def test_recall_at_the_function_floor_ignores_it(self) -> None:
        # Which is the whole reason it is a tier rather than a relaxation: the
        # figure §1.1 requires stays exactly as strict.
        got = only(
            score([a_run([(9, 10)])], [self._record(4, 6, "entry")], resolver(self.ADJACENT))
        )
        assert got.recall(MatchStrength.FUNCTION) == 0.0
        assert got.recall(MatchStrength.CALL_ADJACENT) == 1.0
