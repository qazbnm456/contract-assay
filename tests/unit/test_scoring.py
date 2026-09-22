"""Scoring located findings against pinned ground truth.

Most of this file is about what the scorer refuses to claim. A scorer that
overstates is worse than one that reports less, because the figure it produces
looks exactly like a figure that does not have the problem.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

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
    load_records,
)
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
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
    VerifiedSource,
    recheck_citations,
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
        total = total - amount;
    }

    function withdraw(uint256 amount, address to) external {
        payable(to).transfer(amount);
        total = total - amount;
    }

    function unrelated() external {
        total = total * 0;
    }

    function filler1() external { total = total + 1; }
    function filler2() external { total = total + 2; }
    function filler3() external { total = total + 3; }
    function filler4() external { total = total + 4; }
    function filler5() external { total = total + 5; }
    function filler6() external { total = total + 6; }
    function filler7() external { total = total + 7; }
    function filler8() external { total = total + 8; }
    function filler9() external { total = total + 9; }
    function filler10() external { total = total + 10; }
    function filler11() external { total = total + 11; }
    function filler12() external { total = total + 12; }
    function filler13() external { total = total + 13; }
    function filler14() external { total = total + 14; }
    function filler15() external { total = total + 15; }
    function filler16() external { total = total + 16; }
    function filler17() external { total = total + 17; }
    function filler18() external { total = total + 18; }
    function filler19() external { total = total + 19; }
    function filler20() external { total = total + 20; }
    function filler21() external { total = total + 21; }
    function filler22() external { total = total + 22; }
    function filler23() external { total = total + 23; }
    function filler24() external { total = total + 24; }
    function filler25() external { total = total + 25; }
    function filler26() external { total = total + 26; }
    function filler27() external { total = total + 27; }
    function filler28() external { total = total + 28; }
    function filler29() external { total = total + 29; }
    function filler30() external { total = total + 30; }
    function filler31() external { total = total + 31; }
    function filler32() external { total = total + 32; }
    function filler33() external { total = total + 33; }
    function filler34() external { total = total + 34; }
    function filler35() external { total = total + 35; }
    function filler36() external { total = total + 36; }
    function filler37() external { total = total + 37; }
    function filler38() external { total = total + 38; }
    function filler39() external { total = total + 39; }
    function filler40() external { total = total + 40; }
    function filler41() external { total = total + 41; }
    function filler42() external { total = total + 42; }
    function filler43() external { total = total + 43; }
    function filler44() external { total = total + 44; }
    function filler45() external { total = total + 45; }
}
"""


PLANT = (
    "contract Plant {\n"
    + "\n".join(f"    function everything{n}() external {{ }}" for n in range(60))
    + "\n}\n"
)
"""One contract whose functions are not the record's, for the two-read attack."""


def _at(start: int, end: int, source: str = SOURCE) -> str:
    """The exact text of SOURCE at those lines, so a fixture's citation is true.

    A span past the end of SOURCE falls back to a marker that is not in it --
    a test citing line 40 of a 17-line file is testing a broken citation, and
    should get one rather than a silently passing quote.
    """
    lines = source.split("\n")
    if end > len(lines) or start < 1 or end < start:
        return "beyond the end of this source"
    return "\n".join(lines[start - 1 : end])


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
    platform: str = "p",
    repo: str = "y",
) -> CorpusRecord:
    return CorpusRecord(
        record_id=record_id,
        population=Population.AUDIT_REVIEW,
        split=CorpusSplit.PUBLIC,
        pin=CommitPin(repo_url=f"https://github.com/x/{repo}", commit="a" * 40, path=PATH),
        locator=Locator(
            file=PATH, contract="Vault", function=function, start_line=start, end_line=end
        ),
        locator_provenance=provenance,
        anchor_line=anchor,
        asserted_labels=[LocatorLabel.CONTRACT, LocatorLabel.FUNCTION],
        classes=[cls],
        provenance=Provenance(platform=platform, report_url="https://x/1"),
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
    source_id: str | None = None,
    source: str = SOURCE,
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
                # Quoted out of SOURCE at the span being cited. The fixture used
                # to say `quote="x"` for every span, which passed only because
                # nothing re-read the source -- the exact self-certification the
                # scorer now refuses, so a fixture relying on it was testing a
                # hole rather than a figure.
                quote=_at(a, b, source),
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
                # Deliberately not in the source: this one is the unverifiable
                # claim the test is about, and it arrives already rejected.
                quote="this text is nowhere in the source",
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
        # Defaults to the record's own `source_id`, because the scorer resolves
        # a run's source through the pin that shares it. An invented id has no
        # pin, so nothing can re-read the quote and every finding is demoted as
        # unchecked -- correct behaviour, and it used to be invisible because
        # nothing re-read anything.
        source_id=source_id if source_id is not None else a_record().pin.source_id,
        outcome=outcome,
        evidence_tier=None if outcome is Outcome.SKIPPED else EvidenceTier.SYNTACTIC,
        findings=[] if outcome is Outcome.SKIPPED else findings,
        invalid_reason=InvalidReason.SCHEMA_VIOLATION if outcome is Outcome.INVALID else None,
        skip_reason=SkipReason.UNPARSEABLE if outcome is Outcome.SKIPPED else None,
        # Named, because a run carrying findings has to say what produced them.
        # These fixtures are deterministic, which is a claim rather than a gap.
        produced_without_a_model=outcome is not Outcome.SKIPPED,
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

    def test_without_source_nothing_is_scored_at_all(self) -> None:
        # This used to report a FILE-strength match with function strength
        # unavailable. It cannot any more, and the change is the point: without
        # source the scorer cannot re-read a quote, and a submitted run arrives
        # with `status: verified` set by whoever wrote it. Accepting an unchecked
        # citation is how a hand-written file tops a leaderboard.
        report = score([a_run([(5, 6)])], [a_record()], None)
        got = only(report)
        assert got.by_strength == {}
        assert got.predictions == 0
        assert report.unchecked_citations == 1
        assert "an unchecked citation is not a passed one" in report.statement()

    def test_unresolvable_source_degrades_the_same_way(self) -> None:
        report = score([a_run([(5, 6)])], [a_record()], resolver(None))
        assert report.unchecked_citations == 1
        assert only(report).predictions == 0

    def test_an_anchored_record_is_scored_against_its_anchor(self) -> None:
        # The span was widened from the anchor, so requiring overlap with the
        # span would accept a prediction anywhere in the function.
        record = a_record(provenance=LocatorProvenance.ANCHORED, anchor=5, start=4, end=7)
        covering = only(score([a_run([(5, 5)])], [record], resolver()))
        # Line 6, not 7: line 7 is a bare `}` and a punctuation-only quote is
        # now refused, so citing it would test the citation check rather than
        # the anchor.
        missing = only(score([a_run([(6, 6)])], [record], resolver()))
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
                # (1, 2) rather than (2, 2), and (18, 18) rather than (16, 16):
                # a bare `}` and a lone `uint256 total;` are spans the language
                # supplies, and a citation over one is refused -- which would
                # make this a test of the citation check instead of of precision.
                [a_run([(5, 6), (15, 16), (1, 2), (18, 18)])],
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
        demonstrated_by=("vault-reentrancy-1",),
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
        demonstrated_by=("vault-reentrancy-1",),
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
                demonstrated_by=("vault-reentrancy-1",),
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
                demonstrated_by=("vault-reentrancy-1",),
                unpatched_because="r",
                closed_when="the semantic tier lands",
                isolated=False,
                closed_by="abc1234",
            ),
            DeclaredLimit(
                kind=LimitKind.BLINDNESS,
                shape="b",
                demonstrated_by=("vault-reentrancy-1",),
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
            demonstrated_by=("vault-reentrancy-1",),
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
                demonstrated_by=("vault-reentrancy-1",),
                unpatched_because="y",
                closed_when="z",
            )

    def test_a_limit_must_say_what_would_close_it(self) -> None:
        with pytest.raises(ValidationError):
            DeclaredLimit(  # type: ignore[call-arg]
                kind=LimitKind.BLINDNESS,
                shape="x",
                demonstrated_by=("vault-reentrancy-1",),
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
        total = total - amount;
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
        report = score(
            [a_run([prediction], source=self.ADJACENT)], [record], resolver(self.ADJACENT)
        )
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
        # (5, 6) rather than (5, 5): `_work(amount);` alone is five tokens and
        # a span that short cannot be cited, which would test the citation
        # check rather than the tier.
        assert self._strength_of((5, 6), self._record(4, 6, "entry")) == "exact"

    def test_an_overloaded_name_is_refused_rather_than_resolved(self) -> None:
        # An overload would make two unrelated functions look adjacent, and
        # refusing is the rule the declaration index applies everywhere else.
        assert self._strength_of((20, 20), self._record(16, 16, "_twice")) == "file"

    def test_the_same_signature_in_another_contract_is_not_the_same_function(self) -> None:
        # `Declaration.signature` is `name(paramtypes)` with no qualifier, and a
        # *file* holds several contracts. Unqualified, a prediction inside one
        # contract's `getThePrice(address)` scored a `function` match against a
        # record in another's -- and two of the three records this affects have
        # their twin in a one-line interface stub, quotable from the published
        # function name alone. The signature is qualified by its enclosing type.
        source = """\
contract A {
    function price(address token) external view returns (uint256) {
        return 1;
    }
}

interface B {
    function price(address token) external view returns (uint256);
}
"""
        record = a_record(start=2, end=4, function="price")
        report = score(
            [a_run([(8, 8)], source=source)], [record], resolver(source), predictions_per_unit=9
        )
        [match] = report.matches
        assert match.strength is MatchStrength.FILE

    def test_receive_and_fallback_in_one_contract_are_not_one_function(self) -> None:
        # The pair the grammar gives one kind and two names, so
        # `Declaration.signature` calls both `receive()`. A review cited
        # `fallback() external payable {}` against a record whose locator is the
        # `receive()` line above it and scored a `function` match -- and the
        # record publishes the function name and the line, so the quote is
        # derivable from the corpus alone. The identity carries the
        # declaration's own line span, which two declarations cannot share.
        source = """\
contract Gateway {
    receive() external payable { emit Received(msg.value); }
    fallback() external payable { emit Fell(msg.sender); }
}
"""
        record = a_record(start=2, end=2, function="receive")
        report = score([a_run([(3, 3)], source=source)], [record], resolver(source))
        [match] = report.matches
        assert match.strength is MatchStrength.FILE

    def test_it_ranks_between_file_and_function(self) -> None:
        assert (
            MatchStrength.FILE.rank < MatchStrength.CALL_ADJACENT.rank < MatchStrength.FUNCTION.rank
        )

    def test_recall_at_the_function_floor_ignores_it(self) -> None:
        # Which is the whole reason it is a tier rather than a relaxation: the
        # figure §1.1 requires stays exactly as strict.
        got = only(
            score(
                [a_run([(9, 10)], source=self.ADJACENT)],
                [self._record(4, 6, "entry")],
                resolver(self.ADJACENT),
            )
        )
        assert got.recall(MatchStrength.FUNCTION) == 0.0
        assert got.recall(MatchStrength.CALL_ADJACENT) == 1.0


class TestAFigureIsAboutItsCorpusComposition:
    """One harvest took the corpus from 32 records to 166, 81% from one platform.

    Every figure over it was then mostly a statement about that platform's
    submission style -- a template with a `### Root Cause` section produces
    located findings at a rate a consolidated report does not -- and nothing in
    the report said so. Stratified here rather than described in a document,
    because a sample's composition belongs beside the numbers drawn from it.
    """

    def _three(self) -> list[CorpusRecord]:
        return [
            a_record(record_id="one", platform="sherlock", repo="alpha"),
            a_record(record_id="two", platform="sherlock", repo="alpha", start=20, end=22),
            a_record(record_id="three", platform="code4rena", repo="beta", start=30, end=32),
        ]

    def test_records_are_counted_by_platform_and_repository(self) -> None:
        report = score([a_run([(5, 6)])], self._three(), resolver())
        assert report.by_platform == {"code4rena": 1, "sherlock": 2}
        assert report.by_repository == {"alpha": 2, "beta": 1}

    def test_the_statement_names_the_largest_shares(self) -> None:
        statement = score([a_run([(5, 6)])], self._three(), resolver()).statement()
        assert "3 records scored come from 2 platforms and 2 repositories" in statement
        assert "largest share is sherlock at 66%" in statement

    def test_a_single_platform_corpus_says_so_rather_than_saying_nothing(self) -> None:
        statement = score(
            [a_run([(5, 6)])], [a_record(platform="sherlock")], resolver()
        ).statement()
        assert "1 records scored come from 1 platform and 1 repositories" in statement
        assert "sherlock at 100%" in statement


class TestAPartialSweepSaysSo:
    """A submission over part of the corpus used to read exactly like a whole one.

    `run` flushes per unit so an interrupted sweep leaves its work behind, the
    runs file records what ran and never what it was asked to run, and
    `completion_rate` is about the runs that arrived. Measured: 35 units of 140
    gave `435 records scored across 9 classes`, `completion_rate 1.0`, `0 runs
    were invalid and 0 skipped`, and a `results` listing that called it
    comparable with a full sweep. The scorer can see it without any change to
    the runs format, because it holds the corpus.
    """

    def test_the_statement_names_the_units_never_run(self) -> None:
        one = a_record(record_id="one")
        other = a_record(record_id="two", repo="elsewhere")
        report = score([a_run([(5, 6)], source_id=one.pin.source_id)], [one, other], resolver())
        assert (report.units_scored, report.units_in_corpus) == (1, 2)
        assert report.unit_coverage == 0.5
        assert "produced runs for 1 of 2 source units" in report.statement()

    def test_a_whole_sweep_says_nothing(self) -> None:
        one = a_record(record_id="one")
        report = score([a_run([(5, 6)], source_id=one.pin.source_id)], [one], resolver())
        assert (report.units_scored, report.units_in_corpus) == (1, 1)
        assert report.unit_coverage == 1.0
        assert "source units" not in report.statement()

    def test_an_invalid_run_still_counts_as_covered(self) -> None:
        # It was run and it answered badly, which is a measurement. Counting it
        # as *not covered* would hide a crashing detector inside a coverage gap.
        one = a_record(record_id="one")
        run = a_run([], source_id=one.pin.source_id, outcome=Outcome.INVALID)
        report = score([run], [one], resolver())
        assert report.units_scored == 1


class TestThePoolIsBounded:
    """The per-unit prediction cap.

    It exists because every prediction has to be adjudicated before precision
    exists for its class, so an uncapped pool is a queue nobody can work
    through -- a submission that proposed every declaration in every file would
    buy itself an unbounded amount of somebody else's labour.

    Enforced here rather than by whatever ran the submission, because this is
    the only layer that sees a whole submission's runs at once.
    """

    def test_the_first_n_are_scored_in_the_order_returned(self) -> None:
        # Not re-ranked. A harness that puts its best finding first is making
        # exactly the choice the cap asks it to make.
        runs = [a_run([(5, 6), (20, 21), (30, 31), (40, 41)])]
        got = only(score(runs, [a_record()], resolver(), predictions_per_unit=2))
        assert got.predictions == 2
        assert got.capped_predictions == 2
        # The first span is the one that matches the record, and it survived.
        assert got.by_strength == {MatchStrength.EXACT: 1}

    def test_each_unit_gets_its_own_quota(self) -> None:
        # Two records in two repositories, so two `source_id`s -- an invented one
        # has no pin, and the scorer then has no source to re-read a quote
        # against, which demotes every finding as unchecked.
        one = a_record(record_id="vault-reentrancy-1", repo="one")
        two = a_record(record_id="vault-reentrancy-2", repo="two")
        runs = [
            a_run([(5, 6), (20, 21)], source_id=one.pin.source_id),
            a_run([(5, 6), (20, 21)], source_id=two.pin.source_id),
        ]
        got = only(score(runs, [one, two], resolver(), predictions_per_unit=1))
        assert (got.predictions, got.capped_predictions) == (2, 2)

    def test_one_file_pinned_at_two_commits_is_one_quota(self) -> None:
        # `source_id` carries the commit, so the same file at two revisions is
        # two keys -- and the corpus pins eight paths that way, seven of them
        # byte-identical under both pins. A submission may declare either, so a
        # quota on `source_id` gave those records twice the guesses. The quota
        # keys on `SourcePin.unit_id`, which is the file across revisions.
        one = a_record(record_id="vault-reentrancy-1")
        two = a_record(
            record_id="vault-reentrancy-2",
            start=20,
            end=21,
        )
        moved = two.model_copy(update={"pin": two.pin.model_copy(update={"commit": "b" * 40})})
        assert one.pin.source_id != moved.pin.source_id
        assert one.pin.unit_id == moved.pin.unit_id
        runs = [
            a_run([(5, 6)], source_id=one.pin.source_id),
            a_run([(20, 21)], source_id=moved.pin.source_id),
        ]
        got = only(score(runs, [one, moved], resolver(), predictions_per_unit=1))
        assert (got.predictions, got.capped_predictions) == (1, 1)

    def test_two_detectors_in_one_class_share_the_quota(self) -> None:
        # The case a cap applied per run cannot see: a condition quantified over
        # a set gets satisfied by different members, and the set here is the
        # class's runs for one unit.
        runs = [a_run([(5, 6), (20, 21)]), a_run([(30, 31), (40, 41)])]
        got = only(score(runs, [a_record()], resolver(), predictions_per_unit=3))
        assert (got.predictions, got.capped_predictions) == (3, 1)

    def test_a_capped_prediction_joins_no_adjudication_queue(self) -> None:
        # The whole purpose. An entry in the queue is work somebody has to do.
        runs = [a_run([(5, 6), (20, 21), (30, 31)])]
        uncapped = score(runs, [a_record()], resolver())
        capped = score(runs, [a_record()], resolver(), predictions_per_unit=1)
        assert len(uncapped.unjudged) == 2
        assert len(capped.unjudged) == 0

    def test_the_default_cap_is_generous_and_is_a_cap(self) -> None:
        # It used to be no cap at all, on the argument that a cap states how
        # much adjudication an exercise will fund. That argument was about the
        # queue and it missed the figure: recall over an unbounded pool is not a
        # measurement, and a review published one by submitting 668,655 quotes.
        got = only(score([a_run([(5, 6), (20, 21), (30, 31)])], [a_record()], resolver()))
        assert (got.predictions, got.capped_predictions) == (3, 0)
        ten = only(score([a_run([(20 + n, 21 + n) for n in range(10)])], [a_record()], resolver()))
        assert (ten.predictions, ten.capped_predictions) == (DEFAULT_PREDICTIONS_PER_UNIT, 1)

    def test_the_default_cap_covers_the_shipped_corpus(self) -> None:
        # A cap below the most records any one unit-class pair holds would put a
        # perfect recall out of reach. The constant is checked against the
        # corpus here because a constant relied on in one place and justified in
        # another is a constant that rots.
        records = load_records(Path(__file__).resolve().parents[2] / "corpus" / "records")
        per_unit_class: Counter[tuple[str, VulnerabilityClass]] = Counter()
        for record in records:
            if record.locator is None or not record.is_positive:
                continue
            for cls in record.classes:
                per_unit_class[(record.pin.source_id, cls)] += 1
        assert max(per_unit_class.values()) <= DEFAULT_PREDICTIONS_PER_UNIT

    def test_the_cap_can_be_lifted_for_tooling(self) -> None:
        # `None` is the explicit opt-out, for a consumer that wants the whole
        # pool -- not what a submission gets by default.
        got = only(
            score(
                [a_run([(20 + n, 21 + n) for n in range(10)])],
                [a_record()],
                resolver(),
                predictions_per_unit=None,
            )
        )
        assert (got.predictions, got.capped_predictions) == (10, 0)

    def test_a_cap_of_zero_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            score([a_run([(5, 6)])], [a_record()], resolver(), predictions_per_unit=0)

    def test_a_refused_citation_spends_a_slot(self) -> None:
        # The quota used to skip a refused citation before charging for it,
        # which made the citation check a free search oracle: a review submitted
        # 668,655 generated quotes, had 666,233 refused at no cost, and kept
        # whatever landed. A finding whose citation failed is still a claim the
        # submission made about a location.
        runs = [a_run([(5, 6)], unverifiable=4)]
        got = only(score(runs, [a_record()], resolver(), predictions_per_unit=1))
        assert got.capped_predictions == 4
        # And the one slot it did spend went to whichever finding came first,
        # which is the submission's own ordering and is not reordered here.
        assert got.predictions + got.unverifiable_claims == 1

    def test_a_claim_the_cap_did_not_score_is_neither_a_hit_nor_a_false_positive(self) -> None:
        # Symmetry, and the reason `unverifiable_claims` is counted inside the
        # quota: a finding the cap did not score is not a prediction, so
        # charging precision for it would charge for something that was
        # excluded from the denominator.
        got = only(score([a_run([(5, 6)], unverifiable=4)], [a_record()], resolver()))
        assert (got.unverifiable_claims, got.capped_predictions) == (4, 0)

    def test_the_statement_says_the_cap_and_what_it_cost(self) -> None:
        # A precision over three predictions per unit and one over every
        # prediction a submission cared to make are different measurements.
        report = score(
            [a_run([(5, 6), (20, 21), (30, 31)])], [a_record()], resolver(), predictions_per_unit=1
        )
        statement = report.statement()
        assert "At most 1 prediction per source unit per class was scored" in statement
        assert "2 further predictions went unscored" in statement
        assert report.predictions_per_unit == 1

    def test_a_cap_nobody_reached_still_says_so(self) -> None:
        report = score([a_run([(5, 6)])], [a_record()], resolver(), predictions_per_unit=3)
        assert "no submission reached that limit" in report.statement()


class TestTheScorerTakesNobodysWordForACitation:
    """The four forgeries that scored without reading anything.

    Every one of these was measured against the whole published corpus before it
    was closed, and none had a test -- `refuted_citations`, `recheck_citations`
    and `quote_is_at` appeared nowhere under `tests/`, so the 12-to-0 figure in
    the commit message was a hand measurement that nothing pinned. A review
    found that, and then found three more forgeries the commit had not closed.

    What these tests do NOT establish is in `recheck_citations`' docstring: the
    corpus publishes the locator, so quoting the real span is not a forgery this
    or any check can refuse.
    """

    def a_submitted_run(
        self, quote: str, span: tuple[int, int] = (5, 6), **over: Any
    ) -> DetectorRun:
        """A run as a third party submits one: `status` already set to verified."""
        record = a_record()
        fields: dict[str, Any] = {
            "detector_id": "submitted",
            "class_id": CLS,
            "source_id": record.pin.source_id,
            "outcome": Outcome.VULNERABLE,
            "evidence_tier": EvidenceTier.SYNTACTIC,
            "produced_without_a_model": True,
            "findings": [
                VerifiedFinding(
                    finding=Finding(
                        detector_id="submitted",
                        locator=Locator(file=PATH, start_line=span[0], end_line=span[1]),
                        quote=quote,
                        reasoning="submitted as verified",
                    ),
                    status=CitationStatus.VERIFIED,
                )
            ],
        }
        return DetectorRun.model_validate({**fields, **over})

    def test_a_quote_absent_from_the_source_is_refuted(self) -> None:
        report = score([self.a_submitted_run("THIS TEXT IS NOWHERE")], [a_record()], resolver())
        assert report.refuted_citations == 1
        assert only(report).predictions == 0
        assert "did not survive re-reading" in report.statement()

    @pytest.mark.parametrize(
        "quote",
        [
            # Punctuation, the first forgery found.
            ";",
            "}",
            "{",
            "();",
            "  ;  ",
            "+",
            # Short substrings of ordinary identifiers, the second. `"er"` is
            # inside `require`, `transfer` and `reserve`, and it scored micro
            # recall 0.938 with precision 0.953 over the whole published corpus
            # while a test parametrized only the punctuation above -- so the
            # suite locked in the strings and not the class, and 1141 tests
            # passed with the hole open.
            "er",
            "re",
            "to",
            "ss",
            "ab",
            # A single token, however real: it names something that appears in
            # most spans rather than this one.
            "function",
            "require",
            "address",
            "total",
            # Two tokens, still below the floor.
            "total =",
            "function f",
        ],
    )
    def test_a_quote_that_names_no_span_in_particular_establishes_nothing(self, quote: str) -> None:
        report = score([self.a_submitted_run(quote)], [a_record()], resolver())
        assert report.refuted_citations == 1, f"{quote!r} established a citation"
        assert only(report).predictions == 0

    def test_the_span_a_submission_declares_quoted_back_is_accepted(self) -> None:
        # The other direction. A submission that cites one statement narrows its
        # locator to that statement and quotes it, which is a better locator
        # than the function and scores the same: measured over the whole
        # corpus, quoting one real statement with the locator narrowed to it
        # scores 0.9954, exactly what quoting the whole declared span scores.
        report = score([self.a_submitted_run(_at(6, 6), (6, 6))], [a_record()], resolver())
        assert (report.refuted_citations, report.unchecked_citations) == (0, 0)
        assert only(report).predictions == 1

    def test_whole_lines_inside_a_wider_span_are_accepted(self) -> None:
        # A locator a line wider than the lines quoted is a locator, not a
        # forgery. Demanding equality here cost an honest submission 0.993 ->
        # 0.076 over the whole corpus, against a forger who was getting 0.034.
        report = score(
            [self.a_submitted_run("total = total - amount;", (4, 7))], [a_record()], resolver()
        )
        assert (report.refuted_citations, report.unchecked_citations) == (0, 0)
        assert only(report).predictions == 1

    def test_a_prediction_is_scored_where_its_quote_matched(self) -> None:
        # The span is the submitter's own field and nothing downstream read it:
        # `_strength` takes the containing function from `start_line` alone, so
        # a submission could declare the published start line and an end line
        # hundreds of lines later, keep `exact` strength, and reduce its whole
        # problem to naming one line of a large window. Measured, that took a
        # blind submission from 0.041 to 0.145, and 0.092 of it needed nothing
        # but braces and keywords.
        runs, refuted, unchecked, _stale, moved, elsewhere = recheck_citations(
            [self.a_submitted_run(_at(6, 6), (4, 50))], [a_record()], resolver()
        )
        assert (refuted, unchecked) == (0, 0)
        # And it is reported: an unreported disagreement is the shape of defect
        # this file keeps finding. Here the move stays inside the function the
        # declared locator names, so only the weaker counter rises.
        assert (moved, elsewhere) == (1, 0)
        [finding] = runs[0].findings
        assert finding.status is CitationStatus.VERIFIED
        assert (finding.finding.locator.start_line, finding.finding.locator.end_line) == (6, 6)

    def test_a_locator_that_already_matches_is_not_reported_as_moved(self) -> None:
        # The counter has to mean something, so the guard has to hold: a build
        # that reports every verified citation as repositioned passes every
        # other test here, and the honest-exact submission would read 429
        # instead of 2.
        runs, refuted, unchecked, _stale, moved, elsewhere = recheck_citations(
            [self.a_submitted_run(_at(5, 6), (5, 6))], [a_record()], resolver()
        )
        assert (refuted, unchecked) == (0, 0)
        assert (moved, elsewhere) == (0, 0)
        assert runs[0].findings[0].finding.locator.start_line == 5

    def test_a_widened_span_no_longer_buys_the_function_it_started_in(self) -> None:
        # The consequence, at the level the figures read: a quote matched in
        # another function is scored in that other function, which is a file
        # match and not a function one.
        report = score([self.a_submitted_run(_at(15, 15), (4, 20))], [a_record()], resolver())
        assert report.refuted_citations == 0
        [match] = report.matches
        assert match.strength is MatchStrength.FILE
        # And the report says the scorer replaced the claim rather than
        # tightening it: the declared locator names `withdraw`, the quote is in
        # `unrelated`. Measured on an honest submission five lines wide on both
        # sides, 283 of 431 predictions land in another callable this way.
        assert (report.repositioned_predictions, report.repositioned_into_another_function) == (
            1,
            1,
        )
        assert "in a callable other than the one the declared locator names" in report.statement()

    def test_the_unit_is_read_once_and_the_gate_covers_that_read(self) -> None:
        # The scorer read each unit twice and gated one read. `parsed_for`
        # resolved the unit again, ungated, and its parse decided match
        # strength -- so the bytes that settled recall were not the bytes the
        # citation gate had covered. Measured over the whole corpus, one
        # submission differing only in when the bytes change: 0.0000 when both
        # reads saw the plant, 0.9402 when it arrived after the gate.
        reads: list[str] = []
        digest = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
        record = a_record()
        pinned = record.model_copy(update={"pin": record.pin.model_copy(update={"sha256": digest})})

        def resolve(pin: SourcePin) -> str | None:
            reads.append(pin.source_id)
            # Honest on the first read, a plant on every one after it.
            return SOURCE if len(reads) == 1 else PLANT

        report = score([a_run([(5, 6)])], [pinned], resolve)
        assert reads == [pinned.pin.source_id]
        [match] = report.matches
        assert match.strength is MatchStrength.EXACT

    def test_the_digest_bearing_pin_wins_whatever_order_it_arrives_in(self) -> None:
        # `source_id` excludes the digest, so several records collapse to one
        # unit -- and a last-write-wins dict let one digest-less record disable
        # the gate for every other record pinning the same unit. Four units in
        # the shipped corpus pair a digest-bearing record with a later
        # `*-adjudicated-*` record that has none, and the forged `--source-root`
        # forgery leaked exactly those four. The rule moved into
        # `VerifiedSource` and its test did not follow: a review reverted it and
        # scored four records against planted bytes with every gate green.
        digest = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
        with_digest = a_record(record_id="one")
        with_digest = with_digest.model_copy(
            update={"pin": with_digest.pin.model_copy(update={"sha256": digest})}
        )
        without = a_record(record_id="two", start=20, end=21)
        assert without.pin.sha256 is None
        assert with_digest.pin.source_id == without.pin.source_id

        for order in ([with_digest, without], [without, with_digest]):
            reader = VerifiedSource(order, resolver(PLANT))
            # The plant is not this unit's source, so the gate refuses it --
            # which it can only do if it chose the pin that carries a digest.
            assert reader.of(with_digest.pin.source_id) is None
            assert reader.why(with_digest.pin.source_id) == "digest_mismatch"
            assert reader.pin_for(with_digest.pin.source_id).sha256 == digest

    def test_a_digest_mismatch_says_so_instead_of_naming_the_flag(self) -> None:
        # Both reasons printed "no source was available for this unit ... run
        # with --source-root", which is two false clauses for a mismatch: a
        # source was available and the flag was passed. Measured, an honest
        # submission reads 0.9931 on a clean checkout and 0.9356 with one stale
        # file, and the sentence sent the reader to check a flag they had given.
        record = a_record()
        pinned = record.model_copy(
            update={"pin": record.pin.model_copy(update={"sha256": "0" * 64})}
        )
        report = score([a_run([(5, 6)])], [pinned], resolver())
        assert report.unchecked_citations == 1
        assert "does not match this unit's recorded digest" in report.statement()
        assert "run with --source-root" not in report.statement()

    def test_the_demoted_finding_names_the_digest_in_its_own_detail(self) -> None:
        # The statement is built from the counter; this is the per-finding
        # detail, which is what a consumer reading the runs sees. Collapsing
        # both messages into "no source was available ... run with
        # --source-root" leaves every gate green.
        record = a_record()
        pinned = record.model_copy(
            update={"pin": record.pin.model_copy(update={"sha256": "0" * 64})}
        )
        runs, _, unchecked, stale, *_ = recheck_citations([a_run([(5, 6)])], [pinned], resolver())
        assert (unchecked, stale) == (1, 1)
        [check] = runs[0].findings[0].failed_checks
        assert "recorded digest" in check.detail
        # It may name the flag as *where* the bytes came from; what it must not
        # do is recommend passing it, which is the advice that was wrong.
        assert "run with --source-root" not in check.detail
        assert "contract-assay fetch" in check.detail

    def test_a_quote_that_starts_mid_line_is_refused(self) -> None:
        # The forgery a whole-line rule closes and a token-run rule does not:
        # a generic run that straddles line boundaries. `for (uint256 i = 0; i <`
        # is ten tokens, clears the six-token floor, and sits inside hundreds of
        # published spans -- 0.126 over the whole corpus, reading no source.
        report = score(
            [self.a_submitted_run("msg.sender).transfer(amount);", (4, 7))],
            [a_record()],
            resolver(),
        )
        assert report.refuted_citations == 1
        assert only(report).predictions == 0

    def test_a_quote_that_straddles_tokens_is_refused(self) -> None:
        # `otal = total - amoun` is a substring of the span and not a run of its
        # tokens. Before both sides were tokenised, a substring was enough.
        report = score(
            [self.a_submitted_run("otal = total - amoun", (6, 6))], [a_record()], resolver()
        )
        assert report.refuted_citations == 1

    def test_a_locator_naming_another_file_is_refuted(self) -> None:
        # Measured at recall 1.000 over the whole corpus: every run declared one
        # donor unit, quoted real text out of it, and pointed its locator at a
        # different repository. The quote was checked against neither file.
        run = self.a_submitted_run(_at(5, 6))
        elsewhere = run.findings[0].finding.locator.model_copy(update={"file": "src/Other.sol"})
        moved = run.model_copy(
            update={
                "findings": [
                    run.findings[0].model_copy(
                        update={
                            "finding": run.findings[0].finding.model_copy(
                                update={"locator": elsewhere}
                            )
                        }
                    )
                ]
            }
        )
        report = score([moved], [a_record()], resolver())
        assert report.refuted_citations == 1
        assert only(report).predictions == 0

    def test_the_refusal_names_the_file_mismatch(self) -> None:
        run = self.a_submitted_run(_at(5, 6))
        elsewhere = run.findings[0].finding.locator.model_copy(update={"file": "src/Other.sol"})
        moved = run.model_copy(
            update={
                "findings": [
                    run.findings[0].model_copy(
                        update={
                            "finding": run.findings[0].finding.model_copy(
                                update={"locator": elsewhere}
                            )
                        }
                    )
                ]
            }
        )
        rechecked, refuted, *_ = recheck_citations([moved], [a_record()], resolver())
        assert refuted == 1
        names = [c.check for f in rechecked[0].findings for c in f.failed_checks]
        assert "citation_file_is_not_the_units_file" in names

    def test_source_that_does_not_match_the_pin_is_not_used(self) -> None:
        # `--source-root` is the submitter's in the documented publishing
        # workflow. A directory of synthetic files whose declarations sit at the
        # records' locator lines scored access control at recall 0.982 with
        # precision 1.0, so the scorer was verifying a submission against the
        # submission.
        # The shared fixture pins no digest, so this one does: without a digest
        # there is nothing to check and the record says so rather than this
        # hiding it.
        import hashlib

        record = a_record()
        pinned = record.pin.model_copy(
            update={"sha256": hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()}
        )
        record = record.model_copy(update={"pin": pinned})
        report = score(
            [self.a_submitted_run(_at(5, 6))],
            [record],
            lambda pin: "contract Forged { uint256 total; }\n" * 9,
        )
        assert report.unchecked_citations == 1
        assert only(report).predictions == 0

    def test_an_honest_submission_is_untouched(self) -> None:
        # The other half: nothing above may cost a true citation.
        report = score([self.a_submitted_run(_at(5, 6))], [a_record()], resolver())
        assert (report.refuted_citations, report.unchecked_citations) == (0, 0)
        assert only(report).predictions == 1

    def test_quoting_the_real_span_is_not_refused_and_that_is_the_point(self) -> None:
        # Measured at micro recall 0.9977 with precision 1.0 in all nine
        # classes. It is not a forgery this check can refuse -- the corpus
        # publishes the locator and `fetch` builds the scorer's checkout from
        # the same public coordinates. The test exists so that nobody reads the
        # four refusals above as a neutrality guarantee.
        report = score([self.a_submitted_run(_at(4, 7), span=(4, 7))], [a_record()], resolver())
        assert (report.refuted_citations, report.unchecked_citations) == (0, 0)
        assert only(report).predictions == 1
