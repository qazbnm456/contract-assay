"""bpref: the figure that exists while adjudication is outstanding.

Precision here is all-or-nothing -- one unjudged prediction and the class has no
figure -- and that gate is what leaves a round unrankable while judging is in
progress. bpref dissolves it by ignoring unjudged predictions rather than
counting them either way.

**Most of these assert an exact value.** A ranking measure is easy to write
wrongly in a way that still returns a plausible number between 0 and 1: an
off-by-one in the running count, a cap applied to the wrong list, a sort in the
wrong direction. None of those is visible in a test that only checks the result
is in range, so the cases below are hand-computable and the expected value is
worked out in the docstring rather than copied from a run.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.records import (
    CommitPin,
    CorpusRecord,
    CorpusSplit,
    LocatorProvenance,
    NegativeKind,
    Population,
    Provenance,
)
from contract_assay.models import DifficultyLevel, Locator, VulnerabilityClass
from contract_assay.report.leaderboard import score_submission
from contract_assay.report.scoring import (
    MINIMUM_JUDGED_FOR_BPREF,
    ClassScore,
    JudgedPrediction,
    MatchStrength,
    score,
)
from contract_assay.report.wire import score_document

from .test_scoring import CLS, PATH, a_record, a_run, only, resolver

pytestmark = pytest.mark.offline


def _submitted(report):  # type: ignore[no-untyped-def]
    """A scored submission, which is what the document builder takes."""
    return score_submission(
        "s-1",
        report,
        weights={DifficultyLevel.S: 1.0, DifficultyLevel.M: 2.0, DifficultyLevel.Q: 3.0},
        at_least=MatchStrength.FUNCTION,
    )


def _adjudication(start: int = 14, end: int = 16) -> CorpusRecord:
    """Module-level twin of the method below, for the document tests."""
    return CorpusRecord(
        record_id=f"adjudicated-{start}-{end}",
        population=Population.AUDIT_REVIEW,
        split=CorpusSplit.PUBLIC,
        pin=CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
        classes=[],
        negative_for=[CLS],
        negative_kind=NegativeKind.ADJUDICATED,
        locator=Locator(file=PATH, start_line=start, end_line=end),
        locator_provenance=LocatorProvenance.STATED,
        notes="Read the cited span against the class definition; no instance there.",
        provenance=Provenance(platform="p", report_url="https://x/3"),
    )


HIT = MatchStrength.FUNCTION
WEAK = MatchStrength.FILE


def a_score(
    *judged: JudgedPrediction | None,
    records: int = 2,
    ordered: bool = True,
) -> ClassScore:
    """A class score carrying just what bpref reads."""
    kept = tuple(j for j in judged if j is not None)
    return ClassScore(
        cls=VulnerabilityClass.ACCESS_CONTROL,
        records=records,
        # As many claims as judgements: a real score never has judgements it
        # did not claim, and `bpref` reads `predictions` to tell "claimed
        # nothing" from "claimed without an ordering".
        predictions=len(kept),
        ranked_judgements=kept if ordered else None,
    )


def relevant(score: float) -> JudgedPrediction:
    return JudgedPrediction(score=score, strength=HIT)


def refuted(score: float) -> JudgedPrediction:
    """Judged, and the corpus found no instance at that location."""
    return JudgedPrediction(score=score, strength=None)


class TestTheFormula:
    def test_one_non_relevant_between_two_hits(self) -> None:
        """R=2, N=1, cap=min(2,1)=1. Order: hit, refuted, hit.

        First hit has nothing above it: 1 - 0/1 = 1.0.
        Second hit has one counted non-relevant above it: 1 - 1/1 = 0.0.
        Sum 1.0 over R=2 -> 0.5.
        """
        score = a_score(relevant(0.9), refuted(0.8), relevant(0.7))
        assert score.bpref(HIT) == pytest.approx(0.5)

    def test_a_perfect_ranking_is_one(self) -> None:
        """Both hits above the only non-relevant: 1.0 + 1.0 over R=2."""
        score = a_score(relevant(0.9), relevant(0.8), refuted(0.7))
        assert score.bpref(HIT) == pytest.approx(1.0)

    def test_the_worst_ranking_is_zero(self) -> None:
        """The non-relevant above both hits: 0.0 + 0.0 over R=2."""
        score = a_score(refuted(0.9), relevant(0.8), relevant(0.7))
        assert score.bpref(HIT) == pytest.approx(0.0)

    def test_a_record_nobody_found_stays_in_the_denominator(self) -> None:
        """R is the class's records, not the ones retrieved.

        One hit, one refuted below it, and a second record never found. The hit
        scores 1.0, and dividing by R=2 gives 0.5 -- so bpref declines to reward
        a submission for ranking well over a small part of the corpus, which is
        the property that keeps it from being a precision analogue.
        """
        assert a_score(relevant(0.9), refuted(0.8), records=2).bpref(HIT) == pytest.approx(0.5)
        assert a_score(relevant(0.9), refuted(0.8), records=1).bpref(HIT) == pytest.approx(1.0)

    def test_the_cap_is_min_of_r_and_n(self) -> None:
        """R=1, N=3, cap=1: only the first non-relevant is counted.

        Order: refuted, refuted, refuted, hit. Only the first refuted is inside
        the cap, so the hit sees one above it: 1 - 1/1 = 0.0 over R=1.

        With the cap wrongly taken as N=3 the hit would see three above it and
        `1 - 3/3` is also 0.0 -- which is why the next case exists.
        """
        score = a_score(refuted(0.9), refuted(0.8), refuted(0.7), relevant(0.6), records=1)
        assert score.bpref(HIT) == pytest.approx(0.0)

    def test_non_relevant_beyond_the_cap_are_not_counted(self) -> None:
        """R=2, N=3, cap=2. Order: refuted, hit, refuted, refuted, hit.

        The first two refuted are inside the cap; the third is not.
        First hit: one counted above -> 1 - 1/2 = 0.5.
        Second hit: two counted above -> 1 - 2/2 = 0.0.
        Sum 0.5 over R=2 -> 0.25.

        Counting the third refuted would make the second hit negative, which a
        test that only checked the range would have accepted.
        """
        score = a_score(
            refuted(0.9), relevant(0.8), refuted(0.7), refuted(0.6), relevant(0.5), records=2
        )
        assert score.bpref(HIT) == pytest.approx(0.25)

    def test_the_result_never_goes_below_zero(self) -> None:
        score = a_score(*[refuted(1.0 - i / 10) for i in range(5)], relevant(0.1), records=2)
        value = score.bpref(HIT)
        assert value is not None
        assert 0.0 <= value <= 1.0


class TestWhatCountsAsRelevant:
    def test_a_match_below_the_floor_counts_against_the_submission(self) -> None:
        """It is judged and it is not a hit at this floor.

        Dropping it instead would raise the figure by discarding evidence, which
        is the reasoning `precision` gives for its own denominator. Here the
        weak match sits above the real one, so at a `function` floor it behaves
        exactly as a refuted prediction does: 1 - 1/1 = 0.0 over R=1.
        """
        score = a_score(JudgedPrediction(score=0.9, strength=WEAK), relevant(0.8), records=1)
        assert score.bpref(MatchStrength.FUNCTION) == pytest.approx(0.0)

    def test_the_same_prediction_is_a_hit_at_a_weaker_floor(self) -> None:
        """R=1, and at a `file` floor both are hits, so N=0: each hit has nobody
        above it, and two hits over R=1 is 2.0 -- which is why `R` counts
        records, and a record matched twice is the cap's business, not this one's."""
        score = a_score(JudgedPrediction(score=0.9, strength=WEAK), relevant(0.8), records=2)
        assert score.bpref(MatchStrength.FILE) == pytest.approx(1.0)

    def test_unjudged_predictions_cannot_change_the_figure(self) -> None:
        """The whole point of the measure, asserted as an equality.

        `ranked_judgements` holds judged predictions only, so a submission that
        emitted fifty unadjudicated claims alongside its hit is indistinguishable
        here from one that emitted the hit alone. That is what stops the
        benchmark punishing an entrant for finding defects the corpus has not
        recorded yet -- and under precision the first of those two is unrankable
        while the second is not.

        R=1 with the hit above the one refuted prediction: 1 - 0/1 = 1.0.
        """
        alone = a_score(relevant(0.9), refuted(0.8), records=1)
        assert alone.bpref(HIT) == pytest.approx(1.0)
        # There is no way to pass an unjudged prediction in: the structure
        # admits a strength or a refusal, and an unjudged claim is neither.
        assert len(alone.ranked_judgements or ()) == 2


class TestWhenThereIsNoFigure:
    def test_an_undeclared_ordering_yields_none(self) -> None:
        """A rank is ordinal inside its unit, so arrival order across units is
        this module's loop rather than the submission's intent."""
        assert a_score(relevant(0.9), refuted(0.8), ordered=False).bpref(HIT) is None

    def test_no_positive_record_yields_none(self) -> None:
        assert a_score(relevant(0.9), refuted(0.8), records=0).bpref(HIT) is None


class TestTheFiguresThatUsedToBeRefused:
    """Two cases returned `None` and made the wrong submission unrankable."""

    def test_nothing_judged_non_relevant_is_found_over_r(self) -> None:
        """N=0: every term is 1, so bpref is hits / R (trec_eval's convention).

        Refusing it made the one submission with no known-wrong prediction the
        one that could not be ranked. Precision is 1.0 over an all-hits judged
        set and is not refused; neither is this.
        """
        assert a_score(relevant(0.9), relevant(0.8), records=2).bpref(HIT) == pytest.approx(1.0)
        assert a_score(relevant(0.9), records=4).bpref(HIT) == pytest.approx(0.25)

    def test_nothing_judged_non_relevant_is_still_flagged_thin(self) -> None:
        score = a_score(relevant(0.9), records=4)
        assert score.bpref_basis(HIT) == (4, 0)
        assert score.bpref_below_minimum(HIT)

    def test_claiming_nothing_is_zero_not_absent(self) -> None:
        """No retrieved item, so the sum is empty and R is still the denominator.

        `None` here meant an abstaining submission's total was unavailable --
        unrankable, which is better for it than any zero. Asserted as an exact
        0.0 because the regression is to `None`, and `not x` would pass both.
        """
        empty = ClassScore(cls=VulnerabilityClass.ACCESS_CONTROL, records=2, predictions=0)
        assert empty.ranked_judgements is None
        assert empty.bpref(HIT) == 0.0
        assert empty.bpref(HIT) is not None

    def test_claims_without_an_ordering_are_still_refused(self) -> None:
        """The difference from the case above is `predictions`, and it matters."""
        unordered = ClassScore(cls=VulnerabilityClass.ACCESS_CONTROL, records=2, predictions=3)
        assert unordered.bpref(HIT) is None

    def test_an_empty_judged_set_with_claims_is_zero(self) -> None:
        """Claimed and ordered, nothing judged: no hit was retrieved, so 0.0."""
        assert a_score(records=2).bpref(HIT) == 0.0


class TestTheBasisIsPublished:
    def test_r_and_n_are_reported(self) -> None:
        score = a_score(relevant(0.9), refuted(0.8), refuted(0.7), records=5)
        assert score.bpref_basis(HIT) == (5, 2)

    def test_a_weak_match_moves_n_with_the_floor(self) -> None:
        score = a_score(JudgedPrediction(score=0.9, strength=WEAK), relevant(0.8), records=3)
        assert score.bpref_basis(MatchStrength.FUNCTION) == (3, 1)
        assert score.bpref_basis(MatchStrength.FILE) == (3, 0)

    def test_a_small_min_r_n_is_flagged(self) -> None:
        """At N=1 a single verdict moves the figure between 0 and 1."""
        score = a_score(relevant(0.9), refuted(0.8), records=50)
        assert score.bpref_below_minimum(HIT) is True

    def test_a_sufficient_min_r_n_is_not_flagged(self) -> None:
        judged = [relevant(1.0 - i / 100) for i in range(MINIMUM_JUDGED_FOR_BPREF)]
        judged += [refuted(0.5 - i / 100) for i in range(MINIMUM_JUDGED_FOR_BPREF)]
        score = a_score(*judged, records=MINIMUM_JUDGED_FOR_BPREF)
        assert score.bpref_below_minimum(HIT) is False

    def test_an_undeclared_ordering_reports_no_non_relevant(self) -> None:
        assert a_score(relevant(0.9), ordered=False).bpref_basis(HIT) == (2, 0)


class TestFromRealRuns:
    """The ordering has to survive the journey from a finding to a figure.

    The formula tests above build `ClassScore` directly, which says nothing
    about whether `Finding.score` ever reaches it. These run the scorer.
    """

    def adjudication(self, start: int, end: int) -> CorpusRecord:
        """A verdict at one location: no instance of the class is here.

        The affordable route to a judged prediction. Unlike a file-wide
        negative it settles one span, so a second prediction elsewhere in the
        same file stays unjudged -- which is exactly the state precision cannot
        report on and bpref can.
        """
        return CorpusRecord(
            record_id=f"adjudicated-{start}-{end}",
            population=Population.AUDIT_REVIEW,
            split=CorpusSplit.PUBLIC,
            pin=CommitPin(repo_url="https://github.com/x/y", commit="a" * 40, path=PATH),
            classes=[],
            negative_for=[CLS],
            negative_kind=NegativeKind.ADJUDICATED,
            locator=Locator(file=PATH, start_line=start, end_line=end),
            locator_provenance=LocatorProvenance.STATED,
            notes="Read the cited span against the class definition; no instance there.",
            provenance=Provenance(platform="p", report_url="https://x/3"),
        )

    def test_a_declared_ordering_reaches_the_score(self) -> None:
        report = score(
            [a_run([(4, 7), (14, 16)], scores=[0.9, 0.2])],
            [a_record(), self.adjudication(14, 16)],
            resolver(),
        )
        judged = only(report).ranked_judgements
        assert judged is not None
        assert [j.score for j in judged] == [0.9, 0.2]
        assert judged[0].strength is not None
        assert judged[1].strength is None

    def test_the_merge_across_units_is_by_score_not_by_arrival(self) -> None:
        """The reason `Finding.score` exists at all.

        `DetectorRun` already refuses a run whose findings are out of score
        order, so within one unit arrival order *is* score order and says
        nothing. Across units it is the order this module iterates runs in --
        here the weaker claim arrives first, and the merged list has to put the
        stronger one above it anyway.
        """
        report = score(
            [
                a_run([(14, 16)], scores=[0.1]),
                a_run([(4, 7)], scores=[0.8], source_id=a_record().pin.source_id),
            ],
            [a_record(), self.adjudication(14, 16)],
            resolver(),
        )
        judged = only(report).ranked_judgements
        assert judged is not None
        assert [j.score for j in judged] == [0.8, 0.1]
        # And the stronger one is the hit, so bpref is 1.0 rather than 0.0.
        assert only(report).bpref() == pytest.approx(1.0)

    def test_an_unscored_submission_declares_no_ordering(self) -> None:
        report = score([a_run([(4, 7)])], [a_record()], resolver())
        assert only(report).ranked_judgements is None
        assert only(report).bpref() is None

    def test_one_scored_run_and_one_unscored_is_not_an_ordering(self) -> None:
        """Refused rather than filled in.

        `DetectorRun` already refuses a partially scored list inside one run.
        Across runs it cannot: each is well-formed alone, and only the merged
        class is partial. Putting the unscored ones somewhere by default would
        be this module inventing a confidence the submission withheld.
        """
        report = score(
            [
                a_run([(4, 7)], scores=[0.9]),
                a_run([(14, 16)], source_id=a_record().pin.source_id),
            ],
            [a_record(), self.adjudication(14, 16)],
            resolver(),
        )
        assert only(report).ranked_judgements is None

    def test_bpref_exists_where_precision_does_not(self) -> None:
        """The property the whole measure is for.

        Three predictions: one matches the record, one sits on an adjudicated
        span, one is somewhere nothing has judged. Precision refuses -- its gate
        is every prediction or none -- and bpref reports, because it drops the
        unjudged one instead of guessing which way it would have gone.
        """
        report = score(
            [a_run([(4, 7), (14, 16), (18, 18)], scores=[0.9, 0.5, 0.2])],
            [a_record(), self.adjudication(14, 16)],
            resolver(),
        )
        got = only(report)
        assert got.unjudged_predictions == 1
        assert got.precision() is None
        # R=1, N=1, cap=1. The hit is above the refuted one: 1 - 0/1 = 1.0.
        assert got.bpref() == pytest.approx(1.0)
        assert got.bpref_basis() == (1, 1)

    def test_the_unjudged_prediction_cannot_move_it(self) -> None:
        """Same run without the unjudged claim: the same bpref, and now a
        precision too. The figure bpref reports did not depend on it."""
        both = score(
            [a_run([(4, 7), (14, 16), (18, 18)], scores=[0.9, 0.5, 0.2])],
            [a_record(), self.adjudication(14, 16)],
            resolver(),
        )
        without = score(
            [a_run([(4, 7), (14, 16)], scores=[0.9, 0.5])],
            [a_record(), self.adjudication(14, 16)],
            resolver(),
        )
        assert only(both).bpref() == only(without).bpref()
        assert only(without).precision() is not None


class TestTheDocumentKeepsThemApart:
    def test_bpref_is_its_own_field_and_is_not_precision(self) -> None:
        """A figure in a field named precision will be compared against
        precisions. Here precision is absent and bpref is not, so a reader who
        conflated them would read 1.0 as a precision of 1.0."""
        report = score(
            [a_run([(4, 7), (14, 16), (18, 18)], scores=[0.9, 0.5, 0.2])],
            [a_record(), _adjudication()],
            resolver(),
        )
        document = score_document(_submitted(report), [a_record(), _adjudication()])
        block = next(c for c in document["classes"] if c["class"] == CLS.value)
        assert block["precision"]["value"] is None
        assert block["bpref"]["value"] == pytest.approx(1.0)
        assert block["precision"]["unavailable"]

    def test_the_basis_is_published_beside_the_figure(self) -> None:
        """Without min(R, N) a reader cannot tell a figure resting on two
        verdicts from one resting on two hundred."""
        report = score(
            [a_run([(4, 7), (14, 16)], scores=[0.9, 0.5])],
            [a_record(), _adjudication()],
            resolver(),
        )
        document = score_document(_submitted(report), [a_record(), _adjudication()])
        block = next(c for c in document["classes"] if c["class"] == CLS.value)
        assert block["bpref"]["r"] == 1
        assert block["bpref"]["n"] == 1
        assert block["bpref"]["min_r_n"] == 1
        assert block["bpref"]["below_minimum"] is True
        assert block["bpref"]["minimum"] == MINIMUM_JUDGED_FOR_BPREF

    def test_an_unordered_submission_says_whose_work_is_missing(self) -> None:
        """Two reasons a bpref is absent, and they are different people's work:
        an ordering is the submission's, a verdict is the round's."""
        report = score([a_run([(4, 7)])], [a_record()], resolver())
        document = score_document(_submitted(report), [a_record()])
        block = next(c for c in document["classes"] if c["class"] == CLS.value)
        assert "declared no ordering" in block["bpref"]["unavailable"]
