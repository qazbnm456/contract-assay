"""Ranking, and refusing to rank what the corpus cannot license.

A leaderboard is where every honesty rule either holds or stops mattering,
because the single number is what gets quoted. So most of this file is about
what the ranking refuses to produce.
"""

from __future__ import annotations

import pytest

from contract_assay.models import DifficultyLevel, VulnerabilityClass
from contract_assay.report.leaderboard import leaderboard, score_submission
from contract_assay.report.scoring import ClassScore, MatchStrength, ScoreReport

pytestmark = pytest.mark.offline

WEIGHTS = {DifficultyLevel.S: 1.0, DifficultyLevel.M: 2.0, DifficultyLevel.Q: 3.0}
CLS = VulnerabilityClass.ACCESS_CONTROL


def a_class_score(
    *,
    cls: VulnerabilityClass = CLS,
    records: int = 4,
    predictions: int = 4,
    judged: int = 4,
    hits: int = 2,
    measured: int = 4,
    invalid: int = 0,
) -> ClassScore:
    return ClassScore(
        cls=cls,
        records=records,
        predictions=predictions,
        judged_predictions=judged,
        by_strength={MatchStrength.EXACT: hits},
        judged_by_strength={MatchStrength.EXACT: hits},
        measured_runs=measured,
        invalid_runs=invalid,
    )


def a_report(*scores: ClassScore) -> ScoreReport:
    return ScoreReport(by_class={s.cls: s for s in scores})


def a_submission(
    submission_id: str = "alice", *scores: ClassScore, at_least: MatchStrength = MatchStrength.EXACT
):  # type: ignore[no-untyped-def]
    return score_submission(
        submission_id, a_report(*(scores or (a_class_score(),))), weights=WEIGHTS, at_least=at_least
    )


class TestF1NeedsBothSides:
    def test_it_is_the_harmonic_mean_when_both_exist(self) -> None:
        # 2 hits of 4 predictions and 2 of 4 records: both 50%, so F1 is 50%.
        assert a_submission().f1(CLS) == pytest.approx(0.5)

    def test_an_unjudged_pool_yields_none_not_zero(self) -> None:
        # Substituting zero would rank a submission nobody adjudicated below one
        # that has been, which inverts the incentive adjudication depends on.
        got = a_submission("alice", a_class_score(judged=2))
        assert got.f1(CLS) is None
        assert "not yet adjudicated" in got.unavailable[CLS]

    def test_a_class_with_no_records_yields_none(self) -> None:
        got = a_submission("alice", a_class_score(records=0, hits=0))
        assert got.f1(CLS) is None
        assert "no positive record" in got.unavailable[CLS]

    def test_a_class_the_submission_ignored_yields_none(self) -> None:
        got = a_submission("alice", a_class_score(predictions=0, judged=0, hits=0))
        assert got.f1(CLS) is None
        assert "claimed nothing" in got.unavailable[CLS]

    def test_a_reason_is_given_per_class(self) -> None:
        # Two causes, two different work items: adjudication owed, corpus owed.
        got = a_submission(
            "alice",
            a_class_score(judged=2),
            a_class_score(cls=VulnerabilityClass.REENTRANCY, records=0, hits=0),
        )
        assert set(got.unavailable) == {CLS, VulnerabilityClass.REENTRANCY}


class TestNoAggregateOverAPartialClassSet:
    def test_one_unavailable_class_removes_the_aggregate(self) -> None:
        # A mean over whichever classes had figures ranks a submission on its
        # corpus's readiness, and two submissions measured over different sets
        # are not comparable however close the numbers look.
        got = a_submission(
            "alice",
            a_class_score(),
            a_class_score(cls=VulnerabilityClass.REENTRANCY, judged=1),
        )
        assert got.weighted_f1() is None
        assert got.total() is None

    def test_an_explicit_class_set_is_honoured(self) -> None:
        got = a_submission(
            "alice",
            a_class_score(),
            a_class_score(cls=VulnerabilityClass.REENTRANCY, judged=1),
        )
        assert got.weighted_f1([CLS]) == pytest.approx(0.5)

    def test_weighting_follows_difficulty(self) -> None:
        # The levels are read rather than assumed: hard-coding them here would
        # make the test agree with whatever the table said when it was written.
        deep = VulnerabilityClass.ARITHMETIC_ROUNDING
        got = a_submission("alice", a_class_score(), a_class_score(cls=deep, hits=4))
        near, far = WEIGHTS[CLS.level], WEIGHTS[deep.level]
        assert near != far, "the two classes must differ in level for this to test anything"
        assert got.weighted_f1() == pytest.approx((near * 0.5 + far * 1.0) / (near + far))


class TestNoBuiltInWeights:
    def test_a_missing_weight_removes_the_aggregate(self) -> None:
        # A coefficient written into the harness makes the ranking a property of
        # this code rather than of the exercise it serves.
        got = score_submission(
            "alice", a_report(a_class_score()), weights={}, at_least=MatchStrength.EXACT
        )
        assert got.weighted_f1() is None
        assert "no weight was supplied" in got.statement()


class TestCompletionRateMultiplies:
    def test_it_scales_the_aggregate(self) -> None:
        got = a_submission("alice", a_class_score(measured=3, invalid=1))
        assert got.completion_rate == pytest.approx(0.75)
        assert got.total() == pytest.approx(0.5 * 0.75)

    def test_a_submission_that_ran_nothing_has_no_rate(self) -> None:
        got = a_submission("alice", a_class_score(measured=0))
        assert got.completion_rate is None
        assert got.total() is None


class TestTheUnrankableAreNotPlacedLast:
    def test_they_are_listed_apart_with_a_reason(self) -> None:
        # Ordering an unrankable submission below a ranked one asserts a
        # comparison nobody measured, and the usual cause is work the exercise
        # owes rather than anything the submission did.
        board = leaderboard(
            [
                a_submission("alice", a_class_score(hits=4)),
                a_submission("bob", a_class_score(judged=1)),
            ],
            over=[CLS],
        )
        assert [r.score.submission_id for r in board.ranked] == ["alice"]
        assert [s.submission_id for s in board.unrankable] == ["bob"]
        assert "is not a worse one" in board.statement()

    def test_ranking_is_by_total_descending(self) -> None:
        board = leaderboard(
            [
                a_submission("alice", a_class_score(hits=2)),
                a_submission("bob", a_class_score(hits=4)),
            ],
            over=[CLS],
        )
        assert [r.score.submission_id for r in board.ranked] == ["bob", "alice"]
        assert [r.place for r in board.ranked] == [1, 2]

    def test_ties_are_stable_by_id(self) -> None:
        # Two runs over the same inputs must produce the same table.
        board = leaderboard(
            [a_submission("zoe", a_class_score()), a_submission("adam", a_class_score())],
            over=[CLS],
        )
        assert [r.score.submission_id for r in board.ranked] == ["adam", "zoe"]

    def test_the_statement_names_the_floor_and_the_class_set(self) -> None:
        # A ranking at one floor over one class set is a different ranking, and
        # a table without them invites an incomparable comparison.
        board = leaderboard([a_submission()], over=[CLS])
        assert "exact strength floor" in board.statement()
        assert CLS.value in board.statement()


class TestTheStatementsSayWhatHappened:
    def test_a_ranked_submission_names_its_floor_and_coverage(self) -> None:
        statement = a_submission().statement()
        assert "scores 0.500" in statement
        assert "exact floor" in statement
        assert "completion rate of 100%" in statement

    def test_an_unrankable_one_names_the_class_and_the_reason(self) -> None:
        statement = a_submission("bob", a_class_score(judged=1)).statement()
        assert "has no rankable score" in statement
        assert "a partial class set is not comparable" in statement
        assert CLS.value in statement

    def test_a_submission_that_ran_nothing_says_so(self) -> None:
        statement = a_submission(
            "bob", a_class_score(measured=0, predictions=0, judged=0, hits=0)
        ).statement()
        assert "no rankable score" in statement or "produced no runs" in statement

    def test_zero_on_both_sides_is_zero_not_absent(self) -> None:
        # A submission that claimed things and got none of them right scores
        # zero, which is a measurement. Only an *unavailable* side is absent.
        got = a_submission("bob", a_class_score(hits=0))
        assert got.f1(CLS) == 0.0
        assert got.total() == 0.0

    def test_the_class_set_defaults_to_what_the_submissions_cover(self) -> None:
        board = leaderboard([a_submission("alice"), a_submission("bob")])
        assert board.over == (CLS,)

    def test_an_empty_board_states_itself(self) -> None:
        board = leaderboard([])
        assert "0 of 0 submissions ranked" in board.statement()
        assert "no classes" in board.statement()
