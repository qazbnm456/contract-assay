"""Ranking, and refusing to rank what the corpus cannot license.

A leaderboard is where every honesty rule either holds or stops mattering,
because the single number is what gets quoted. So most of this file is about
what the ranking refuses to produce.
"""

from __future__ import annotations

import pytest

from contract_assay.models import (
    DifficultyLevel,
    ModelRole,
    ModelUse,
    VulnerabilityClass,
)
from contract_assay.report.leaderboard import Measure, leaderboard, score_submission
from contract_assay.report.scoring import (
    ClassScore,
    JudgedPrediction,
    MatchStrength,
    ScoreReport,
)
from contract_assay.report.wire import leaderboard_document, score_document

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

    def test_a_class_the_submission_ignored_scores_zero(self) -> None:
        # F1 = 2TP / (2TP + FP + FN) = 0 / R, defined without precision. `None`
        # made the row unrankable, which rewarded skipping a hard class.
        got = a_submission("alice", a_class_score(predictions=0, judged=0, hits=0))
        assert got.f1(CLS) == 0.0
        assert CLS not in got.unavailable

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
        assert got.weighted_figure() is None
        assert got.total() is None

    def test_an_explicit_class_set_is_honoured(self) -> None:
        got = a_submission(
            "alice",
            a_class_score(),
            a_class_score(cls=VulnerabilityClass.REENTRANCY, judged=1),
        )
        assert got.weighted_figure([CLS]) == pytest.approx(0.5)

    def test_weighting_follows_difficulty(self) -> None:
        # The levels are read rather than assumed: hard-coding them here would
        # make the test agree with whatever the table said when it was written.
        deep = VulnerabilityClass.ARITHMETIC_ROUNDING
        got = a_submission("alice", a_class_score(), a_class_score(cls=deep, hits=4))
        near, far = WEIGHTS[CLS.level], WEIGHTS[deep.level]
        assert near != far, "the two classes must differ in level for this to test anything"
        assert got.weighted_figure() == pytest.approx((near * 0.5 + far * 1.0) / (near + far))


class TestNoBuiltInWeights:
    def test_a_missing_weight_removes_the_aggregate(self) -> None:
        # A coefficient written into the harness makes the ranking a property of
        # this code rather than of the exercise it serves.
        got = score_submission(
            "alice", a_report(a_class_score()), weights={}, at_least=MatchStrength.EXACT
        )
        assert got.weighted_figure() is None
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


def under(model: str | None, submission_id: str = "alice", *, deterministic: int = 0):  # type: ignore[no-untyped-def]
    """A submission whose runs named `model` as their main model, or none."""
    report = ScoreReport(
        by_class={CLS: a_class_score()},
        models=(
            (ModelUse(model_id=model, role=ModelRole.MAIN, calls=3, tokens=900),)
            if model is not None
            else ()
        ),
        deterministic_runs=deterministic,
    )
    return score_submission(submission_id, report, weights=WEIGHTS, at_least=MatchStrength.EXACT)


class TestTheSameBaselineOrNoComparison:
    """An exercise that agrees one model is making a claim about process.

    A leaderboard that cannot name the model behind a row cannot check that
    claim, and a reader shown no model assumes the agreed one. These rows carry
    real figures -- the refusal is about the comparison, not the submission, and
    `incomparable` is kept apart from a missing F1 for exactly that reason.
    """

    def test_rows_under_the_agreed_baseline_are_ranked(self) -> None:
        board = leaderboard(
            [under("agreed-model", "alice"), under("agreed-model", "bob")],
            baseline="agreed-model",
        )
        assert len(board.ranked) == 2
        assert board.incomparable == {}

    def test_a_row_under_another_model_is_listed_apart_with_the_reason(self) -> None:
        board = leaderboard(
            [under("agreed-model", "alice"), under("other-model", "bob")],
            baseline="agreed-model",
        )
        assert [row.score.submission_id for row in board.ranked] == ["alice"]
        assert "other-model" in board.incomparable["bob"]
        assert "agreed-model" in board.incomparable["bob"]

    def test_deterministic_findings_are_a_different_measurement_not_a_worse_one(self) -> None:
        board = leaderboard(
            [under("agreed-model", "alice"), under(None, "bob", deterministic=4)],
            baseline="agreed-model",
        )
        assert [row.score.submission_id for row in board.ranked] == ["alice"]
        assert "deterministic" in board.incomparable["bob"]
        # Not placed last: an unranked row asserts no comparison at all.
        assert all(row.score.submission_id != "bob" for row in board.ranked)

    def test_runs_naming_two_main_models_are_a_mixture(self) -> None:
        mixed = ScoreReport(
            by_class={CLS: a_class_score()},
            models=(
                ModelUse(model_id="one", role=ModelRole.MAIN, calls=1),
                ModelUse(model_id="two", role=ModelRole.MAIN, calls=1),
            ),
        )
        board = leaderboard(
            [score_submission("bob", mixed, weights=WEIGHTS, at_least=MatchStrength.EXACT)],
            baseline="one",
        )
        assert board.ranked == ()
        assert "more than one main model" in board.incomparable["bob"]

    def test_with_no_agreed_baseline_disagreeing_rows_rank_nothing(self) -> None:
        # Ranking whichever models happen to agree would turn the exercise's
        # silence into a decision it never made.
        board = leaderboard([under("one", "alice"), under("two", "bob")])
        assert board.ranked == ()
        assert set(board.incomparable) == {"alice", "bob"}
        assert "nothing states which was agreed" in board.incomparable["alice"]

    def test_with_no_agreed_baseline_and_one_model_everything_ranks(self) -> None:
        board = leaderboard([under("one", "alice"), under("one", "bob")])
        assert len(board.ranked) == 2

    def test_a_sub_model_does_not_block_a_comparison(self) -> None:
        # Which helpers a harness calls is what the exercise is comparing; the
        # budgets are what meter them. Only the main model has to match.
        report = ScoreReport(
            by_class={CLS: a_class_score()},
            models=(
                ModelUse(model_id="agreed-model", role=ModelRole.MAIN, calls=2),
                ModelUse(model_id="a-reranker", role=ModelRole.SUB, calls=9, tokens=50),
            ),
        )
        board = leaderboard(
            [score_submission("bob", report, weights=WEIGHTS, at_least=MatchStrength.EXACT)],
            baseline="agreed-model",
        )
        assert [row.score.submission_id for row in board.ranked] == ["bob"]


class TestTheClassSetIsStated:
    """`over` is what the exercise says it ranks on, not what happened to work.

    Left to itself the ranking requires every class the submissions share, which
    is the safe default and rarely the intended one: a mean over whichever
    classes had figures ranks a submission on its corpus's readiness instead of
    on itself.
    """

    def test_ranking_over_one_ready_class_ignores_the_rest(self) -> None:
        ready, waiting = CLS, VulnerabilityClass.REENTRANCY
        report = ScoreReport(
            by_class={
                ready: a_class_score(cls=ready),
                waiting: a_class_score(cls=waiting, judged=1),
            },
            models=(ModelUse(model_id="agreed", role=ModelRole.MAIN),),
        )
        submission = score_submission(
            "alice", report, weights=WEIGHTS, at_least=MatchStrength.EXACT
        )
        assert leaderboard([submission], baseline="agreed").ranked == ()
        [row] = leaderboard([submission], baseline="agreed", over=[ready]).ranked
        assert row.total == pytest.approx(0.5)

    def test_the_statement_reads_for_one_submission(self) -> None:
        board = leaderboard([under("other", "bob")], baseline="agreed")
        assert "1 could not be ranked and is listed" in board.statement()
        assert "1 of those was not compared" in board.statement()


def capped_at(cap: int | None, submission_id: str = "alice"):  # type: ignore[no-untyped-def]
    """A submission scored under a per-unit prediction cap, or none."""
    report = ScoreReport(
        by_class={CLS: a_class_score()},
        models=(ModelUse(model_id="agreed-model", role=ModelRole.MAIN, calls=1, tokens=10),),
        predictions_per_unit=cap,
    )
    return score_submission(submission_id, report, weights=WEIGHTS, at_least=MatchStrength.EXACT)


class TestTheSamePoolOrNoComparison:
    """The same argument as the baseline, on a different parameter.

    A precision computed over three predictions per unit and one computed over
    every prediction a submission cared to make are different measurements. A
    table that put them in one column would be comparing how much adjudication
    each submission was allowed to consume.
    """

    def test_rows_under_one_cap_are_ranked(self) -> None:
        board = leaderboard([capped_at(3, "alice"), capped_at(3, "bob")], baseline="agreed-model")
        assert len(board.ranked) == 2
        assert board.incomparable == {}

    def test_rows_under_different_caps_are_not_ranked_against_each_other(self) -> None:
        board = leaderboard([capped_at(3, "alice"), capped_at(1, "bob")], baseline="agreed-model")
        assert board.ranked == ()
        assert {"alice", "bob"} == set(board.incomparable)
        assert "different per-unit prediction caps" in board.incomparable["alice"]

    def test_an_uncapped_row_beside_a_capped_one_is_named_as_uncapped(self) -> None:
        # "uncapped" rather than a blank, because the reader has to be able to
        # tell which of the two it was.
        board = leaderboard(
            [capped_at(3, "alice"), capped_at(None, "bob")], baseline="agreed-model"
        )
        assert "uncapped" in board.incomparable["bob"]

    def test_uncapped_rows_agree_with_each_other(self) -> None:
        board = leaderboard(
            [capped_at(None, "alice"), capped_at(None, "bob")], baseline="agreed-model"
        )
        assert len(board.ranked) == 2


class TestAClassWeightingIsTheGeneralCase:
    """Nine classes share three difficulty levels, so a level weighting asserts
    that four of them are equally hard. An exercise with results in hand can
    say otherwise, and this is the field that lets it.

    Nothing here computes a weight. A class weighting arrived at by measuring a
    cohort and one arrived at by opinion are the same thing to this module,
    which is what keeps the coefficient out of the package.
    """

    def two_classes(self) -> tuple[ClassScore, ClassScore]:
        """One class at half the other's F1, so a weighting is visible."""
        weak = a_class_score(cls=VulnerabilityClass.ORACLE_INTEGRITY, records=4, hits=1)
        strong = a_class_score(cls=CLS, records=4, hits=4)
        return weak, strong

    def test_a_class_weight_overrides_the_level_weight(self) -> None:
        weak, strong = self.two_classes()
        by_level = score_submission("alice", a_report(weak, strong), weights=WEIGHTS)
        by_class = score_submission(
            "alice",
            a_report(weak, strong),
            weights=WEIGHTS,
            class_weights={CLS: 1.0, VulnerabilityClass.ORACLE_INTEGRITY: 9.0},
        )
        assert by_level.weighted_figure() != pytest.approx(by_class.weighted_figure())

    def test_leaning_on_the_harder_class_lowers_a_submission_that_misses_it(self) -> None:
        """The property the whole field is for: a class few can do is worth
        more, so a submission strong only on the easy one ranks lower."""
        weak, strong = self.two_classes()
        report = a_report(weak, strong)
        even = score_submission(
            "alice", report, weights=WEIGHTS, class_weights={CLS: 1.0, weak.cls: 1.0}
        )
        leaning = score_submission(
            "alice", report, weights=WEIGHTS, class_weights={CLS: 1.0, weak.cls: 9.0}
        )
        even_total, leaning_total = even.weighted_figure(), leaning.weighted_figure()
        assert even_total is not None and leaning_total is not None
        assert leaning_total < even_total

    def test_a_class_weighting_with_a_gap_is_refused_not_filled_in(self) -> None:
        """Falling back to the level weight for the missing class would mix two
        weightings inside one mean, and the total would have no stated basis."""
        weak, strong = self.two_classes()
        partial = score_submission(
            "alice", a_report(weak, strong), weights=WEIGHTS, class_weights={CLS: 1.0}
        )
        assert partial.weighted_figure() is None
        assert partial.total() is None

    def test_the_gap_is_named_by_class_in_the_document(self) -> None:
        weak, strong = self.two_classes()
        partial = score_submission(
            "alice", a_report(weak, strong), weights=WEIGHTS, class_weights={CLS: 1.0}
        )
        document = score_document(partial, [])
        why = document["aggregate"]["total"]["unavailable"]
        assert "oracle_integrity" in why
        assert "covers every class it ranks" in why

    def test_the_class_weighting_reaches_the_document(self) -> None:
        """`weights` is one of the seven comparability fields and a class
        weighting replaces it. Unpublished, two rounds weighting the same levels
        differently per class would present identical bases."""
        weak, strong = self.two_classes()
        submission = score_submission(
            "alice",
            a_report(weak, strong),
            weights=WEIGHTS,
            class_weights={CLS: 1.0, weak.cls: 9.0},
        )
        document = score_document(submission, [])
        assert document["class_weights"] == {"access_control": 1.0, "oracle_integrity": 9.0}

    def test_a_level_weighted_submission_publishes_no_class_weighting(self) -> None:
        """`None` rather than `{}`: an empty mapping would compare equal to
        another empty one and call two level-weighted results class-weighted."""
        document = score_document(a_submission(), [])
        assert document["class_weights"] is None


class TestARoundChoosesWhatItRanksOn:
    """F1 accounts for every prediction; bpref exists while judging is not done.

    The trade is real and it is the round's to make, so the choice is carried
    on the submission and named in the document rather than inferred from which
    figures happen to exist -- a board that ranked on whatever was available
    would be ranking on how much adjudication it had finished.
    """

    def ordered(self, *, judged_non_relevant: int = 2) -> ClassScore:
        """A class with a declared ordering, so bpref exists and F1 does not."""
        judged = [
            JudgedPrediction(score=0.9 - i / 10, strength=MatchStrength.EXACT) for i in range(2)
        ]
        judged += [
            JudgedPrediction(score=0.5 - i / 10, strength=None) for i in range(judged_non_relevant)
        ]
        return ClassScore(
            cls=CLS,
            records=4,
            # More predictions than judged ones, so precision has no figure.
            predictions=10,
            judged_predictions=len(judged),
            by_strength={MatchStrength.EXACT: 2},
            judged_by_strength={MatchStrength.EXACT: 2},
            ranked_judgements=tuple(judged),
            measured_runs=4,
        )

    def test_an_f1_board_cannot_rank_an_unadjudicated_submission(self) -> None:
        score = self.ordered()
        submission = score_submission("alice", a_report(score), weights=WEIGHTS)
        assert submission.f1(CLS) is None
        assert submission.total() is None
        assert "not yet" in submission.unavailable[CLS]

    def test_a_bpref_board_ranks_the_same_submission(self) -> None:
        """The property the option exists for."""
        score = self.ordered()
        submission = score_submission(
            "alice", a_report(score), weights=WEIGHTS, measure=Measure.BPREF
        )
        assert submission.figure(CLS) is not None
        assert submission.total() is not None

    def test_the_figure_is_the_bpref_and_not_the_f1(self) -> None:
        score = self.ordered()
        submission = score_submission(
            "alice", a_report(score), weights=WEIGHTS, measure=Measure.BPREF
        )
        assert submission.figure(CLS) == pytest.approx(score.bpref(MatchStrength.FUNCTION))

    def test_a_bpref_board_says_whose_work_is_missing(self) -> None:
        """An unordered submission is the submission's gap, not the round's, and
        telling the round to adjudicate would be sending it to do work that
        would not produce the figure."""
        unordered = ClassScore(
            cls=CLS, records=4, predictions=4, judged_predictions=2, measured_runs=4
        )
        submission = score_submission(
            "alice", a_report(unordered), weights=WEIGHTS, measure=Measure.BPREF
        )
        assert "declared no ordering" in submission.unavailable[CLS]

    def test_two_measures_in_one_board_are_refused(self) -> None:
        """The same refusal as two prediction caps, on the figure itself.

        An F1 and a bpref are not two precisions of one thing, so a column
        holding both would rank submissions on which measure their round
        announced.
        """
        score = self.ordered()
        board = leaderboard(
            [
                score_submission("alice", a_report(score), weights=WEIGHTS),
                score_submission("bob", a_report(score), weights=WEIGHTS, measure=Measure.BPREF),
            ]
        )
        assert board.ranked == ()
        assert "different measures" in board.incomparable["alice"]

    def test_the_board_names_the_measure_and_keys_the_column_by_it(self) -> None:
        """Putting a bpref under `f1_by_class` is the error this project refuses
        one level down, where a bpref must never sit in a field called
        precision."""
        score = self.ordered()
        board = leaderboard(
            [score_submission("alice", a_report(score), weights=WEIGHTS, measure=Measure.BPREF)]
        )
        document = leaderboard_document(board, [])
        assert document["ranked_on"] == "bpref"
        assert "bpref_by_class" in document["ranked"][0]
        assert "f1_by_class" not in document["ranked"][0]

    def test_an_f1_board_still_keys_its_column_f1(self) -> None:
        board = leaderboard([a_submission()])
        document = leaderboard_document(board, [])
        assert document["ranked_on"] == "f1"
        assert "f1_by_class" in document["ranked"][0]


class TestWhatTheMinimumDoesAndDoesNotDo:
    """`MINIMUM_RECORDS_PER_CLASS` is a label, not a gate.

    Its docstring says so -- "a convention rather than a finding" -- and the
    sentence it produced said the opposite: that thin classes "are not averaged
    in". They were. These pin the computation and the sentence to each other, so
    changing one without the other fails here rather than in a reader's head.
    """

    def test_a_thin_class_is_averaged_into_the_total(self) -> None:
        """Measured: a two-record class at F1 0.0 beside twenty at 1.0 moved the
        total from 1.0 to 0.4. That is the behaviour, and it is deliberate --
        dropping thin classes would be an unannounced threshold on every total."""
        fat = a_class_score(cls=CLS, records=20, predictions=20, judged=20, hits=20)
        thin = a_class_score(
            cls=VulnerabilityClass.SLIPPAGE, records=2, predictions=2, judged=2, hits=0
        )
        alone = score_submission("a", a_report(fat), weights=WEIGHTS).total()
        with_thin = score_submission("a", a_report(fat, thin), weights=WEIGHTS).total()
        assert thin.below_minimum
        assert alone is not None and with_thin is not None
        assert with_thin < alone

    def test_the_statement_does_not_claim_the_opposite(self) -> None:
        fat = a_class_score(cls=CLS, records=20, predictions=20, judged=20, hits=20)
        thin = a_class_score(
            cls=VulnerabilityClass.SLIPPAGE, records=2, predictions=2, judged=2, hits=0
        )
        said = a_report(fat, thin).statement()
        assert "not averaged in" not in said
        assert "averaged into the total" in said

    def test_a_thin_class_is_still_rankable(self) -> None:
        """Nothing refuses it. A round that ranks on a five-record class is
        allowed, and carries the label rather than being stopped."""
        thin = a_class_score(cls=CLS, records=5, predictions=5, judged=5, hits=3)
        board = leaderboard([score_submission("a", a_report(thin), weights=WEIGHTS)])
        assert len(board.ranked) == 1
