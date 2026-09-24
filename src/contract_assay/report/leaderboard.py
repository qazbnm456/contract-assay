"""Ranking submissions, and refusing to rank what the corpus cannot license.

A leaderboard is where every honesty rule in this project either holds or stops
mattering, because a single number is what gets quoted. So the arithmetic is
arranged so that the number cannot exist unless the things it rests on do.

Three refusals, each of which a simpler implementation would have made silently:

*   **No F1 without both sides.** Precision is unavailable until every
    prediction in a class has been adjudicated (§7.3), and a harmonic mean with
    one side missing is not a weaker F1, it is a different quantity. So the
    class contributes nothing and says why.
*   **No aggregate over a partial set of classes.** Averaging the classes that
    happen to have figures ranks a submission on the classes its corpus was
    ready for, and two submissions measured over different class sets are not
    comparable. So an aggregate exists only when every class in the requested
    set has an F1.
*   **No built-in weights.** Difficulty weighting is supplied by whoever runs
    the exercise. A weight per level is a coefficient, and a coefficient written
    into the harness makes the ranking a property of this code rather than of
    the exercise it serves.

Completion rate *multiplies* the aggregate rather than folding into the matrix
(§7.1): a submission that crashes on a third of the corpus must not rank beside
one that does not, and an error must never be counted as a judgement.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from contract_assay.models import DifficultyLevel, VulnerabilityClass
from contract_assay.report.scoring import MatchStrength, ScoreReport

__all__ = [
    "Leaderboard",
    "Ranked",
    "SubmissionScore",
    "leaderboard",
    "score_submission",
]


def _f1(precision: float | None, recall: float | None) -> float | None:
    """The harmonic mean, or nothing when either side is missing.

    Not a weaker F1 with one side absent -- a different quantity. Substituting
    zero for an unavailable precision would rank a submission nobody has
    adjudicated below one that has been, which inverts the incentive the
    adjudication discipline depends on.
    """
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


class Measure(StrEnum):
    """Which per-class figure a board ranks on. Announced by the exercise.

    **Two measures, and they are not interchangeable**, which is why the choice
    is named in the document rather than inferred from which figures happen to
    exist.

    - `F1` is the harmonic mean of precision and recall. Precision is
      all-or-nothing -- one unjudged prediction and the class has none -- so an
      F1 board cannot exist while adjudication is outstanding.
    - `BPREF` ignores unjudged predictions instead of counting them either way,
      so it exists during judging. It is a ranking measure over judged
      predictions, not a precision, and a board built on it answers a different
      question from an F1 board.

    A round ranked on one is **not comparable** with a round ranked on the
    other, and the boards say so rather than leaving a reader to notice that
    one column is called something else.
    """

    F1 = "f1"
    BPREF = "bpref"


@dataclass(frozen=True, slots=True)
class SubmissionScore:
    """What one submission earned, and what could not be computed for it."""

    submission_id: str
    report: ScoreReport
    at_least: MatchStrength
    weights: Mapping[DifficultyLevel, float]
    measure: Measure = Measure.F1
    """Which figure this submission is ranked on. See `Measure`.

    Defaults to `F1`, which is the measure this benchmark has always ranked on
    and the one with the stronger claim: it accounts for every prediction, and
    a board that has it does not need a weaker one.
    """

    class_weights: Mapping[VulnerabilityClass, float] | None = None
    """A weight per class, when the exercise measured one, overriding `weights`.

    **The general case, and `weights` is the special case of it.** Nine classes
    share three difficulty levels, so a level weighting says that
    `oracle_integrity`, `slippage`, `flashloan_manipulation` and
    `arithmetic_rounding` are equally hard -- which is a claim, and one an
    exercise with results in hand can replace with a measurement.

    Both are still "supplied by whoever runs the exercise", which is the rule
    that keeps a coefficient out of this package. What this field adds is
    *granularity*, not a policy: nothing here computes a weight, and a class
    weighting arrived at by measuring is indistinguishable from one arrived at
    by opinion as far as this module is concerned.

    **All or nothing over the requested classes.** A partial mapping silently
    falling back to the level weight would mix two weightings inside one mean,
    and the resulting total would have no stated basis -- the same failure a
    partly scored class has in `bpref`. A gap is refused with the classes named.
    """

    @property
    def classes(self) -> tuple[VulnerabilityClass, ...]:
        return tuple(sorted(self.report.by_class))

    def f1(self, cls: VulnerabilityClass) -> float | None:
        score = self.report.by_class.get(cls)
        if score is None:
            return None
        if score.records and not score.predictions:
            # Defined, and zero: F1 = 2TP / (2TP + FP + FN) = 0 / R. Precision
            # is 0/0 here, but F1 does not need it -- and `None` would have made
            # skipping a class better than attempting it, since an absent class
            # makes the row unrankable and no zero is worse than that. This is
            # not the case `_f1` guards: nothing is waiting on adjudication.
            return 0.0
        return _f1(score.precision(self.at_least), score.recall(self.at_least))

    def bpref(self, cls: VulnerabilityClass) -> float | None:
        score = self.report.by_class.get(cls)
        return None if score is None else score.bpref(self.at_least)

    def figure(self, cls: VulnerabilityClass) -> float | None:
        """The figure this submission is ranked on, whichever that is."""
        return self.bpref(cls) if self.measure is Measure.BPREF else self.f1(cls)

    @property
    def unavailable(self) -> Mapping[VulnerabilityClass, str]:
        """Why each class without the ranking figure does not have one.

        A reason per class rather than one aggregate absence, because the two
        causes call for different work: an unjudged pool is adjudication owed,
        and a class with no records is corpus owed.
        """
        out: dict[VulnerabilityClass, str] = {}
        for cls, score in sorted(self.report.by_class.items()):
            if self.figure(cls) is not None:
                continue
            if not score.records:
                out[cls] = "the corpus holds no positive record of this class"
            elif self.measure is Measure.BPREF:
                # bpref's two absences are different people's work, and saying
                # "not yet adjudicated" for the first would send the round to do
                # judging that would not produce the figure.
                records, non_relevant = score.bpref_basis(self.at_least)
                if score.ranked_judgements is None:
                    out[cls] = (
                        "the submission declared no ordering, and bpref needs a score "
                        "on every finding of the class"
                    )
                else:
                    out[cls] = f"bpref is unavailable over R={records}, N={non_relevant}"
            elif not score.pool_is_fully_judged:
                out[cls] = (
                    f"{score.unjudged_predictions} of its predictions are not yet "
                    "adjudicated, so precision is unlicensed"
                )
            else:
                out[cls] = "recall is unavailable"
        return out

    @property
    def completion_rate(self) -> float | None:
        """Share of this submission's runs that produced a usable answer."""
        measured = sum(s.measured_runs for s in self.report.by_class.values())
        invalid = sum(s.invalid_runs for s in self.report.by_class.values())
        total = measured + invalid
        return measured / total if total else None

    def _weight_for(self, cls: VulnerabilityClass) -> float | None:
        """This class's weight, from the class weighting if one was supplied.

        Returns `None` when a class weighting exists and does not cover `cls`,
        rather than falling back to the level weight: falling back would mix two
        weightings inside one mean and produce a total with no stated basis.
        """
        if self.class_weights is not None:
            return self.class_weights.get(cls)
        return self.weights.get(cls.level)

    def weighted_figure(self, over: Sequence[VulnerabilityClass] | None = None) -> float | None:
        """Difficulty-weighted mean of the ranking figure, or nothing if a class lacks it.

        Named for what it holds rather than for F1, because it holds whichever
        measure the round announced. It was `weighted_f1`, and a mean of bprefs
        returned from a method with that name is the same error this project
        refuses one level down, where a bpref must never sit in a field called
        precision.

        `over` is the class set the exercise ranks on, and defaults to every
        class the report covers. Requiring all of them is the point: a mean over
        whichever classes happened to have figures ranks a submission on its
        corpus's readiness, and two submissions measured over different sets are
        not comparable however similar the numbers look.
        """
        wanted = tuple(over) if over is not None else self.classes
        if not wanted:
            return None
        numerator = 0.0
        denominator = 0.0
        for cls in wanted:
            value = self.figure(cls)
            if value is None:
                return None
            weight = self._weight_for(cls)
            if weight is None:
                return None
            numerator += weight * value
            denominator += weight
        return numerator / denominator if denominator else None

    def total(self, over: Sequence[VulnerabilityClass] | None = None) -> float | None:
        """The one number, when it exists: the weighted figure times completion rate."""
        weighted = self.weighted_figure(over)
        rate = self.completion_rate
        if weighted is None or rate is None:
            return None
        return weighted * rate

    def statement(self, over: Sequence[VulnerabilityClass] | None = None) -> str:
        """What has to accompany this submission's number, or its absence."""
        wanted = tuple(over) if over is not None else self.classes
        total = self.total(over)
        if total is None:
            missing = {cls: reason for cls, reason in self.unavailable.items() if cls in wanted}
            if missing:
                named = "; ".join(f"{cls.value}: {reason}" for cls, reason in missing.items())
                return (
                    f"{self.submission_id} has no rankable score, because an aggregate over "
                    f"a partial class set is not comparable with one over another -- {named}."
                )
            if self.completion_rate is None:
                return f"{self.submission_id} produced no runs, so nothing was measured."
            return (
                f"{self.submission_id} has no rankable score: no weight was supplied for "
                "some class's difficulty level, and a weight invented here would make the "
                "ranking a property of this code rather than of the exercise."
            )
        return (
            f"{self.submission_id} scores {total:.3f} -- difficulty-weighted F1 at the "
            f"{self.at_least.value} floor over {len(wanted)} classes, multiplied by a "
            f"completion rate of {self.completion_rate:.0%}."
        )


@dataclass(frozen=True, slots=True)
class Ranked:
    """One row of a leaderboard."""

    place: int
    score: SubmissionScore
    total: float
    replicates: tuple[SubmissionScore, ...] = ()
    """Every measurement of this submission, when it was measured more than once.

    Empty for a submission measured once, where `score` is the measurement. With
    several, `score` is the first and `total` is the **mean** of their totals:
    a model at temperature zero still answers differently from run to run, and
    one sweep of a small corpus moves a class by a whole record on that alone.
    Measured before this existed: one harness, seven sweeps of one ten-unit
    holdout, totals from 0.065 to 0.138.
    """

    totals: tuple[float, ...] = ()

    def figure(self, cls: VulnerabilityClass) -> float | None:
        """This row's ranking figure for `cls`: the mean over its measurements."""
        measured = self.replicates or (self.score,)
        values = [replicate.figure(cls) for replicate in measured]
        if any(value is None for value in values):
            return None
        return sum(v for v in values if v is not None) / len(values)

    @property
    def measurements(self) -> int:
        return len(self.replicates) or 1

    @property
    def spread(self) -> float | None:
        """Highest minus lowest total, published beside the mean. `None` for one."""
        return max(self.totals) - min(self.totals) if len(self.totals) > 1 else None


@dataclass(frozen=True, slots=True)
class Leaderboard:
    """Ranked submissions, and the ones that could not be ranked."""

    ranked: tuple[Ranked, ...] = ()
    unrankable: tuple[SubmissionScore, ...] = ()
    incomparable: Mapping[str, str] = field(default_factory=dict)
    """Why a submission was not ranked *for a reason other than its figures*.

    Keyed by submission id. A missing F1 is already explained per class by
    `SubmissionScore.unavailable`; this is for the other kind, where the figures
    exist and the comparison does not -- a different baseline model, or none
    named. Kept apart because the two are different work for different people:
    one is the corpus's or the submission's, the other is the exercise's.
    """

    over: tuple[VulnerabilityClass, ...] = ()
    at_least: MatchStrength = MatchStrength.FUNCTION
    any_model: bool = False
    """The exercise ranks rows whatever main model they ran under.

    Stated on the board and in its statement, because it changes what a gap
    between two rows is about: the harnesses, and the models behind them."""

    def statement(self) -> str:
        """The sentence that goes beside the table.

        Names the class set and the strength floor, because a ranking at one
        floor over one class set is a different ranking, and a table printed
        without them invites comparison between two that cannot be compared.
        """
        classes = ", ".join(cls.value for cls in self.over) or "no classes"
        parts = [
            f"{len(self.ranked)} of {len(self.ranked) + len(self.unrankable)} submissions "
            f"ranked, at the {self.at_least.value} strength floor over {classes}."
        ]
        if self.unrankable:
            one = len(self.unrankable) == 1
            parts.append(
                f"{len(self.unrankable)} could not be ranked and "
                f"{'is' if one else 'are'} listed with the reason rather than placed "
                "last: an unrankable submission is not a worse one, and ordering it "
                "below a ranked one would assert something nobody measured."
            )
        if self.any_model:
            models = sorted(
                {m for row in self.ranked for m in row.score.report.main_models} or {"none named"}
            )
            parts.append(
                "The exercise ranks rows run under different main models ("
                + ", ".join(models)
                + "): each row names its model, and a gap between two rows is as much "
                "the models' as the harnesses'."
            )
        repeated = sorted({row.measurements for row in self.ranked if row.measurements > 1})
        if repeated:
            counts = " or ".join(str(n) for n in repeated)
            parts.append(
                f"Rows measured more than once ({counts} times) are ranked on the mean of "
                "their totals, and the spread between measurements is published beside each: "
                "a difference smaller than the spread is not one this board can tell apart."
            )
        if self.incomparable:
            one = len(self.incomparable) == 1
            parts.append(
                f"{len(self.incomparable)} of those "
                f"{'was' if one else 'were'} not compared at all rather than "
                "scored and found wanting: "
                + "; ".join(f"{name} -- {why}" for name, why in sorted(self.incomparable.items()))
                + "."
            )
        return " ".join(parts)


def score_submission(
    submission_id: str,
    report: ScoreReport,
    *,
    weights: Mapping[DifficultyLevel, float],
    at_least: MatchStrength = MatchStrength.FUNCTION,
    class_weights: Mapping[VulnerabilityClass, float] | None = None,
    measure: Measure = Measure.F1,
) -> SubmissionScore:
    """Wrap one submission's score report for ranking."""
    return SubmissionScore(
        submission_id=submission_id,
        report=report,
        at_least=at_least,
        weights=dict(weights),
        class_weights=None if class_weights is None else dict(class_weights),
        measure=measure,
    )


def _baseline_objection(score: SubmissionScore, baseline: str | None) -> str | None:
    """Why this submission's figures cannot be compared with the others', if they cannot.

    An exercise that agrees one model and runs every submission against it is
    making a claim about process. A leaderboard that cannot name the model
    behind a row cannot check that claim, and "unknown" then reads as "the
    agreed one" -- so a row is ranked only when its runs say which main model
    produced them and that model is the agreed baseline.

    A submission whose findings came from deterministic code is *not* at fault
    and is not worse; it was measured under different conditions, which is
    exactly what an unrankable row with a reason is for.
    """
    named = score.report.main_models
    if len(named) > 1:
        return (
            "its runs name more than one main model (" + ", ".join(named) + "), so its "
            "figures are a mixture of two measurements"
        )
    if baseline is None:
        return None
    if not named:
        return f"the agreed baseline is {baseline}, and its runs name no main model" + (
            " -- its findings were produced deterministically, which is a different "
            "measurement rather than a worse one"
            if score.report.deterministic_runs
            else ""
        )
    if named[0] != baseline:
        return f"it ran under {named[0]}, not the agreed baseline {baseline}"
    return None


def leaderboard(
    scores: Iterable[SubmissionScore],
    *,
    over: Sequence[VulnerabilityClass] | None = None,
    baseline: str | None = None,
    any_model: bool = False,
) -> Leaderboard:
    """Rank what can be ranked and list the rest with a reason.

    `baseline` is the main model the exercise agreed on. Given, a submission run
    under anything else is listed apart with that as its reason. Left out, the
    submissions are still checked against *each other*: if they name different
    main models, none of them is ranked, because picking the majority would
    publish a comparison nobody agreed to.

    `any_model` is that agreement made the other way: the exercise ranks every
    row whatever model it names -- a classroom where teams bring their own --
    and the board says so. A single submission naming two models is still a
    mixture and is still listed apart.

    An unrankable submission is *not* placed last. Ordering it below a ranked
    one asserts a comparison nobody measured, and the usual cause is work the
    exercise owes -- unadjudicated predictions, or a class the corpus does not
    cover -- rather than anything the submission did.

    Submissions scored under different per-unit prediction caps are not ranked
    against each other either, for the same reason: their precisions are over
    different pools.

    Ties keep a stable order by submission id so that two runs of the same
    inputs produce the same table.
    """
    scores = list(scores)
    wanted: tuple[VulnerabilityClass, ...]
    if over is not None:
        wanted = tuple(over)
    else:
        shared = {cls for score in scores for cls in score.classes}
        wanted = tuple(sorted(shared))

    if any_model and baseline is not None:
        raise ValueError("a board either agrees one baseline model or ranks any model, not both")
    agreed = baseline
    if agreed is None and not any_model:
        distinct = {score.report.main_models for score in scores}
        if len(distinct) > 1:
            # Nothing states which baseline was agreed and the runs disagree.
            # Ranking the ones that happen to share a model would make the
            # exercise's silence into a decision.
            named = sorted({model for models in distinct for model in models})
            reason = (
                "these submissions name different main models ("
                + (", ".join(named) or "and some name none")
                + ") and nothing states which was agreed"
            )
            return Leaderboard(
                unrankable=tuple(sorted(scores, key=lambda s: s.submission_id)),
                incomparable={score.submission_id: reason for score in scores},
                over=wanted,
                at_least=scores[0].at_least if scores else MatchStrength.FUNCTION,
            )

    caps = {score.report.predictions_per_unit for score in scores}
    if len(caps) > 1:
        # The same argument as the baseline check, on a different parameter. A
        # precision computed over three predictions per unit and one computed
        # over every prediction a submission cared to make are different
        # measurements, and a table that put them in one column would be
        # comparing how much adjudication each was allowed to consume.
        stated = ", ".join(
            "uncapped" if cap is None else str(cap) for cap in sorted(caps, key=lambda c: c or 0)
        )
        reason = (
            f"these submissions were scored under different per-unit prediction caps ({stated}), "
            "so their precisions are over different pools"
        )
        return Leaderboard(
            unrankable=tuple(sorted(scores, key=lambda s: s.submission_id)),
            incomparable={score.submission_id: reason for score in scores},
            over=wanted,
            at_least=scores[0].at_least if scores else MatchStrength.FUNCTION,
        )

    measures = {score.measure for score in scores}
    if len(measures) > 1:
        # The same argument again, on the figure itself rather than on a
        # parameter of it. An F1 and a bpref are not two precisions of the same
        # thing: one accounts for every prediction and the other ignores the
        # unjudged, so a column holding both would be ranking submissions on
        # which measure their round happened to announce.
        reason = (
            "these submissions were ranked on different measures ("
            + ", ".join(sorted(m.value for m in measures))
            + "), which answer different questions over different denominators"
        )
        return Leaderboard(
            unrankable=tuple(sorted(scores, key=lambda s: s.submission_id)),
            incomparable={score.submission_id: reason for score in scores},
            over=wanted,
            at_least=scores[0].at_least if scores else MatchStrength.FUNCTION,
        )

    # A submission id given more than once is one submission measured more than
    # once. Grouped here, after the whole-board checks above, which apply to
    # every measurement alike.
    groups: dict[str, list[SubmissionScore]] = {}
    for score in scores:
        groups.setdefault(score.submission_id, []).append(score)

    rankable: list[
        tuple[float, SubmissionScore, tuple[SubmissionScore, ...], tuple[float, ...]]
    ] = []
    unrankable: list[SubmissionScore] = []
    incomparable: dict[str, str] = {}
    for submission_id, group in groups.items():
        objection = next(
            (found for member in group if (found := _baseline_objection(member, agreed))), None
        )
        if objection is not None:
            incomparable[submission_id] = objection
            unrankable.append(group[0])
            continue
        totals = [member.total(wanted) for member in group]
        missing = next((m for m, t in zip(group, totals, strict=True) if t is None), None)
        if missing is not None:
            # One measurement without a total makes the mean a mean of the
            # others, which is a different number measured fewer times. The
            # row is unrankable, with that measurement's reasons.
            unrankable.append(missing)
            continue
        present = tuple(t for t in totals if t is not None)
        rankable.append(
            (
                sum(present) / len(present),
                group[0],
                tuple(group) if len(group) > 1 else (),
                present if len(group) > 1 else (),
            )
        )

    # Row order breaks ties by id so two runs print the same table; the *place*
    # does not. Equal totals share a place and the next is skipped (1, 1, 3):
    # handing the tie to whichever id sorts first would award a place nothing
    # measured. Equal means equal -- a tolerance would be a policy about how
    # close is a tie, and that is not this module's to set.
    rankable.sort(key=lambda row: (-row[0], row[1].submission_id))
    ranked = tuple(
        Ranked(
            place=1 + sum(1 for other, *_ in rankable if other > total),
            score=score,
            total=total,
            replicates=replicates,
            totals=totals,
        )
        for total, score, replicates, totals in rankable
    )
    return Leaderboard(
        ranked=ranked,
        unrankable=tuple(sorted(unrankable, key=lambda s: s.submission_id)),
        incomparable=incomparable,
        over=wanted,
        at_least=scores[0].at_least if scores else MatchStrength.FUNCTION,
        any_model=any_model,
    )
