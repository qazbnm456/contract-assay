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
from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class SubmissionScore:
    """What one submission earned, and what could not be computed for it."""

    submission_id: str
    report: ScoreReport
    at_least: MatchStrength
    weights: Mapping[DifficultyLevel, float]

    @property
    def classes(self) -> tuple[VulnerabilityClass, ...]:
        return tuple(sorted(self.report.by_class))

    def f1(self, cls: VulnerabilityClass) -> float | None:
        score = self.report.by_class.get(cls)
        if score is None:
            return None
        return _f1(score.precision(self.at_least), score.recall(self.at_least))

    @property
    def unavailable(self) -> Mapping[VulnerabilityClass, str]:
        """Why each class without an F1 does not have one.

        A reason per class rather than one aggregate absence, because the two
        causes call for different work: an unjudged pool is adjudication owed,
        and a class with no records is corpus owed.
        """
        out: dict[VulnerabilityClass, str] = {}
        for cls, score in sorted(self.report.by_class.items()):
            if self.f1(cls) is not None:
                continue
            if not score.records:
                out[cls] = "the corpus holds no positive record of this class"
            elif not score.predictions:
                out[cls] = "the submission claimed nothing in this class"
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

    def weighted_f1(self, over: Sequence[VulnerabilityClass] | None = None) -> float | None:
        """Difficulty-weighted mean F1, or nothing if any requested class lacks one.

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
            value = self.f1(cls)
            if value is None:
                return None
            weight = self.weights.get(cls.level)
            if weight is None:
                return None
            numerator += weight * value
            denominator += weight
        return numerator / denominator if denominator else None

    def total(self, over: Sequence[VulnerabilityClass] | None = None) -> float | None:
        """The one number, when it exists: weighted F1 times completion rate."""
        weighted = self.weighted_f1(over)
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


@dataclass(frozen=True, slots=True)
class Leaderboard:
    """Ranked submissions, and the ones that could not be ranked."""

    ranked: tuple[Ranked, ...] = ()
    unrankable: tuple[SubmissionScore, ...] = ()
    over: tuple[VulnerabilityClass, ...] = ()
    at_least: MatchStrength = MatchStrength.FUNCTION

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
            parts.append(
                f"{len(self.unrankable)} could not be ranked and are listed with the "
                "reason rather than placed last: an unrankable submission is not a "
                "worse one, and ordering it below a ranked one would assert something "
                "nobody measured."
            )
        return " ".join(parts)


def score_submission(
    submission_id: str,
    report: ScoreReport,
    *,
    weights: Mapping[DifficultyLevel, float],
    at_least: MatchStrength = MatchStrength.FUNCTION,
) -> SubmissionScore:
    """Wrap one submission's score report for ranking."""
    return SubmissionScore(
        submission_id=submission_id, report=report, at_least=at_least, weights=dict(weights)
    )


def leaderboard(
    scores: Iterable[SubmissionScore],
    *,
    over: Sequence[VulnerabilityClass] | None = None,
) -> Leaderboard:
    """Rank what can be ranked and list the rest with a reason.

    An unrankable submission is *not* placed last. Ordering it below a ranked
    one asserts a comparison nobody measured, and the usual cause is work the
    exercise owes -- unadjudicated predictions, or a class the corpus does not
    cover -- rather than anything the submission did.

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

    rankable: list[tuple[float, SubmissionScore]] = []
    unrankable: list[SubmissionScore] = []
    for score in scores:
        total = score.total(wanted)
        if total is None:
            unrankable.append(score)
        else:
            rankable.append((total, score))

    rankable.sort(key=lambda pair: (-pair[0], pair[1].submission_id))
    ranked = tuple(
        Ranked(place=index, score=score, total=total)
        for index, (total, score) in enumerate(rankable, start=1)
    )
    return Leaderboard(
        ranked=ranked,
        unrankable=tuple(sorted(unrankable, key=lambda s: s.submission_id)),
        over=wanted,
        at_least=scores[0].at_least if scores else MatchStrength.FUNCTION,
    )
