"""JSON documents for callers outside this process.

A submission surface -- a web front end, a queue worker, a marking script -- must
not re-implement scoring, because a second implementation of a refusal is a
first implementation of a default. §7.6 refuses to publish an F1 without both
sides, an aggregate over a partial class set, or a built-in set of weights, and
every one of those refusals is cheap to lose in translation: a caller reading a
missing key as zero has silently invented the number this module declines to
state.

So the documents here follow three rules, and they are the whole design.

**A figure and its absence are the same shape.** Every measurement is
`{"value": …, "unavailable": …}`. A `value` of `null` always arrives with a
sentence saying why, and a caller that renders `value` without checking prints
an empty cell rather than a zero. The alternative -- omitting the key -- makes
`0` and "not licensed" indistinguishable to every consumer that uses `or 0`.

**A number a human is told is a list a human can act on.** "59 of its
predictions are not yet adjudicated" is only actionable if the 59 can be opened,
so `adjudication_queue` carries them with their unit and line range. Precision
waits on that queue, which makes the queue the exercise's own work rather than a
submission's defect.

**A document says what it was computed against.** `corpus.digest` changes when
any record changes, so a stored leaderboard row can be checked rather than
trusted. Two rows with different digests were not measured against the same
ground truth and are not comparable, whatever the numbers say.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from contract_assay import __version__
from contract_assay.corpus.records import CorpusRecord
from contract_assay.models import ModelRole, VulnerabilityClass
from contract_assay.report.leaderboard import Leaderboard, SubmissionScore
from contract_assay.report.scoring import ClassScore, MatchStrength, ScoreReport

__all__ = [
    "SCHEMA_VERSION",
    "corpus_fingerprint",
    "leaderboard_document",
    "score_document",
]

SCHEMA_VERSION = "1.0"
"""Version of the document shapes below, not of the engine.

Separate from `engine_version` because they change for different reasons: a
detector's behaviour moving is not a reason for a consumer to re-read its
parser, and a field being removed is, whatever the engine did.
"""


def _figure(value: float | None, unavailable: str | None) -> dict[str, Any]:
    """One measurement, or its absence with the reason attached.

    A `value` of `null` and no reason would be a refusal the caller cannot
    explain to whoever is reading the page, so an unavailable figure without a
    stated cause is a defect in this module rather than a state to represent.
    """
    if value is None and unavailable is None:
        unavailable = "not licensed, and this engine failed to say why"
    return {"value": value, "unavailable": unavailable}


def corpus_fingerprint(records: Iterable[CorpusRecord]) -> dict[str, Any]:
    """What this score was measured against, as a digest and a census.

    The digest covers each record's identity *and* the bytes it was verified
    against, so adding a record, re-pinning one, or repointing a locator all
    change it. Class counts travel beside it because the commonest reason two
    leaderboards disagree is not a scoring change but a corpus that grew.
    """
    entries = sorted(
        f"{record.record_id}:{record.pin.source_id}:{record.pin.sha256 or ''}" for record in records
    )
    digest = hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()
    census: dict[str, int] = {}
    for record in records:
        for cls in record.classes:
            census[cls.value] = census.get(cls.value, 0) + 1
    return {"digest": digest, "records": len(entries), "positives_by_class": census}


def _models(report: ScoreReport) -> dict[str, Any]:
    """What produced these figures, which is what makes them comparable.

    A row whose model is unknown cannot be checked against the exercise's agreed
    baseline, and a reader shown no model assumes the agreed one. So the main
    model is its own field -- present or explicitly `null` -- rather than
    something to infer from a list.
    """
    main = [use for use in report.models if use.role is ModelRole.MAIN]
    return {
        "main": main[0].model_id if len(main) == 1 else None,
        "main_models_named": list(report.main_models),
        "sub": [
            {"model_id": use.model_id, "calls": use.calls, "tokens": use.tokens}
            for use in report.models
            if use.role is ModelRole.SUB
        ],
        "calls": sum(use.calls for use in report.models),
        "tokens": sum(use.tokens for use in report.models),
        "deterministic_runs": report.deterministic_runs,
    }


def _limits(report: ScoreReport, cls: VulnerabilityClass) -> list[dict[str, Any]]:
    return [
        {
            "kind": limit.kind.value,
            "shape": limit.shape,
            # The records this shape hides. It was a single id serialised with
            # `list()`, which spread the string into one entry per character --
            # and the wrong shape read as the right one, because a consumer
            # would have rendered a list of ids faithfully either way.
            "demonstrated_by": list(limit.demonstrated_by),
            "unpatched_because": limit.unpatched_because,
            "closed_when": limit.closed_when,
            "closed_by": limit.closed_by,
            "isolated": limit.isolated,
        }
        for limit in report.declared_limits.get(cls, ())
    ]


def _class_document(
    score: ClassScore,
    report: ScoreReport,
    *,
    at_least: MatchStrength,
    f1: float | None,
    f1_unavailable: str | None,
) -> dict[str, Any]:
    precision_unavailable = (
        None
        if score.pool_is_fully_judged
        else (
            f"{score.unjudged_predictions} of its predictions are not yet adjudicated"
            if score.predictions
            else "the submission claimed nothing in this class"
        )
    )
    recall_unavailable = None if score.records else "the corpus holds no positive record"
    return {
        "class": score.cls.value,
        "records": score.records,
        "predictions": score.predictions,
        "matched": score.matched,
        "false_negatives": score.false_negatives,
        "false_positives": score.false_positives,
        "unverifiable_claims": score.unverifiable_claims,
        "capped_predictions": score.capped_predictions,
        "hits_by_strength": {
            strength.value: count for strength, count in sorted(score.by_strength.items())
        },
        "recall": _figure(score.recall(at_least), recall_unavailable),
        "precision": _figure(score.precision(at_least), precision_unavailable),
        "f1": _figure(f1, f1_unavailable),
        # Not a score. A count below the stated minimum is reported so a caller
        # can refuse to draw a bar for it, which is the only honest rendering.
        "below_minimum": score.below_minimum,
        "judging": {
            "judged_predictions": score.judged_predictions,
            "unjudged_predictions": score.unjudged_predictions,
            "pool_fully_judged": score.pool_is_fully_judged,
            "adjudications": score.adjudications,
            "completeness_records": score.completeness_records,
        },
        "runs": {
            "measured": score.measured_runs,
            "invalid": score.invalid_runs,
            "skipped": score.skipped_runs,
            "qualified_negatives": score.qualified_negatives,
        },
        "missed_record_ids": list(score.missed_record_ids),
        "declared_limits": _limits(report, score.cls),
    }


def _why_no_total(submission: SubmissionScore) -> str | None:
    """Why there is no one number, distinguishing the two reasons there can be.

    A missing weight and a missing F1 are different failures with different
    owners: the first is a policy the exercise has not stated, the second is a
    class the corpus or the submission cannot yet support. Reporting both as
    "unavailable" leaves the reader unable to tell whose turn it is.
    """
    if submission.total() is not None:
        return None
    unweighted = sorted(
        {cls.level.value for cls in submission.classes if cls.level not in submission.weights}
    )
    reasons: list[str] = []
    if unweighted:
        reasons.append(
            "no weight was supplied for difficulty " + ", ".join(unweighted) + " -- this engine "
            "ships none, because a weighting is a statement about what the exercise values"
        )
    partial = "; ".join(
        f"{cls.value}: {why}" for cls, why in sorted(submission.unavailable.items())
    )
    if partial:
        reasons.append("no aggregate over a partial class set -- " + partial)
    if submission.completion_rate is None:
        reasons.append(
            "no run produced a usable answer, so there is no completion rate to scale by"
        )
    return "; ".join(reasons) or "not licensed, and this engine failed to say why"


def score_document(
    submission: SubmissionScore,
    records: Sequence[CorpusRecord],
) -> dict[str, Any]:
    """One submission's score, with every refusal stated rather than implied."""
    report = submission.report
    unavailable = submission.unavailable
    return {
        "schema_version": SCHEMA_VERSION,
        "engine_version": __version__,
        "submission_id": submission.submission_id,
        "strength_floor": submission.at_least.value,
        # Beside the weights and the floor, because it is the same kind of
        # thing: a parameter of the exercise, without which the figures below
        # have no stated basis. A precision over three predictions per unit and
        # one over every prediction a submission cared to make are different
        # measurements.
        "predictions_per_unit": report.predictions_per_unit,
        "weights": {level.value: weight for level, weight in sorted(submission.weights.items())},
        "corpus": corpus_fingerprint(records),
        "models": _models(report),
        "statement": report.statement(),
        "classes": [
            _class_document(
                report.by_class[cls],
                report,
                at_least=submission.at_least,
                f1=submission.f1(cls),
                f1_unavailable=unavailable.get(cls),
            )
            for cls in sorted(report.by_class, key=lambda c: c.value)
        ],
        "aggregate": {
            "completion_rate": submission.completion_rate,
            "total": _figure(submission.total(), _why_no_total(submission)),
        },
        "stratified": {
            "by_level": {level.value: n for level, n in sorted(report.by_level.items())},
            "by_tier": {tier.value: n for tier, n in sorted(report.by_tier.items())},
            "by_provenance": {p.value: n for p, n in sorted(report.by_provenance.items())},
            "by_population": {p.value: n for p, n in sorted(report.by_population.items())},
            # What the corpus these figures came from is made of. One harvest
            # took it from 32 records to 166 with 81% from a single platform,
            # and every figure over it became mostly a statement about that
            # platform's submission style with nothing saying so.
            "by_platform": dict(sorted(report.by_platform.items())),
            "by_repository": dict(sorted(report.by_repository.items())),
        },
        "unscoreable": {
            "claims": {cls.value: n for cls, n in sorted(report.unscoreable_claims.items())},
            "runs": {cls.value: n for cls, n in sorted(report.unscoreable_runs.items())},
        },
        "unexplained_misses": {
            cls.value: n for cls, n in sorted(report.unexplained_misses.items())
        },
        # What ranking waits on. Carried in full: a queue truncated for size is
        # a queue that cannot be worked through, and the count beside it would
        # then disagree with the leaderboard's own sentence.
        #
        # `unlocks` says what judging the entry can buy, because two of six
        # entries over one sample could buy nothing: they are predictions in a
        # class the corpus holds no positive record of, so judging them licenses
        # a precision that will never meet a recall. A queue length with no such
        # mark sends an adjudicator to work that cannot pay.
        "adjudication_queue": [
            {
                "class": entry.class_id.value,
                "source_id": entry.source_id,
                "detector_id": entry.detector_id,
                "file": entry.locator.file,
                "start_line": entry.locator.start_line,
                "end_line": entry.locator.end_line,
                "unlocks": (
                    "f1"
                    if report.by_class[entry.class_id].records
                    else "precision only -- this class has no positive record, so no f1"
                ),
            }
            for entry in report.unjudged
        ],
    }


def leaderboard_document(
    board: Leaderboard,
    records: Sequence[CorpusRecord],
    *,
    documents: Mapping[str, dict[str, Any]] | None = None,
    baseline: str | None = None,
) -> dict[str, Any]:
    """The ranking, and the submissions it declines to rank, in one document.

    Unrankable submissions are a separate list rather than rows with a null
    total, because a table sorts and a caller sorting nulls to the bottom has
    published the comparison §7.6 refuses to make. They carry their reasons, so
    a page can say what the exercise owes rather than what the submission
    lacks.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "engine_version": __version__,
        "strength_floor": board.at_least.value,
        # One value, because `leaderboard` declines to rank rows that disagree
        # about it. Stated here so a board can be re-derived without opening a
        # row's report.
        "predictions_per_unit": next(
            (row.score.report.predictions_per_unit for row in board.ranked), None
        ),
        "over_classes": [cls.value for cls in board.over],
        "corpus": corpus_fingerprint(records),
        "baseline": baseline,
        "statement": board.statement(),
        "ranked": [
            {
                "place": row.place,
                "submission_id": row.score.submission_id,
                "total": row.total,
                "completion_rate": row.score.completion_rate,
                "models": _models(row.score.report),
                "f1_by_class": {
                    cls.value: _figure(row.score.f1(cls), row.score.unavailable.get(cls))
                    for cls in board.over
                },
                "report": (documents or {}).get(row.score.submission_id),
            }
            for row in board.ranked
        ],
        "unrankable": [
            {
                "submission_id": score.submission_id,
                # Two different kinds of "cannot". `incomparable` means the
                # figures exist and the comparison does not, which is the
                # exercise's own gap rather than the submission's.
                "incomparable": board.incomparable.get(score.submission_id),
                "reasons": {cls.value: why for cls, why in sorted(score.unavailable.items())},
                "models": _models(score.report),
                "report": (documents or {}).get(score.submission_id),
            }
            for score in board.unrankable
        ],
    }
