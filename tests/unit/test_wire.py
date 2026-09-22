"""The JSON documents a submission surface is built on.

Every test here is about a way a consumer could be misled by a shape rather
than by a number: a refusal rendered as a zero, a queue count that disagrees
with the sentence beside it, two rows measured against different ground truth
compared anyway.
"""

from __future__ import annotations

import json

import pytest

from contract_assay.corpus.records import (
    CommitPin,
    CorpusRecord,
    CorpusSplit,
    LocatorLabel,
    LocatorProvenance,
    Population,
    Provenance,
)
from contract_assay.models import (
    DifficultyLevel,
    Locator,
    ModelRole,
    ModelUse,
    VulnerabilityClass,
)
from contract_assay.report.leaderboard import leaderboard, score_submission
from contract_assay.report.scoring import (
    ClassScore,
    MatchStrength,
    ScoreReport,
    Unjudged,
)
from contract_assay.report.wire import (
    SCHEMA_VERSION,
    corpus_fingerprint,
    leaderboard_document,
    score_document,
)

pytestmark = pytest.mark.offline

SHA = "a" * 40
CLS = VulnerabilityClass.ACCESS_CONTROL
OTHER_CLS = VulnerabilityClass.REENTRANCY
WEIGHTS = {DifficultyLevel.S: 1.0, DifficultyLevel.M: 2.0, DifficultyLevel.Q: 3.0}


def a_record(record_id: str = "r-1", digest: str = "b" * 64) -> CorpusRecord:
    return CorpusRecord(
        record_id=record_id,
        population=Population.AUDIT_REVIEW,
        split=CorpusSplit.PUBLIC,
        pin=CommitPin(
            repo_url="https://github.com/example/vault",
            commit=SHA,
            path="src/Vault.sol",
            sha256=digest,
        ),
        locator=Locator(
            file="src/Vault.sol", contract="Vault", function="f", start_line=1, end_line=2
        ),
        classes=(CLS,),
        locator_provenance=LocatorProvenance.STATED,
        provenance=Provenance(platform="example", report_url="https://example.invalid/1"),
    )


def a_report(*, judged: int = 4, unjudged: tuple[Unjudged, ...] = (), models=()) -> ScoreReport:  # type: ignore[no-untyped-def]
    return ScoreReport(
        by_class={
            CLS: ClassScore(
                cls=CLS,
                records=4,
                predictions=4,
                judged_predictions=judged,
                by_strength={MatchStrength.EXACT: 2},
                judged_by_strength={MatchStrength.EXACT: 2},
                measured_runs=4,
            )
        },
        unjudged=unjudged,
        models=models,
    )


def a_submission(report: ScoreReport, submission_id: str = "alice"):  # type: ignore[no-untyped-def]
    return score_submission(submission_id, report, weights=WEIGHTS, at_least=MatchStrength.EXACT)


class TestEveryDisagreementReachesAJsonReader:
    """The `citations` block, key by key and value by value.

    The block exists because `refuted_citations` lived only in `statement()`'s
    prose: a consumer parsing JSON could not see that the scorer had disagreed
    with the submitter about its own evidence. It was then unpinned, so a review
    deleted all four keys and swapped two of them with the suite green -- which
    is the same defect one level up.
    """

    def test_the_four_counters_are_published_with_their_own_values(self) -> None:
        report = ScoreReport(
            by_class=a_report().by_class,
            refuted_citations=7,
            unchecked_citations=5,
            stale_citations=2,
            repositioned_predictions=3,
            repositioned_into_another_function=2,
        )
        document = score_document(a_submission(report), [a_record()])
        assert document["citations"] == {
            "refuted": 7,
            "unchecked": 5,
            "stale": 2,
            "repositioned": 3,
            "repositioned_into_another_function": 2,
        }


class TestAFigureAndItsAbsenceAreTheSameShape:
    """A missing key is a zero to every consumer that writes `or 0`."""

    def test_an_available_figure_carries_a_null_reason(self) -> None:
        document = score_document(a_submission(a_report()), [a_record()])
        [entry] = document["classes"]
        assert entry["f1"] == {"value": pytest.approx(0.5), "unavailable": None}

    def test_an_unavailable_figure_is_null_with_a_reason(self) -> None:
        document = score_document(a_submission(a_report(judged=2)), [a_record()])
        [entry] = document["classes"]
        assert entry["precision"]["value"] is None
        assert "not yet adjudicated" in entry["precision"]["unavailable"]
        assert entry["f1"]["value"] is None
        assert entry["f1"]["unavailable"]

    def test_the_document_round_trips_as_json(self) -> None:
        document = score_document(a_submission(a_report()), [a_record()])
        assert json.loads(json.dumps(document))["schema_version"] == SCHEMA_VERSION


class TestTheNumberIsAList:
    """ "59 predictions await adjudication" is only actionable if the 59 open."""

    def test_the_queue_carries_every_unjudged_prediction(self) -> None:
        queued = (
            Unjudged(
                class_id=CLS,
                source_id="vault@abc",
                detector_id="d",
                locator=Locator(file="src/Vault.sol", start_line=9, end_line=11),
            ),
        )
        document = score_document(a_submission(a_report(judged=3, unjudged=queued)), [a_record()])
        [entry] = document["adjudication_queue"]
        assert entry == {
            "class": CLS.value,
            "source_id": "vault@abc",
            "detector_id": "d",
            "file": "src/Vault.sol",
            "start_line": 9,
            "end_line": 11,
            # The class holds positive records, so judging this can complete an
            # F1. Where it cannot, the entry says so -- two of six entries over
            # one sample were predictions in a class with no positive record,
            # and judging those licenses a precision no recall will ever meet.
            "unlocks": "f1",
        }

    def test_the_queue_length_agrees_with_the_class_count(self) -> None:
        queued = tuple(
            Unjudged(
                class_id=CLS,
                source_id="vault@abc",
                detector_id="d",
                locator=Locator(file="src/Vault.sol", start_line=n, end_line=n),
            )
            for n in (5, 6)
        )
        document = score_document(a_submission(a_report(judged=2, unjudged=queued)), [a_record()])
        [entry] = document["classes"]
        assert entry["judging"]["unjudged_predictions"] == len(document["adjudication_queue"])


class TestADocumentSaysWhatItWasMeasuredAgainst:
    def test_the_digest_moves_when_a_record_is_repinned(self) -> None:
        one = corpus_fingerprint([a_record()])
        other = corpus_fingerprint([a_record(digest="c" * 64)])
        assert one["digest"] != other["digest"]

    def test_the_digest_does_not_depend_on_order(self) -> None:
        first, second = a_record("r-1"), a_record("r-2")
        assert corpus_fingerprint([first, second]) == corpus_fingerprint([second, first])

    def test_the_digest_moves_when_a_locator_is_repointed(self) -> None:
        """The docstring claimed this for a while and it was false.

        The digest material was `record_id:source_id:sha256`, which does not
        contain a locator, so a record repointed five hundred lines away
        published the same digest and `results.compare` called the two
        comparable.
        """
        moved = a_record().model_copy(
            update={
                "locator": Locator(
                    file="src/Vault.sol",
                    contract="Vault",
                    function="f",
                    start_line=501,
                    end_line=502,
                )
            }
        )
        assert corpus_fingerprint([a_record()])["digest"] != corpus_fingerprint([moved])["digest"]

    def test_the_digest_moves_when_an_adjudication_is_added_to_a_record(self) -> None:
        """The reason this is not merely untidy.

        A `negative_for` added to an existing record is what makes precision
        available for that (unit, class) pair. Recorded as an edit rather than
        as a new record it changed no digest, so two results resting on
        different adjudication sets were called comparable -- while the same
        judgement written as a new record did change it. A hole open for one of
        the two ways of writing the same thing down is the shape that survives
        review.
        """
        adjudicated = a_record().model_copy(update={"negative_for": [OTHER_CLS]})
        assert (
            corpus_fingerprint([a_record()])["digest"]
            != corpus_fingerprint([adjudicated])["digest"]
        )

    def test_the_digest_moves_when_a_class_is_added(self) -> None:
        """`classes` is recall's denominator."""
        relabelled = a_record().model_copy(update={"classes": (CLS, OTHER_CLS)})
        assert (
            corpus_fingerprint([a_record()])["digest"] != corpus_fingerprint([relabelled])["digest"]
        )

    def test_the_digest_moves_when_a_record_changes_split(self) -> None:
        """A record moving between splits leaves one corpus and joins another."""
        moved = a_record().model_copy(update={"split": CorpusSplit.PRIVATE_HOLDOUT})
        assert corpus_fingerprint([a_record()])["digest"] != corpus_fingerprint([moved])["digest"]

    def test_the_digest_does_not_move_when_an_asserted_label_is_added(self) -> None:
        """This test asserted the opposite, on a justification that was false.

        `asserted_labels` was put in the basis with the reason that it caps the
        strength a match can reach. Nothing in `report/` reads it -- it reaches
        `CorpusRecord.independent_claims`, which no document publishes -- so by
        the other half of the rule, a field nothing computes over must not
        invalidate a comparison. It joins the moment a report reads it, and
        `test_scoring.py`'s two-sided test is what will say so.
        """
        labelled = a_record().model_copy(update={"asserted_labels": [LocatorLabel.FUNCTION]})
        assert (
            corpus_fingerprint([a_record()])["digest"] == corpus_fingerprint([labelled])["digest"]
        )

    def test_the_digest_moves_when_the_locators_provenance_changes(self) -> None:
        """Same reason: a `derived` span and a `stated` one of the same lines
        are not the same claim about where the defect is."""
        derived = a_record().model_copy(update={"locator_provenance": LocatorProvenance.DERIVED})
        assert corpus_fingerprint([a_record()])["digest"] != corpus_fingerprint([derived])["digest"]

    def test_the_digest_does_not_move_when_a_note_is_edited(self) -> None:
        """Deliberate. A digest that moved when somebody improved a note would
        group results apart for a reason that is not a measurement."""
        annotated = a_record().model_copy(update={"notes": "an improved note"})
        assert (
            corpus_fingerprint([a_record()])["digest"] == corpus_fingerprint([annotated])["digest"]
        )

    def test_the_census_counts_positives_by_class(self) -> None:
        got = corpus_fingerprint([a_record("r-1"), a_record("r-2")])
        assert got["positives_by_class"] == {CLS.value: 2}


class TestTheModelBehindEachRow:
    """A row whose model is unknown cannot be checked against the baseline."""

    def test_the_main_model_is_its_own_field(self) -> None:
        models = (ModelUse(model_id="agreed", role=ModelRole.MAIN, calls=2, tokens=40),)
        document = score_document(a_submission(a_report(models=models)), [a_record()])
        assert document["models"]["main"] == "agreed"
        assert document["models"]["calls"] == 2

    def test_no_model_is_explicit_rather_than_missing(self) -> None:
        document = score_document(a_submission(a_report()), [a_record()])
        assert document["models"]["main"] is None

    def test_an_unranked_row_says_which_kind_of_cannot(self) -> None:
        agreed = a_submission(
            a_report(models=(ModelUse(model_id="agreed", role=ModelRole.MAIN),)), "alice"
        )
        other = a_submission(
            a_report(models=(ModelUse(model_id="other", role=ModelRole.MAIN),)), "bob"
        )
        board = leaderboard([agreed, other], baseline="agreed")
        document = leaderboard_document(board, [a_record()], baseline="agreed")
        assert document["baseline"] == "agreed"
        assert [row["submission_id"] for row in document["ranked"]] == ["alice"]
        [unranked] = document["unrankable"]
        assert "other" in unranked["incomparable"]
        assert unranked["models"]["main"] == "other"


class TestAFieldsTypeIsPartOfItsMeaning:
    """`demonstrated_by` is a record id, and `list()` on a string spreads it.

    The document carried one entry per character and a consumer would have
    rendered that faithfully. Caught by reading the output, which is the only
    thing that catches it: every type checks, every test passed, and the JSON
    was well formed.
    """

    def test_a_declared_limit_names_the_records_it_hides(self) -> None:
        from contract_assay.models import DeclaredLimit, LimitKind

        limit = DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape="a shape this tier cannot see",
            demonstrated_by=("some-record-id", "another"),
            isolated=True,
            unpatched_because="because",
            closed_when="when",
        )
        report = ScoreReport(
            by_class={CLS: ClassScore(cls=CLS, records=1)},
            declared_limits={CLS: (limit,)},
        )
        document = score_document(a_submission(report), [a_record()])
        [entry] = document["classes"]
        assert entry["declared_limits"][0]["demonstrated_by"] == ["some-record-id", "another"]
