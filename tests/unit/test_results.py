"""Pointers to published results, and the comparisons that are refused.

The interesting behaviour is all refusal. A directory of pointers is easy; a
directory that quietly puts two incomparable figures in one column is the
failure this file exists to prevent, and it is the failure a leaderboard makes
by default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from contract_assay.results import (
    ResultPointer,
    compare,
    load_pointers,
    pointer_from_document,
)

pytestmark = pytest.mark.offline

DIGEST = "0" * 64
OTHER = "1" * 64


def a_pointer(**over: Any) -> ResultPointer:
    fields: dict[str, Any] = {
        "submission_id": "alpha-detector",
        "published_by": "Alpha Lab",
        "document_url": "https://example.org/alpha.json",
        "engine_version": "0.1.0",
        "corpus_digest": DIGEST,
        "strength_floor": "function",
        "weights": {"S": 1.0, "M": 2.0},
        "predictions_per_unit": 3,
        "main_model": "the-agreed-model",
        "total": 0.5,
    }
    return ResultPointer.model_validate({**fields, **over})


def a_document(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "submission_id": "alpha-detector",
        "engine_version": "0.1.0",
        "strength_floor": "function",
        "predictions_per_unit": 3,
        "weights": {"S": 1.0},
        "corpus": {"digest": DIGEST, "records": 442},
        "models": {"main": "the-agreed-model"},
        "aggregate": {"total": {"value": 0.42, "unavailable": None}},
    }
    return {**base, **over}


class TestAPointerComesOutOfTheDocument:
    def test_every_field_is_read_rather_than_claimed(self) -> None:
        # A pointer assembled by hand is a number somebody typed.
        pointer = pointer_from_document(
            a_document(), published_by="Alpha Lab", document_url="https://example.org/a.json"
        )
        assert pointer.corpus_digest == DIGEST
        assert pointer.engine_version == "0.1.0"
        assert pointer.predictions_per_unit == 3
        assert pointer.total == 0.42
        assert pointer.main_model == "the-agreed-model"

    def test_a_refused_total_carries_the_documents_own_sentence(self) -> None:
        document = a_document(
            aggregate={"total": {"value": None, "unavailable": "3 classes await adjudication"}}
        )
        pointer = pointer_from_document(
            document, published_by="Alpha Lab", document_url="https://example.org/a.json"
        )
        assert pointer.total is None
        assert pointer.unavailable == "3 classes await adjudication"

    def test_a_deterministic_submission_names_no_model_and_that_is_not_a_gap(self) -> None:
        document = a_document(models={"main": None})
        pointer = pointer_from_document(
            document, published_by="Alpha Lab", document_url="https://example.org/a.json"
        )
        assert pointer.main_model is None


class TestANullNeverStandsAlone:
    def test_a_missing_total_with_no_reason_is_refused(self) -> None:
        # The whole point of the wire format one level down: a reader that
        # renders a null prints an empty cell, and one that defaults it has
        # published a number the engine refused to state.
        with pytest.raises(ValueError, match="renders the null as a zero"):
            a_pointer(total=None, unavailable=None)

    def test_a_real_total_beside_a_refusal_sentence_is_refused(self) -> None:
        # Both directions. One of the two is wrong and nothing here can say
        # which, so a reader has no way to choose.
        with pytest.raises(ValueError, match="one of"):
            a_pointer(total=0.5, unavailable="precision is unavailable")


class TestComparisonIsRefusedMoreOftenThanGranted:
    def test_results_on_one_basis_are_ranked_together(self) -> None:
        got = compare([a_pointer(submission_id="a-low", total=0.1), a_pointer(total=0.9)])
        assert len(got.comparable) == 1
        assert [p.submission_id for p in got.comparable[0]] == ["alpha-detector", "a-low"]
        assert "Comparable." in got.statement()

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("corpus_digest", OTHER),
            ("engine_version", "0.2.0"),
            ("strength_floor", "exact"),
            ("weights", {"S": 9.0}),
            ("predictions_per_unit", 1),
        ],
    )
    def test_a_different_basis_is_a_different_group(self, field: str, value: Any) -> None:
        # None of these is a scoring bug; each makes the two figures answers to
        # different questions.
        got = compare([a_pointer(), a_pointer(submission_id="beta-detector", **{field: value})])
        assert len(got.comparable) == 2
        assert "NOT comparable" in got.statement()
        assert field in got.statement()

    def test_a_corpus_that_grew_is_named_as_the_usual_cause(self) -> None:
        got = compare([a_pointer(), a_pointer(submission_id="beta-detector", corpus_digest=OTHER)])
        assert "a corpus that grew" in got.statement()

    def test_a_refused_total_is_listed_after_the_ranked_but_is_not_last(self) -> None:
        # Ordering it below a ranked result asserts a comparison nobody
        # measured, and the usual cause is work the exercise owes.
        got = compare(
            [
                a_pointer(submission_id="ranked-low", total=0.1),
                a_pointer(submission_id="no-total", total=None, unavailable="queue is not empty"),
                a_pointer(submission_id="ranked-high", total=0.9),
            ]
        )
        assert [p.submission_id for p in got.comparable[0]] == [
            "ranked-high",
            "ranked-low",
            "no-total",
        ]

    def test_no_results_says_so_rather_than_ranking_nothing(self) -> None:
        assert compare([]).statement() == "No published results."


class TestLoading:
    def test_pointers_load_in_a_stable_order(self, tmp_path: Path) -> None:
        for name in ("b", "a", "c"):
            (tmp_path / f"{name}.json").write_text(
                a_pointer(submission_id=f"{name}-detector").model_dump_json(), encoding="utf-8"
            )
        assert [p.submission_id for p in load_pointers(tmp_path)] == [
            "a-detector",
            "b-detector",
            "c-detector",
        ]

    def test_an_invalid_pointer_names_its_file_and_stops(self, tmp_path: Path) -> None:
        # A directory that silently drops a result is a comparison over a subset
        # nobody chose.
        (tmp_path / "good.json").write_text(a_pointer().model_dump_json(), encoding="utf-8")
        (tmp_path / "bad.json").write_text(json.dumps({"submission_id": "x"}), encoding="utf-8")
        with pytest.raises(ValueError, match=r"bad\.json"):
            load_pointers(tmp_path)

    def test_an_empty_directory_is_not_an_error(self, tmp_path: Path) -> None:
        assert load_pointers(tmp_path) == []
