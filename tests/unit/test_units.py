"""A holdout is published as questions. The answers are what it withholds."""

from __future__ import annotations

import json

import pytest

from contract_assay.corpus.records import CorpusRecord
from contract_assay.corpus.units import manifest_pins, read_manifest, unit_manifest

pytestmark = pytest.mark.offline


def a_record(record_id: str, path: str, cls: str = "access_control", **pin: object) -> CorpusRecord:
    return CorpusRecord.model_validate(
        {
            "record_id": record_id,
            "population": "audit_review",
            "split": "private_holdout",
            "pin": {
                "kind": "commit",
                "repo_url": "https://github.com/x/y",
                "commit": "a" * 40,
                "path": path,
                **pin,
            },
            "locator": {
                "file": path,
                "contract": "C",
                "function": "f",
                "start_line": 1,
                "end_line": 2,
            },
            "locator_provenance": "stated",
            "classes": [cls],
            "notes": "Adjudicated by reading the source; the guard is absent.",
            "provenance": {"platform": "p", "report_url": "https://x/1"},
        }
    )


class TestTheManifestCarriesNoAnswer:
    def test_no_field_of_a_record_survives_except_the_pin(self) -> None:
        """The structural one. Asserting `locator` is absent would pass while
        `classes` leaked; this asserts the field set **is** the pin's."""
        record = a_record("holdout-1", "src/A.sol")
        document = unit_manifest([record])
        allowed = set(type(record.pin).model_fields)
        for unit in document["units"]:
            assert set(unit) <= allowed
        outside = set(CorpusRecord.model_fields) - allowed
        text = json.dumps(document)
        for field in outside:
            assert f'"{field}"' not in text, f"{field} reached the manifest"

    def test_the_record_id_is_absent_and_that_is_the_point(self) -> None:
        """Every id in the holdout this was built for names its own class, as in
        `2025-04-virtuals-protocol-flashloan-manipulation-d79a7338`. A manifest
        that kept ids to look tidy would publish all 55 answers in the
        filenames while every field a reviewer thought to check was absent."""
        document = unit_manifest([a_record("app-flashloan-manipulation-1", "src/A.sol")])
        assert "flashloan" not in json.dumps(document)

    def test_the_class_name_never_appears(self) -> None:
        document = unit_manifest([a_record("h-1", "src/A.sol", cls="slippage")])
        assert "slippage" not in json.dumps(document)

    def test_a_provenance_only_pin_field_is_left_out(self) -> None:
        """`resolved_from` says how a coordinate was obtained. An audit needs
        it; a participant running a harness does not, and it is marked on the
        field rather than listed here."""
        document = unit_manifest(
            [a_record("h-1", "src/A.sol", resolved_from="the commit its citations name most often")]
        )
        assert "resolved_from" not in json.dumps(document)
        assert "citations" not in json.dumps(document)


class TestWhichUnitsAreNamed:
    def test_two_records_in_one_file_are_one_unit(self) -> None:
        """Publishing it twice would say which files hold more than one defect."""
        document = unit_manifest([a_record("h-1", "src/A.sol"), a_record("h-2", "src/A.sol")])
        assert len(document["units"]) == 1

    def test_the_pin_carrying_a_digest_wins(self) -> None:
        """`units_from`'s rule, applied here so the two cannot disagree."""
        document = unit_manifest(
            [
                a_record("h-2", "src/A.sol"),
                a_record("h-1", "src/A.sol", sha256="b" * 64),
            ]
        )
        assert document["units"][0]["sha256"] == "b" * 64

    def test_units_are_in_a_stable_order(self) -> None:
        first = unit_manifest([a_record("h-2", "src/B.sol"), a_record("h-1", "src/A.sol")])
        second = unit_manifest([a_record("h-1", "src/A.sol"), a_record("h-2", "src/B.sol")])
        assert first == second


class TestReadingOneBack:
    def test_a_manifest_round_trips_to_pins(self) -> None:
        record = a_record("h-1", "src/A.sol")
        pins = read_manifest(json.dumps(unit_manifest([record])))
        assert [pin.source_id for pin in pins] == [record.pin.source_id]

    def test_a_malformed_entry_fails_with_the_pins_own_message(self) -> None:
        with pytest.raises(ValueError, match="problem"):
            manifest_pins({"units": [{"kind": "commit", "repo_url": "not a url"}]})

    def test_a_document_with_no_units_list_is_refused(self) -> None:
        with pytest.raises(ValueError, match="`units` list"):
            manifest_pins({"schema_version": "1.0"})

    def test_text_that_is_not_json_says_so(self) -> None:
        with pytest.raises(ValueError, match="not JSON"):
            read_manifest("{oh no")
