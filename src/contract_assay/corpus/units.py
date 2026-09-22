"""The questions without the answers: a corpus's units, and nothing else.

A submission is run with `--records`, and a record carries the answer -- its
locator says where the defect is. That is right for the public split, where the
answers are published on purpose, and impossible for a held-out one: a
participant cannot run against a holdout they are not allowed to see.

So a **unit manifest** is what a holdout publishes. It is the pins and nothing
else: enough to fetch the source, name a unit and produce runs a scorer can
match, and carrying no statement about what is wrong with any of them.

## What is left out, and why each would have leaked

- **`locator`** is the answer in the most direct form.
- **`classes`** is the answer at one remove. Knowing a file holds a slippage
  defect is most of finding it.
- **`negative_for`** is the answer inverted, and a held-out negative is a fact
  about the file a participant could act on.
- **`record_id`**, which is the one worth stating plainly: **every id in the
  holdout measured for this contains its own class name**, as in
  `2025-04-virtuals-protocol-flashloan-manipulation-d79a7338`. A manifest that
  kept ids to look tidy would publish all 55 answers in the filenames while
  every field a reviewer thought to check was absent.

## Derived, not listed

The manifest is built by dumping the pin model, so its field set *is* the pin's.
Nothing here enumerates what to keep, and a field added to `SourcePin` appears
without this module changing -- while a field added to `CorpusRecord` cannot
appear at all. A hand-written allow-list is the version of this that is correct
on the day it is written, and `report/wire.py` records what happened the last
time one was kept by hand.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import TypeAdapter, ValidationError

from contract_assay.corpus.records import CorpusRecord, SourcePin

__all__ = ["manifest_pins", "read_manifest", "unit_manifest"]

_PINS = TypeAdapter(list[SourcePin])


def _provenance_only(pin: SourcePin) -> set[str]:
    """Field names this pin marks as audit metadata rather than coordinates.

    Read off the model, so a pin field added later is in a manifest unless
    whoever added it said otherwise beside the field. The alternative is a list
    here, which is correct on the day it is written -- `report/wire.py` records
    what happened the last time one was kept by hand.
    """
    return {
        name
        for name, field in type(pin).model_fields.items()
        if isinstance(field.json_schema_extra, dict)
        and field.json_schema_extra.get("provenance_only")
    }


def unit_manifest(records: Iterable[CorpusRecord]) -> dict[str, Any]:
    """One entry per distinct unit, pins only, in a stable order.

    Distinct by `source_id`, for the reason `units_from` is: two records in one
    file are two defects in one unit, and publishing it twice would tell a
    participant which files hold more than one -- a weak signal, and one the
    manifest has no reason to carry.

    The pin carrying a digest wins where two disagree, matching `units_from`'s
    rule. Three different answers to "which pin represents this unit" is how one
    of them ends up wrong.
    """
    chosen: dict[str, SourcePin] = {}
    ordered = sorted(records, key=lambda r: (r.pin.sha256 is None, r.record_id))
    for record in ordered:
        chosen.setdefault(record.pin.source_id, record.pin)
    return {
        "schema_version": "1.0",
        "units": [
            pin.model_dump(mode="json", exclude_none=True, exclude=_provenance_only(pin))
            for _, pin in sorted(chosen.items())
        ],
    }


def manifest_pins(document: dict[str, Any]) -> list[SourcePin]:
    """The pins a manifest names, validated as pins.

    Validated rather than trusted: a manifest is a file somebody was handed, and
    a malformed entry should fail here with the pin's own message rather than
    as a missing attribute somewhere inside a run.
    """
    units = document.get("units")
    if not isinstance(units, list):
        raise ValueError("a unit manifest has a `units` list")
    try:
        return list(_PINS.validate_python(units))
    except ValidationError as invalid:
        raise ValueError(f"{invalid.error_count()} problem(s) in the manifest\n{invalid}") from (
            invalid
        )


def read_manifest(text: str) -> Sequence[SourcePin]:
    """Parse and validate a manifest's text."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as bad:
        raise ValueError(f"the manifest is not JSON: {bad}") from bad
    if not isinstance(document, dict):
        raise ValueError("a unit manifest is a JSON object")
    return manifest_pins(document)
