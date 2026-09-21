"""Published results, as pointers rather than as a leaderboard.

What this is for: comparing your figures with somebody else's without either of
you having to trust a service, and without this repository becoming the place
that decides who won.

The shape is deliberate. A result lives wherever its author put it -- a repo, a
paper, a blog -- and what lands here is a **pointer**: the identity of the
measurement, a URL for the document, and who published it. Two reasons.

A leaderboard in a benchmark's own repository makes its maintainers the
adjudicators of their own instrument, and this project already refuses that one
level down: a detector's author cannot adjudicate its own predictions, because
precision would be 1 by construction. The same argument applies to the
benchmark's authors and the benchmark's own ranking.

And a pointer is checkable in a way a claimed number is not. Every field below
is one the engine wrote into the score document, so a pointer either matches the
document it points at or it does not.

**Comparison is refused more often than it is granted, and that is the useful
part.** Two results computed against different corpus digests, engine versions,
strength floors, weightings or prediction caps are not two measurements of the
same thing, and `compare` says which of those differ instead of putting them in
one column. The commonest reason two leaderboards disagree is not a scoring
change but a corpus that grew.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

__all__ = [
    "Comparison",
    "ResultPointer",
    "compare",
    "load_pointers",
    "pointer_from_document",
]

_BASIS = ("engine_version", "corpus_digest", "strength_floor", "weights", "predictions_per_unit")
"""The fields two results must agree on before their totals mean the same thing.

Named once, here, because `compare` reports on them and the docs list them, and a
check that has to be repeated is a check that will be forgotten in one of its
places.
"""


class ResultPointer(BaseModel):
    """One published result: what was measured, where the document is, who says so."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    submission_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9\-]{2,63}$")]
    published_by: Annotated[str, Field(min_length=1, description="A person or an organisation.")]
    document_url: HttpUrl
    """Where the full score document lives. Not copied into this repository: a
    copy is a second thing to keep in step with the original, and the original
    is the one that carries the digest."""

    engine_version: Annotated[str, Field(min_length=1)]
    corpus_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    strength_floor: Annotated[str, Field(pattern=r"^(exact|function|call_adjacent|file)$")]
    weights: dict[str, float] = Field(default_factory=dict)
    predictions_per_unit: int | None = None

    main_model: str | None = None
    """The model behind the figures, or `None` for a deterministic submission.
    Not a gap: the benchmark declines to rank a row that names no main model
    against one that does, and says why."""

    total: float | None = None
    """The aggregate the document reported, or `None` where it refused to
    compute one. Copied so a reader can sort without fetching every document,
    and **`None` is never rendered as zero** -- `unavailable` is why."""

    unavailable: str | None = None
    """The document's own sentence for a missing total. Present iff `total` is
    `None`; validated, because a null with no reason beside it is the one thing
    this project's wire format exists to prevent."""

    notes: str = ""

    @model_validator(mode="after")
    def _a_missing_total_states_why(self) -> ResultPointer:
        """A null with no reason beside it is what this wire format exists to stop.

        Both directions. A `total` of `None` with no `unavailable` is a number
        somebody dropped; an `unavailable` beside a real total is a sentence that
        contradicts the figure next to it, and a reader has no way to tell which
        of the two to believe.
        """
        if self.total is None and not self.unavailable:
            raise ValueError(
                "total is null and unavailable is empty: a refused figure carries the "
                "document's own reason, or a reader renders the null as a zero"
            )
        if self.total is not None and self.unavailable:
            raise ValueError(
                f"total is {self.total} and unavailable says {self.unavailable!r}: one of "
                "them is wrong and nothing here can say which"
            )
        return self

    def basis(self) -> tuple[Any, ...]:
        """The values two pointers must share to be comparable."""
        return tuple(
            json.dumps(getattr(self, field), sort_keys=True, default=str) for field in _BASIS
        )


def pointer_from_document(
    document: dict[str, Any], *, published_by: str, document_url: str, notes: str = ""
) -> ResultPointer:
    """Build a pointer from a score document, so its fields cannot drift from it.

    Every value comes out of the document rather than from a hand-written claim.
    A pointer assembled by hand is a number somebody typed; this one either
    matches the document or fails to build.
    """
    aggregate = document.get("aggregate", {})
    total = aggregate.get("total", {})
    models = document.get("models", {})
    return ResultPointer(
        submission_id=document["submission_id"],
        published_by=published_by,
        document_url=HttpUrl(document_url),
        engine_version=document["engine_version"],
        corpus_digest=document["corpus"]["digest"],
        strength_floor=document["strength_floor"],
        weights=document.get("weights", {}),
        predictions_per_unit=document.get("predictions_per_unit"),
        main_model=models.get("main"),
        total=total.get("value"),
        unavailable=total.get("unavailable"),
        notes=notes,
    )


def load_pointers(directory: Path) -> list[ResultPointer]:
    """Every pointer under `directory`, validated, in a stable order.

    Raises on one that does not validate rather than skipping it: a directory
    that silently drops a result is a comparison over a subset nobody chose.
    """
    out: list[ResultPointer] = []
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(ResultPointer.model_validate_json(path.read_text(encoding="utf-8")))
        except ValueError as invalid:
            raise ValueError(f"{path}: {invalid}") from invalid
    return out


@dataclass(frozen=True, slots=True)
class Comparison:
    """Results grouped by what they were measured against."""

    comparable: tuple[tuple[ResultPointer, ...], ...]
    """Groups sharing a basis, largest first. A group of one is still a group."""

    def statement(self) -> str:
        """What may be compared with what, and why the rest may not."""
        if not self.comparable:
            return "No published results."
        groups = self.comparable
        total = sum(len(g) for g in groups)
        if len(groups) == 1:
            return (
                f"{total} published result(s), all measured against the same corpus digest, "
                "engine version, floor, weighting and prediction cap. Comparable."
            )
        parts = [
            f"{total} published result(s) in {len(groups)} group(s) that are NOT comparable "
            "with each other."
        ]
        for group in groups:
            first = group[0]
            differs = ", ".join(
                f"{field}={json.dumps(getattr(first, field), sort_keys=True, default=str)}"
                for field in _BASIS
            )
            parts.append(
                f"  [{len(group)}] {', '.join(p.submission_id for p in group)} -- {differs}"
            )
        parts.append(
            "Totals from different groups are not two measurements of the same thing. The "
            "commonest reason two leaderboards disagree is not a scoring change but a corpus "
            "that grew."
        )
        return "\n".join(parts)


def compare(pointers: Iterable[ResultPointer]) -> Comparison:
    """Group results by basis, ordering each group by total with refusals last.

    A result whose total the document refused to compute is **not** sorted to the
    bottom. Ordering it below a ranked one asserts a comparison nobody measured,
    and the usual cause is work the exercise owes -- unadjudicated predictions,
    or a class the corpus does not cover -- rather than anything the submission
    did. It is listed after the ranked ones and marked, which is a different
    thing from being last.
    """
    grouped: dict[tuple[Any, ...], list[ResultPointer]] = {}
    for pointer in pointers:
        grouped.setdefault(pointer.basis(), []).append(pointer)

    def order(group: Sequence[ResultPointer]) -> tuple[ResultPointer, ...]:
        ranked = sorted(
            (p for p in group if p.total is not None),
            key=lambda p: (-(p.total or 0.0), p.submission_id),
        )
        refused = sorted((p for p in group if p.total is None), key=lambda p: p.submission_id)
        return (*ranked, *refused)

    groups = sorted(grouped.values(), key=lambda g: (-len(g), g[0].submission_id))
    return Comparison(comparable=tuple(order(g) for g in groups))
