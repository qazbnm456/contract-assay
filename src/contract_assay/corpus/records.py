"""Corpus record schema.

A corpus record is a pointer, not a copy. It says where a known finding lives --
repository, commit, file, function, line span -- and carries the labels needed to
score against it. It never carries the source itself.

Three things follow from that, and all three are load-bearing:

* The annotation set is the only original work in the corpus, so it can carry
  this project's licence without entanglement.
* No third-party source is redistributed, so no third-party licence attaches to
  distributing the corpus.
* A pinned commit SHA makes the corpus reproducible. Sources are fetched at run
  time and checked against a recorded digest.

Records are only admitted after `verify` confirms each one against reality. A
record that cannot be confirmed is rejected, not stored with a warning: a corpus
is ground truth, and ground truth that might be wrong is worse than a smaller
corpus that is right.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contract_assay.models import DifficultyLevel, Locator, VulnerabilityClass

__all__ = [
    "CorpusRecord",
    "NegativeKind",
    "Provenance",
    "SourcePin",
    "VulnerabilityClass",
]

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class NegativeKind(StrEnum):
    """Why a record is a negative sample.

    A benchmark with weak negatives measures nothing. All three kinds are
    required, and `CROSS_CLASS` is the reason the nine classes are built together
    rather than one at a time: it is the only negative that forces a detector to
    distinguish "has a bug" from "has *this* bug".
    """

    POST_FIX = "post_fix"
    """The same source at the fix commit. Everything identical except the defect."""

    CROSS_CLASS = "cross_class"
    """Vulnerable to another class, clean for this one."""

    CONFIRMED_CLEAN = "confirmed_clean"
    """Manually verified as carrying no instance of this class."""


class SourcePin(BaseModel):
    """Exactly which bytes to analyse, and how to know they are the right ones."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repo_url: str = Field(description="Clone URL.")
    commit: str = Field(description="Full 40-hex commit SHA. Refs and short SHAs move.")
    path: str = Field(description="File path within the repository at `commit`.")
    sha256: str | None = Field(
        default=None,
        description="Digest of the file's bytes at `commit`, recorded by verify.",
    )

    @model_validator(mode="after")
    def _commit_is_a_full_sha(self) -> SourcePin:
        if not _SHA1.match(self.commit):
            raise ValueError(
                f"commit must be a full 40-character lowercase hex SHA, got {self.commit!r}; "
                "branch names and short SHAs are not reproducible"
            )
        return self

    @property
    def source_id(self) -> str:
        return f"{self.repo_url.rstrip('/').rsplit('/', 1)[-1]}@{self.commit[:12]}:{self.path}"


class Provenance(BaseModel):
    """Where this record's claim comes from.

    `reported_severity` is what the original auditors assigned. It is a fact
    about the report, kept for filtering and analysis. It is never compared with,
    or substituted for, anything a model produced -- no model in this system is
    asked for a severity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    platform: str = Field(description="Audit platform or disclosure source.")
    report_url: str
    reported_severity: str | None = Field(
        default=None, description="Verbatim severity label from the source report."
    )
    fix_commit: str | None = Field(
        default=None, description="Commit that fixed it, where public. Enables pair-differential."
    )

    @model_validator(mode="after")
    def _fix_commit_is_a_full_sha(self) -> Provenance:
        if self.fix_commit is not None and not _SHA1.match(self.fix_commit):
            raise ValueError(
                f"fix_commit must be a full 40-character hex SHA, got {self.fix_commit!r}"
            )
        return self


class CorpusRecord(BaseModel):
    """One ground-truth entry.

    Positive records (`classes` non-empty) assert that an instance of each listed
    class exists at `locator`. Negative records (`classes` empty) assert that no
    instance of `negative_for` exists anywhere in the pinned file, and say which
    kind of negative they are.

    Multi-labelling is allowed and expected: one location can host instances of
    several classes, and a corpus that forces a single label teaches detectors
    that classes are mutually exclusive when they are not.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{2,63}$")
    pin: SourcePin
    locator: Locator | None = Field(
        default=None,
        description="Where the defect is. Required for positives, absent for negatives.",
    )
    classes: list[VulnerabilityClass] = Field(
        default_factory=list, description="Classes present at `locator`. Empty means negative."
    )
    negative_for: list[VulnerabilityClass] = Field(
        default_factory=list, description="Classes this record is a confirmed negative for."
    )
    vulnerable_to: list[VulnerabilityClass] = Field(
        default_factory=list,
        description=(
            "Classes this source does carry, for a cross-class negative. It is what makes "
            "the sample hard: the source is not clean, only clean for the class in question."
        ),
    )
    negative_kind: NegativeKind | None = None
    provenance: Provenance
    notes: str = ""

    @property
    def is_positive(self) -> bool:
        return bool(self.classes)

    @property
    def level(self) -> DifficultyLevel:
        """Deepest difficulty among this record's classes.

        `model_copy(update=...)` bypasses validation in pydantic, so a record can
        be handed here with neither list populated even though the validator
        forbids it. A property on a frozen model must not raise for any reachable
        state, so the floor is returned rather than an exception from `max`.
        """
        pool = self.classes or self.negative_for
        return max((c.level for c in pool), key=lambda lv: lv.rank, default=DifficultyLevel.S)

    def covers(self, cls: VulnerabilityClass) -> bool:
        """True if this record says anything about `cls`, positive or negative."""
        return cls in self.classes or cls in self.negative_for

    @model_validator(mode="after")
    def _record_is_coherent(self) -> CorpusRecord:
        # Applies to both polarities: a locator naming a different file from the
        # pin would be checked against the pinned file's bytes, so every line
        # number in it would be meaningless.
        if self.locator is not None and self.locator.file != self.pin.path:
            raise ValueError(
                f"locator.file {self.locator.file!r} does not match pin.path {self.pin.path!r}"
            )

        if self.is_positive:
            if self.locator is None:
                raise ValueError(
                    "a positive record must say where the defect is; an unlocated positive "
                    "cannot be scored at function granularity and is not ground truth"
                )
            if self.locator.function is None:
                raise ValueError(
                    "a positive record must name the function the defect is in; function "
                    "granularity is what this benchmark scores against, and a record without "
                    "it silently weakens every comparison made with it"
                )
            if self.negative_kind is not None:
                raise ValueError("a positive record is not a negative sample")
            if overlap := set(self.classes) & set(self.negative_for):
                raise ValueError(
                    f"record is both positive and negative for {sorted(c.value for c in overlap)}"
                )
        else:
            if not self.negative_for:
                raise ValueError(
                    "a record with no classes must state what it is a negative for; "
                    "a record asserting nothing cannot be scored"
                )
            if self.negative_kind is None:
                raise ValueError("a negative record must state its kind")

            if self.negative_kind is NegativeKind.POST_FIX:
                if self.provenance.fix_commit is None:
                    raise ValueError("a post-fix negative must record the fix commit it came from")
                if self.pin.commit != self.provenance.fix_commit:
                    raise ValueError(
                        "a post-fix negative must be pinned to the fix commit, "
                        f"but pin.commit is {self.pin.commit[:12]} and fix_commit is "
                        f"{self.provenance.fix_commit[:12]}"
                    )

            if self.negative_kind is NegativeKind.CROSS_CLASS and not self.vulnerable_to:
                raise ValueError(
                    "a cross-class negative must name what it IS vulnerable to; without it "
                    "the record is an ordinary clean sample, and the hard negative it was "
                    "collected to provide does not exist"
                )

            if self.negative_kind is NegativeKind.CONFIRMED_CLEAN and not self.notes.strip():
                raise ValueError(
                    "a confirmed-clean negative must record how it was confirmed; "
                    "'someone checked' is not reviewable and not reproducible"
                )

        if overlap := set(self.vulnerable_to) & set(self.negative_for):
            raise ValueError(
                f"record is both vulnerable to and clean for {sorted(c.value for c in overlap)}"
            )
        return self
