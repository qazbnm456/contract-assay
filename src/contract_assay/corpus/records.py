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
    "CorpusSplit",
    "LocatorLabel",
    "LocatorProvenance",
    "NegativeKind",
    "Population",
    "Provenance",
    "SourcePin",
    "VulnerabilityClass",
]

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class Population(StrEnum):
    """Which body of work a record was drawn from.

    A stratification axis like difficulty and evidence tier, and required for the
    same reason: the two populations are not samples of one thing, and a figure
    computed across a mixture describes neither.

    They skew in close to opposite directions. Pre-deployment review output is
    dominated by protocol-specific logic -- accounting that deflates a reported
    total, a balance that stops tracking one-to-one -- because that is what
    reviewers find in code nobody has attacked yet. Exploited incidents are
    dominated by patterns that were reachable *and* worth the trouble, which
    over-represents profitable manipulation and under-represents everything
    caught before deployment, everything unprofitable, and everything in code
    that never held enough value to attack.

    So neither is unbiased and they are not substitutable. What makes recording
    it worth a field is that the classes one population is thin in are the
    classes the other is thick in -- and that a detector scoring differently
    across populations on the same class is a finding about the detector rather
    than noise. It says whether it recognises exploited patterns or reviewed
    ones.
    """

    AUDIT_REVIEW = "audit_review"
    """Found by review before deployment. Reported, not necessarily exploited."""

    EXPLOITED_INCIDENT = "exploited_incident"
    """Exploited in the wild and written up afterwards."""


class LocatorLabel(StrEnum):
    """A locator field the *source report* asserted, as opposed to one read off
    the declaration index.

    Recorded because whether a location was independently confirmed depends on
    it. The index can adjudicate between two things the report said; it cannot
    adjudicate its own answer. A report giving a span and a function name has
    made two claims that the index can contradict; a report giving only a span,
    whose function name the index then supplied, has made one -- and asking
    whether that function sits in that span is answered by construction.
    """

    CONTRACT = "contract"
    FUNCTION = "function"


class LocatorProvenance(StrEnum):
    """Who decided where the defect is.

    The distinction exists because verification is not equally informative for
    the two. A record whose span the auditor stated is cross-checked: `verify`
    confirms the named function is declared inside that span, so a transcription
    error by whoever entered the record is caught. A record whose span was
    *computed* from the declaration index has no second source to cross-check
    against -- asking the index whether the function sits in a span the index
    itself produced is a tautology, and it passes at a rate indistinguishable
    from real confirmation.

    What still does work for a derived locator: the digest check, which
    establishes the file is byte-identical to the one the derivation ran against,
    and the ambiguity check, which refuses a name resolving to more than one
    declaration. What does not: the span check that carries the weight for a
    stated locator. So a derived record rests entirely on the original report's
    prose naming the right function, with nothing to contradict it.

    Carried on the record so reports can stratify by it, or exclude it. Without
    the flag an admitted count silently mixes records that passed a real check
    with records that passed a vacuous one -- the invisibility of §1.3, occurring
    inside the machinery built to implement §1.3.
    """

    STATED = "stated"
    """The source report gave the line span. `verify` cross-checks it."""

    QUOTED = "quoted"
    """The report quoted the code; the span is where that text uniquely occurs.

    The strongest confirmation available, and the only one in this set produced
    by two sources neither of which was derived from the other: the text came
    from the report, the bytes came from the repository, and the span is where
    they agree. The match is required to be unique -- a normalised snippet
    occurring twice in the file locates nothing, and taking the first would be a
    wrong record that the contiguity guard cannot catch, because a wrong match
    can be perfectly contiguous.

    It fails differently from `STATED` rather than better, and the two are
    recorded rather than ranked. A stated line number goes stale when the report
    numbered a different commit than the one pinned; a matched quote cannot go
    stale. A matched quote can land in the wrong place when the code is
    unremarkable; a stated line cannot.
    """

    ANCHORED = "anchored"
    """The report gave a single line; the span is the declaration containing it.

    Between the other two, and closer to `stated` than the name suggests. The
    anchor line is an assertion the original report actually made, at finer
    granularity than a function, and it is kept on the record rather than
    discarded once the span is computed -- it is the whole reason this value is
    worth having.
    """

    DERIVED = "derived"
    """The span was computed from a function named in prose. Weakest of the three."""

    @property
    def supports_exact_match(self) -> bool:
        """Whether a record of this provenance can support an `exact` location match.

        `exact` means the spans overlap within the same function (§7). For a
        `DERIVED` record the ground-truth span *is* the whole function, so any
        prediction inside it overlaps and `exact` is satisfied trivially --
        reporting it as a hit would inflate every exact-match figure by however
        many derived records the corpus happened to contain, with nothing in the
        output able to say by how much. Such records report `exact` as
        unavailable rather than as satisfied.

        `ANCHORED` supports it because the anchor is strictly finer than the
        function and came from the report; it is scored against the anchor, not
        against the enclosing span.
        """
        return self is not LocatorProvenance.DERIVED


class CorpusSplit(StrEnum):
    """Which corpus a record belongs to, and therefore what may be done with it.

    Carried from the first record rather than added once annotation is under way.
    Retrofitting a split leaks: whatever criterion is used to divide an existing
    set is itself a signal about the set, and applying it after the fact means
    the division is visible in the annotation history even when it is absent from
    the data.

    Three members, not two, because the third obeys distribution rules that match
    neither of the others. A held-out record is ordinary annotation that is
    merely withheld, so it could be published tomorrow by changing one field. A
    synthetic variant could not: structure-preserving mutation of a contract
    produces a derivative of that contract, and a derivative carries the
    original's licence however thoroughly the identifiers were changed. Executing
    one server-side distributes nothing and is fine; publishing the variant set
    would relicense somebody else's code. Collapsing the two into a single
    "private" value would leave nothing in the schema able to tell the difference.
    """

    PUBLIC = "public"
    """Published with the corpus. Anyone may read it, so nothing may be scored secretly."""

    PRIVATE_HOLDOUT = "private_holdout"
    """Real annotation, withheld. Publishable by decision, not blocked by licence."""

    SYNTHETIC_VARIANT = "synthetic_variant"
    """Mutated from a real record. Never distributed: it is a derivative work."""

    @property
    def is_distributable(self) -> bool:
        """True only for `PUBLIC`. The others are executed, never shipped."""
        return self is CorpusSplit.PUBLIC


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
    commit_resolved_from: str | None = Field(
        default=None,
        description=(
            "How the commit was obtained when the source did not state it, in prose. "
            "None means the source stated it outright."
        ),
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
    def is_commit_stated(self) -> bool:
        """Whether the source named this commit, rather than it being inferred.

        A resolved commit is reproducible -- it is a full SHA like any other, and
        the digest still witnesses the bytes -- but it rests on an assumption the
        source did not make. Reports frequently cite a *branch*, which names
        whatever it currently points at and cannot be pinned; recovering one by
        resolving the repository as it stood at the report's own date is a bounded
        inference, where resolving it as it stands today is unbounded drift.

        Bounded is not free, so the assumption travels with the record and
        reports can stratify on it. `commit_resolved_from` states which
        assumption in prose, because "resolved" alone does not say from what.
        """
        return self.commit_resolved_from is None

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
    population: Population = Field(
        description=(
            "Which body of work this was drawn from. Required, with no default: the two "
            "populations skew in opposite directions and a figure computed across a "
            "mixture describes neither."
        )
    )
    split: CorpusSplit = Field(
        description=(
            "Which corpus this belongs to. Required, with no default: a forgotten split "
            "would publish a record that was meant to be withheld, and the mistake is "
            "unrecoverable once the record is out."
        )
    )
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
    locator_provenance: LocatorProvenance | None = Field(
        default=None,
        description=(
            "Who decided the line span. Required whenever a locator is present, and "
            "forbidden when it is absent."
        ),
    )
    asserted_labels: list[LocatorLabel] = Field(
        default_factory=list,
        description=(
            "Locator labels the source report itself stated. Labels absent from this "
            "list were read off the declaration index and cannot corroborate the span."
        ),
    )
    anchor_line: int | None = Field(
        default=None,
        ge=1,
        description=(
            "The single line the source report pointed at. Required for an anchored "
            "locator and forbidden otherwise; it is what such a record is scored against."
        ),
    )
    negative_kind: NegativeKind | None = None
    derived_from: str | None = Field(
        default=None,
        pattern=r"^[a-z0-9][a-z0-9\-]{2,63}$",
        description="record_id this was mutated from. Required for a synthetic variant.",
    )
    provenance: Provenance
    notes: str = ""

    @property
    def is_positive(self) -> bool:
        return bool(self.classes)

    @property
    def report_assertion_count(self) -> int:
        """How many independent claims about the location the source report made.

        The span counts when the report gave it, the anchor counts when the
        report pointed at a line, and each label counts when the report named it.
        A label the declaration index supplied does not count -- it is not a
        second source, it is the adjudicator answering.
        """
        span = self.locator_provenance in (
            LocatorProvenance.STATED,
            LocatorProvenance.ANCHORED,
        )
        return int(span) + len(set(self.asserted_labels))

    @property
    def is_cross_checked(self) -> bool:
        """Whether something that did not produce this location confirmed it.

        Not a property of the provenance, which is the mistake this replaced. A
        `quoted` span is confirmed outright: the repository's bytes contain the
        report's text, uniquely, and the bytes are not the report. Otherwise
        confirmation requires the report to have made **two** claims about the
        location, which the declaration index can then adjudicate -- a span and a
        function name, a line and a contract, a contract and a function.

        One claim is not enough however strong it looks. A report giving a span
        and nothing else gets its function name from the index, and `verify` then
        asks the index whether that function lies in the span it was read from.
        That answer is certain, so the check cannot fail, so it confirms nothing
        beyond what the digest already guarantees.
        """
        if self.locator_provenance is LocatorProvenance.QUOTED:
            return True
        return self.report_assertion_count >= 2

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

        # Checked for both polarities and immediately after the path check, so
        # that a record carrying a locator always says where the span came from.
        if self.locator is not None and self.locator_provenance is None:
            raise ValueError(
                "a record with a locator must say whether the span was stated by the "
                "source report or derived from the declaration index; verification "
                "cross-checks the first and cannot check the second, so an unmarked "
                "locator makes a weaker record indistinguishable from a stronger one"
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

        # Checked after the polarity rules, so a positive record missing its
        # locator reports that rather than reporting a field describing nothing.
        if self.locator is None and self.locator_provenance is not None:
            raise ValueError(
                "locator_provenance is set on a record with no locator, so it describes nothing"
            )

        anchored = self.locator_provenance is LocatorProvenance.ANCHORED
        if anchored and self.anchor_line is None:
            raise ValueError(
                "an anchored locator must record the line the report pointed at; the span "
                "was computed from it, and discarding it leaves a record indistinguishable "
                "from one whose span was guessed from prose"
            )
        if self.locator is None and self.asserted_labels:
            raise ValueError(
                "asserted_labels is set on a record with no locator, so it describes nothing"
            )
        for label in self.asserted_labels:
            if getattr(self.locator, label.value, None) is None:
                raise ValueError(
                    f"the report is recorded as asserting {label.value!r}, but the locator "
                    f"carries no {label.value}"
                )

        if not anchored and self.anchor_line is not None:
            raise ValueError(
                f"anchor_line is set on a {self.locator_provenance} locator, where the span "
                "was not computed from a single stated line"
            )
        if (
            anchored
            and self.locator is not None
            and self.anchor_line is not None
            and not (self.locator.start_line <= self.anchor_line <= self.locator.end_line)
        ):
            raise ValueError(
                f"anchor_line {self.anchor_line} lies outside the span "
                f"{self.locator.start_line}-{self.locator.end_line} it produced"
            )

        if overlap := set(self.vulnerable_to) & set(self.negative_for):
            raise ValueError(
                f"record is both vulnerable to and clean for {sorted(c.value for c in overlap)}"
            )

        if self.split is CorpusSplit.SYNTHETIC_VARIANT:
            if self.derived_from is None:
                raise ValueError(
                    "a synthetic variant must name the record it was mutated from; without "
                    "it the variant cannot be traced back to the finding that justifies it, "
                    "and neither its licence nor its ground truth has a source"
                )
            if self.derived_from == self.record_id:
                raise ValueError("a synthetic variant cannot be derived from itself")
            if not self.notes.strip():
                raise ValueError(
                    "a synthetic variant must record how the defect was confirmed to have "
                    "survived mutation; a structure-preserving edit can repair the bug by "
                    "accident, and an unconfirmed variant is a negative labelled positive"
                )
        elif self.derived_from is not None:
            raise ValueError(
                f"derived_from is set on a {self.split.value!r} record; only a synthetic "
                "variant is derived from another record"
            )
        return self
