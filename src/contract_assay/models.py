"""Core data contract.

Every type here exists to make a specific failure mode structurally impossible
rather than merely discouraged. Benchmarks in this space fail in characteristic
ways -- scoring at the wrong granularity, counting infrastructure errors as
model judgements, letting a required field be invented when it goes missing.
None of those failures crash; they produce plausible numbers. Each docstring
below names the one its invariant forecloses.

The two load-bearing rules:

1.  A finding is a *citation*. It carries a locator and the exact source text at
    that locator, and it is re-verified against the source after the model
    returns -- unconditionally, every run. A finding that cannot be re-verified
    becomes `unverified`; it is neither silently dropped nor silently accepted.

2.  Evidence is produced by deterministic predicates and is independent of the
    model's verdict. A model may decline to report, or report wrongly; it cannot
    remove a piece of evidence from the record.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "MAX_DESCRIPTION_CHARS",
    "MAX_QUOTE_CHARS",
    "MAX_REASONING_CHARS",
    "CitationStatus",
    "DetectorRun",
    "DifficultyLevel",
    "Escalation",
    "EvidenceRef",
    "EvidenceTier",
    "FailedCheck",
    "Finding",
    "InvalidReason",
    "KnownBlindness",
    "Locator",
    "Outcome",
    "RejectionKind",
    "SkipReason",
    "VerifiedFinding",
    "VulnerabilityClass",
]


class _Frozen(BaseModel):
    """Records are immutable once built: a run artifact must not be edited in place."""

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Text bounds
# ---------------------------------------------------------------------------
#
# Free-text fields are bounded because the code that fills them is not always
# trusted. When a submission written by someone else produces a finding, any
# unbounded string on that finding is a channel out of the sandbox: source bytes
# encoded into prose leave with the result, and no egress rule sees it, because
# the result is exactly what the harness is supposed to send back.
#
# Bounding every such field rather than the most obvious one is the whole point.
# A cap on `reasoning` alone is routed around in one line by moving the payload
# into `quote`, so a partial cap buys the appearance of a control and not the
# control. The limits are generous enough that an honest finding never meets
# them: they bound a channel's bandwidth, they are not a style rule.

MAX_REASONING_CHARS = 2_000
"""Upper bound on a finding's justification prose."""

MAX_QUOTE_CHARS = 4_000
"""Upper bound on quoted source. Ample for a long function; not ample for a file."""

MAX_DESCRIPTION_CHARS = 1_000
"""Upper bound on a classification claim's description."""


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------


class DifficultyLevel(StrEnum):
    """Expected analytical depth, after the EEA EthTrust Security Levels taxonomy.

    Used to stratify reports. A single aggregate score averages together classes
    that static analysis has handled for years and classes it cannot reach in
    principle, producing a number that answers no question anyone has. Reported
    per level, the results answer the one that matters: does the model earn its
    keep where deterministic tooling cannot follow?

    The taxonomy is referenced by identifier only; no specification text is
    reproduced in this project.
    """

    S = "S"
    """Static analysis is expected to detect it."""

    M = "M"
    """Manual review, or static analysis with stronger assumptions."""

    Q = "Q"
    """Requires business-logic understanding. The frontier."""

    @property
    def rank(self) -> int:
        """Ordering by depth. `StrEnum` compares as text, which sorts M < Q < S."""
        return "SMQ".index(self.value)


class VulnerabilityClass(StrEnum):
    """The nine classes.

    Derived from the OWASP Smart Contract Top 10 for naming and incident-oriented
    grouping, and from the EEA EthTrust Security Levels Specification for
    per-requirement verifiability and difficulty grading. EthTrust requirements
    are referenced by identifier only; no specification text is reproduced here.

    Difficulty is a property of the class, not an independent field. Carrying the
    two separately invites a run that claims a class and contradicts its grade,
    and nothing downstream could tell which one to believe.
    """

    ACCESS_CONTROL = "access_control"
    ORACLE_INTEGRITY = "oracle_integrity"
    SLIPPAGE = "slippage"
    FLASHLOAN_MANIPULATION = "flashloan_manipulation"
    REENTRANCY = "reentrancy"
    UNCHECKED_EXTERNAL_CALL = "unchecked_external_call"
    DENIAL_OF_SERVICE = "denial_of_service"
    ARITHMETIC_ROUNDING = "arithmetic_rounding"
    INSECURE_RANDOMNESS = "insecure_randomness"

    @property
    def level(self) -> DifficultyLevel:
        """The depth at which instances of this class are normally found.

        Where a class spans levels, this is the deepest: it decides whether the
        detector may reach for the escape hatch, and under-grading would close it
        on exactly the cases that need it.
        """
        return _CLASS_LEVEL[self]


_CLASS_LEVEL: dict[VulnerabilityClass, DifficultyLevel] = {
    VulnerabilityClass.UNCHECKED_EXTERNAL_CALL: DifficultyLevel.S,
    VulnerabilityClass.ACCESS_CONTROL: DifficultyLevel.M,
    VulnerabilityClass.REENTRANCY: DifficultyLevel.M,
    VulnerabilityClass.DENIAL_OF_SERVICE: DifficultyLevel.M,
    VulnerabilityClass.INSECURE_RANDOMNESS: DifficultyLevel.M,
    VulnerabilityClass.ORACLE_INTEGRITY: DifficultyLevel.Q,
    VulnerabilityClass.ARITHMETIC_ROUNDING: DifficultyLevel.Q,
    VulnerabilityClass.SLIPPAGE: DifficultyLevel.Q,
    VulnerabilityClass.FLASHLOAN_MANIPULATION: DifficultyLevel.Q,
}

assert set(_CLASS_LEVEL) == set(VulnerabilityClass), "every class must carry a difficulty grade"


# ---------------------------------------------------------------------------
# Localization
# ---------------------------------------------------------------------------


class Locator(_Frozen):
    """Where a finding lives.

    A location is only worth recording if something checks it. Carrying a
    function name that no scorer ever reads is worse than carrying nothing: it
    lends the appearance of precision while a finding anywhere in a repository
    still scores as a hit for a finding anywhere else. This type exists to be
    verified at the point of production, which is what
    `contract_assay.corpus.verify` does for ground truth.

    Line numbers are 1-indexed and inclusive, matching every compiler and editor
    a reader will cross-check against.

    `function` is optional here because scoring recognises weaker matches than
    exact (see `docs/design.md` section 7), and a finding may legitimately point
    at contract scope. Ground-truth records are stricter: a positive corpus
    record must name a function, because it is what everything is scored against.
    """

    file: str = Field(min_length=1, description="Path relative to the compilation root.")
    contract: str | None = Field(default=None, description="Enclosing contract/library/interface.")
    function: str | None = Field(default=None, description="Enclosing function, if any.")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def _span_is_ordered(self) -> Locator:
        if self.end_line < self.start_line:
            raise ValueError(f"end_line {self.end_line} precedes start_line {self.start_line}")
        return self

    def overlaps(self, other: Locator) -> bool:
        """True if the two spans intersect in the same file."""
        return (
            self.file == other.file
            and self.start_line <= other.end_line
            and other.start_line <= self.end_line
        )

    def __str__(self) -> str:
        span = (
            f"{self.start_line}"
            if self.start_line == self.end_line
            else f"{self.start_line}-{self.end_line}"
        )
        qualifier = ":".join(p for p in (self.contract, self.function) if p)
        return f"{self.file}:{span}" + (f" ({qualifier})" if qualifier else "")


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class EvidenceTier(StrEnum):
    """How much analytical depth was available for a source unit.

    Not every repository compiles. When the semantic backend cannot build a
    compilation unit, analysis degrades to the syntactic tier and says so, rather
    than dropping the unit. The tier travels with every result so that reports can
    stratify by it -- a `clean` verdict reached on syntactic evidence alone is a
    weaker claim than one reached with def-use and call-graph information, and the
    two must never be averaged together silently.
    """

    SEMANTIC = "semantic"
    """Compiled: def-use chains, control flow, call graph."""

    SYNTACTIC = "syntactic"
    """Parsed only: syntax tree, no types, no data flow."""


class KnownBlindness(_Frozen):
    """A defect shape a detector cannot see, and the record that proves it.

    A score and a blindness are not a strong and a weak version of one claim. A
    score is an estimate from a sample and it moves with the sample: add a
    hundred records of a class and its recall becomes some other number. A
    demonstrated blindness is a fact about the instrument and it does not move
    -- one counterexample settles "this predicate cannot see this shape"
    permanently, which is why it is certain at a single record where no score
    ever is.

    That asymmetry is why it is reported on its own line rather than as a
    caveat beside the score. Burying a certain fact inside an uncertain one
    loses the certain half, and the caveat reads as though both were provisional.

    Declared on the detector and carried on every run, so a submission's score
    cannot be reported without its declared blindnesses travelling beside it.
    Self-declaration is the obvious weakness and it is bounded in one direction
    only: `demonstrated_by` names a corpus record, which makes a *claimed*
    blindness checkable -- run the detector and confirm the silence. Nothing can
    force a detector to declare a blindness it would rather not, so the score
    reports how many misses no declared blindness accounts for, which is the
    closest available thing to making omission visible.
    """

    shape: str = Field(
        min_length=1,
        description=(
            "The defect shape that is invisible, as a property rather than as one "
            "instance of it -- 'a guard that references msg.sender inside the broken "
            "comparison', not 'the Visor bug'."
        ),
    )
    demonstrated_by: str = Field(
        min_length=1,
        description=(
            "Record id of a corpus record this detector is silent on. What makes the "
            "entry a proof rather than an opinion, and what makes it checkable."
        ),
    )
    unpatched_because: str = Field(
        min_length=1,
        description=(
            "Why it is a stated gap rather than a fix. A blindness with no reason is a "
            "bug report filed against oneself and left open."
        ),
    )
    isolated: bool = Field(
        default=True,
        description=(
            "Whether `demonstrated_by` shows this shape alone. False when the record "
            "trips several independently sufficient blindnesses at once, so closing "
            "this one will not make the detector see that record."
        ),
    )
    closed_by: str | None = Field(
        default=None,
        description=(
            "What closed it, once something has. Present so the register is a work "
            "list rather than a graveyard: an entry that can be closed is falsifiable "
            "in the direction that matters."
        ),
    )


class EvidenceRef(_Frozen):
    """One deterministic predicate that fired, with where it fired.

    Produced by a detector's `evidence()` phase, never by a model. This is the
    part of the record a model cannot influence: it may sway the verdict, but it
    cannot remove an evidence item, and a verdict asserted against the evidence
    is visible as exactly that.

    A predicate is named for the **property** it establishes, never for the form
    in which it found it. `oracle_price_read_without_staleness_check` names a
    property; `chainlink_latest_round_data_unchecked` names one shape of it, and
    a second shape of the same property then needs a second name, so counting
    either one under-reports the property. The form belongs in `detail`.

    The two payloads below are split because they are compared differently, and
    the difference is load-bearing rather than cosmetic -- see the field
    descriptions and section 2.3 of docs/design.md.
    """

    predicate: str = Field(
        min_length=1,
        description=(
            "Stable predicate id, naming the property established -- "
            "e.g. 'swap_call_min_out_is_literal'."
        ),
    )
    tier: EvidenceTier
    locator: Locator
    detail: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict,
        description=(
            "Canonical payload. Every value must be stable under any edit that "
            "preserves the property, because this is what gets compared."
        ),
    )
    diagnostic: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict,
        description=(
            "Human-facing context. Never compared, so unstable values such as local "
            "identifiers belong here."
        ),
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding(_Frozen):
    """What a detector claims, in a form that can be checked.

    `quote` is the exact source text spanned by `locator`. It is what makes the
    claim falsifiable: the verifier re-reads the source and compares. A quote that
    does not match is not a formatting problem, it is an unverified claim.
    """

    detector_id: str = Field(min_length=1)
    locator: Locator
    quote: str = Field(
        min_length=1, max_length=MAX_QUOTE_CHARS, description="Exact source text at `locator`."
    )
    reasoning: str = Field(min_length=1, max_length=MAX_REASONING_CHARS)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class RejectionKind(StrEnum):
    """Why a check turned a finding away.

    The distinction decides what the run as a whole is, so it cannot be left to a
    free-text label. A verdict rejection is a *judgement* -- the detector looked,
    applied its rules, and concluded this is not an instance. The run is a
    measurement and the answer is `clean`.

    A citation failure is an *error* -- the claim could not be checked against the
    source at all, so nothing was measured. The run is `invalid` and must not be
    scored. Recording both as "a check failed" makes the second indistinguishable
    from the first, which is precisely how infrastructure errors come to be
    counted as model judgements.
    """

    VERDICT = "verdict"
    """A deterministic verdict predicate rejected the claim. The run still measures."""

    CITATION = "citation"
    """The claim could not be confirmed against the source. The run measures nothing."""


class FailedCheck(_Frozen):
    """One named check that rejected a finding, and what kind of rejection it was."""

    check: str = Field(min_length=1, description="Stable check id.")
    kind: RejectionKind
    detail: str = ""


class CitationStatus(StrEnum):
    VERIFIED = "verified"
    """`quote` matches the source at `locator`, and every verdict predicate passed."""

    UNVERIFIED = "unverified"
    """A check rejected it. Retained in the record with the reason, never dropped."""


class VerifiedFinding(_Frozen):
    """A finding after re-verification, carrying the reasons it failed if it did.

    When a verdict predicate rejects a finding, it must name itself.

    A rule that lives only in prompt text and silently yields an empty result
    teaches nobody anything: the rejection becomes indistinguishable from the
    model never having looked, and the recall cost of tightening the rule is
    invisible. Here a rejection is a named, counted, reportable event, which
    makes strictness tunable rather than a matter of faith.
    """

    finding: Finding
    status: CitationStatus
    failed_checks: list[FailedCheck] = Field(
        default_factory=list,
        description="Checks that rejected this finding. Empty iff verified.",
    )

    @property
    def has_citation_failure(self) -> bool:
        """True if any rejection was an inability to check, rather than a judgement."""
        return any(c.kind is RejectionKind.CITATION for c in self.failed_checks)

    @model_validator(mode="after")
    def _status_matches_checks(self) -> VerifiedFinding:
        if self.status is CitationStatus.VERIFIED and self.failed_checks:
            raise ValueError("a verified finding cannot carry failed checks")
        if self.status is CitationStatus.UNVERIFIED and not self.failed_checks:
            raise ValueError("an unverified finding must name what failed")
        return self


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------


class Outcome(StrEnum):
    """The result of running one detector against one source unit.

    Collapsing model misses, schema-parse failures, transport errors and missing
    corpus paths into a single negative label yields a false-negative count that
    is a blend of unrelated causes, attributable to none of them. Only the first
    two members below are measurements; the others must state a cause, are
    reported separately as harness health, and never enter a confusion matrix.
    """

    VULNERABLE = "vulnerable"
    """At least one finding survived re-verification. Enters the matrix."""

    CLEAN = "clean"
    """The detector ran to completion and claimed nothing that stood. Enters the matrix."""

    INVALID = "invalid"
    """The run did not produce a usable answer. Excluded from the matrix."""

    SKIPPED = "skipped"
    """The source could not be analysed at all. Excluded from the matrix."""

    @property
    def is_measurement(self) -> bool:
        """True iff this outcome may be scored. Excluded outcomes are reported, not scored."""
        return self in (Outcome.VULNERABLE, Outcome.CLEAN)


class InvalidReason(StrEnum):
    """Why a run produced no usable answer. Never conflated with `clean`."""

    SCHEMA_VIOLATION = "schema_violation"
    CITATION_UNVERIFIED = "citation_unverified"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TRANSPORT_FAILURE = "transport_failure"
    SANDBOX_FAILURE = "sandbox_failure"


class SkipReason(StrEnum):
    """Why a source was not analysed.

    Deliberately short. These are the only conditions under which a source may be
    passed over, and both mean "there is provably nothing here to read" -- not "this
    looks unpromising". Gate predicates are lenient by construction: when in doubt
    they admit the source and let the detector spend a cheap call on it, because a
    wasted call costs a fraction of a cent and a wrong skip costs a true positive.
    """

    UNPARSEABLE = "unparseable"
    """Neither the semantic nor the syntactic backend could read the source."""

    NO_CONTRACT_DECLARATION = "no_contract_declaration"
    """The unit declares no contract, library or interface."""


class Escalation(_Frozen):
    """One hand-off from the working model to a larger one.

    The escape hatch is metered. Recording every escalation -- and whether it moved
    the verdict -- turns "how much did the large model actually contribute?" from an
    article of faith into a number: escalation rate, and verdict-flip rate given
    escalation, per difficulty level.
    """

    reason: str = Field(min_length=1)
    from_model: str = Field(min_length=1)
    to_model: str = Field(min_length=1)
    changed_verdict: bool


# ---------------------------------------------------------------------------
# Run record
# ---------------------------------------------------------------------------


class DetectorRun(_Frozen):
    """One detector, one source unit, one result.

    The validators below are the point of this module. Each forecloses a record
    that is easy to produce by accident and impossible to detect afterwards:

    * a `clean` verdict that actually carried a failure
    * a `clean` verdict over a finding nobody could check -- an error wearing a
      measurement's clothes, and the subtlest of the set
    * an `invalid` result with no stated cause
    * a `vulnerable` verdict with nothing verified
    * a `skipped` source that nonetheless reports findings or evidence
    * a severity invented by code when none was supplied -- foreclosed by the
      absence of any severity field on this model at all

    Severity is deliberately not represented. It is a value judgement, not an
    observation; the model is asked only for facts it can point at. Ground-truth
    severity assigned by the original auditors travels with corpus records as
    provenance, and is never mixed with anything a model produced.

    Difficulty is derived from `class_id` rather than stored, so a run cannot
    claim a class and contradict its grade.
    """

    detector_id: str = Field(min_length=1)
    class_id: VulnerabilityClass
    source_id: str = Field(min_length=1, description="Stable id of the analysed unit.")

    outcome: Outcome
    evidence_tier: EvidenceTier | None = None
    findings: list[VerifiedFinding] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(
        default_factory=list,
        description="Everything the deterministic phase observed, reported whatever the verdict.",
    )

    known_blindness: list[KnownBlindness] = Field(
        default_factory=list,
        description=(
            "Defect shapes this detector declares it cannot see, copied from the "
            "detector by the runner so that a score cannot be reported without them."
        ),
    )

    invalid_reason: InvalidReason | None = None
    skip_reason: SkipReason | None = None
    escalations: list[Escalation] = Field(default_factory=list)
    trace_path: str | None = Field(default=None, description="Path to the run's JSONL trajectory.")

    @property
    def level(self) -> DifficultyLevel:
        return self.class_id.level

    @property
    def verified_findings(self) -> list[VerifiedFinding]:
        return [f for f in self.findings if f.status is CitationStatus.VERIFIED]

    @property
    def has_citation_failure(self) -> bool:
        return any(f.has_citation_failure for f in self.findings)

    @model_validator(mode="after")
    def _outcome_is_self_consistent(self) -> DetectorRun:
        verified = bool(self.verified_findings)

        match self.outcome:
            case Outcome.VULNERABLE:
                if not verified:
                    raise ValueError(
                        "'vulnerable' requires at least one verified finding; "
                        "unverified claims are not results"
                    )
            case Outcome.CLEAN:
                if verified:
                    raise ValueError("'clean' contradicts a verified finding")
                if self.invalid_reason is not None or self.skip_reason is not None:
                    raise ValueError(
                        "'clean' must not carry a failure reason -- that is the exact "
                        "conflation this type exists to prevent"
                    )
                if self.has_citation_failure:
                    raise ValueError(
                        "'clean' cannot stand over a finding that could not be checked; "
                        "a citation failure measured nothing, so the outcome is 'invalid' "
                        "with reason 'citation_unverified'"
                    )
            case Outcome.INVALID:
                if self.invalid_reason is None:
                    raise ValueError("'invalid' must state its cause")
                if verified:
                    raise ValueError("'invalid' contradicts a verified finding")
            case Outcome.SKIPPED:
                if self.skip_reason is None:
                    raise ValueError("'skipped' must state its cause")
                if self.evidence_tier is not None:
                    raise ValueError("a skipped source has no evidence tier")
                if self.findings:
                    raise ValueError(
                        "a skipped source was never analysed, so it cannot report findings"
                    )
                if self.evidence:
                    raise ValueError(
                        "a skipped source was never analysed, so it cannot report evidence"
                    )
                if self.escalations:
                    raise ValueError("a skipped source never ran, so it cannot have escalated")

        if self.outcome is not Outcome.INVALID and self.invalid_reason is not None:
            raise ValueError(f"invalid_reason set on a {self.outcome.value} outcome")
        if self.outcome is not Outcome.SKIPPED and self.skip_reason is not None:
            raise ValueError(f"skip_reason set on a {self.outcome.value} outcome")
        if self.outcome.is_measurement and self.evidence_tier is None:
            raise ValueError("a scored outcome must record the evidence tier it was reached on")

        if self.level is DifficultyLevel.S and self.escalations:
            raise ValueError(
                f"class {self.class_id.value!r} is graded S, where the escape hatch is closed; "
                "an S-level escalation is a policy violation, not a recordable event"
            )

        return self
