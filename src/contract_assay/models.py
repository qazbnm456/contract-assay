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
    "DeclaredLimit",
    "DetectorRun",
    "Determination",
    "DifficultyLevel",
    "Escalation",
    "EvidenceRef",
    "EvidenceTier",
    "FailedCheck",
    "Finding",
    "InvalidReason",
    "LimitKind",
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


class Determination(StrEnum):
    """Whether a predicate's answer at a site is a finding about the code.

    The founding separation of this system, one layer further down. At the
    outcome layer `invalid` -- could not measure -- is kept apart from `clean` --
    measured, found nothing -- because merging them makes an error
    indistinguishable from a conclusion afterwards (`Outcome`). A predicate that
    can only fire or stay silent has the merged version of exactly that problem:
    its silence means both "the property is absent here" and "I had no basis to
    decide", and only the first is a fact about the code.

    So a predicate evaluation is three-valued. Indeterminacy is recorded at the
    **site**, not on the unit's evidence tier: a tier says what the backend
    could do for a compilation unit, while indeterminacy is a property of one
    evaluation -- this call's effect is unknowable because the callee's
    implementation is not in the bytes we hold. Putting a per-site fact in a
    per-unit field would be the same misplacement in a new spot.
    """

    ESTABLISHED = "established"
    """The predicate's condition holds here, and the evidence says what holds."""

    INDETERMINATE = "indeterminate"
    """The predicate could not decide here, and says why.

    Recorded rather than dropped, and it does **not** make the run `invalid`:
    the model can still reason about the code, and only the deterministic layer
    failed to corroborate. What it must never do is stand in for absence --
    `verdict()` treating indeterminate as "the property is not here" is the
    merged version of this distinction reappearing one layer up, and it is the
    natural thing to write when a three-valued input meets a two-valued
    condition.
    """


class LimitKind(StrEnum):
    """What kind of statement a declared limit makes about the world.

    Two, and they are not a strong and a weak version of one thing. They close
    differently, they say different things about the instrument, and one of them
    is the instrument working correctly.
    """

    BLINDNESS = "blindness"
    """The instrument cannot see a shape it should be able to see.

    A defect in the instrument. Better analysis closes it.
    """

    INDETERMINACY = "indeterminacy"
    """The instrument correctly reports that something is unknowable at this scope.

    Not a lesser blindness -- a different kind of statement, and a true one. A
    submission reporting "I cannot determine this here" has done the right
    thing, and counting that against it would make an honest limit read as a
    defect and make silently guessing the better-looking strategy. More *scope*
    closes it: more bytes, not better analysis.
    """


class DeclaredLimit(_Frozen):
    """Something a detector states it cannot establish, and the record that proves it.

    Named for the set rather than for half of it. An earlier name -- known
    blindness -- described only one of the two kinds this holds, and a container
    named wrongly attracts the wrong contents, which is this project's own rule
    about causes (§1.3) applied to a type.

    A score and a declared limit are not a strong and a weak version of one
    claim. A score is an estimate from a sample and it moves with the sample:
    add a hundred records of a class and its recall becomes some other number. A
    demonstrated limit is a fact about the instrument and it does not move --
    one counterexample settles "this cannot be established here" permanently,
    which is why it is certain at a single record where no score ever is.

    That asymmetry is why limits are reported on their own line rather than as a
    caveat beside the score. Burying a certain claim inside an uncertain one
    loses the certain half and makes both read as provisional.

    Declared on the detector and carried on every run, so a submission's score
    cannot be reported without its declared limits travelling beside it.
    Self-declaration is the obvious weakness and it is bounded in one direction
    only: `demonstrated_by` names a corpus record, which makes a *claimed* limit
    checkable -- run the detector and confirm it. Nothing can force a detector to
    declare a limit it would rather not, so the score reports how many misses no
    declared limit accounts for, which is the closest available thing to making
    omission visible.
    """

    kind: LimitKind = Field(
        description=(
            "Whether the instrument cannot see this, or correctly reports it as "
            "unknowable at this scope. Required with no default: the two close "
            "differently and a reader deciding where to spend effort needs to know "
            "which they are looking at, so it is a value somebody can review rather "
            "than a choice made silently by whoever filed the entry."
        )
    )
    shape: str = Field(
        min_length=1,
        description=(
            "What cannot be established, as a property rather than as one instance of "
            "it -- 'a guard that references msg.sender inside the broken comparison', "
            "not 'the Visor bug'."
        ),
    )
    demonstrated_by: tuple[str, ...] = Field(
        min_length=1,
        description=(
            "Record ids this limit applies to. What makes the entry a proof rather than "
            "an opinion, and what makes it checkable: run the detector and confirm it is "
            "silent on each. Several, because a limit is a property of the instrument "
            "and one shape hides however many records show it -- naming one of them made "
            "the declaration list grow with the corpus instead of with the blindnesses, "
            "and left the rest of a known shape's records counted as unexplained."
        ),
    )
    unpatched_because: str = Field(
        min_length=1,
        description=(
            "Why it is a stated limit rather than a fix. A limit with no reason is a "
            "bug report filed against oneself and left open."
        ),
    )
    closed_when: str = Field(
        min_length=1,
        description=(
            "What would close this entry, stated rather than inferred from `kind`. The "
            "reader's actual question is whether a planned change will absorb it, and "
            "deriving the answer from the kind would encode a general claim -- better "
            "analysis closes blindnesses, more scope closes indeterminacies -- of "
            "exactly the sort that has already been wrong here once."
        ),
    )
    isolated: bool = Field(
        default=True,
        description=(
            "Whether `demonstrated_by` shows this limit alone. False when the record "
            "trips several independently sufficient limits at once, so closing this one "
            "will not make that record visible."
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

    determination: Determination = Field(
        default=Determination.ESTABLISHED,
        description=(
            "Whether the predicate decided here or could not. Defaults to established, "
            "because a predicate that reports a site without saying otherwise is "
            "reporting a fact about the code."
        ),
    )
    indeterminate_because: str | None = Field(
        default=None,
        description=(
            "Why the predicate could not decide, in prose. Required for an "
            "indeterminate result and refused for an established one."
        ),
    )

    @model_validator(mode="after")
    def _indeterminacy_states_its_reason(self) -> EvidenceRef:
        """An indeterminate result says why, and an established one may not claim to.

        The same discipline every cause here carries (§1.3): a cause with no
        reason behind it is a guess about why, and a guess about why survives
        review because the thing beside it is correct. Refusing the reason on an
        established result is the other half -- a field that is sometimes a
        reason and sometimes decoration cannot be read.
        """
        if self.determination is Determination.INDETERMINATE:
            if not (self.indeterminate_because or "").strip():
                raise ValueError(
                    "an indeterminate evidence result must say why it could not decide; "
                    "silence about the reason is what makes an indeterminacy "
                    "indistinguishable from an absence"
                )
        elif self.indeterminate_because is not None:
            raise ValueError(
                "indeterminate_because is set on an established result, which then "
                "reads as a caveat on a fact"
            )
        return self

    @property
    def is_established(self) -> bool:
        return self.determination is Determination.ESTABLISHED


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

    MODEL_NOT_PERMITTED = "model_not_permitted"
    """The harness asked for a model the exercise did not agree to, and the call
    was refused before it was made.

    Distinct from `budget_exhausted`, and the distinction is the whole reason it
    exists: a run recorded as out of budget sends its author to look at how much
    it spends, when the fix is to stop naming that model. A cause recorded
    wrongly points investigation away from the fix.

    Also distinct from `sandbox_failure`, which says the host could not run the
    submission. This says the host ran it and it asked for something outside the
    agreement -- a fact about the submission, not about the infrastructure."""


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


class ModelRole(StrEnum):
    """Which part a model played in one run."""

    MAIN = "main"
    """The model the exercise agreed on. At most one per run."""

    SUB = "sub"
    """A helper the harness also called -- a summariser, a re-ranker, a judge."""


class ModelUse(_Frozen):
    """One model a run called, and what the call cost.

    Recorded because the whole comparability claim rests on it. An exercise that
    agrees a baseline model and runs every submission against it is making a
    statement about *process*; a leaderboard that cannot name the model behind
    each row cannot check that statement, and two rows produced under different
    models are not comparable however similar the numbers look.

    `Escalation` already names the models involved in a hand-off. This is the
    ordinary case, where nothing was handed off and the run still has to say
    what it called.
    """

    model_id: str = Field(min_length=1, description="Exactly the identifier the host called.")
    role: ModelRole
    calls: int = Field(default=0, ge=0)
    tokens: int = Field(default=0, ge=0)


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

    declared_limits: list[DeclaredLimit] = Field(
        default_factory=list,
        description=(
            "What this detector declares it cannot establish, copied from the detector "
            "by the runner so that a score cannot be reported without them."
        ),
    )

    invalid_reason: InvalidReason | None = None
    skip_reason: SkipReason | None = None
    escalations: list[Escalation] = Field(default_factory=list)
    trace_path: str | None = Field(default=None, description="Path to the run's JSONL trajectory.")

    models: list[ModelUse] = Field(
        default_factory=list,
        description="Every model this run called, recorded by the host that called them.",
    )
    produced_without_a_model: bool = Field(
        default=False,
        description=(
            "Set when the findings came from deterministic code rather than a model. "
            "Explicit, because 'no model is named' and 'no model ran' are different "
            "claims and only one of them supports a baseline comparison."
        ),
    )

    @property
    def established_evidence(self) -> list[EvidenceRef]:
        """Evidence that says something about the code."""
        return [e for e in self.evidence if e.is_established]

    @property
    def indeterminate_evidence(self) -> list[EvidenceRef]:
        """Sites the deterministic layer could not decide, each with its reason."""
        return [e for e in self.evidence if not e.is_established]

    @property
    def negative_is_established(self) -> bool:
        """Whether a `clean` outcome rests on anything.

        `clean` means the detector looked and found nothing. When the
        deterministic layer could not decide at some site, a clean verdict is
        still a measurement -- the model reasoned about the code -- but it is
        not the same claim as "nothing is here", and a report that could not
        tell them apart would have the founding conflation of `Outcome` back
        inside the evidence that feeds it.

        Not a rejection. An indeterminate site does not make a run `invalid`,
        because the run measured something; it makes the run's negative
        qualified, and says so.
        """
        if self.outcome is not Outcome.CLEAN:
            return True
        return not self.indeterminate_evidence

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

        # A finding with no named producer is the gap this closes. The host
        # supplies the findings, so only the host knows whether a model made
        # them; a run that says nothing leaves a leaderboard unable to state
        # what it measured, and "unknown" then reads as "the agreed baseline".
        if self.findings and not self.models and not self.produced_without_a_model:
            raise ValueError(
                "findings name no producer: record the models called, or set "
                "produced_without_a_model when deterministic code made them"
            )
        # Both may be set, and the rule that forbade it was written when only one
        # was possible. `Detector.propose()` lets a detector assert findings from
        # source and `plan()` lets the same detector call a model, so a run can
        # genuinely carry some of each -- and refusing that combination turned a
        # legitimate submission into an uncaught `ValidationError` that ended the
        # whole sweep. Two producers named is more information than one, not
        # less.
        #
        # The stated limit: the split is not recorded per finding. A run saying
        # both says "code produced at least one of these and a model produced at
        # least one", and nothing here says which is which. That is a real gap
        # in the record rather than a claim it makes wrongly.
        if sum(1 for use in self.models if use.role is ModelRole.MAIN) > 1:
            raise ValueError("a run has at most one main model; the rest are sub models")
        named = {use.model_id for use in self.models}
        if named:
            for escalation in self.escalations:
                for model in (escalation.from_model, escalation.to_model):
                    if model not in named:
                        raise ValueError(
                            f"escalation names {model!r}, which is not among the models "
                            "this run records calling"
                        )
        if self.outcome is Outcome.SKIPPED and (self.models or self.produced_without_a_model):
            raise ValueError("a skipped source never ran, so nothing produced findings for it")

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
