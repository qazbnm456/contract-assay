"""The detector interface, and the boundary it is trusted across.

This module is a **public API**. Its compatibility surface, and what changing it
costs, are stated in `docs/api.md`; everything named in `__all__` is covered by
that commitment and everything prefixed with an underscore is not.

Why that changes the design
---------------------------
An interface written for nine detectors in this repository and an interface
strangers write submissions against are not the same artifact, even when the
method names coincide. Two differences drive almost every decision below.

*Trust.* A submission is arbitrary code. An abstract base class among
cooperating authors is a convention: the compiler does not check that
`verdict()` returns what it promised, and among colleagues it does not need to.
Across an untrusted boundary the same class is a claim to be checked. So every
value a submission hands back is validated against its model before it is
believed, and a finding's quote is re-read against the source; an evidence
item's claim is not re-verified, and `Detector.evidence` says why -- see
`contract_assay.detectors.loading` -- and a submission that returns nonsense
yields `invalid` with `schema_violation`, never a crash and never `clean`.

*Stability.* A method signature that subclasses implement cannot gain a
parameter without breaking every submission already written. So the inputs
travel in one frozen object, `AnalysisContext`, which can gain fields
compatibly, and the signatures stay fixed. This is the difference between
"we added a capability" and "we broke the cohort's code".

What this module deliberately does not do
-----------------------------------------
It does not sandbox anything. Loading a submission in this process runs the
submission's module-level code in this process. Container isolation, egress
denial and budget enforcement are infrastructure, and they sit *outside* this
module; `SubmissionLimits` tells a detector what it has been allotted, but a
detector that ignores it is stopped from outside or not at all. Documenting a
limit is not enforcing one, and this file must not be read as providing
isolation it has no way to provide.

It also does not re-export a task type from the model harness. A public API that
re-exports a third-party type silently inherits that type's stability guarantees,
which this project does not control and cannot promise on. `ModelTaskSpec` is
therefore a plain declarative record owned here, and translating it into whatever
the model runtime wants is the harness's job, on the harness's side of the
boundary.
"""

from __future__ import annotations

import re
from abc import ABC
from collections.abc import Sequence
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contract_assay.evidence.predicates import predicates, run_all
from contract_assay.evidence.solidity import index_source
from contract_assay.evidence.syntax import Syntax
from contract_assay.models import (
    MAX_DESCRIPTION_CHARS,
    MAX_QUOTE_CHARS,
    DeclaredLimit,
    DifficultyLevel,
    EvidenceRef,
    EvidenceTier,
    FailedCheck,
    Finding,
    Locator,
    RejectionKind,
    SkipReason,
    VulnerabilityClass,
)

__all__ = [
    "API_VERSION",
    "AnalysisContext",
    "ClassificationClaim",
    "Detector",
    "LabelSpaceSpec",
    "ModelTaskSpec",
    "SubmissionLimits",
    "TaskOutput",
    "check_citation",
    "cited_lines",
    "gate",
    "is_compatible",
    "quote_is_at",
    "validate_claim",
]


API_VERSION = "1.1"
"""Version of this interface, as `major.minor`.

Major changes break submissions; minor changes do not. A submission declares the
version it was written against and the loader refuses a major mismatch rather
than failing somewhere deep in a run, where the cause would be attributed to the
submission's logic instead of to a version skew.
"""


def is_compatible(declared: str) -> bool:
    """True if a submission declaring `declared` can run against `API_VERSION`.

    Same major version is the whole rule. A submission written against a newer
    minor version than the host is accepted: minor versions only add, so the
    fields it does not know about are ones it never reads.
    """
    try:
        return declared.split(".", 1)[0] == API_VERSION.split(".", 1)[0]
    except AttributeError:
        return False


class _Frozen(BaseModel):
    """Immutable, and refuses unknown fields.

    `extra="forbid"` is load-bearing on this boundary rather than merely tidy. A
    submission returning an object with an extra key has misunderstood the
    contract, and accepting it silently would let two different meanings of the
    same type coexist until something downstream read the wrong one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# What a detector is given
# ---------------------------------------------------------------------------


class SubmissionLimits(_Frozen):
    """What one run is allotted.

    Visible to the detector so that it can spend its allowance sensibly, and
    enforced from outside because a limit a submission can choose to observe is
    not a limit. Both halves are needed: without the record a detector cannot
    plan, and without external enforcement the record is advice.
    """

    wall_seconds: int = Field(ge=1)
    max_model_calls: int = Field(ge=0)
    max_tokens: int = Field(ge=0)
    escalation_allowed: bool = Field(
        description="Whether the larger model may be requested. False at difficulty S."
    )

    @classmethod
    def for_level(
        cls, level: DifficultyLevel, *, wall_seconds: int, max_model_calls: int, max_tokens: int
    ) -> SubmissionLimits:
        """Limits with escalation metered by difficulty level.

        The escape hatch is closed at `S` and open above it. Deriving the flag
        here rather than letting a caller pass it means the policy lives in one
        place; `DetectorRun` rejects an `S`-level escalation at construction, and
        a flag set by hand could contradict it.
        """
        return cls(
            wall_seconds=wall_seconds,
            max_model_calls=max_model_calls,
            max_tokens=max_tokens,
            escalation_allowed=level is not DifficultyLevel.S,
        )


class LabelSpaceSpec(_Frozen):
    """A label taxonomy, supplied as data.

    Classification-style scoring needs a set of valid tags, subtags and severity
    labels. Those belong to whoever is running the exercise, so they arrive as
    data rather than living in this package: hardcoding one taxonomy would adopt
    an arrangement this project has no reason to adopt, and would turn a general
    capability into a special case for a single consumer.

    `tags` maps each tag to its permitted subtags. An empty list means the tag
    takes no subtag.
    """

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    tags: dict[str, list[str]] = Field(min_length=1)
    severities: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _labels_are_usable(self) -> LabelSpaceSpec:
        if any(not tag.strip() for tag in self.tags):
            raise ValueError("a tag must not be blank")
        if any(not sev.strip() for sev in self.severities):
            raise ValueError("a severity label must not be blank")
        if len(set(self.severities)) != len(self.severities):
            raise ValueError("severity labels must be distinct")
        return self


class AnalysisContext(_Frozen):
    """Everything a detector is given for one source unit.

    Inputs travel in one object so that the interface can gain capabilities
    without changing any signature a submission implements. Adding a field here
    is a minor version; adding a parameter to `evidence()` would break every
    submission ever written against it.

    `facts` carries evidence the harness computed before the detector ran --
    today always the syntactic tier, later whatever the semantic backend
    produces. A detector reads it instead of recomputing, which matters because
    semantic facts may not be recomputable inside the sandbox at all: the
    compiler and its dependency resolution live outside.
    """

    source_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    source: str = Field(description="The Solidity source under analysis.")
    tier: EvidenceTier = Field(
        description="Strongest backend that could read this unit. Never absent: a unit "
        "that no backend could read is skipped by the gate and never reaches a detector."
    )
    level: DifficultyLevel
    limits: SubmissionLimits
    facts: list[EvidenceRef] = Field(
        default_factory=list, description="Evidence the harness computed before the detector ran."
    )
    labels: LabelSpaceSpec | None = Field(
        default=None,
        description="Label taxonomy for classification output. None outside competition mode.",
    )

    @property
    def classification_expected(self) -> bool:
        """True when a label taxonomy was supplied, and so classification output is wanted."""
        return self.labels is not None


# ---------------------------------------------------------------------------
# What a detector produces
# ---------------------------------------------------------------------------


class TaskOutput(StrEnum):
    """Which shape of answer a model task is asked for."""

    FINDINGS = "findings"
    """Located claims, each carrying a quote that is re-verified against source."""

    CLASSIFICATION = "classification"
    """Repository-level labels, which no source check can confirm or refute."""

    BOTH = "both"


class ModelTaskSpec(_Frozen):
    """A declarative description of what to ask the model.

    Deliberately thin. This is the one part of the interface whose eventual shape
    depends on a runtime this module does not import, so it says what is wanted
    and leaves how to a translation layer on the harness's side. A richer spec
    invented now would be a stability promise about a design that does not exist
    yet, which is the most expensive kind of guess a versioned API can make.
    """

    instruction: str = Field(min_length=1)
    expects: TaskOutput = TaskOutput.FINDINGS
    max_steps: int | None = Field(default=None, ge=1)


class ClassificationClaim(_Frozen):
    """A repository-level label claim: what kind of bug, how bad, described.

    Kept off `Finding` on purpose, and the separation is the point rather than
    tidiness. A `Finding` carries a locator and a quote, so it can be checked
    against source and refuted. A claim of this shape carries neither and cannot
    be: "this repository has a high-severity access-control bug" is either
    scored against a label list or not scored at all. Merging the two would let
    an unfalsifiable claim inherit the credibility of a verified one.

    Severity appears here and nowhere else in the system. `Finding` has no
    severity field and will not get one -- a model inventing a severity is
    stating a value judgement as an observation. Reproducing a severity that a
    named auditor recorded, against a stated label list, is a different claim:
    it has a ground truth to be wrong about. `Provenance.reported_severity`
    holds that truth, and it is never compared with anything but this.
    """

    tag: str = Field(min_length=1)
    subtag: str | None = None
    severity: str = Field(min_length=1)
    description: str = Field(
        min_length=1,
        max_length=MAX_DESCRIPTION_CHARS,
        description="Prose description, scored by similarity against the reference text.",
    )


def validate_claim(claim: ClassificationClaim, spec: LabelSpaceSpec) -> list[str]:
    """Problems that make `claim` unscorable against `spec`, or an empty list.

    Returns every problem rather than the first. An author fixing a submission
    should learn everything wrong with a claim in one run; reporting one problem
    per attempt turns a three-field mistake into three rounds of guessing.
    """
    problems: list[str] = []

    if claim.tag not in spec.tags:
        problems.append(f"tag {claim.tag!r} is not in label space {spec.name!r}")
    else:
        permitted = spec.tags[claim.tag]
        if claim.subtag is not None and claim.subtag not in permitted:
            problems.append(f"subtag {claim.subtag!r} is not permitted under tag {claim.tag!r}")
        elif claim.subtag is None and permitted:
            problems.append(f"tag {claim.tag!r} requires a subtag, and none was given")

    if claim.severity not in spec.severities:
        problems.append(f"severity {claim.severity!r} is not in label space {spec.name!r}")

    return problems


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


def gate(source: str) -> SkipReason | None:
    """Whether a source unit may be passed over entirely. `None` means analyse it.

    Harness-owned, and deliberately **not** a method on `Detector`. Both halves
    of that are decisions.

    Lenient by construction: it blocks only where there is provably nothing to
    read. A wasted model call costs a fraction of a cent; a wrong skip costs a
    true positive and leaves no trace in the output that it happened, so "this
    looks unpromising" is never a reason. The two conditions below are the whole
    list, which is why `SkipReason` has exactly two members.

    Not overridable because a per-detector skip is indistinguishable, in the
    recorded result, from a detector that looked and found nothing. Letting a
    submission declare its own skips would hand it a way to convert misses into
    exclusions, and nothing downstream could tell the two apart.

    Only the syntactic tier is consulted, because it is the only backend built.
    When the semantic backend lands, a unit *it* can read must not be skipped
    here even if the parser fails on it -- §3 skips only when both tiers fail.
    """
    index = index_source(source)
    if not index.parsed:
        return SkipReason.UNPARSEABLE
    if not any(decl.kind.is_type for decl in index.declarations):
        return SkipReason.NO_CONTRACT_DECLARATION
    return None


_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")
"""One Solidity token, roughly: an identifier, a number, or one other character.

Rough is enough. This is not a parser -- it exists so that a quote is compared
to a span **at token boundaries**, and any tokenisation that agrees with itself
on both sides gives that.

A multi-character operator is two tokens here: `-=` is `-` then `=`. Worth
knowing because the floor below counts these, so a quote carrying one clears a
six-token floor with five Solidity tokens.
"""

_MINIMUM_QUOTE_TOKENS = 6
"""How many tokens a quote must carry to cite anything.

Harmless rather than optimal, and the docstring used to claim the second. A
review swept it under the whole-line rule: floors of one, three, five and six
are **identical on every attack measured**, because whole lines already closed
the families a length floor was for, and the next value that moves anything is
eight -- which costs an honest submitter 0.24 of its recall. So six keeps out a
quote too short to mean anything and does no other work; `_LANGUAGES_OWN_WORDS`
does the work this was once credited with.
"""

_LANGUAGES_OWN_WORDS = frozenset(
    [
        "abstract",
        "after",
        "alias",
        "anonymous",
        "apply",
        "as",
        "assembly",
        "assert",
        "auto",
        "break",
        "byte",
        "calldata",
        "case",
        "catch",
        "constant",
        "constructor",
        "continue",
        "contract",
        "copyof",
        "days",
        "default",
        "define",
        "delete",
        "do",
        "else",
        "emit",
        "enum",
        "error",
        "ether",
        "event",
        "external",
        "fallback",
        "false",
        "final",
        "for",
        "function",
        "gwei",
        "hex",
        "if",
        "immutable",
        "implements",
        "import",
        "indexed",
        "inline",
        "interface",
        "internal",
        "is",
        "let",
        "library",
        "mapping",
        "match",
        "memory",
        "minutes",
        "modifier",
        "mutable",
        "new",
        "null",
        "of",
        "override",
        "partial",
        "payable",
        "pragma",
        "private",
        "promise",
        "public",
        "pure",
        "receive",
        "reference",
        "relocatable",
        "require",
        "return",
        "returns",
        "revert",
        "sealed",
        "seconds",
        "selfdestruct",
        "sizeof",
        "static",
        "storage",
        "string",
        "struct",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "type",
        "typedef",
        "typeof",
        "unchecked",
        "unicode",
        "using",
        "var",
        "view",
        "virtual",
        "weeks",
        "wei",
        "while",
        "years",
        "abi",
        "addmod",
        "blockhash",
        "block",
        "ecrecover",
        "gasleft",
        "keccak256",
        "mulmod",
        "msg",
        "now",
        "ripemd160",
        "sha256",
        "tx",
        "balance",
        "call",
        "code",
        "data",
        "delegatecall",
        "gas",
        "length",
        "number",
        "origin",
        "pop",
        "push",
        "send",
        "sender",
        "staticcall",
        "timestamp",
        "transfer",
        "value",
        "address",
        "bool",
        "bytes",
        "int",
        "uint",
    ]
)
"""The words a submitter can write without having read any particular file.

Reserved words, elementary type names and the globals every file may use
without declaring them. Enumerated rather than inferred, because it is the
language's vocabulary and not a property of this corpus.

Why a citation must name something outside it: the identifier test used to be
`token[0].isalpha()`, which `return`, `false` and `unchecked` satisfy -- so
`} } return false; }` was "substantive" at six tokens, and a review built a
blind submission out of nothing but braces and keywords. Measured, this clause
costs an honest submission 0.9931 -> 0.9885 (two records whose natural quote is
language only) and takes the brace-and-keyword family from 0.0138 to 0.0092.

Elementary types are listed by prefix only -- `uint`, `int`, `bytes` -- and
their widths are matched in `_is_the_languages_own`, so `uint256` and `bytes32`
need no entry each.
"""


def _is_the_languages_own(token: str) -> bool:
    """Whether one identifier is the language's rather than a file's."""
    if token in _LANGUAGES_OWN_WORDS:
        return True
    for stem in ("uint", "int", "bytes"):
        if token.startswith(stem) and token[len(stem) :].isdigit():
            return True
    return False


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text)


def _is_token_run_of(quote_tokens: list[str], span_tokens: list[str]) -> bool:
    """Whether the quote's tokens are a contiguous run of the span's.

    Not the acceptance test -- `quote_is_at` compares whole lines. This tells
    two refusals apart: a quote that is a token run but not a line run is a
    mid-line fragment, and a quote that is a run of the file somewhere else is a
    locator pointing at the wrong lines. Each has a different fix.
    """
    width = len(quote_tokens)
    if width == 0 or width > len(span_tokens):
        return False
    return any(
        span_tokens[start : start + width] == quote_tokens
        for start in range(len(span_tokens) - width + 1)
    )


def _line_tokens(text: str) -> list[list[str]]:
    """One token list per non-blank line, indentation and inner spacing dropped."""
    return [_tokens(line) for line in text.split("\n") if line.strip()]


def _is_line_run_of(quote_lines: list[list[str]], span_lines: list[list[str]]) -> bool:
    """Whether the quote is a contiguous run of whole lines of the span."""
    width = len(quote_lines)
    if width == 0 or width > len(span_lines):
        return False
    return any(
        span_lines[start : start + width] == quote_lines
        for start in range(len(span_lines) - width + 1)
    )


def cited_lines(
    source: str, locator: Locator, quote: str
) -> tuple[Locator | None, FailedCheck | None]:
    """Where `quote` really is in the source, or why it is nowhere.

    Returns the locator **narrowed to the lines the quote matched**, which is
    what the scorer positions the prediction at. `quote_is_at` is the same check
    without the position, for the in-process path that only needs a verdict.

    Extracted so the **scorer** can run it. `check_citation` is called from
    `run_detector`, which means it only ever protected a run this package
    produced -- while `contract-assay score` takes a JSON Lines file, which is
    the documented way a third party submits. A submitted run arrived with
    `status: verified` already set and nothing re-read the source.

    Measured before the check existed: a submission quoting `"THIS TEXT IS
    NOWHERE IN THE SOURCE"` at every recorded access-control locator scored 12
    predictions, **12 matches**, and `unverifiable_claims: 0`.

    **Whole lines, contiguous, inside the declared span.** Four versions of this
    check have been broken by review, each at a different granularity, and the
    numbers are what chose this one. Every figure is micro recall at the
    exact+function floor over the whole published corpus, through
    `contract-assay score`, for a submission that opens no `.sol` file:

    | rule | `";"` | `"er"` | 181 idioms | generic runs | blind slots |
    | --- | --- | --- | --- | --- | --- |
    | bytes, floor 1 | 0.972 | -- | -- | -- | -- |
    | quote tokenised, span not | -- | 0.938 | -- | -- | -- |
    | both tokenised, token run, floor 3 | 0 | 0 | **0.913** | -- | -- |
    | token run, floor 6 | 0 | 0 | 0 | **0.126** | -- |
    | span equality, floor 6 | 0 | 0 | 0 | 0 | 0.034 |
    | line run, floor 6 | 0 | 0 | 0 | 0 | **0.145** |
    | **line run, positioned, named** | 0 | 0 | 0 | 0 | **0.062** |

    A token run lets a fragment straddle line boundaries, which is where
    `for (uint256 i = 0; i <` and `require(msg.sender ==` live -- ten tokens
    each, generic, and inside hundreds of spans. Whole lines close that family
    without closing anything an honest submitter does, because an honest
    submitter slices the file by line.

    **Equality was the previous rule and this replaces it at no cost to
    forgery resistance and a large gain to the honest side.** Equality demanded
    the quote *be* the declared span, which made a correct quote fail whenever
    the locator was a line wide -- the commonest thing a model gets wrong about
    a span. Measured, same honest submission, only the declared span moving:

    | honest submission, quote unchanged | equality | now |
    | --- | --- | --- |
    | locator exactly the quoted lines | 0.993 | 0.989 |
    | locator one line wider below | **0.076** | **0.989** |
    | locator five lines wider below | 0.005 | 0.989 |
    | locator one line wider above | 0.409 | 0.989 |
    | locator one line wider on both sides | 0.005 | 0.989 |
    | locator five lines wider on both sides | 0.005 | 0.989 |
    | each record's whole span, truncated at `MAX_QUOTE_CHARS` | 0.989 | 0.991 |

    Locator slop in *any* direction is free now. Two of those rows were not
    free under a line run alone: a span starting a line above a function
    resolved to a different function and dropped to `file` strength.
    Positioning (below) fixed them as a side effect -- the prediction is where
    its quote is, and its quote is inside the function. The 0.993 -> 0.989 in
    the first row is `_LANGUAGES_OWN_WORDS` refusing two records whose natural
    one-line quote is language only.

    Accepting part of a span has a price, and the price was under-measured
    twice. A donor-unit forgery -- real text out of one file, every locator
    pointing at another -- reads 0.0023 when it is built naively and **0.0782**
    when the locators are widened, because a wide span makes duplicated
    boilerplate land somewhere. Positioning (below) takes it to **0**. The
    honest side of that trade is the 0.917 of recall that demanding the whole
    span cost, so it was the right trade even at 0.0782.

    **The span is the submitter's field, so the scorer stopped reading it.**
    `cited_lines` returns the locator narrowed to the lines the quote matched,
    and `recheck_citations` puts the prediction there. Without that, "inside the
    declared span" bounded nothing: `_strength` takes the containing function
    from `start_line` alone and `_overlaps` needs only to reach the record's
    anchor, so a submission could declare the published start line and an end
    line hundreds of lines later, keep `exact` strength, and reduce its whole
    problem to naming **one line of a large window**. Measured, that took a
    blind submission from 0.0414 to **0.1448**, and 0.092 of it needed nothing
    but braces and keywords. Positioning costs an honest submission nothing at any
    slop measured -- one line or five, above, below or both -- and for two of
    those it is what makes them free.

    **What is left, and it is not zero.** Nine slots off the published function
    name and line numbers score 0.0276, and **0.0621** when they are declared
    over widened spans and ranked against corpus yield. No rule about quoted
    text can make derivable text unguessable, and the record publishes the
    function's name.

    This is the fifth version of this check and the fifth number. The first
    three were published as zeroes and every one of the five was exceeded by the
    next review -- 0.938, then 0.913, then 0.1448, then 0.0621. So: **0.0621 is
    a measurement of the best blind attack anybody has run here, not a floor.**
    The size of what is left is clearest from the other side: a submitter who
    could name one real line of each published span would score **0.9885**. The
    defence is entirely that it cannot name one.

    Two further rules were measured and **declined**, recorded here so the next
    reviewer does not have to rediscover them:

    - *The quote must also not name the locator's own contract or function.*
      The stricter cousin of `_LANGUAGES_OWN_WORDS`, which is adopted: this adds
      the two names the record itself publishes. It cuts the nine-slot attack
      from 0.034 to 0.011 and costs the honest side 0.993 -> 0.956, because a
      correct finding about a zero-argument function often quotes exactly that
      function's declaration line. Sixteen true citations to remove eleven
      forged ones is the wrong direction for an instrument whose honest ceiling
      should be 1.0.
    - *The quote's token run must occur exactly once in the file.* A cheaper
      test of "could not have been produced without reading this file". Honest
      recall 0.9931 -> **0.9448**, and the strongest blind attack 0.0759 ->
      0.0506 on the same code. An earlier version of this note said the honest
      cost was 0.446; that was a measurement bug -- the uniqueness cache was
      keyed on `id(source)`, and CPython recycles ids, so it answered for the
      wrong file. The corrected trade still declines it: 21 true citations
      refused to remove 11 forged ones, and the true ones are refused silently
      and forever, because a correct finding often quotes a guard the file
      repeats.

    So: a figure over the published corpus is **self-reported**, and this check
    holds a blind submitter to a *measured* 0.06 rather than to zero. A
    competitive ranking needs records whose locators are not published --
    `CorpusSplit.PRIVATE_HOLDOUT` and `assay-arena`'s `docs/operations.md` step
    3 -- and that is where the guarantee has to live. `docs/api.md` §1 says the
    same thing where a submitter reads it.
    """
    # Split on "\n" only, matching `corpus.verify`: str.splitlines() also breaks
    # on \v, \f, \x1c-\x1e and U+2028/2029, none of which a compiler or an
    # editor treats as a line break.
    lines = source.split("\n")

    if locator.end_line > len(lines):
        return None, FailedCheck(
            check="citation_span_out_of_range",
            kind=RejectionKind.CITATION,
            detail=f"span ends at {locator.end_line}, source has {len(lines)} lines",
        )

    span = "\n".join(lines[locator.start_line - 1 : locator.end_line])
    if not quote.strip():
        return None, FailedCheck(
            check="citation_quote_absent_from_source",
            kind=RejectionKind.CITATION,
            detail="the quote is blank once whitespace is normalised",
        )

    quote_tokens = _tokens(quote)
    names_something = any(
        (token[0].isalpha() or token[0] == "_") and not _is_the_languages_own(token)
        for token in quote_tokens
    )
    if len(quote_tokens) < _MINIMUM_QUOTE_TOKENS or not names_something:
        # Two things at once, and the second is the load-bearing one. A review
        # scored **micro recall 0.972** by quoting `";"` at every published
        # locator, which the length floor closes. It then scored **0.0138**
        # reading no source at all out of brace-and-keyword lines like
        # `} } return false; }` -- six tokens, and "an identifier" under a test
        # that only asked whether a character was a letter. A quote that names
        # nothing outside the language names no file in particular.
        return None, FailedCheck(
            check="citation_quote_is_not_substantive",
            kind=RejectionKind.CITATION,
            detail=f"{quote.strip()[:40]!r} is {len(quote_tokens)} token(s) and needs at "
            f"least {_MINIMUM_QUOTE_TOKENS}, one of them naming something the language "
            "does not supply; a quote of keywords and punctuation names no file in "
            "particular",
        )

    quote_lines = _line_tokens(quote)
    # The span's non-blank lines, each keeping the number it has in the file, so
    # a match can be reported at its real coordinates.
    numbered = [
        (number, _tokens(line))
        for number, line in enumerate(
            lines[locator.start_line - 1 : locator.end_line], locator.start_line
        )
        if line.strip()
    ]
    width = len(quote_lines)
    if width and width <= len(numbered):
        for first in range(len(numbered) - width + 1):
            if [tokens for _, tokens in numbered[first : first + width]] == quote_lines:
                return (
                    locator.model_copy(
                        update={
                            "start_line": numbered[first][0],
                            "end_line": numbered[first + width - 1][0],
                        }
                    ),
                    None,
                )
    if _is_line_run_of(quote_lines, _line_tokens(source)):
        return None, FailedCheck(
            check="citation_quote_elsewhere_in_file",
            kind=RejectionKind.CITATION,
            detail="the quote is in the file but not at the cited lines",
        )
    if _is_token_run_of(_tokens("\n".join(" ".join(line) for line in quote_lines)), _tokens(span)):
        # Real text at the cited lines, and not whole lines of it: a fragment
        # that starts or stops mid-line. Refused because that is where a blind
        # guess lives -- `for (uint256 i = 0; i <` is ten generic tokens and
        # sits inside hundreds of spans -- and it is not what an honest
        # submitter produces, because slicing a file gives whole lines.
        return None, FailedCheck(
            check="citation_quote_is_not_whole_lines",
            kind=RejectionKind.CITATION,
            detail="the quote starts or ends mid-line; quote the whole of each line it "
            "covers, which is what slicing the source at a locator gives",
        )
    return None, FailedCheck(
        check="citation_quote_absent_from_source",
        kind=RejectionKind.CITATION,
        detail="the quote is not in the source",
    )


def quote_is_at(source: str, locator: Locator, quote: str) -> FailedCheck | None:
    """Whether `quote` is whole lines of the source inside `locator`.

    The verdict without the position. `run_detector` wants only this: it is
    checking a finding its own detector produced, and a submission's locator is
    not something it is in a position to correct. The **scorer** uses
    `cited_lines`, because there the locator is a claim by somebody else.
    """
    return cited_lines(source, locator, quote)[1]


def check_citation(ctx: AnalysisContext, finding: Finding) -> FailedCheck | None:
    """Re-read the source at a finding's locator and compare it to the quote.

    Harness-owned and always run, for the same reason `gate` is: the data
    contract says a finding is re-verified against source unconditionally, every
    run, and that is simply false if each submission has to remember to do it. A
    detector that omitted the check would have its unverifiable claims accepted,
    which is the same hole as an overridable gate wearing different clothes. So
    `verdict()` is left for class-specific rules, and this runs whatever it
    returns.

    Every failure here is a `CITATION` rejection, never a `VERDICT` one, and the
    distinction decides what the whole run is. A finding whose quote is not where
    it says establishes nothing about whether the class is present at that
    location -- the detector may have found a real defect and mis-cited it, or
    invented both. Recording it as `clean` would assert "nothing here" on the
    strength of a broken citation.

    Comparison normalises leading and trailing whitespace per line and ignores
    blank lines. Indentation is not semantic, and a model reproducing a
    function's body with its indentation shifted has still quoted the code;
    demanding byte-exact whitespace would reject true findings for a reason
    unrelated to whether they are true, which is a wrong skip paid for in
    recall.
    """
    return quote_is_at(ctx.source, finding.locator, finding.quote)


class Detector(ABC):
    """One vulnerability class, in three layers.

    A subclass declares what it is and implements two deterministic methods; the
    model-driven middle is optional.

        class MyReentrancyDetector(Detector):
            detector_id = "my-reentrancy"
            class_id = VulnerabilityClass.REENTRANCY
            api_version = "1.0"

            def evidence(self, ctx): ...
            def verdict(self, ctx, finding, evidence): ...

    The layers run in a fixed order -- `evidence`, then `plan` and the model, then
    `verdict` on each returned finding -- and the ordering carries a guarantee
    worth naming: **evidence is recorded whatever the model concludes**. A model
    may decline to report, or report wrongly; it cannot remove an evidence item.
    A verdict asserted against the evidence is therefore visible as exactly that,
    which is a signal worth having and one that disappears the moment the two are
    allowed to influence each other.

    It is also what makes a multi-condition rule enforceable. "Exploitable only
    if A and B and C" written into prompt text is enforced by the model's
    attention holding across the whole input. Written in `verdict()`, it is
    `and`.

    A purely deterministic detector is a first-class citizen: leave `plan()`
    returning `None` and no model runs. Static analysers are the baseline this
    project measures against, and an interface that could not express one could
    not express its own control group.
    """

    detector_id: ClassVar[str]
    class_id: ClassVar[VulnerabilityClass]
    api_version: ClassVar[str]

    declared_limits: ClassVar[tuple[DeclaredLimit, ...]] = ()
    """What this detector states it cannot establish, each proved by a corpus record.

    Two kinds, kept apart rather than merged (`models.LimitKind`): a
    **blindness** is a shape the instrument should see and does not, and an
    **indeterminacy** is the instrument correctly reporting that something is
    unknowable at this scope -- which is it working, and must not read as a
    defect.

    Empty by default, and not one of the three required declarations: a detector
    with nothing demonstrated against it has nothing to declare, and demanding
    an entry would produce invented ones. It is populated when a record shows
    something the detector cannot establish -- see `models.DeclaredLimit` for
    why that is reported apart from a score rather than beside it.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Check the declaration at class-definition time.

        A submission missing `class_id` should fail on import, with a message
        naming the field, rather than partway through a run where the failure
        reads as a defect in the detector's logic. Abstract intermediate classes
        are exempt: a shared base that subclasses complete is a normal thing to
        write, and forcing it to invent a `detector_id` would push authors into
        declaring a fake one.

        Abstractness is read from the methods themselves rather than from
        `cls.__abstractmethods__`. That attribute is a slot on `type` which
        raises until `ABCMeta` fills it in, and it is filled in *after* this hook
        runs -- so consulting it here reports every class as concrete, including
        the abstract ones this exemption exists for.

        A class declaring *none* of the three is exempt too, and that second
        exemption is not the same as the first. A shared base that implements
        both methods and leaves the declarations to its subclasses has no
        abstract methods left, so the test above would treat it as a submission
        entry point and demand a `detector_id` it has no business owning --
        pushing authors into inventing a fake one, which is exactly what this
        check exists to prevent. Declaring none of them says "not an entry
        point"; declaring some but not all is the actual mistake, and it is
        still caught, with the missing fields named.
        """
        super().__init_subclass__(**kwargs)
        if any(
            getattr(getattr(cls, name, None), "__isabstractmethod__", False) for name in dir(cls)
        ):
            return

        fields = ("detector_id", "class_id", "api_version")
        declared = [field for field in fields if getattr(cls, field, None) is not None]
        if not declared:
            return
        missing = [field for field in fields if field not in declared]
        if missing:
            raise TypeError(
                f"{cls.__name__} declares {', '.join(declared)} but not "
                f"{', '.join(missing)}; a detector declares all three or none"
            )
        if not is_compatible(cls.api_version):
            raise TypeError(
                f"{cls.__name__} declares api_version {cls.api_version!r}, which is "
                f"incompatible with {API_VERSION!r}"
            )

    @property
    def level(self) -> DifficultyLevel:
        """Difficulty of this detector's class. Derived, never declared separately."""
        return self.class_id.level

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        """Structural facts about the source, each with a location.

        **The default is the benchmark's own evidence layer**, run for this
        detector's class. A submission that writes nothing here is not a
        submission with no evidence: it gets the same predicates the reference
        detectors use, over the same parser, and its figures then differ from
        another submission's because of what the two *conclude* rather than
        because of who wrote the better tree-sitter query.

        That is the point of the default. This class of benchmark is meant to
        compare judgement about vulnerabilities, and making every entrant
        reimplement source analysis puts a second variable into every
        comparison. `contract_assay.evidence` is public for the same reason --
        use `Syntax` and `predicates.run_all` directly when you want a subset,
        a different tier, or facts of your own.

        Override it when you can establish something this layer cannot. Two
        constraints if you do:

        - **Deterministic, model-free, and always run.** Must not consult a
          model, a network or a clock: the guarantee that evidence is
          independent of the verdict holds only if nothing here can be
          influenced by what the model later says.
        - **Predicates test shapes, not names.** Identifiers are chosen by
          whoever wrote the contract and can change without changing behaviour,
          so a predicate keyed on one measures the author's naming habits.
          Solidity is case-sensitive; do not case-fold identifiers, which
          manufactures matches the compiler would not make.

        What is checked, precisely: the host validates that every item is a
        well-formed `EvidenceRef` and drops what is not. It does **not** verify
        that the property an item claims actually holds at that location --
        nothing re-reads the source to confirm a predicate fired. An evidence
        item is therefore your claim, and the only thing that consumes it is
        your own `verdict()`. A `Finding`'s quote is the value that *is* checked
        against source, unconditionally, by the host (`check_citation`).
        """
        parsed = Syntax.of(ctx.source)
        if parsed is None:
            # Unparseable source establishes nothing rather than nothing being
            # there. `gate` is what decides whether a unit is skipped; this
            # returns an honest empty list.
            return []
        return run_all(parsed, ctx.path, classes=[self.class_id])

    def propose(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> Sequence[Finding]:
        """Findings this detector asserts from the source alone, with no model.

        This layer exists because without it the interface could not express a
        static analyser at all. Findings reached a run only through the host's
        `model_findings`, so a detector with `plan()` returning `None` could
        report nothing but `clean` -- while the documentation called a
        deterministic detector a first-class citizen and named static analysis
        as this benchmark's own control group. Both were false for as long as
        this method did not exist.

        **The default asserts nothing**, and deliberately: an evidence item says
        something structural is present, which is a precondition rather than a
        claim that a defect is there. A default that turned every evidence item
        into a finding would make every model-driven detector start claiming its
        own preconditions, which is a different detector than its author wrote.
        `PredicateDetector` is the subclass that does make that leap, for a
        submission that wants exactly it.

        Nothing returned here is trusted more than a model's output. A proposed
        finding goes through the same two checks in the same order:
        `check_citation`, which is the host's and cannot be overridden, then this
        detector's own `verdict()`. The only difference is the producer -- the
        run records `produced_without_a_model`, a true claim about code, and the
        leaderboard then declines to rank it against a model baseline and says
        why, which is the behaviour a deterministic submission already had.

        Quote from the source, not from memory. `ctx.source` is right there and
        `site.text` on any `contract_assay.evidence` site is the exact span, so
        a deterministic finding has no excuse for failing its citation check.
        """
        return ()

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        """What to ask the model, or `None` to run no model at all.

        Receives the evidence so the request can build on what is already known.
        The default runs no model, which makes a deterministic detector the
        cheapest thing to write rather than the hardest.
        """
        return None

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        """Checks that reject `finding`. Empty means it stands.

        **The default rejects nothing**, and that is the honest default rather
        than a lenient one: a default that invented rejections would turn away
        findings on rules the submission never chose. Writing no `verdict()`
        says "I assert nothing about this class beyond what the citation check
        establishes" -- and the citation check is the host's, runs first, and
        cannot be overridden.

        What this method can and cannot do is worth being exact about, because
        it looks like self-judging and is not. It can only **discard your own
        findings**. It cannot make the corpus agree with one: matching a
        prediction against a ground-truth record happens in the scorer, which a
        submission never touches, as does every figure computed from it. So a
        rejection costs you recall and buys you precision, which is the trade a
        detector exists to make.

        Override it to be strict, in the opposite direction from `gate`: reject
        when unsure. That is affordable only because every rejection is recorded
        and named. A rejected finding is retained with `status=unverified` and
        the list of checks that rejected it, so the recall cost of each rule is
        a number rather than a matter of faith.

        The rule worth internalising before writing one: **the layer that
        decides must ask for the property the layer that observes established.**
        If `evidence()` established that a function takes a deadline argument,
        ask the evidence for that -- do not re-derive it from the finding's
        text. Six separate bugs in this project's own reference detectors were
        that mistake, and the sixth was written while fixing the fifth.
        """
        return []

    def classify(
        self, ctx: AnalysisContext, findings: Sequence[Finding]
    ) -> Sequence[ClassificationClaim]:
        """Repository-level label claims, for classification-style scoring.

        Called only when `ctx.labels` is supplied. The default returns nothing,
        because a detector built to locate defects has no obligation to also
        guess labels, and a default that fabricated them would put words in its
        mouth.

        `findings` are those that survived `verdict()`. A claim need not
        correspond to one -- label-only scoring does not check location, so a
        detector may legitimately claim a category it could not localise. That
        gap is exactly what dual-track reporting exists to expose, and it is the
        reason this method's output is never merged into the located results.
        """
        return ()


class PredicateDetector(Detector):
    """A static-analysis submission: this benchmark's predicates, as claims.

    The baseline an entrant improves on, and the control group the design
    documents have always named. Subclass it, declare the three fields, and that
    is a complete submission:

        class Baseline(PredicateDetector):
            detector_id = "baseline-access-control"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

    It runs no model, asserts one finding per evidence item its class's
    predicates fired, quotes the source at each item's own locator -- so its
    citations pass by construction -- and rejects nothing beyond the host's
    citation check.

    What it is and is not: a real, scoreable figure produced with no model, which
    is the point of having it. Not a strong detector. Its predicates establish
    that a *shape* is present, and a shape is not a defect; measured on this
    corpus it reports many more locations than hold defects, and the
    adjudication queue it produces is the honest cost of that. A submission
    beats it by being more selective, not by finding more.
    """

    def propose(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> Sequence[Finding]:
        summaries = {spec.predicate_id: spec.summary for spec in predicates()}
        lines = ctx.source.split("\n")
        out: list[Finding] = []
        for ref in evidence:
            if not ref.is_established:
                # An `indeterminate` evidence item is the predicate saying it had
                # no basis to decide -- the three-valued answer this system
                # exists to keep apart from "absent". Asserting it as a finding
                # converts the disclaimer back into a claim: the run comes out
                # `vulnerable`, `negative_is_established` reads True, and the
                # prediction enters somebody's adjudication queue carrying a
                # `reasoning` string that states the property the item itself
                # declined to establish. Found by review, and it had tainted the
                # measured baseline figure this class's docstring quotes.
                continue
            start, end = ref.locator.start_line, ref.locator.end_line
            if start < 1 or end < start or end > len(lines):
                # An evidence span outside this source has nothing to quote.
                # Skipped rather than quoted emptily: a `Finding` requires a
                # non-empty quote and inventing one is exactly what the citation
                # check exists to catch.
                continue
            quote = "\n".join(lines[start - 1 : end])
            if not quote.strip():
                continue
            if len(quote) > MAX_QUOTE_CHARS:
                # A whole-function span over a long function exceeds `Finding`'s
                # own bound, and `_validate_each` raises on the first bad item --
                # so one 4,000-character function turned the entire unit into
                # `invalid`/`schema_violation`, discarding every other proposed
                # finding and blaming the submission. Skipped instead, because a
                # truncated quote would fail the citation check and a truncated
                # locator would point somewhere the predicate did not.
                continue
            out.append(
                Finding(
                    detector_id=self.detector_id,
                    locator=ref.locator,
                    quote=quote,
                    reasoning=summaries.get(ref.predicate, ref.predicate),
                )
            )
        return out
