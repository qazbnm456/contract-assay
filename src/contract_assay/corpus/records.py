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
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from contract_assay.models import DifficultyLevel, Locator, VulnerabilityClass

__all__ = [
    "AddressPin",
    "CommitPin",
    "CorpusRecord",
    "CorpusSplit",
    "LocatorLabel",
    "LocatorProvenance",
    "NegativeKind",
    "NegativeScope",
    "Population",
    "Provenance",
    "SourcePin",
    "VulnerabilityClass",
    "check_unit_path",
    "defect_key",
    "fold_preference",
    "load_records",
]

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_TX_HASH = re.compile(r"^0x[0-9a-f]{64}$")


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


class NegativeScope(StrEnum):
    """How much of the source a negative record speaks for.

    Made explicit rather than inferred from whether a locator is present,
    because an implicit scope is two claims sharing one appearance -- the shape
    this design keeps having to separate.
    """

    FILE = "file"
    """No instance of the class exists anywhere in the pinned file.

    The only scope that licenses a precision figure over a whole unit, and the
    only one a human can assert without examining every prediction.
    """

    LOCATION = "location"
    """This location was examined and holds no instance of the class.

    Judges exactly the predictions that overlap it and nothing else. Bounded and
    reviewable in a way a file-wide claim is not: "this read of a
    producer-chosen value is a deadline, not a source of unpredictability" is
    checkable by reading five lines, where "this file contains no such use
    anywhere" is not checkable at all.
    """

    NOTHING = "nothing"
    """Speaks for no region. The claim is about a change, not about a region."""


class NegativeKind(StrEnum):
    """Why a record is a negative sample.

    A benchmark with weak negatives measures nothing. All three kinds are
    required, and `CROSS_CLASS` is the reason the nine classes are built together
    rather than one at a time: it is the only negative that forces a detector to
    distinguish "has a bug" from "has *this* bug".
    """

    POST_FIX = "post_fix"
    """The same source at the fix commit. The reported instance is gone.

    Deliberately *not* "the file is clean for this class". A fix removes the
    defect that was reported; other instances of the same class may remain, and
    nothing in the fix speaks to them. The strongest control for a
    pair-differential (§6.4) and no completeness claim at all.
    """

    CROSS_CLASS = "cross_class"
    """Vulnerable to another class, clean for this one.

    A human asserts the cleanliness, having had to name what the file *is*
    vulnerable to, so the assertion is reviewable and covers the whole file.
    """

    CONFIRMED_CLEAN = "confirmed_clean"
    """Manually verified as carrying no instance of this class.

    A human asserts completeness directly and records how they confirmed it.
    """

    ADJUDICATED = "adjudicated"
    """One location examined and found to hold no instance of the class.

    The kind that makes a precision figure reachable without a completeness
    claim anywhere. If what gets judged is the set of locations something
    *predicted*, then every prediction is judged by construction and precision
    is defined over them -- while no record ever asserts what a file does not
    contain. Judging is driven by what was claimed rather than by the size of
    the corpus, which is the standard treatment of incomplete relevance
    judgements in information retrieval (pooled judgements, and `bpref` for the
    metric side).

    It is also the only form of hand review that is worth anything here. A
    confirmation resting on a structural absence licenses nothing, because the
    absence that makes it cheap is the absence the predicate looks for (§6.2) --
    so review has to happen exactly where a detector has an opinion, and that is
    a location rather than a file.
    """

    @property
    def scope(self) -> NegativeScope:
        """How much of the source this kind speaks for."""
        if self is NegativeKind.POST_FIX:
            return NegativeScope.NOTHING
        if self is NegativeKind.ADJUDICATED:
            return NegativeScope.LOCATION
        return NegativeScope.FILE

    @property
    def licenses_completeness(self) -> bool:
        """Whether this kind asserts the file holds *no* instance of the class.

        The distinction that decides whether a negative can license a precision
        figure (§7.3), and it is a property of the kind rather than of negatives
        in general -- which is the error it exists to prevent. "Cheap to verify"
        and "sufficient for the purpose" are different properties, and a
        post-fix negative has the first without the second: its verification
        needs no human judgement at all, and what it verifies is that one
        reported defect is gone.

        Bridging that to completeness needs the assumption that the audit found
        every instance of the class in the file, which is the corpus-
        completeness assumption §7.3 exists to refuse. So the two file-wide
        human-asserted kinds license it; the mechanical one and the
        location-scoped one do not, for different reasons.
        """
        return self.scope is NegativeScope.FILE


def check_unit_path(raw: str) -> None:
    """Refuse a `path` that names no file, or names one outside a checkout.

    `path` is joined to a `--source-root` by every consumer that resolves a pin,
    and it had no check at all. Three failures, in order of how badly they went:
    `"."` made `corpus.fetch.revisioned_name` raise
    `ValueError: PurePosixPath('.') has an empty name` out of the resolver, so
    the gate that exists to refuse a bad record died on it and took the scorer
    with it; `"../../etc/passwd"` and `"/etc/passwd"` resolve outside the root,
    in a read *and*, since revision names, in a write; and `"a/b/"` had its
    trailing separator silently swallowed.

    A **function** and not only a validator, because putting it on `_Pin` alone
    moved the crash upstream rather than removing it. `normalize` builds a
    `CommitPin` from a `DraftRecord`'s path at two sites and contains no `try`,
    so one malformed permalink in one harvested report -- `adapters.markdown`
    takes the path from a blob URL with nothing but `lstrip("/")` -- aborted the
    whole corpus build where it used to be one counted rejection. `DraftRecord`
    calls this too, which is where its own docstring says invariants belong:
    "refused at the point it is built, where the adapter that built it is still
    identifiable".

    `.` components are checked on the raw string rather than on `parts`, because
    `PurePosixPath` normalises a single dot away before `parts` is read: `a/./b`
    passed and collapsed to `a/b`, which makes two `path` strings -- and so two
    `source_id`s -- name one file, and `fetch`'s collision detector keys on the
    string.
    """
    if not raw or raw != raw.strip():
        raise ValueError(f"path must be a non-empty key with no surrounding space, got {raw!r}")
    if raw.startswith("/") or raw.endswith("/") or "\\" in raw:
        raise ValueError(
            f"path must be relative, with no leading or trailing separator, got {raw!r}"
        )
    if any(part in {"", ".", ".."} for part in raw.split("/")):
        # Split on the raw string, not `PurePosixPath.parts`, which normalises a
        # single dot away before it can be seen: `a/./b` passed and collapsed
        # onto `a/b`, so two `path` strings -- two `source_id`s -- named one
        # file, and `fetch`'s collision detector keys on the string. The empty
        # component this also refuses is `a//b`, the same thing spelled shorter.
        raise ValueError(
            f"path must name a file and stay inside a checkout, got {raw!r}; "
            "'.', '..' and empty components name no file of their own"
        )
    if any(character.isspace() or not character.isprintable() for character in raw):
        raise ValueError(f"path must hold no whitespace or control characters, got {raw!r}")


class _Pin(BaseModel):
    """What every kind of pin owes its consumers.

    A pin answers one question -- exactly which bytes to analyse, and how to know
    they are the right ones -- and there is more than one way for bytes to have
    an address in the world. A repository at a commit is one. Verified source
    for a contract deployed at an address is another, and an incident population
    is made almost entirely of the second: 82% of a sampled incident archive has
    retrievable verified source and none of it has a commit (§6.6).

    The two are kept as one type with a common surface so that the many
    consumers needing only `path`, `sha256` and `source_id` never learn there
    are two kinds. Only the consumers that genuinely differ -- resolution, and
    anything reporting coordinates -- narrow on `kind`. Two separate types would
    push that branch into every signature that carries a pin.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _path_names_a_file_inside_a_checkout(self) -> _Pin:
        check_unit_path(self.path)
        return self

    path: str = Field(
        description=(
            "Which file within the pinned unit. A repository path for a commit pin and "
            "a key into a verified-source set for an address pin -- the same role in a "
            "different namespace, which is why it is one field. NOT necessarily a "
            "filesystem path: see `is_filesystem_path`."
        )
    )
    sha256: str | None = Field(
        default=None,
        description="Digest of the file's bytes as resolved, recorded by verify.",
    )
    resolved_from: str | None = Field(
        default=None,
        description=(
            "How the pin's coordinates were obtained when the source did not state them, "
            "in prose. None means the source stated them outright."
        ),
    )

    @property
    def is_stated(self) -> bool:
        """Whether the source named these coordinates, rather than them being inferred.

        An inferred pin is still reproducible -- the digest witnesses the bytes
        either way -- but it rests on an assumption the source did not make, so
        the assumption travels with the record and reports can stratify on it.
        `resolved_from` states which assumption in prose, because "resolved"
        alone does not say from what.
        """
        return self.resolved_from is None

    @property
    def is_filesystem_path(self) -> bool:
        """Whether `path` may be joined to a directory on disk.

        The trap this exists to close: verified source frequently arrives with
        import-style keys -- `@openzeppelin/contracts/token/ERC20/ERC20.sol` and
        the like -- which look exactly like repository paths and are not
        joinable to any checkout. Code that joins `path` to a root because it
        looked like a path reads the wrong file, or no file, and says nothing
        about why.
        """
        return False


class CommitPin(_Pin):
    """A file in a repository at a commit."""

    kind: Literal["commit"] = "commit"
    repo_url: str = Field(description="Clone URL.")
    commit: str = Field(description="Full 40-hex commit SHA. Refs and short SHAs move.")

    @model_validator(mode="after")
    def _commit_is_a_full_sha(self) -> CommitPin:
        if not _SHA1.match(self.commit):
            raise ValueError(
                f"commit must be a full 40-character lowercase hex SHA, got {self.commit!r}; "
                "branch names and short SHAs are not reproducible"
            )
        return self

    @property
    def is_filesystem_path(self) -> bool:
        return True

    @property
    def source_id(self) -> str:
        """An opaque key for the pinned unit. **Never parse this.**

        Readable so that a log or a failure message is legible, and that is the
        only thing its shape is for. Anything needing the repository, the commit
        or the path reads the field, because an identifier that code takes apart
        to recover its components is an identifier doing double duty as a data
        structure -- and the coupling stays invisible until a second kind of pin
        arrives.

        It leads with the pin's kind for that reason: a consumer that assumed
        one shape fails visibly on another rather than silently mis-parsing it.
        """
        repo = self.repo_url.rstrip("/").rsplit("/", 1)[-1]
        return f"commit:{repo}@{self.commit[:12]}:{self.path}"

    @property
    def unit_id(self) -> str:
        """The same file across revisions. **Never parse this either.**

        `source_id` includes the commit, so one file pinned at two commits is
        two `source_id`s -- correct for "exactly which bytes", and wrong for
        "how many guesses does a submission get here". The shipped corpus pins
        eight paths under two commits each, and a per-unit quota keyed on
        `source_id` handed the records on those paths twice the quota. Keyed on
        this, a submission declaring either pin lands in the same bucket, and
        two repositories that happen to share a path still do not.
        """
        return f"commit:{self.repo_url}:{self.path}"

    def describe(self) -> str:
        return f"{self.repo_url}@{self.commit[:12]}:{self.path}"


class AddressPin(_Pin):
    """Verified source for a contract deployed at an address, at a point in a chain.

    Not weaker than a commit pin. Deployed bytecode is immutable, so an address
    plus a chain plus a fork point is at least as reproducible as a commit and
    rather more so, since an address cannot be force-pushed. The digest
    witnesses the bytes exactly as it does for a commit.

    `fork_point` is required, and not because it pins the source -- the digest
    does that, here as everywhere. It pins the **state**: which implementation
    stood behind a proxy, and what the chain looked like while the defect was
    live. Those are separate claims and a record should be able to be wrong
    about either. It is required unconditionally rather than only for proxies
    because proxy status cannot be known without asking a verification
    repository, and a validator that needed a network call to decide whether a
    field is mandatory would be the only impure validator here.
    """

    kind: Literal["address"] = "address"
    chain_id: int = Field(gt=0, description="EIP-155 chain id. 1 is Ethereum mainnet.")
    address: str = Field(description="Contract address, 0x-prefixed, 40 hex, lowercase.")
    fork_point: str = Field(
        description=(
            "Where in the chain's history this pin applies: a decimal block number, or a "
            "0x-prefixed 32-byte transaction hash. A transaction hash pins a block *and* "
            "a position within it, so it is the stronger of the two forms."
        )
    )
    implementation_of: str | None = Field(
        default=None,
        description=(
            "The proxy this address implements, when the pin deliberately names an "
            "implementation rather than the address users call. None means the address "
            "is the contract itself."
        ),
    )

    @model_validator(mode="after")
    def _coordinates_are_canonical(self) -> AddressPin:
        if not _ADDRESS.match(self.address):
            raise ValueError(
                f"address must be 0x followed by 40 lowercase hex digits, got "
                f"{self.address!r}; mixed case is a checksum, not an identifier"
            )
        if self.implementation_of is not None and not _ADDRESS.match(self.implementation_of):
            raise ValueError(
                f"implementation_of must be a canonical address, got {self.implementation_of!r}"
            )
        if not (self.fork_point.isdigit() or _TX_HASH.match(self.fork_point)):
            raise ValueError(
                f"fork_point must be a decimal block number or a 0x-prefixed 32-byte "
                f"transaction hash, got {self.fork_point!r}"
            )
        return self

    @property
    def pins_a_transaction(self) -> bool:
        return not self.fork_point.isdigit()

    @property
    def source_id(self) -> str:
        """An opaque key for the pinned unit. **Never parse this.** See `CommitPin`."""
        point = self.fork_point if self.fork_point.isdigit() else self.fork_point[:14]
        return f"address:{self.chain_id}:{self.address}@{point}:{self.path}"

    @property
    def unit_id(self) -> str:
        """The same file across fork points. See `CommitPin.unit_id`."""
        return f"address:{self.chain_id}:{self.address}:{self.path}"

    def describe(self) -> str:
        at = "tx" if self.pins_a_transaction else "block"
        return f"chain {self.chain_id} {self.address} @{at} {self.fork_point[:14]}:{self.path}"


SourcePin = Annotated[CommitPin | AddressPin, Field(discriminator="kind")]
"""Exactly which bytes to analyse, and how to know they are the right ones."""


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
                if self.pin.kind != "commit":
                    # A stated limitation, not an oversight. A post-fix negative
                    # is the same code after the repair, and "after" is
                    # identified by a commit; an address pin has no commit to
                    # compare the fix against. The deployed analogue -- the
                    # implementation behind the proxy after an upgrade -- is a
                    # different claim and needs its own kind of negative.
                    raise ValueError(
                        "a post-fix negative must be pinned to a commit, because the fix it "
                        f"is defined against is a commit; this pin is {self.pin.kind!r}"
                    )
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

            if self.negative_kind is NegativeKind.ADJUDICATED:
                if self.locator is None:
                    raise ValueError(
                        "an adjudicated negative must say which location was examined; "
                        "without one it is a file-wide claim wearing a narrower name"
                    )
                if not self.notes.strip():
                    raise ValueError(
                        "an adjudicated negative must record what was found at that "
                        "location and why it is not an instance; the judgement is the "
                        "record's whole content and 'examined' is not reviewable"
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


# ---------------------------------------------------------------------------
# When two records are one defect
# ---------------------------------------------------------------------------
#
# Here rather than in `normalize`, because the question is about records and
# two stages ask it. `normalize` folds within one batch; the corpus on disk is
# the *union* of every batch ever run, and nothing folded that -- so a defect
# whose second report arrived in a later harvest was held twice. Forty-five
# such pairs, and a duplicate understates recall by half at that location
# (§6.7), which is the direction that is invisible.


def defect_key(record: CorpusRecord) -> tuple[str, ...]:
    """What makes two records the same defect.

    The pinned bytes, the function, and the class. Two reports naming the same
    function of the same commit for the same class are describing one defect in
    all but pathological cases; two *different* defects in one function would be
    merged, which is the error this trade accepts, and it is the smaller one --
    an under-counted corpus understates recall where a duplicated one overstates
    it, and only the second is invisible.
    """
    assert record.locator is not None
    return (
        record.pin.source_id,
        record.locator.function or "",
        ",".join(sorted(c.value for c in record.classes)),
        # What a *negative* is about, which `classes` does not carry: an
        # adjudication holds no class and states the class it is negative for.
        # Without this, two adjudications of one function for two different
        # classes had the same key, and the corpus-level fold deleted one of
        # them -- a hand-curated record, removed as a duplicate of a record
        # about something else.
        ",".join(sorted(c.value for c in record.negative_for)),
        record.negative_kind.value if record.negative_kind else "",
    )


def fold_preference(record: CorpusRecord) -> tuple[int, int, int, str]:
    """Which of two records describing one defect to keep.

    Confirmation first, then how many claims the report made, then the narrower
    span, then the id so the choice is deterministic. Deliberately not a ranking
    of provenances against each other: `stated` and `quoted` fail differently
    and neither outranks the other (§6.6), so the tie is broken on what the
    report asserted rather than on how the span was obtained.
    """
    assert record.locator is not None
    width = record.locator.end_line - record.locator.start_line
    return (
        -int(record.is_cross_checked),
        -record.report_assertion_count,
        width,
        record.record_id,
    )


def load_records(path: Path) -> list[CorpusRecord]:
    """Every record at `path`, validated, in a stable order.

    A file or a directory of `*.json`. Public because a consumer cannot connect
    to this corpus without it, and until it was public each one re-implemented
    it -- a check that has to be repeated is a check that will be forgotten in
    one of its places. The omission surfaced the first time a runner outside
    this package tried to read a corpus.

    Sorted by path, so two runs over one directory see the same units in the
    same order. Raises `ValueError` naming the file that would not validate,
    rather than skipping it: a corpus that silently loses a record produces a
    recall figure over a denominator nobody chose.
    """
    paths = sorted(path.glob("*.json")) if path.is_dir() else [path]
    records: list[CorpusRecord] = []
    for one in paths:
        try:
            records.append(CorpusRecord.model_validate_json(one.read_text(encoding="utf-8")))
        except ValidationError as invalid:
            raise ValueError(f"{one}: {invalid.error_count()} problems\n{invalid}") from invalid
    if not records:
        raise ValueError(f"no records under {path}")
    return records
