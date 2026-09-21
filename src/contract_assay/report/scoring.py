"""Scoring located findings against pinned ground truth.

Separate from the harness on purpose: the run records what happened, scoring
interprets it, and interpretation changes far more often than capture does
(§7). Nothing here mutates a run.

Three things this module refuses to do, each of which would produce a number
that looks exactly like a number without the problem.

**It will not claim a strength it cannot establish.** `exact` means the spans
overlap within the same function. For a record whose span was inferred from a
function named in prose, the ground-truth span *is* the whole function, so any
prediction inside it overlaps and `exact` is satisfied trivially. Such records
report `exact` as **unavailable** rather than as satisfied, and the count of
unavailable travels with every figure. The same applies to `function` when no
source is available to compare signatures with.

**It will not compare function names.** Solidity permits overloading, so
`swap(uint256)` and `swap(uint256,address)` share a name and are different
functions. Verification guarantees a record's function is unambiguous *within
its span*, not within its file, so a prediction naming the right name in the
wrong overload would otherwise score as having found the right function -- §1.1's
failure inside the mechanism built to prevent it. Signatures are resolved
through the declaration index instead, which is why a resolver is injected.

**It will not fold errors into the matrix.** `invalid` and `skipped` runs are
counted and reported beside every figure, never inside one, and a detector's
unverifiable claims still cost it precision (§7.2) -- output that costs nothing
to produce must not be free to produce.

Assignment
----------
Predictions are assigned to ground truth one-to-one, strongest tier first, and
within a tier by **maximum matching** rather than greedily. Greedy differs from
optimal and the difference is not an approximation: with two predictions able to
match one truth and a second truth reachable by only one of them, greedy can
leave that truth unmatched. §7.1 requires the rule in use to be stated where it
is used, so: maximum matching per tier, tiers in descending order.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from contract_assay.corpus.records import (
    CorpusRecord,
    LocatorProvenance,
    NegativeKind,
    Population,
    SourcePin,
)
from contract_assay.corpus.verify import SourceResolver
from contract_assay.detectors.base import cited_lines
from contract_assay.evidence.syntax import Syntax
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
    CitationStatus,
    DeclaredLimit,
    DetectorRun,
    DifficultyLevel,
    EvidenceTier,
    FailedCheck,
    InvalidReason,
    Locator,
    ModelRole,
    ModelUse,
    Outcome,
    RejectionKind,
    VerifiedFinding,
    VulnerabilityClass,
)

__all__ = [
    "ClassScore",
    "Match",
    "MatchStrength",
    "ScoreReport",
    "score",
]

MINIMUM_RECORDS_PER_CLASS = 10
"""Below this, a class's figures are reported with the shortfall named.

A class carried by two records supports no claim while still appearing in every
aggregate. The number is a convention rather than a finding, and it is stated
here so that changing it is a visible decision.
"""


class MatchStrength(StrEnum):
    """How precisely a prediction located a defect (§7)."""

    EXACT = "exact"
    """Same file, same function, and the spans overlap."""

    FUNCTION = "function"
    """Same file and same declared function, spans apart."""

    CALL_ADJACENT = "call_adjacent"
    """Same file, different function, one call edge apart.

    The tier that exists because a defect can span a call edge while the corpus
    names one end and a submission names the other. Two instances arose the same
    week: a record at an entry point whose loop is in an internal callee, and a
    pair of records describing one rounding defect at a caller and its callee.

    Reported **separately and never folded into the function figure**, which is
    the whole reason it is a tier rather than a relaxation. `file` is already
    weaker than `function` and nobody reads a file match as function-granular;
    this sits between them and is read the same way. Recall at the `function`
    floor stays exactly as strict as §1.1 requires.

    Established only when each function name is declared once in the unit, so an
    overload cannot make two unrelated functions look adjacent -- the same
    refusal the declaration index applies everywhere else.
    """

    FILE = "file"
    """Same file only."""

    NONE = "none"
    """Different file, or no overlap at any strength."""

    @property
    def rank(self) -> int:
        return ("none", "file", "call_adjacent", "function", "exact").index(self.value)


@dataclass(frozen=True, slots=True)
class Match:
    """One prediction assigned to one ground-truth record.

    Carries what could *not* be established as well as what was. A match at
    `file` strength means something different when `function` was unavailable
    than when it was available and failed.
    """

    record_id: str
    strength: MatchStrength
    exact_available: bool
    function_available: bool


@dataclass(frozen=True, slots=True)
class Unjudged:
    """A prediction nothing in the corpus has judged.

    The block on precision, as data rather than as a count. A leaderboard says
    "59 of its predictions are not yet adjudicated" and that sentence is only
    actionable if the 59 can be listed: judging scales with what was claimed, so
    the work the exercise owes is exactly this list. Carried per prediction with
    the unit and the detector that claimed it, which is what an adjudicator has
    to open.
    """

    class_id: VulnerabilityClass
    source_id: str
    detector_id: str
    locator: Locator


@dataclass(frozen=True, slots=True)
class ClassScore:
    """Counts for one vulnerability class. Errors are beside the matrix, never in it."""

    cls: VulnerabilityClass
    records: int = 0
    predictions: int = 0
    """Every verified finding this class's runs produced, matched or not.

    Kept because it is the denominator of precision, and a denominator assembled
    from parts is a denominator that can lose a part. A prediction assigned at
    `file` strength is not a hit at the `function` floor *and* is not an
    unmatched false positive -- computing precision from those two counts alone
    would drop it from the total and inflate the figure.
    """

    by_strength: Mapping[MatchStrength, int] = field(default_factory=dict)
    unverifiable_claims: int = 0
    """Claims that failed their citation check. They measured nothing and still cost
    precision, so that emitting many is not free (§7.2)."""

    capped_predictions: int = 0
    """Findings this class offered that the per-unit cap did not score.

    Published rather than absorbed, for the same reason the runner publishes its
    discarded count: a cap that silently ate a submission's best finding would be
    a trap, and a participant should be able to see that the cap bit.

    **Offered, not verified.** A finding whose citation the scorer refused still
    spends a slot, because it is still a claim the submission made about a
    location -- and counting only the survivors made the citation check a free
    search oracle, which a review used to submit 668,655 quotes and keep
    whatever landed. So this counts both, and the ones it counts enter no
    confusion matrix and no adjudication queue: a finding the cap did not score
    is not a prediction, so it can be neither a hit nor a false positive.
    """

    false_negatives: int = 0
    invalid_runs: int = 0
    skipped_runs: int = 0
    measured_runs: int = 0
    adjudications: int = 0
    """Locations examined and found to hold no instance of this class.

    Counted apart from `completeness_records` because the two license different
    things: one judges a whole file, the other judges the predictions that
    overlap it. Merging them would lose whether precision rests on a file-wide
    assertion or on the predictions actually being adjudicated -- and only the
    second scales with what was claimed rather than with the corpus.
    """

    completeness_records: int = 0
    """Negative records for this class, each asserting a file holds no instance.

    The only thing in the corpus that licenses a precision figure. Counted apart
    from `judged_units` so that "no negative record exists" is distinguishable
    from "negatives exist and nothing ran against their units" -- two states
    that would otherwise share the single appearance of a `n/a`.
    """

    judged_units: int = 0
    """Units a completeness record covers and something ran against."""

    judged_predictions: int = 0
    """Predictions made in those units. The denominator of precision."""

    judged_by_strength: Mapping[MatchStrength, int] = field(default_factory=dict)
    """Matches in judged units, by strength. The numerator of precision."""

    @property
    def pool_is_fully_judged(self) -> bool:
        """Whether every prediction has been adjudicated, which precision needs.

        The condition is about the predictions, not about the corpus: judging
        scales with what was claimed rather than with the size of the source,
        and nothing has to assert what a file does not contain.
        """
        return bool(self.predictions) and self.judged_predictions == self.predictions

    @property
    def unjudged_predictions(self) -> int:
        """Predictions the corpus has no standing to call right or wrong.

        Counted and disclosed, never folded into precision. At present this is
        almost all of them, because the corpus holds no negative records -- which
        is a fact about the corpus and is stated as one.
        """
        return self.predictions - self.judged_predictions

    qualified_negatives: int = 0
    """Clean runs resting on a site the deterministic layer could not decide.

    A `clean` outcome means the detector looked and found nothing. When some
    site was indeterminate, the run still measured something -- the model
    reasoned about the code -- but "nothing is here" is not the claim it
    supports, and a matrix that could not tell the two apart would have
    `Outcome`'s founding conflation back inside the evidence feeding it
    (`models.Determination`). Counted and disclosed, entering no matrix, which is
    the treatment `invalid` and `skipped` already get.
    """

    missed_record_ids: tuple[str, ...] = ()
    """Which records nothing matched, so a miss can be told from a declared limit."""

    exact_unavailable: int = 0
    function_unavailable: int = 0

    @property
    def matched(self) -> int:
        return sum(
            count
            for strength, count in self.by_strength.items()
            if strength is not MatchStrength.NONE
        )

    @property
    def below_minimum(self) -> bool:
        return self.records < MINIMUM_RECORDS_PER_CLASS

    @property
    def false_positives(self) -> int:
        """Predictions that located nothing, plus claims nobody could check."""
        return self.predictions - self.matched + self.unverifiable_claims

    def precision(self, at_least: MatchStrength = MatchStrength.FUNCTION) -> float | None:
        """Precision at a strength floor, over the units the corpus can judge.

        **A positive record does not establish completeness.** It asserts that
        an instance of its class exists at its location, and says nothing about
        whether other instances exist elsewhere in the same file. So an
        unmatched prediction in such a unit is not a false positive -- it is a
        prediction the corpus has no standing to judge, which is the same
        standing argument that keeps the findings of an uncovered class out of
        the matrix entirely (§7.2).

        A **negative** record does establish it: `negative_for` asserts that no
        instance of that class exists anywhere in the pinned file. Precision is
        therefore defined over the (unit, class) pairs a negative covers, and
        computed over predictions in those units only -- matches included, since
        counting a match from an unjudged unit against a denominator that
        excludes its siblings would inflate the figure in the other direction.

        Returns None when no unit is judged, which is not the same as "nothing
        was claimed" and is disclosed as its own thing. Reporting a figure
        anyway would understate precision by an amount that varies with how
        thoroughly each unit happens to be annotated -- worst for the most
        productive predicates, which is the worst available direction.

        The denominator within a judged unit is every prediction plus every
        unverifiable claim, not the hits plus the unmatched: a prediction
        matched below the floor is a miss at that floor, and dropping it would
        raise the figure by discarding the evidence against it.
        """
        # Available only when the pool is *fully* judged -- every prediction
        # either matched a known positive or was adjudicated as not an instance.
        # Both partial cases are degenerate rather than merely weak: a judged
        # set made only of matches is identically 1.0, since a match is correct
        # by definition, and one made only of adjudicated non-instances is
        # identically 0. Neither says anything about the detector, and both look
        # like a figure. So the condition is completeness *with respect to what
        # was predicted*, which is what makes precision reachable without any
        # claim about what a file does not contain.
        if not self.predictions or self.judged_predictions < self.predictions:
            return None
        hits = sum(c for s, c in self.judged_by_strength.items() if s.rank >= at_least.rank)
        claimed = self.judged_predictions + self.unverifiable_claims
        return hits / claimed if claimed else None

    def recall(self, at_least: MatchStrength = MatchStrength.FUNCTION) -> float | None:
        hits = sum(c for s, c in self.by_strength.items() if s.rank >= at_least.rank)
        return hits / self.records if self.records else None

    @property
    def completion_rate(self) -> float | None:
        """Share of runs that produced a usable answer.

        Multiplies a ranking score rather than folding into the matrix (§7.1): a
        detector crashing on a third of the corpus must not rank alongside one
        that does not, and an error must not be counted as a judgement.
        """
        total = self.measured_runs + self.invalid_runs
        return self.measured_runs / total if total else None


@dataclass(frozen=True, slots=True)
class ScoreReport:
    """Per-class scores plus the axes §7 requires them stratified by."""

    by_class: Mapping[VulnerabilityClass, ClassScore] = field(default_factory=dict)
    by_level: Mapping[DifficultyLevel, int] = field(default_factory=dict)
    by_tier: Mapping[EvidenceTier, int] = field(default_factory=dict)
    by_provenance: Mapping[LocatorProvenance, int] = field(default_factory=dict)
    by_population: Mapping[Population, int] = field(default_factory=dict)
    by_platform: Mapping[str, int] = field(default_factory=dict)
    """Positive records scored, by the platform their report came from.

    Added when one harvest took the corpus from 32 records to 166 and 81% of
    them came from a single platform. Every figure computed over it was then
    mostly a statement about that platform's submission style -- a template with
    a `### Root Cause` section produces located findings at a rate a
    consolidated report does not -- and nothing in the report said so. §6.6 is
    about what the corpus is a sample of, and a sample's composition belongs in
    the same place as the numbers drawn from it.
    """

    by_repository: Mapping[str, int] = field(default_factory=dict)
    """Positive records scored, by repository. Twenty-seven of them held 166
    records, with five holding more than half, so a recall figure is also a
    statement about a handful of codebases."""

    matches: tuple[Match, ...] = ()
    models: tuple[ModelUse, ...] = ()
    """Every model the scored runs called, with calls and tokens summed.

    Collected from the runs for the same reason declared limits are: the scorer
    never sees the detectors, and a figure that cannot say what produced it
    cannot be compared against one produced by something else.
    """

    deterministic_runs: int = 0
    """Runs whose findings came from code rather than a model, as they declared."""

    refuted_citations: int = 0
    """Findings the submission marked verified whose quote is not at its locator.

    Counted, because it is the one number that separates a submission from a
    file somebody wrote. Non-zero means the scorer disagreed with the submitter
    about its own evidence, and the runs were demoted before any figure was
    computed."""

    repositioned_predictions: int = 0
    """Predictions the scorer moved to the lines their quote actually matched.

    Published because it is a disagreement, and an unreported disagreement is
    the shape of defect this file keeps finding. The citation rule accepts a
    quote that is whole lines *inside* the declared span, so a locator wider
    than its quote is fine -- and the prediction is then scored at the quote,
    not at the declaration. A submitter that thought it was reporting a function
    and is scored at two lines of it should be able to see that from the report.

    Measured on an honest submission whose locator is five lines wide on both
    sides: every prediction moves, and `repositioned_into_another_function`
    counts how many landed in a callable other than the one the declared locator
    resolves to -- 283 of 431 in that case. The figures are unchanged by it
    (0.9885 either way), which is the point: the mechanism is favourable and it
    was silent."""

    repositioned_into_another_function: int = 0
    """Of those, the ones whose declared locator named a different callable.

    A stronger statement than the count above: the scorer did not tighten the
    submission's claim, it replaced it. Zero for a submission whose locators sit
    where its quotes do."""

    unchecked_citations: int = 0
    """Verified findings whose source the scorer could not obtain.

    Demoted rather than accepted: an unchecked citation is not a passed one, and
    treating it as one would restore the hole for anybody invoking `score`
    without `--source-root`. A non-zero count here means the figures are over
    what could be checked."""

    predictions_per_unit: int | None = None
    """The per-unit-per-class cap these figures were computed under, if any.

    Carried on the report because a precision computed over three predictions
    per unit and one computed over every prediction a submission cared to make
    are not the same measurement, and nothing else in the document would say
    which happened. It is also one of the six fields `results.compare` requires
    two figures to share.

    `None` means uncapped and is **not** the default any more. It was, on the
    argument that a cap states how much adjudication an exercise is willing to
    fund and is therefore the exercise's to state -- an argument about the queue
    that missed the figure, since recall over an unbounded pool is not a
    measurement. `score`'s default is `DEFAULT_PREDICTIONS_PER_UNIT`; this field
    is `None` here only because a dataclass default has to be something and an
    uncapped report is a thing this type must be able to describe.
    """

    unjudged: tuple[Unjudged, ...] = ()
    """Predictions no negative record judges, per class. See `Unjudged`."""

    unscoreable_claims: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    """Verified findings in classes the corpus holds no record for.

    Found by running three detectors against eleven real records: 90 verified
    findings went in and 2 came out, because the class-keyed loop visited only
    the classes the *records* carried. The other 88 were emitted, verified
    against source, and then dropped -- which is §7.2's own failure mode, on
    §7.2's own metric. A detector for a class the corpus does not cover could
    emit any number of claims for nothing.

    They are counted here and enter no confusion matrix, the treatment `invalid`
    and `skipped` runs already get. Scoring them as false positives would be the
    opposite overclaim: the corpus holds no record for that class, so it has no
    standing to call them wrong. What it can say is how many there were, and
    that it could not adjudicate them.
    """

    unscoreable_runs: Mapping[VulnerabilityClass, int] = field(default_factory=dict)
    """Measured runs in classes the corpus holds no record for."""

    declared_limits: Mapping[VulnerabilityClass, tuple[DeclaredLimit, ...]] = field(
        default_factory=dict
    )
    """Declared limits of the detectors scored, by class.

    Reported on their own line rather than as a caveat beside a score, because a
    score is an estimate that moves with the sample and a demonstrated limit
    is a fact about the instrument that does not. Burying the certain claim
    inside the uncertain one loses the certain half and makes both read as
    provisional. See `models.DeclaredLimit`.
    """

    @property
    def main_models(self) -> tuple[str, ...]:
        """The main models these runs name -- one, if the exercise held.

        More than one means the submission was run against two baselines and its
        figures are a mixture; none means either nothing claimed anything or the
        findings were deterministic, which `deterministic_runs` distinguishes.
        """
        return tuple(sorted({use.model_id for use in self.models if use.role is ModelRole.MAIN}))

    @property
    def limits_by_record(self) -> Mapping[str, tuple[DeclaredLimit, ...]]:
        """Which open entries name each record, because entries do not add up.

        A record can trip several independently sufficient limits. Closing
        any one of them leaves it invisible, so a count of open entries is not a
        count of remaining work, and printing one hands a reader a number whose
        arithmetic does not hold. The relation is recorded and the consumer
        decides the policy -- the same treatment the caller/callee duplicates
        get (§6.7) and for the same reason: collapsing the entries or summing
        them would encode a policy in a number.

        A figure for work remaining, if a report ever wants one, is computed
        over **records made visible** and never over entries closed.
        """
        out: dict[str, list[DeclaredLimit]] = {}
        for entries in self.declared_limits.values():
            for entry in entries:
                if not entry.closed_by:
                    for record_id in entry.demonstrated_by:
                        out.setdefault(record_id, []).append(entry)
        return {record: tuple(v) for record, v in sorted(out.items())}

    @property
    def unexplained_misses(self) -> Mapping[VulnerabilityClass, int]:
        """Records missed with no declared limit naming them.

        The closest available answer to the one thing self-declaration cannot
        provide. A claimed limit is checkable -- it names a record the
        detector is silent on -- but nothing can force a detector to declare one
        it would rather not. So the report says how many misses are accounted
        for by a declared limit and how many are not, and an undeclared miss
        costs visibility rather than nothing (§7.2).
        """
        out: dict[VulnerabilityClass, int] = {}
        for cls, score in self.by_class.items():
            # A class nothing ran against has no detector to have declared
            # anything, so its records are unmeasured rather than missed.
            # Counting them here would merge "the detector did not see it" with
            # "there is no detector", which is the conflation this whole report
            # is built to avoid.
            if not score.false_negatives or not score.measured_runs:
                continue
            explained = {
                record_id
                for b in self.declared_limits.get(cls, ())
                if not b.closed_by
                for record_id in b.demonstrated_by
            }
            missed = {r for r in score.missed_record_ids if r not in explained}
            out[cls] = len(missed)
        return out

    @property
    def thin_classes(self) -> tuple[VulnerabilityClass, ...]:
        return tuple(cls for cls, score in sorted(self.by_class.items()) if score.below_minimum)

    def statement(self) -> str:
        """The sentence that has to accompany any figure taken from this report."""
        records = sum(s.records for s in self.by_class.values())
        if not records:
            return "No ground-truth records were scored against."

        classes = len(self.by_class)
        parts = [
            f"{_plural(records, 'record')} scored across {_plural(classes, 'class', 'classes')}."
        ]

        thin = self.thin_classes
        if thin:
            named = ", ".join(f"{cls.value} ({self.by_class[cls].records})" for cls in thin)
            parts.append(
                f"Below the stated minimum of {MINIMUM_RECORDS_PER_CLASS}: {named} — "
                "figures for these support no claim and are not averaged in."
            )

        unavailable_exact = sum(s.exact_unavailable for s in self.by_class.values())
        if unavailable_exact:
            parts.append(
                f"{_plural(unavailable_exact, 'record')} cannot support an exact-location "
                "match, because the span was inferred from a function name rather than stated."
            )
        unavailable_fn = sum(s.function_unavailable for s in self.by_class.values())
        if unavailable_fn:
            parts.append(
                f"{_plural(unavailable_fn, 'comparison')} could not resolve a signature, so "
                "function-strength matching was unavailable there."
            )

        if self.predictions_per_unit is not None:
            dropped = sum(s.capped_predictions for s in self.by_class.values())
            said = (
                f"At most {_plural(self.predictions_per_unit, 'prediction')} per source unit "
                "per class was scored"
            )
            parts.append(
                f"{said}; {_plural(dropped, 'further prediction')} went unscored."
                if dropped
                else f"{said}, and no submission reached that limit."
            )

        if self.refuted_citations:
            parts.append(
                f"{_plural(self.refuted_citations, 'finding')} the submission marked verified "
                "did not survive re-reading the source inside the cited span, and were demoted "
                "before anything was counted."
            )
        if self.repositioned_predictions:
            moved = _plural(self.repositioned_predictions, "prediction")
            elsewhere = self.repositioned_into_another_function
            parts.append(
                f"{moved} declared a locator wider than the lines quoted and were scored at "
                f"the quote"
                + (
                    f", {elsewhere} of them in a callable other than the one the declared "
                    "locator names."
                    if elsewhere
                    else "."
                )
            )
        if self.unchecked_citations:
            parts.append(
                f"{_plural(self.unchecked_citations, 'finding')} could not be re-read because "
                "no source was available for its unit, and were demoted rather than accepted -- "
                "an unchecked citation is not a passed one. Run with --source-root."
            )

        unscoreable = sum(self.unscoreable_claims.values())
        if unscoreable:
            named = ", ".join(
                f"{cls.value} ({n})" for cls, n in sorted(self.unscoreable_claims.items())
            )
            parts.append(
                f"{_plural(unscoreable, 'verified finding')} could not be adjudicated "
                f"because the corpus holds no record of their class: {named}. Counted "
                "here and in no confusion matrix -- the corpus cannot call them wrong, "
                "only unscored."
            )

        open_entries = [
            (cls, entry)
            for cls, entries in sorted(self.declared_limits.items())
            for entry in entries
            if not entry.closed_by
        ]
        if open_entries:
            named = "; ".join(
                f"{cls.value} [{entry.kind.value}]: {entry.shape} (shown by "
                f"{', '.join(entry.demonstrated_by)}"
                + ("" if entry.isolated else ", jointly with another limit")
                + f"; closed when {entry.closed_when})"
                for cls, entry in open_entries
            )
            unexplained = sum(self.unexplained_misses.values())
            shared = sum(1 for entries in self.limits_by_record.values() if len(entries) > 1)
            # Deliberately no count of open entries. A record can trip several
            # independently sufficient limits, so entries are not units of
            # work and a total would be a number whose arithmetic fails. It
            # would also invert the incentive below by giving a submission a
            # figure that grows when it declares.
            arithmetic = (
                f" Entries are not units of work: {_plural(shared, 'record')} above "
                f"{'is' if shared == 1 else 'are'} named by more than one independently "
                "sufficient entry, so closing one of those entries does not make it "
                "visible."
                if shared
                else ""
            )
            parts.append(
                f"Declared and open limits -- {named}. These are facts about the "
                "detectors rather than estimates from this sample: a score moves as "
                "records are added and a declared limit does not. A blindness is "
                "something the instrument should see and does not; an indeterminacy is "
                "the instrument correctly reporting that something is unknowable at this "
                f"scope, which is it working.{arithmetic} Among classes something ran "
                f"against, {_plural(unexplained, 'miss', 'misses')} "
                f"{'is' if unexplained == 1 else 'are'} accounted for by no declared "
                "limit -- which is the figure to read as a weakness. Declaring a limit "
                "moves a miss out of it and adds no count that grows, so a submission "
                "reports its own limits by preferring to."
            )

        unjudged = sum(s.unjudged_predictions for s in self.by_class.values())
        if unjudged:
            # A work item with a number on it, not an unadjudicable pile. The
            # earlier wording said these "fell in a unit no negative record
            # covers", which was true of file-wide negatives and wrong of
            # adjudications -- those judge a location, so a prediction can be
            # unjudged in a unit that has several.
            waiting = ", ".join(
                f"{cls.value} {score.unjudged_predictions}"
                for cls, score in sorted(self.by_class.items())
                if score.unjudged_predictions
            )
            adjudicated = sum(s.adjudications for s in self.by_class.values())
            done = (
                f" {_plural(adjudicated, 'location')} "
                f"{'has' if adjudicated == 1 else 'have'} been adjudicated so far."
                if adjudicated
                else ""
            )
            parts.append(
                f"{_plural(unjudged, 'prediction')} {'is' if unjudged == 1 else 'are'} "
                "not yet adjudicated, so the corpus has no standing to call "
                f"{'it' if unjudged == 1 else 'them'} right or wrong and precision is "
                f"unavailable where any remain -- {waiting}.{done} Judging is driven by "
                "what was predicted rather than by the size of the corpus, so this count "
                "is the work outstanding and not a property of the source."
            )

        qualified = sum(s.qualified_negatives for s in self.by_class.values())
        if qualified:
            parts.append(
                f"{_plural(qualified, 'clean run')} rested on a site the deterministic "
                f"layer could not decide, so {'its' if qualified == 1 else 'their'} "
                "negative is qualified rather than a finding of absence. Counted here "
                "and in no confusion matrix."
            )

        invalid = sum(s.invalid_runs for s in self.by_class.values())
        skipped = sum(s.skipped_runs for s in self.by_class.values())
        parts.append(
            f"{invalid} runs were invalid and {skipped} skipped; both are reported here "
            "and enter no confusion matrix."
        )
        if self.by_platform:
            total = sum(self.by_platform.values())
            platform, count = max(self.by_platform.items(), key=lambda kv: (kv[1], kv[0]))
            repo, repo_count = max(
                self.by_repository.items(), key=lambda kv: (kv[1], kv[0]), default=("none", 0)
            )
            parts.append(
                f"The {total} records scored come from {len(self.by_platform)} "
                f"{_plural(len(self.by_platform), 'platform')[2:]} and "
                f"{len(self.by_repository)} repositories; the largest share is "
                f"{platform} at {100 * count // total}% and the largest single "
                f"repository is {repo} at {100 * repo_count // total}%. A figure over a "
                "corpus is a figure about its composition, and this is that composition "
                "rather than a warning about it."
            )
        parts.append(
            "Assignment is maximum matching per strength tier, strongest first, which "
            "differs from greedy."
        )
        return " ".join(parts)


def _plural(count: int, noun: str, plural: str | None = None) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {plural or noun + 's'}"


def _signature_at(
    parsed: Syntax | None, locator: Locator
) -> tuple[str | None, str, int, int] | None:
    """Which callable contains a locator, identified so that no two collide.

    "The same function" is declaration identity, and a signature is only a
    proxy for it. The proxy leaked twice:

    - Unqualified by the enclosing type. A *file* holds several contracts and
      `Declaration.signature` is `name(paramtypes)`, so a prediction inside one
      contract's `getThePrice(address)` scored a `function` match against a
      record in another's -- 3 of 435 records have such a twin, two of them a
      one-line interface stub quotable from the published function name alone.
    - Qualified, and still colliding. `signature` names a declaration by
      `names[0]`, and the grammar gives `receive` and `fallback` one kind with
      both names, so a contract declaring both yields `receive()` twice. A
      review cited `fallback() external payable {}` against a record whose
      locator is the `receive()` line above it and scored a `function` match.
      The docstring that licensed the proxy -- "the compiler rejects a contract
      that declares the same signature twice" -- is false for exactly that
      pair.

    So the identity carries the declaration's own line span, which two distinct
    declarations cannot share. `callable_at` returns the same declaration for
    every line inside it, so this is stable across a prediction and a record
    that really are in one function, which is the only thing it has to be.
    """
    if parsed is None:
        return None
    declaration = parsed.callable_at(locator.start_line)
    if declaration is None:
        return None
    return (
        declaration.parent,
        declaration.signature,
        declaration.start_line,
        declaration.end_line,
    )


def _call_adjacent(parsed: Syntax | None, prediction: Locator, truth: Locator) -> bool:
    """Whether the two locators sit one call edge apart in the same unit.

    One question settles both of this week's locator cases, and the answer is a
    single rule: **nothing weaker than the same function counts as the same
    location, and everything weaker is reported as its own named strength.** So
    a prediction at the callee of a record's function is not a function match --
    it is this, which has its own figure.

    Resolution is name lookup within the unit, which is what resolving a call
    amounts to when nothing overloads the name (§4.2). Each name must be
    declared exactly once or this returns false: an overload would make two
    unrelated functions look adjacent, and refusing is the rule the declaration
    index applies to an overloaded name everywhere else.
    """
    if parsed is None:
        return False
    hosts = (
        parsed.callable_at(prediction.start_line),
        parsed.callable_at(truth.start_line),
    )
    if any(host is None for host in hosts):
        return False
    names = [host.names[0] for host in hosts if host is not None]
    if len(names) != 2 or names[0] == names[1]:
        return False
    if any(parsed.declarations_of(name) != 1 for name in names):
        return False
    return names[0] in parsed.callers_of(names[1]) or names[1] in parsed.callers_of(names[0])


def _strength(
    prediction: Locator,
    record: CorpusRecord,
    parsed: Syntax | None,
) -> Match:
    """How well one prediction locates one record."""
    truth = record.locator
    assert truth is not None  # only positive records are scored against
    provenance = record.locator_provenance
    exact_available = provenance is not None and provenance.supports_exact_match

    if prediction.file != truth.file:
        return Match(record.record_id, MatchStrength.NONE, exact_available, True)

    predicted_signature = _signature_at(parsed, prediction)
    truth_signature = _signature_at(parsed, truth)
    function_available = predicted_signature is not None and truth_signature is not None

    if not function_available:
        # Names are not compared as a fallback: overloads share them, and a
        # prediction naming the right name in the wrong overload would score as
        # having found the right function.
        return Match(record.record_id, MatchStrength.FILE, exact_available, False)

    if predicted_signature != truth_signature:
        if _call_adjacent(parsed, prediction, truth):
            return Match(record.record_id, MatchStrength.CALL_ADJACENT, exact_available, True)
        return Match(record.record_id, MatchStrength.FILE, exact_available, True)

    if exact_available and _overlaps(prediction, record):
        return Match(record.record_id, MatchStrength.EXACT, True, True)
    return Match(record.record_id, MatchStrength.FUNCTION, exact_available, True)


def _overlaps(prediction: Locator, record: CorpusRecord) -> bool:
    """Whether the prediction covers what the record actually asserted.

    For an anchored record that is the anchor line, not the enclosing span: the
    span was widened from the anchor, so requiring overlap with the span would
    accept a prediction anywhere in the function. The anchor is the finest thing
    the report asserted and is what the record is scored against (§7).
    """
    truth = record.locator
    assert truth is not None
    if record.anchor_line is not None:
        return prediction.start_line <= record.anchor_line <= prediction.end_line
    return prediction.start_line <= truth.end_line and truth.start_line <= prediction.end_line


def _maximum_matching(edges: Sequence[tuple[int, int]], left: int) -> dict[int, int]:
    """Maximum bipartite matching by augmenting paths, left index -> right index.

    Small inputs, so the simple algorithm is the right one. Used instead of
    greedy because greedy is not an approximation of it: with two predictions
    able to match one record and a second record reachable by only one of them,
    greedy can leave that record unmatched.
    """
    adjacency: dict[int, list[int]] = {i: [] for i in range(left)}
    for a, b in edges:
        adjacency[a].append(b)

    pair_right: dict[int, int] = {}

    def augment(a: int, seen: set[int]) -> bool:
        for b in adjacency[a]:
            if b in seen:
                continue
            seen.add(b)
            if b not in pair_right or augment(pair_right[b], seen):
                pair_right[b] = a
                return True
        return False

    for a in range(left):
        augment(a, set())
    return {a: b for b, a in pair_right.items()}


def _repository_of(record: CorpusRecord) -> str:
    """The unit a record's pin names, as a short label for stratification."""
    pin = record.pin
    if pin.kind == "commit":
        return pin.repo_url.rstrip("/").rsplit("/", 1)[-1]
    return f"chain {pin.chain_id}:{pin.address[:10]}"


def recheck_citations(
    runs: Sequence[DetectorRun], records: Sequence[CorpusRecord], resolve: SourceResolver | None
) -> tuple[list[DetectorRun], int, int, int, int]:
    """Re-read every verified quote against the scorer's own copy of the source.

    **What this establishes, and what it cannot.** It rules out an *incoherent*
    submission: a quote absent from the file, a quote that is punctuation, a
    locator naming a file other than the unit's, and source that does not match
    the record's digest. Each of those was a way to score without reading
    anything, and each is measured below.

    It does **not** establish that a submitter found a defect, and the first
    version of this docstring said it did. The corpus publishes the full
    locator -- file, contract, function, start and end line -- and `fetch`
    builds the scorer's checkout from public coordinates, so the submitter's
    bytes and the scorer's bytes are the same bytes and the answer is a
    published field. A review demonstrated the consequence: quoting the *real*
    span at each published locator scores **micro recall 0.9931**, with
    precision 0.9815 in access control, 0.9947 in denial of service and 1.0 in
    the rest. Two earlier versions of this sentence were wrong in two different
    ways: "0.9977 with every counter at zero" cannot hold, because one positive
    record's source resolves from no public coordinates and another resolves to
    bytes whose digest disagrees with its pin, so the cleanest submission
    possible still reports an unchecked citation; and the correction of it,
    "434 of 435 is the ceiling ... = 0.9908", is two errors in one clause, since
    434/435 is 0.9977 and 0.9908 is 431/435. Re-reading public source at a
    published locator cannot
    distinguish a finding from a copy, and no amount of strictness in this
    function changes that.

    So: a figure this package computes over the published corpus is
    **self-reported**. It is a real measurement of an honest submission and it
    is not evidence against a motivated one. A competitive ranking needs records
    whose locators are not published -- `CorpusSplit.PRIVATE_HOLDOUT` and
    `assay-arena`'s `docs/operations.md` step 3 -- and that is where the
    guarantee has to live. `docs/api.md` §1 says the same thing where a
    submitter reads it.

    What the checks close, every figure measured over the whole corpus through
    `contract-assay score`:

    | forgery, reading no source | before | now |
    | --- | --- | --- |
    | a constant absent from the source | 12/12 matched | 0 |
    | `";"` at every published locator | 0.972 | 0 |
    | `"er"`, inside `require`/`transfer`/`reserve` | 0.938 | 0 |
    | `"function"` at every published locator | 0.754 | 0 |
    | a 181-entry generated dictionary of idioms | **0.913** | **0** |
    | generic mid-line runs of six or more tokens | 0.126 | 0 |
    | generic whole-line statements, at a 1- or 2-line locator | 0.249 | 0 |
    | the same, at the whole published span | -- | 0.0046 |
    | brace-and-keyword lines, over widened spans | 0.0138 | **0** |
    | one donor unit, every locator elsewhere | 1.000 | 0.0069 |
    | a submitter's own `--source-root` | 0.922 | 0 |
    | **a generic vocabulary over widened windows, in-sample** | -- | **0.2161** |
    | **the same, cross-fitted** | -- | **0.0414** |

    **The last two rows are the same attack, and the difference between them is
    the most important number here.** A blind attack is a list of guesses, and
    every list in this table was chosen by its yield over the same 435 published
    records it was then scored on. Cross-fitted -- rank the guesses on half the
    corpus, score the other half, so every record is measured under an order
    that never saw it -- the strongest family falls from **0.2161 to 0.0414**.
    In-sample says how much a published corpus leaks to somebody willing to fit
    it; cross-fitted says what the same method gets on records it has not seen,
    and that is the figure a competitive ranking has to be designed against.
    Every earlier version of this table published an in-sample number without
    saying so.

    What the rule itself closes is every dictionary family above: a citation
    must be whole lines of the span its locator declares, six tokens or more,
    one of them naming something the language does not supply. What it cannot
    close is an attack built on what the corpus publishes -- the function's
    *name* makes its declaration line partly derivable -- and `quote_is_at`
    carries that argument with the rest of the numbers.

    Positioning each prediction at the lines its quote matched is why the
    in-sample figure is 0.2161 rather than higher again: the declared span is
    the submitter's own field, `_strength` takes the containing function from
    `start_line` alone, and a window hundreds of lines long used to keep `exact`
    strength while the attack reduced to "name one line of this function". That
    was worth 0.1448 on its own, and the donor forgery 0.0782.

    **The donor row's zero was an artefact.** The "0.0782 -> 0" published here
    took its before and its after from two *different* submission files, one of
    which scores 0 with the fix reverted. A before/after pair drawn from two
    artefacts is not a measurement. The family is 0.0069 -- three records, on
    `unchecked {` / `++i;` boilerplate the donor also contains.

    The last row is zero because a pin carrying a digest now wins its
    `source_id`. Measured: with every digest stripped the forgery scores 0.922,
    under the previous last-write-wins rule it kept 3 of 435 at the four units
    that pair a digest-bearing record with a later digest-less one, and at HEAD
    it keeps none. The earlier docstring printed that 3 as a *remaining*
    residue; it was the amount the rule removed.

    Returns the runs with failed citations demoted, how many were demoted, and
    how many could not be checked at all.

    **Unchecked is not passed.** Without source, or for a unit whose source does
    not match its pin, nothing here can establish the quote -- so the finding is
    demoted with `citation_unchecked`. Treating it as good would restore the
    hole for anybody invoking `score` without `--source-root`, which is the
    easier way to invoke it.
    """
    # A pin carrying a digest wins. `source_id` is
    # `commit:<repo>@<commit>:<path>` and excludes `sha256`, so several records
    # collapse to one key -- and a last-write-wins dict let one digest-less
    # record disable the digest gate for every other record pinning the same
    # unit. Measured: four units in the shipped corpus pair a digest-bearing
    # record with a later `*-adjudicated-*` record that has none, and the forged
    # `--source-root` forgery leaked exactly those four.
    by_source: dict[str, SourcePin] = {}
    for record in records:
        held = by_source.get(record.pin.source_id)
        if held is None or (held.sha256 is None and record.pin.sha256 is not None):
            by_source[record.pin.source_id] = record.pin
    cache: dict[str, str | None] = {}

    def source_of(source_id: str) -> str | None:
        if source_id not in cache:
            found = by_source.get(source_id)
            cache[source_id] = None if (found is None or resolve is None) else resolve(found)
        return cache[source_id]

    def _demoted(finding: VerifiedFinding, why: FailedCheck) -> VerifiedFinding:
        """One shape for both demotions, so the two cannot drift apart."""
        return finding.model_copy(
            update={
                "status": CitationStatus.UNVERIFIED,
                "failed_checks": [*finding.failed_checks, why],
            }
        )

    parsed_cache: dict[str, Syntax | None] = {}

    def parsed_for(source_id: str, source: str) -> Syntax | None:
        """Parsed once per unit. Only reached when a prediction actually moved."""
        if source_id not in parsed_cache:
            parsed_cache[source_id] = Syntax.of(source)
        return parsed_cache[source_id]

    out: list[DetectorRun] = []
    refuted = unchecked = moved = moved_elsewhere = 0
    for run in runs:
        pin = by_source.get(run.source_id)
        source = source_of(run.source_id)
        # The bytes must be the bytes the record was authored against, or the
        # locators index lines that have moved. `--source-root` is the
        # submitter's in the documented publishing workflow, so without this the
        # scorer verified a submission against the submission: a review built
        # synthetic `.sol` files whose declarations sit at the records' locator
        # lines and scored access control at recall 0.982 with precision 1.0,
        # quoting text that exists nowhere in the real source.
        if (
            source is not None
            and pin is not None
            and pin.sha256 is not None
            and hashlib.sha256(source.encode("utf-8")).hexdigest() != pin.sha256
        ):
            source = None
        rechecked: list[VerifiedFinding] = []
        changed = False
        for finding in run.findings:
            if finding.status is not CitationStatus.VERIFIED:
                # Already carrying its reason. A second opinion on a rejection
                # changes nothing the figures read.
                rechecked.append(finding)
                continue
            if source is None:
                unchecked += 1
                changed = True
                rechecked.append(
                    finding.model_copy(
                        update={
                            "status": CitationStatus.UNVERIFIED,
                            "failed_checks": [
                                *finding.failed_checks,
                                FailedCheck(
                                    check="citation_unchecked",
                                    kind=RejectionKind.CITATION,
                                    detail="no source was available for this unit, so the "
                                    "quote could not be re-read; run with --source-root",
                                ),
                            ],
                        }
                    )
                )
                continue
            cited_file = finding.finding.locator.file
            if pin is not None and cited_file != pin.path:
                # The invariant this file was missing while two others enforce
                # it: `corpus/records.py` requires a record's `locator.file` to
                # equal its `pin.path`, and `detectors/reference.py` rejects a
                # finding whose locator names another file. Here it was absent,
                # so a submission could declare one unit, quote real text out of
                # it, and point every locator at a different repository --
                # measured at recall 1.0 over the whole corpus with every new
                # counter at zero and a clean statement.
                refuted += 1
                changed = True
                rechecked.append(
                    _demoted(
                        finding,
                        FailedCheck(
                            check="citation_file_is_not_the_units_file",
                            kind=RejectionKind.CITATION,
                            detail=f"the locator names {cited_file!r} and this run's unit is "
                            f"{pin.path!r}; the quote was checked against neither",
                        ),
                    )
                )
                continue
            at, failure = cited_lines(source, finding.finding.locator, finding.finding.quote)
            if at is not None:
                # **Positioned where the quote is, not where the locator said.**
                # The citation rule binds the quote to the span a *submitter*
                # declared, and nothing downstream read that span: `_strength`
                # takes the containing function from `start_line` alone and
                # `_overlaps` needs only to cover the record's anchor. So a
                # submission could declare the published start line and an end
                # line hundreds of lines later, keep `exact` strength, and turn
                # "name one line of this function" into its whole problem --
                # measured, that took a blind submission from 0.041 to 0.145,
                # and 0.092 of it needed nothing but braces and keywords.
                #
                # Narrowing to the matched lines costs an honest submission
                # nothing, measured at locators one and five lines wider than
                # the quote, because an honest quote is where its locator says
                # it is. It is also the invariant the rule claims: the citation
                # and the locator now agree on which lines are being cited.
                if at != finding.finding.locator:
                    changed = True
                    moved += 1
                    parsed = parsed_for(run.source_id, source)
                    if _signature_at(parsed, at) != _signature_at(parsed, finding.finding.locator):
                        moved_elsewhere += 1
                    finding = finding.model_copy(
                        update={"finding": finding.finding.model_copy(update={"locator": at})}
                    )
                rechecked.append(finding)
                continue
            assert failure is not None
            refuted += 1
            changed = True
            rechecked.append(
                finding.model_copy(
                    update={
                        "status": CitationStatus.UNVERIFIED,
                        "failed_checks": [
                            *finding.failed_checks,
                            failure.model_copy(
                                update={
                                    "detail": failure.detail
                                    + " (re-read by the scorer against its own copy of the "
                                    "source; the submission had marked this verified)"
                                }
                            ),
                        ],
                    }
                )
            )
        if not changed:
            out.append(run)
            continue
        # A run whose every verified finding was refuted measured nothing rather
        # than finding nothing -- the same rule `run_detector` applies, applied
        # to a run this package did not produce.
        survives = any(f.status is CitationStatus.VERIFIED for f in rechecked)
        update: dict[str, Any] = {"findings": rechecked}
        if run.outcome is Outcome.VULNERABLE and not survives:
            update["outcome"] = Outcome.INVALID
            update["invalid_reason"] = InvalidReason.CITATION_UNVERIFIED
        out.append(run.model_copy(update=update))
    return out, refuted, unchecked, moved, moved_elsewhere


def score(
    runs: Iterable[DetectorRun],
    records: Iterable[CorpusRecord],
    resolve: SourceResolver | None = None,
    *,
    predictions_per_unit: int | None = DEFAULT_PREDICTIONS_PER_UNIT,
) -> ScoreReport:
    """Score runs against ground truth, per class and stratified.

    `resolve` supplies source so that function signatures can be compared. Left
    out, function-strength matching is reported as unavailable rather than
    approximated from names -- which is a weaker report, and an honest one.

    `predictions_per_unit` scores at most that many findings per source unit per
    class, in the order the runs and their findings arrived. Two reasons, and
    the second is the load-bearing one:

    **Every prediction has to be adjudicated before precision exists for its
    class**, so an uncapped pool is a queue nobody can work through -- and a
    submission that proposed every declaration in every file would buy itself an
    unbounded amount of somebody else's labour.

    And **recall over an unbounded pool is not a measurement.** Precision waits
    on adjudication; recall does not. A review used that asymmetry: 668,655
    quotes over 435 records, recall published per class, precision unlicensed in
    all nine. The default is `DEFAULT_PREDICTIONS_PER_UNIT` -- nine, the most
    records any one unit-class pair holds, so a perfect submission is never
    capped -- and it used to be `None`, on the argument that "a cap states how
    much adjudication an exercise will fund and the benchmark is not the
    exercise". That argument was about the queue and it missed the figure.
    `None` is still accepted by this function and still caps nothing, for
    tooling that wants the whole pool. It is not reachable from the CLI, which
    types the option as `int`: the published submission surface is capped.

    Enforced here rather than by whatever ran the submission, because this is the
    only layer that sees a whole submission's runs at once. A cap applied by the
    runner is a cap applied inside the process running the code it limits, which
    is a convention; a cap applied per run cannot see that two detectors for one
    class already used the quota between them.

    The order is the submission's own and is not reordered: a harness that puts
    its best finding first is making exactly the choice the cap asks it to make,
    and re-ranking for it would take the choice away and then charge it for the
    result.
    """
    if predictions_per_unit is not None and predictions_per_unit < 1:
        raise ValueError(
            "predictions_per_unit must be at least 1: a cap of zero scores nothing "
            "and would report every submission as having found nothing"
        )
    runs = list(runs)
    records = list(records)
    # `unit_id` is the pinned file across revisions; `source_id` includes the
    # revision. An unknown `source_id` falls back to the cited file: it has no
    # source to re-read a quote against, so its findings are refused either way,
    # and keying by file stops a submission inventing quota by inventing pins.
    units = {record.pin.source_id: record.pin.unit_id for record in records}
    # Before anything is counted. See `recheck_citations`: a submitted run
    # arrives with its own `status: verified`, and until this ran a hand-written
    # file could top the board with fabricated quotes at published locators.
    (
        runs,
        refuted_citations,
        unchecked_citations,
        repositioned,
        repositioned_elsewhere,
    ) = recheck_citations(runs, records, resolve)
    truths = [r for r in records if r.is_positive and r.locator is not None]

    # Which files a negative record says hold no instance of a class. The only
    # thing that licenses a precision figure: a positive record asserts an
    # instance exists at one location and nothing about the rest of its file.
    # Two ways a prediction can be judged, and they are different claims.
    # `complete_for` is file-wide: no instance of the class anywhere in that
    # file. `adjudicated_for` is one examined location, judging exactly the
    # predictions that overlap it -- so if what gets judged is the set of
    # locations something predicted, every prediction is judged and precision is
    # defined over them, while nothing asserts what a file does not contain.
    complete_for: dict[VulnerabilityClass, set[str]] = {}
    adjudicated_for: dict[VulnerabilityClass, list[Locator]] = {}
    for record in records:
        if record.negative_kind is NegativeKind.ADJUDICATED and record.locator is not None:
            for cls in record.negative_for:
                adjudicated_for.setdefault(cls, []).append(record.locator)
    for record in records:
        # Gated on the *kind*, because only some negatives assert completeness.
        # A post-fix negative says the reported instance is gone, which is not
        # the same claim and does not license a precision figure -- treating
        # every negative alike was the error one level up from the one §7.3
        # corrects, and it is the cheaper of the two to make.
        if record.negative_kind is None or not record.negative_kind.licenses_completeness:
            continue
        for cls in record.negative_for:
            complete_for.setdefault(cls, set()).add(record.pin.path)

    by_class: dict[VulnerabilityClass, ClassScore] = {}
    all_matches: list[Match] = []
    all_unjudged: list[Unjudged] = []
    by_level: Counter[DifficultyLevel] = Counter()
    by_tier: Counter[EvidenceTier] = Counter()
    by_provenance: Counter[LocatorProvenance] = Counter()
    by_population: Counter[Population] = Counter()
    by_platform: Counter[str] = Counter()
    by_repository: Counter[str] = Counter()

    for record in truths:
        by_population[record.population] += 1
        by_platform[record.provenance.platform] += 1
        by_repository[_repository_of(record)] += 1
        if record.locator_provenance is not None:
            by_provenance[record.locator_provenance] += 1

    parsed_cache: dict[str, Syntax | None] = {}

    def parsed_for(record: CorpusRecord) -> Syntax | None:
        if resolve is None:
            return None
        key = record.pin.source_id
        if key not in parsed_cache:
            source = resolve(record.pin)
            parsed_cache[key] = Syntax.of(source) if source else None
        return parsed_cache[key]

    # Every measured run is stratified, including runs in classes no record
    # covers. Restricting these tables to scoreable classes made them describe
    # the corpus's coverage while appearing to describe the submission.
    for run in runs:
        if not run.outcome.is_measurement:
            continue
        by_level[run.level] += 1
        if run.evidence_tier is not None:
            by_tier[run.evidence_tier] += 1

    # Declared limits travel with the runs, so they are collected from the
    # runs rather than asked of the detectors -- which the scorer never sees.
    limits: dict[VulnerabilityClass, list[DeclaredLimit]] = {}
    for run in runs:
        for entry in run.declared_limits:
            bucket = limits.setdefault(run.class_id, [])
            if entry not in bucket:
                bucket.append(entry)

    # The same argument, for the same reason: what produced a figure is a
    # property of the run, and a leaderboard cannot ask the harness afterwards.
    usage: dict[tuple[str, ModelRole], list[int]] = {}
    deterministic_runs = 0
    for run in runs:
        if run.produced_without_a_model:
            deterministic_runs += 1
        for use in run.models:
            totals = usage.setdefault((use.model_id, use.role), [0, 0])
            totals[0] += use.calls
            totals[1] += use.tokens

    # Any record speaking to a class puts it in the matrix, positive or negative.
    # Taking only positives meant a class whose predictions had all been
    # adjudicated still reported nothing -- its findings stayed "unscoreable"
    # while the corpus was in fact able to judge every one of them. Recall is
    # still unavailable without positives, which `recall()` already says by
    # returning nothing; precision is not, and that asymmetry is the point of
    # judging the pool at all.
    scoreable = {c for record in truths for c in record.classes} | {
        c for record in records for c in record.negative_for
    }
    unscoreable_claims: Counter[VulnerabilityClass] = Counter()
    unscoreable_runs: Counter[VulnerabilityClass] = Counter()
    for run in runs:
        if run.class_id in scoreable:
            continue
        if run.outcome.is_measurement:
            unscoreable_runs[run.class_id] += 1
        unscoreable_claims[run.class_id] += sum(
            1 for f in run.findings if f.status is CitationStatus.VERIFIED
        )

    for cls in scoreable:
        class_records = [r for r in truths if cls in r.classes]
        class_runs = [run for run in runs if run.class_id is cls]

        # Capped per unit, in the order the runs and their findings arrived. The
        # count is per `source_id` and spans every run in the class, because two
        # detectors for one class can use the quota between them -- a cap applied
        # per run could not see that, and a class quantified over a set gets
        # satisfied by different members.
        #
        # **The quota counts what was offered, not what survived.** It used to
        # skip a refused citation before charging for it, which made the
        # citation check a free search oracle: a review submitted 668,655
        # generated quotes, 666,233 of them refused at no cost, and kept
        # whatever landed. A finding whose citation failed is still a claim the
        # submission made about a location, so it spends a slot -- and the order
        # is the submission's own, so spending slots on guesses is its choice.
        claimed: list[tuple[str, str, Locator]] = []
        capped = 0
        uncheckable = 0
        per_unit: Counter[str] = Counter()
        for run in class_runs:
            for finding in run.findings:
                # Keyed by the *unit*, not by the run's declared `source_id`.
                # `source_id` includes the revision, so the corpus's eight paths
                # pinned at two commits each are sixteen keys -- and a
                # submission is free to declare either, which handed the 35
                # records on those paths eighteen guesses instead of nine.
                # `SourcePin.unit_id` is the file across revisions.
                unit = units.get(run.source_id) or f"file:{finding.finding.locator.file}"
                if predictions_per_unit is not None and per_unit[unit] >= predictions_per_unit:
                    capped += 1
                    continue
                per_unit[unit] += 1
                # A claim that failed its citation measured nothing about the
                # source, and costs precision so that emitting many is not free
                # (§7.2). Counted inside the quota for the same reason `claimed`
                # is: a finding the cap did not score is not a prediction, so it
                # can be neither a hit nor a false positive.
                if finding.has_citation_failure:
                    uncheckable += 1
                if finding.status is not CitationStatus.VERIFIED:
                    continue
                claimed.append((run.source_id, run.detector_id, finding.finding.locator))
        predictions = [locator for _, _, locator in claimed]
        judged_files = complete_for.get(cls, set())
        adjudications = adjudicated_for.get(cls, [])
        covered = [
            index
            for index, prediction in enumerate(predictions)
            if prediction.file in judged_files
            or any(
                adjudication.file == prediction.file
                and prediction.start_line <= adjudication.end_line
                and adjudication.start_line <= prediction.end_line
                for adjudication in adjudications
            )
        ]
        candidates: list[tuple[int, int, Match]] = []
        for pi, prediction in enumerate(predictions):
            for ri, record in enumerate(class_records):
                match = _strength(prediction, record, parsed_for(record))
                if match.strength is not MatchStrength.NONE:
                    candidates.append((pi, ri, match))

        assigned: dict[int, Match] = {}
        used_records: set[int] = set()
        used_predictions: set[int] = set()
        for tier in (
            MatchStrength.EXACT,
            MatchStrength.FUNCTION,
            MatchStrength.CALL_ADJACENT,
            MatchStrength.FILE,
        ):
            edges = [
                (pi, ri)
                for pi, ri, m in candidates
                if m.strength is tier and pi not in used_predictions and ri not in used_records
            ]
            if not edges:
                continue
            for pi, ri in _maximum_matching(edges, len(predictions)).items():
                match = next(m for p, r, m in candidates if p == pi and r == ri)
                assigned[pi] = match
                used_predictions.add(pi)
                used_records.add(ri)

        # A prediction that matched a positive record is already judged: the
        # record asserts an instance is there. So the judged set is everything
        # the corpus speaks to at that location -- a positive it matched, a
        # file-wide negative covering it, or an adjudication overlapping it.
        # Leaving matches out made precision count only the predictions somebody
        # had bothered to adjudicate, which is every hit discarded and every
        # miss kept.
        judged = sorted(set(covered) | set(assigned))
        # Built from `judged`, not from `covered`: a prediction that matched a
        # positive record needs no adjudication, and queueing it would ask for
        # work the corpus has already done -- while making this list disagree
        # with the sentence the leaderboard prints from the same counts.
        all_unjudged.extend(
            Unjudged(class_id=cls, source_id=source_id, detector_id=detector_id, locator=locator)
            for index, (source_id, detector_id, locator) in enumerate(claimed)
            if index not in set(judged)
        )
        strengths: Counter[MatchStrength] = Counter(m.strength for m in assigned.values())
        judged_strengths: Counter[MatchStrength] = Counter(
            match.strength for index, match in assigned.items() if index in set(judged)
        )
        all_matches.extend(assigned.values())

        by_class[cls] = ClassScore(
            cls=cls,
            records=len(class_records),
            predictions=len(predictions),
            by_strength=dict(strengths),
            unverifiable_claims=uncheckable,
            capped_predictions=capped,
            false_negatives=len(class_records) - len(used_records),
            missed_record_ids=tuple(
                record.record_id
                for index, record in enumerate(class_records)
                if index not in used_records
            ),
            invalid_runs=sum(1 for r in class_runs if r.outcome is Outcome.INVALID),
            skipped_runs=sum(1 for r in class_runs if r.outcome is Outcome.SKIPPED),
            measured_runs=sum(1 for r in class_runs if r.outcome.is_measurement),
            qualified_negatives=sum(1 for r in class_runs if not r.negative_is_established),
            # Gated on kind for the same reason `complete_for` is: this count
            # exists to tell "nothing licenses completeness here" from
            # "something does and nothing ran against it", and a post-fix
            # negative belongs in neither.
            completeness_records=sum(
                1
                for r in records
                if cls in r.negative_for
                and r.negative_kind is not None
                and r.negative_kind.licenses_completeness
            ),
            adjudications=len(adjudications),
            judged_units=len({predictions[index].file for index in judged}),
            judged_predictions=len(judged),
            judged_by_strength=dict(judged_strengths),
            exact_unavailable=sum(
                1
                for r in class_records
                if r.locator_provenance is not None
                and not r.locator_provenance.supports_exact_match
            ),
            function_unavailable=sum(1 for m in assigned.values() if not m.function_available),
        )

    return ScoreReport(
        by_class=by_class,
        by_level=dict(by_level),
        by_tier=dict(by_tier),
        by_provenance=dict(by_provenance),
        by_population=dict(by_population),
        by_platform=dict(sorted(by_platform.items())),
        by_repository=dict(sorted(by_repository.items())),
        matches=tuple(all_matches),
        models=tuple(
            ModelUse(model_id=model_id, role=role, calls=calls, tokens=tokens)
            for (model_id, role), (calls, tokens) in sorted(
                usage.items(), key=lambda item: (item[0][1].value, item[0][0])
            )
        ),
        deterministic_runs=deterministic_runs,
        refuted_citations=refuted_citations,
        repositioned_predictions=repositioned,
        repositioned_into_another_function=repositioned_elsewhere,
        unchecked_citations=unchecked_citations,
        predictions_per_unit=predictions_per_unit,
        unjudged=tuple(all_unjudged),
        unscoreable_claims={c: n for c, n in sorted(unscoreable_claims.items()) if n},
        unscoreable_runs=dict(sorted(unscoreable_runs.items())),
        declared_limits={c: tuple(v) for c, v in sorted(limits.items())},
    )
