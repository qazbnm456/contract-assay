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

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from contract_assay.corpus.records import CorpusRecord, LocatorProvenance, Population
from contract_assay.corpus.verify import SourceResolver
from contract_assay.evidence.syntax import Syntax
from contract_assay.models import (
    CitationStatus,
    DetectorRun,
    DifficultyLevel,
    EvidenceTier,
    KnownBlindness,
    Locator,
    Outcome,
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

    FILE = "file"
    """Same file only."""

    NONE = "none"
    """Different file, or no overlap at any strength."""

    @property
    def rank(self) -> int:
        return ("none", "file", "function", "exact").index(self.value)


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

    false_negatives: int = 0
    invalid_runs: int = 0
    skipped_runs: int = 0
    measured_runs: int = 0
    missed_record_ids: tuple[str, ...] = ()
    """Which records nothing matched, so a miss can be told from a blindness."""

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
        """Precision at a strength floor, or None when nothing was claimed.

        The denominator is every prediction plus every unverifiable claim, not
        the hits plus the unmatched. A prediction matched at a weaker strength
        than the floor is a miss at that floor, and leaving it out of the total
        would raise the figure by discarding the evidence against it.
        """
        hits = sum(c for s, c in self.by_strength.items() if s.rank >= at_least.rank)
        claimed = self.predictions + self.unverifiable_claims
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
    matches: tuple[Match, ...] = ()
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

    blindness: Mapping[VulnerabilityClass, tuple[KnownBlindness, ...]] = field(default_factory=dict)
    """Declared blindnesses of the detectors scored, by class.

    Reported on their own line rather than as a caveat beside a score, because a
    score is an estimate that moves with the sample and a demonstrated blindness
    is a fact about the instrument that does not. Burying the certain claim
    inside the uncertain one loses the certain half and makes both read as
    provisional. See `models.KnownBlindness`.
    """

    @property
    def blindness_by_record(self) -> Mapping[str, tuple[KnownBlindness, ...]]:
        """Which open entries name each record, because entries do not add up.

        A record can trip several independently sufficient blindnesses. Closing
        any one of them leaves it invisible, so a count of open entries is not a
        count of remaining work, and printing one hands a reader a number whose
        arithmetic does not hold. The relation is recorded and the consumer
        decides the policy -- the same treatment the caller/callee duplicates
        get (§6.7) and for the same reason: collapsing the entries or summing
        them would encode a policy in a number.

        A figure for work remaining, if a report ever wants one, is computed
        over **records made visible** and never over entries closed.
        """
        out: dict[str, list[KnownBlindness]] = {}
        for entries in self.blindness.values():
            for entry in entries:
                if not entry.closed_by:
                    out.setdefault(entry.demonstrated_by, []).append(entry)
        return {record: tuple(v) for record, v in sorted(out.items())}

    @property
    def unexplained_misses(self) -> Mapping[VulnerabilityClass, int]:
        """Records missed with no declared blindness naming them.

        The closest available answer to the one thing self-declaration cannot
        provide. A claimed blindness is checkable -- it names a record the
        detector is silent on -- but nothing can force a detector to declare one
        it would rather not. So the report says how many misses are accounted
        for by a declared blindness and how many are not, and an undeclared miss
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
            explained = {b.demonstrated_by for b in self.blindness.get(cls, ()) if not b.closed_by}
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
            for cls, entries in sorted(self.blindness.items())
            for entry in entries
            if not entry.closed_by
        ]
        if open_entries:
            named = "; ".join(
                f"{cls.value}: {entry.shape} (shown by {entry.demonstrated_by}"
                + ("" if entry.isolated else ", jointly with another blindness")
                + ")"
                for cls, entry in open_entries
            )
            unexplained = sum(self.unexplained_misses.values())
            shared = sum(1 for entries in self.blindness_by_record.values() if len(entries) > 1)
            # Deliberately no count of open entries. A record can trip several
            # independently sufficient blindnesses, so entries are not units of
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
                f"Declared and unpatched blindnesses -- {named}. These are facts about "
                "the detectors rather than estimates from this sample: a score moves as "
                f"records are added and a blindness does not.{arithmetic} Among classes "
                f"something ran against, {_plural(unexplained, 'miss', 'misses')} "
                f"{'is' if unexplained == 1 else 'are'} accounted for by no declared "
                "blindness -- which is the figure to read as a weakness. Declaring a "
                "blindness moves a miss out of it and adds no count that grows, so a "
                "submission reports its own limits by preferring to."
            )

        invalid = sum(s.invalid_runs for s in self.by_class.values())
        skipped = sum(s.skipped_runs for s in self.by_class.values())
        parts.append(
            f"{invalid} runs were invalid and {skipped} skipped; both are reported here "
            "and enter no confusion matrix."
        )
        parts.append(
            "Assignment is maximum matching per strength tier, strongest first, which "
            "differs from greedy."
        )
        return " ".join(parts)


def _plural(count: int, noun: str, plural: str | None = None) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {plural or noun + 's'}"


def _signature_at(parsed: Syntax | None, locator: Locator) -> str | None:
    """The declared signature of the function containing a locator, if resolvable."""
    if parsed is None:
        return None
    declaration = parsed.callable_at(locator.start_line)
    return declaration.signature if declaration is not None else None


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


def score(
    runs: Iterable[DetectorRun],
    records: Iterable[CorpusRecord],
    resolve: SourceResolver | None = None,
) -> ScoreReport:
    """Score runs against ground truth, per class and stratified.

    `resolve` supplies source so that function signatures can be compared. Left
    out, function-strength matching is reported as unavailable rather than
    approximated from names -- which is a weaker report, and an honest one.
    """
    runs = list(runs)
    truths = [r for r in records if r.is_positive and r.locator is not None]

    by_class: dict[VulnerabilityClass, ClassScore] = {}
    all_matches: list[Match] = []
    by_level: Counter[DifficultyLevel] = Counter()
    by_tier: Counter[EvidenceTier] = Counter()
    by_provenance: Counter[LocatorProvenance] = Counter()
    by_population: Counter[Population] = Counter()

    for record in truths:
        by_population[record.population] += 1
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

    # Declared blindnesses travel with the runs, so they are collected from the
    # runs rather than asked of the detectors -- which the scorer never sees.
    blindness: dict[VulnerabilityClass, list[KnownBlindness]] = {}
    for run in runs:
        for entry in run.known_blindness:
            bucket = blindness.setdefault(run.class_id, [])
            if entry not in bucket:
                bucket.append(entry)

    scoreable = {c for record in truths for c in record.classes}
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

        predictions = [
            finding.finding.locator
            for run in class_runs
            for finding in run.findings
            if finding.status is CitationStatus.VERIFIED
        ]
        # A claim that failed its citation measured nothing about the source, and
        # costs precision so that emitting many is not free (§7.2).
        uncheckable = sum(
            1 for run in class_runs for finding in run.findings if finding.has_citation_failure
        )

        candidates: list[tuple[int, int, Match]] = []
        for pi, prediction in enumerate(predictions):
            for ri, record in enumerate(class_records):
                match = _strength(prediction, record, parsed_for(record))
                if match.strength is not MatchStrength.NONE:
                    candidates.append((pi, ri, match))

        assigned: dict[int, Match] = {}
        used_records: set[int] = set()
        used_predictions: set[int] = set()
        for tier in (MatchStrength.EXACT, MatchStrength.FUNCTION, MatchStrength.FILE):
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

        strengths: Counter[MatchStrength] = Counter(m.strength for m in assigned.values())
        all_matches.extend(assigned.values())

        by_class[cls] = ClassScore(
            cls=cls,
            records=len(class_records),
            predictions=len(predictions),
            by_strength=dict(strengths),
            unverifiable_claims=uncheckable,
            false_negatives=len(class_records) - len(used_records),
            missed_record_ids=tuple(
                record.record_id
                for index, record in enumerate(class_records)
                if index not in used_records
            ),
            invalid_runs=sum(1 for r in class_runs if r.outcome is Outcome.INVALID),
            skipped_runs=sum(1 for r in class_runs if r.outcome is Outcome.SKIPPED),
            measured_runs=sum(1 for r in class_runs if r.outcome.is_measurement),
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
        matches=tuple(all_matches),
        unscoreable_claims={c: n for c, n in sorted(unscoreable_claims.items()) if n},
        unscoreable_runs=dict(sorted(unscoreable_runs.items())),
        blindness={c: tuple(v) for c, v in sorted(blindness.items())},
    )
