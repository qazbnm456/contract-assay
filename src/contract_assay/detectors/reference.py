"""This project's own detectors, which double as the worked examples.

Three classes, all reachable at the syntactic tier (§4.2). They exist for two
reasons: to measure something, and to be the thing a submission author reads
before writing their own. The second is why they are commented at the level they
are.

Why `verdict()` does not consult the evidence
---------------------------------------------
The obvious rule -- reject any finding our predicates did not already support --
is wrong, and wrong in a way that would quietly invert what the benchmark
measures. A detector's measured recall would be capped at its predicates'
recall, so the score would answer "does the model agree with our static
analysis?" rather than "does the model find defects?". §4.1 asks the opposite
question, and the `Q` classes exist precisely because deterministic tooling
cannot reach them.

The library's own documented blind spots make this concrete: a discarded
`IERC20.transfer` return is a real and common defect that
`low_level_call_result_discarded` cannot see, because it cannot tell that
`transfer` from `address.transfer`. A model that finds it must be able to score
for it.

So `verdict()` re-derives the claim **at the location the finding states**,
using the shape queries directly. That keeps it strict about the claim -- a
finding pointing at a line with no call in it is rejected, named -- while leaving
it blind to whether any predicate happened to fire. Evidence and verdict stay
independent, which is §2.1's guarantee read in the direction people forget:
evidence must not be removable by the model, *and* the verdict must not be
bounded by the evidence.

Conjunctions
------------
Each detector's rule is a conjunction, and expressing it as `and` rather than as
prose in a prompt is the point of having a verdict layer at all. Where a
condition would need types or data flow, it is left out and said so, rather than
approximated by something that happens to pass the tests written for it.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Sequence
from functools import lru_cache
from typing import ClassVar

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec, TaskOutput
from contract_assay.evidence.predicates import (
    externally_growable_arrays,
    looks_like_a_time,
    mentions_the_sender,
    run_all,
)
from contract_assay.evidence.syntax import CHAIN_STATE_MEMBERS, FunctionSite, Syntax
from contract_assay.models import (
    DeclaredLimit,
    EvidenceRef,
    FailedCheck,
    Finding,
    LimitKind,
    RejectionKind,
    VulnerabilityClass,
)

__all__ = [
    "AccessControlDetector",
    "InsecureRandomnessDetector",
    "UncheckedExternalCallDetector",
]


@lru_cache(maxsize=16)
def _syntax(source: str) -> Syntax | None:
    """Parse once per source, not once per call.

    `evidence()` runs once but `verdict()` runs per finding, and re-parsing a
    large file for each of twenty findings is the kind of accidental cost that
    only shows up under a budget.
    """
    return Syntax.of(source)


def _reject(check: str, detail: str) -> FailedCheck:
    """A judgement, not an error: a rule was applied and the claim did not meet it.

    `VERDICT` keeps the run a measurement. Using `CITATION` here would report a
    rule that fired as an inability to check, turning a conclusion into an
    infrastructure failure.
    """
    return FailedCheck(check=check, kind=RejectionKind.VERDICT, detail=detail)


class _SyntacticDetector(Detector):
    """Shared plumbing for the syntactic-tier detectors.

    Declares none of `detector_id`, `class_id` or `api_version`: it is not a
    submission entry point, and inventing values here so that a base class looks
    complete is exactly the fake declaration the interface check exists to
    prevent.
    """

    predicate_ids: ClassVar[frozenset[str]]
    """Predicates whose output this detector reports as its evidence."""

    instruction: ClassVar[str]

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        """Every fact this detector's predicates establish about the unit.

        Reported whatever the model later concludes. Restricted to this
        detector's own predicates so that one detector's evidence does not
        silently carry another's -- the record has to say which detector observed
        what, or per-class reporting means nothing.
        """
        parsed = _syntax(ctx.source)
        if parsed is None:
            # Unreachable through the harness, which gates unparseable units out
            # before a detector runs. Handled anyway: a detector is a public
            # interface and may be called directly.
            return []
        return [
            ref
            for ref in run_all(parsed, ctx.path, classes=[self.class_id])
            if ref.predicate in self.predicate_ids
        ]

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        """Ask the model to look, with the deterministic findings already in hand.

        The instruction says what to look for and never contains the source. The
        contract is a variable the model explores; pasting it into the prompt
        would make the task's difficulty a function of the file's length.
        """
        return ModelTaskSpec(
            instruction=self.instruction,
            expects=TaskOutput.CLASSIFICATION
            if ctx.classification_expected
            else TaskOutput.FINDINGS,
        )

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return [
                FailedCheck(
                    check="source_unreadable",
                    kind=RejectionKind.CITATION,
                    detail="the unit could not be parsed, so the claim could not be checked",
                )
            ]
        if finding.locator.file != ctx.path:
            return [
                _reject(
                    "locator_names_another_file",
                    f"the finding names {finding.locator.file!r}, the unit is {ctx.path!r}",
                )
            ]
        return self.class_checks(ctx, finding, parsed)

    @abstractmethod
    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        """The class-specific conjunction. Abstract because it is the whole point."""

    @staticmethod
    def _spans(finding: Finding, start_line: int, end_line: int) -> bool:
        return start_line <= finding.locator.end_line and finding.locator.start_line <= end_line


class UncheckedExternalCallDetector(_SyntacticDetector):
    """A call reporting failure by return value, whose result nobody inspects.

    Graded `S`, so the escape hatch is closed and a static analyser is expected
    to win. That is the point of including it: a negative result here is a clear
    one, and a benchmark with no class the baseline should win is not measuring
    against a baseline.
    """

    detector_id = "reference-unchecked-external-call"
    class_id = VulnerabilityClass.UNCHECKED_EXTERNAL_CALL
    api_version = "1.1"
    predicate_ids = frozenset(
        {"low_level_call_result_discarded", "low_level_call_result_bound_but_unread"}
    )
    instruction = (
        "Find calls whose failure is reported by a return value and whose result is "
        "never inspected. Report the call site, not the enclosing function. A call "
        "whose result is checked, or which reverts on failure instead of returning a "
        "flag, is not an instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        calls = [
            call
            for call in parsed.calls
            if self._spans(finding, call.site.start_line, call.site.end_line)
        ]
        if not calls:
            return [_reject("no_call_at_locator", "the stated location contains no call")]

        # Deliberately not restricted to the members this project's predicates
        # recognise. A discarded `IERC20.transfer` return is a real defect the
        # library cannot see, and a verdict that only admitted what the library
        # already found would make the model unable to score for it.
        unchecked = [
            call
            for call in calls
            if call.is_bare_statement
            or any(
                parsed.identifier_uses(host, name) == 1
                for name in call.bound_names
                if (host := parsed.callable_at(call.site.start_line)) is not None
            )
        ]
        if not unchecked:
            return [
                _reject(
                    "call_result_is_inspected",
                    "every call at the stated location binds its result to a name that is "
                    "read again",
                )
            ]
        return []


class InsecureRandomnessDetector(_SyntacticDetector):
    """A value whoever produces the block controls, used as though unpredictable."""

    detector_id = "reference-insecure-randomness"
    class_id = VulnerabilityClass.INSECURE_RANDOMNESS
    api_version = "1.1"
    predicate_ids = frozenset({"producer_controlled_value_read"})
    instruction = (
        "Find values read from chain state that whoever produces the block can choose "
        "or influence, used where unpredictability is required. Report the read, not "
        "the function. A chain-state read used as a deadline or a timestamp comparison "
        "is not an instance of this class."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        reads = [
            site
            for site, receiver, prop in parsed.member_reads
            if self._spans(finding, site.start_line, site.end_line)
            and prop in CHAIN_STATE_MEMBERS.get(receiver, frozenset())
        ]
        blockhash = [
            call
            for call in parsed.calls
            if call.callee == "blockhash"
            and call.receiver is None
            and self._spans(finding, call.site.start_line, call.site.end_line)
        ]
        if not reads and not blockhash:
            return [
                _reject(
                    "no_producer_controlled_read_at_locator",
                    "the stated location reads no chain state the block producer controls",
                )
            ]

        # A `pure` function cannot read block state at all -- the compiler
        # rejects it -- so a claim located in one does not describe this source.
        host_line = finding.locator.start_line
        hosts = [f for f in parsed.functions if f.site.start_line <= host_line <= f.site.end_line]
        if hosts and all(f.state_mutability == "pure" for f in hosts):
            return [
                _reject(
                    "host_cannot_read_chain_state",
                    "the enclosing function is pure, which cannot read block state",
                )
            ]

        # This used to say that whether the value is *used* as randomness rather
        # than as a deadline needs data flow, so it was not checked. That was
        # right about the general case and wrong about the shallow one, which is
        # the third time the same mistake has been made here. Reaching a hash, a
        # modulo or a subscript inside the cited span is a syntactic property,
        # and a value that reaches none of them is read as a quantity however
        # unpredictable its source. Measured: of 83 producer-controlled reads
        # across one corpus, none reached any of the three, and the detector had
        # been claiming all of them.
        # The selection must *contain* the read, not merely share a line with
        # it. `lastVoted[id] = block.timestamp;` has a subscript on the line and
        # the timestamp is not what indexes it -- checking overlap alone left 21
        # of 88 firing on exactly that shape.
        read_sites = reads + [call.site for call in blockhash]
        selections = [
            site for site in parsed.selections if any(site.contains(read) for read in read_sites)
        ]
        if not selections:
            return [
                _reject(
                    "the_value_reaches_no_selection",
                    "nothing in the cited span hashes, takes a modulo of, or indexes by "
                    "this value, so it is read as a quantity rather than used as though "
                    "unpredictable",
                )
            ]

        # What remains genuinely needs data flow: a value assigned to a local
        # and selected on later is outside the cited span and not seen here.
        return []


class AccessControlDetector(_SyntacticDetector):
    """State reachable from outside with nothing restricting who may change it.

    What it cannot see, stated because a real record made it measurable rather
    than arguable: **a guard that is present and unsound.** The predicate's
    proxy for "is the caller checked?" is "is `msg.sender` referenced?", and one
    corpus record is a function whose authorisation check reads
    `owner()` from a caller-supplied address and compares it to `msg.sender`.
    The reference is there, the check is worthless, and the predicate is silent.

    The blindness is systematic rather than a missed case: every defective guard
    that mentions `msg.sender` is invisible to it. Deciding soundness means
    knowing whether the other side of the comparison is caller-controlled, which
    is def-use through an external call -- the semantic tier, which is why §4.2
    grades this class "partly" at the syntactic tier rather than "mostly".

    Left as a stated gap rather than patched. A predicate that guessed at
    soundness from syntax would fire on sound guards too, and a detector that
    trades a silent miss for a confident false positive has not improved.
    """

    detector_id = "reference-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = "1.1"
    predicate_ids = frozenset(
        {
            "state_change_reachable_without_modifier_or_sender_reference",
            "authorisation_reads_its_answer_from_caller_supplied_address",
        }
    )
    # Two entries rather than one, and the corpus record trips both. Isolating
    # them took four minimal cases: a storage write with no guard fires; the
    # same write with an unsound guard does not; an external effect with no
    # guard does not. Each condition is independently sufficient to silence the
    # predicate, so recording only the first would tell a reader that removing
    # the guard reference would make the record visible, and it would not.
    declared_limits = (
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a guard that is present and unsound: an authorisation check whose "
                "compared value is read from a caller-supplied address, so the "
                "function references msg.sender and the predicate reads that "
                "reference as a check"
            ),
            demonstrated_by=("rewardshypervisor-access-control-13849006",),
            isolated=False,
            unpatched_because=(
                "deciding soundness means knowing whether the other side of the "
                "comparison is caller-controlled, which is def-use through an external "
                "call and needs the semantic tier. A predicate guessing at soundness "
                "from syntax would fire on sound guards too, and trading a silent miss "
                "for a confident false positive is not an improvement."
            ),
            closed_when=(
                "the semantic tier lands and caller-taint becomes available, so the "
                "other side of the comparison can be traced to a parameter"
            ),
            # The prediction above is left as written and the outcome recorded
            # beside it, because the pair is the record of the error. It said
            # the semantic tier; depth-one taint needed no tier at all, since a
            # caller-supplied value enters under a parameter name and the parser
            # already knows both. Third time a confident claim about *why*
            # something was invisible turned out wrong, which is why
            # `closed_when` is a field rather than an inference.
            closed_by=(
                "the syntactic predicate authorisation_reads_its_answer_from_caller_"
                "supplied_address; the semantic tier this entry predicted was not needed"
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.INDETERMINACY,
            shape=(
                "a state change effected through an external call rather than by "
                "writing storage: the function mints, transfers or delegates, so "
                "whether it changes state depends on what the callee does"
            ),
            demonstrated_by=("rewardshypervisor-access-control-13849006",),
            isolated=False,
            unpatched_because=(
                "knowing that a call changes state means knowing what the callee does, "
                "and for an interface declaration the implementation is not in the "
                "pinned bytes at all -- so the semantic tier does not close this one. "
                "Full def-use, control flow and a call graph over the unit still cannot "
                "read code the unit does not contain. The site is therefore reported as "
                "indeterminate rather than absent, which is the honest answer available "
                "at any tier over one unit. For an address-pinned record the callee is "
                "a deployed contract at a known address and block, so its verified "
                "source is fetchable and the indeterminacy is closeable there in a way "
                "it is not for a commit pin -- recorded, deliberately not built, and "
                "waiting for something that needs it."
            ),
            closed_when=(
                "the callee's bytes come into scope -- recursive resolution of an "
                "address-pinned callee's verified source. NOT the semantic tier, which "
                "cannot read code the analysed unit does not contain, and which is why "
                "this is stated rather than derived from the kind"
            ),
        ),
    )
    instruction = (
        "Find functions an outside caller can reach that change contract state with "
        "nothing restricting who may call them. Report the function declaration. A "
        "function that is internal or private, that carries a guarding modifier, or "
        "that checks the caller's identity is not an instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        hosts = [
            function
            for function in parsed.functions
            if self._spans(finding, function.site.start_line, function.site.end_line)
        ]
        if not hosts:
            return [
                _reject(
                    "no_function_at_locator", "the stated location contains no function declaration"
                )
            ]

        # Every condition holds of **one** function. Quantified over the set of
        # functions in the span -- which a quoted excerpt easily covers two of --
        # an externally reachable function without a modifier and a separate
        # internal one that writes state together satisfied all three, and the
        # verdict passed on neither of them. The class is a claim about a
        # function, so it is checked at a function; the same defect the slippage
        # and reentrancy verdicts had, in a third place.
        per_host = [self._host_failures(host, parsed) for host in hosts]
        if any(not failures for failures in per_host):
            return []
        # The nearest miss, rather than the union: a message naming one
        # function's shortcomings is diagnosable, where a merged list describes
        # no function that exists.
        return min(per_host, key=len)

    def _host_failures(self, host: FunctionSite, parsed: Syntax) -> list[FailedCheck]:
        """What stops this one function from being an unguarded state change."""
        failures: list[FailedCheck] = []
        if not host.is_externally_reachable:
            failures.append(
                _reject(
                    "host_not_externally_reachable",
                    "the enclosing function is internal or private, so its own reachability "
                    "is not the defect",
                )
            )
        if host.modifiers:
            # Coarse on purpose: a modifier need not guard anything. The verdict
            # side is the strict side, rejections are recorded and countable, and
            # a modifier on a function claimed as unguarded is usually a guard.
            failures.append(
                _reject(
                    "host_carries_a_modifier",
                    "the enclosing function carries a modifier, which this tier cannot "
                    "distinguish from a guard",
                )
            )

        # The predicate's fourth condition, which the verdict never asked: a
        # body that reads `msg.sender` is either guarding on it or is
        # permissionless by design, and this tier cannot tell those apart. 47 of
        # 59 unadjudicated predictions over one sample were the second kind.
        # Fourth class in a row where the strict layer was looser than its own
        # evidence, and the reason is structural: `class_checks` re-derives the
        # rules from the source and nothing made it re-derive *these* rules.
        if mentions_the_sender(parsed, host.declaration):
            failures.append(
                _reject(
                    "host_reads_the_sender",
                    "the enclosing function reads msg.sender, which this tier cannot "
                    "tell from a guard on it -- and a function that reads the sender "
                    "while guarding nothing is usually permissionless by design",
                )
            )

        def inside(start: int) -> bool:
            return host.site.start_line <= start <= host.site.end_line

        writes = [
            write for write in parsed.writes if write.writes_state and inside(write.site.start_line)
        ]
        if not writes:
            # Two causes, not one. A function with no writes and no outgoing
            # calls changes nothing, and the rejection asserts a fact. A
            # function that mints or transfers through an external call may well
            # change state, and "writes no contract state, so there is nothing
            # to protect" would then be a false assertion used to discard a true
            # finding -- the three-valued predicate result meeting a two-valued
            # condition, which is the substitution `Determination` exists to
            # stop. The claim is still not admitted, because §2.2 keeps the
            # verdict side strict and an undecided basis is not a confirmation;
            # what changes is that the cause is accurate and counted apart.
            outbound = [
                call
                for call in parsed.calls
                if call.receiver is not None and inside(call.site.start_line)
            ]
            if outbound:
                failures.append(
                    _reject(
                        "host_state_change_indeterminate",
                        "the enclosing function writes no state directly and makes "
                        f"{len(outbound)} external "
                        f"{'call' if len(outbound) == 1 else 'calls'}, so whether there is "
                        "state for an access check to protect depends on code outside the "
                        "analysed unit",
                    )
                )
            else:
                failures.append(
                    _reject(
                        "host_writes_no_state",
                        "the enclosing function writes no contract state and calls nothing "
                        "external, so there is nothing for an access check to protect",
                    )
                )
        return failures


class DenialOfServiceDetector(_SyntacticDetector):
    """An iteration an outsider can make longer than a block will hold.

    Built because §4.2's audit found this class needed no compiled backend after
    all: an array's declared type says whether it is dynamic, the loop's
    condition says what bounds it, and the appending function has a visibility.

    Reports the loop rather than the array. The array is fine; iterating all of
    it in one transaction is the defect, and a corpus scored at function
    granularity needs the location where the work happens.
    """

    detector_id = "reference-denial-of-service"
    class_id = VulnerabilityClass.DENIAL_OF_SERVICE
    api_version = "1.1"
    predicate_ids = frozenset({"loop_bounded_by_externally_growable_storage_array"})

    # Four entries from one run against five records, and the headline is about
    # the *class* rather than the detector: this predicate names one denial-of-
    # service mechanism, and the corpus's five records contain at least four.
    # §4.2 treats the class as needing one capability; the records say it is a
    # family. Three of the four are stated here; the fifth record's mechanism
    # could not be read from its span, so it is left as an unexplained miss
    # rather than filed under a guess.
    declared_limits = (
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "the append that grows the iterated collection is one internal call "
                "away from any externally reachable function, so the collection is "
                "caller-growable and nothing in this unit says so directly"
            ),
            demonstrated_by=("alchemix-v2-dao-denial-of-service-e76b70f1",),
            unpatched_because=(
                "deciding it needs to know which externally reachable functions reach "
                "the internal appender, which is a call graph over the unit rather than "
                "a shape in it. Treating any internal appender as externally reachable "
                "would fire on every collection a contract maintains for itself."
            ),
            closed_when=(
                "a call graph over the analysed unit -- which is §4.2's one remaining "
                "row for the semantic tier, and now has five records behind it rather "
                "than the reentrancy row alone"
            ),
            # The prediction above is left as written and the outcome recorded
            # beside it: the pair is the record of the error. It said a call
            # graph from the semantic tier. A call graph's job is resolving
            # which function a call names, and within one file with no overload
            # that is name lookup -- so the reachability was syntactic all
            # along. Sixth premise to collapse on the same check, and the
            # second register entry to do so.
            closed_by=(
                "name lookup within the unit, guarded by the name resolving to exactly "
                "one declaration; no tier was needed. The demonstrating record now "
                "matches at exact strength."
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "the loop's bound is a local variable assigned from a collection's "
                "length, so the condition names the local and not the collection"
            ),
            demonstrated_by=("alchemix-v2-dao-denial-of-service-6b54ee07",),
            isolated=False,
            unpatched_because=(
                "the capability this entry named is now built and works -- a local "
                "assigned a collection's length once in a body is followed, and an "
                "alias assigned twice is refused rather than guessed. The record still "
                "misses, and for a different reason than this entry gave: the defect's "
                "loop is in an internal callee of the recorded function, so the "
                "predicted location is a different function from the recorded one. That "
                "is a locator question rather than a detection one, and it is restated "
                "here rather than closed because the miss is real and its cause moved."
            ),
            closed_when=(
                "a rule for which location to report when the iteration is in a callee "
                "of the recorded entry point -- the loop, the entry point, or both. Not "
                "a tier matter: the detection already works."
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a loop capped by a literal, whose cap cannot cover the work it must "
                "do -- the defect is too *few* iterations, which is the opposite of the "
                "property this detector names. Three records, one shape: weeks that "
                "cannot be caught up (`i < 255` over elapsed epochs, twice) and a "
                "Newton iteration that need not converge inside its cap"
            ),
            demonstrated_by=(
                "2024-08-basin-denial-of-service-1cb83cfa",
                "alchemix-v2-dao-denial-of-service-27f60fa8",
                "alchemix-v2-dao-denial-of-service-ab3d30ba",
            ),
            unpatched_because=(
                "it is a different property rather than a weaker view of this one, and "
                "it needs its own predicate: a bound that is constant while the work it "
                "must cover is not. No analysis depth helps, so no tier closes it."
            ),
            closed_when=(
                "a predicate naming the opposite property, a constant cap over "
                "unbounded work. Not a tier matter."
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a denial of service whose mechanism is not iteration at all. Five "
                "records, five mechanisms: an external dependency that can be made to "
                "revert; a re-entrancy guard the contract carries itself, blocking an "
                "inbound call its own withdrawal path requires; an outbound value "
                "transfer the recipient can refuse; value retained with no path to "
                "return it; and a timestamp written by one action that a later one "
                "requires to be older"
            ),
            demonstrated_by=(
                "2024-04-renzo-denial-of-service-02c33f80",
                "2024-04-renzo-denial-of-service-75265ee2",
                "2024-07-traitforge-denial-of-service-03b21871",
                "2024-07-traitforge-denial-of-service-d68b57bc",
                "evm-smart-contracts-denial-of-service-65fa591f",
            ),
            unpatched_because=(
                "this detector holds one predicate and that predicate is about "
                "iteration. The class covers several mechanisms (§4.3) and the others "
                "have no predicate yet."
            ),
            closed_when=(
                "predicates for the class's other mechanisms, starting with a "
                "dependency whose failure a caller can force"
            ),
        ),
    )

    instruction = (
        "Find loops whose iteration count an outside caller can increase without "
        "bound, so that the enclosing function eventually cannot complete. Report the "
        "loop. A loop bounded by a constant, by a fixed-size collection, or by a "
        "length only the contract itself can grow is not an instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        loops = [
            loop
            for loop in parsed.loops
            if self._spans(finding, loop.site.start_line, loop.site.end_line)
        ]
        if not loops:
            return [_reject("no_loop_at_locator", "the stated location contains no loop")]

        failures: list[FailedCheck] = []
        dynamic = {
            name
            for name, declared in parsed.state_variable_types.items()
            if declared.endswith("[]")
        }
        bounding = {name for loop in loops for name in loop.bound_identifiers} & dynamic
        if not bounding:
            failures.append(
                _reject(
                    "loop_not_bounded_by_a_dynamic_collection",
                    "the loop's condition names no dynamically sized state variable, so "
                    "its iteration count is not something state can grow",
                )
            )
        # The same array, appended from somewhere an outsider can reach. Both
        # halves were missing: the append only had to target *a* dynamic array
        # rather than the one this loop iterates, and the appender's reachability
        # -- which is the whole of "externally growable", and which the predicate
        # checks -- was never asked. Third class in a row where the verdict was
        # looser than its own evidence, and the second where conditions held of
        # different sites.
        #
        # Asked of the predicate's own helper rather than re-derived. A
        # re-derivation written here required the `push` to sit directly inside
        # an external function and so lost the one-hop case -- an internal
        # appender called from an external function, which is this class's only
        # true positive in the corpus. Recall falling by one is what caught it.
        if not (bounding & set(externally_growable_arrays(parsed))):
            failures.append(
                _reject(
                    "nothing_an_outsider_can_reach_appends_to_it",
                    "no externally reachable function in this unit appends to the "
                    "collection this loop iterates, so nothing an outsider controls makes "
                    "the iteration longer",
                )
            )
        return failures


class OracleIntegrityDetector(_SyntacticDetector):
    """A freshness value the code asked for and then never consulted.

    Built because §4.2's audit found the blocker was misdescribed. The class was
    parked on needing an ABI to know which interface returns a price; naming the
    *property* rather than the oracle removes the need -- a caller that binds a
    timestamp beside a value and never mentions it in a condition discarded a
    freshness claim, whoever the callee is.
    """

    detector_id = "reference-oracle-integrity"
    class_id = VulnerabilityClass.ORACLE_INTEGRITY
    api_version = "1.1"

    declared_limits = (
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a freshness value discarded at the binding site rather than after it: "
                "`(, int256 quoteAnswer,,,) = feed.latestRoundData()` names two of five "
                "slots and drops the rest, so there is no binding whose type and name "
                "could be tested for time-ness"
            ),
            demonstrated_by=("2024-05-predy-oracle-integrity-b01cf382",),
            isolated=True,
            unpatched_because=(
                "an unbound slot carries neither a type nor a name, so which of the "
                "dropped slots was the timestamp is not in the analysed unit at all. A "
                "rule that fired on any tuple with an unbound slot would report every "
                "discarded success flag as a discarded freshness claim, which is the "
                "false positive this detector was just narrowed to stop making."
            ),
            closed_when=(
                "the callee's return signature comes into scope, naming the slots a "
                "caller chose not to bind"
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a freshness value that does reach a guard, where the guard does not "
                "establish freshness: `require(updatedAt != 0)` consults the value and "
                "asserts only that a round exists"
            ),
            demonstrated_by=("2024-07-benddao-oracle-integrity-4fd907a4",),
            isolated=True,
            unpatched_because=(
                "a guard comparing the value against a stored timestamp is a sound "
                "freshness check and a guard comparing it against zero is not, and both "
                "are a comparison of the bound name against another expression. "
                "Distinguishing them means deciding what the other side *is*."
            ),
            closed_when=(
                "a predicate for the comparison rather than the mention: the freshness "
                "value measured against a chain time source, or against a bound that can "
                "be shown to be one. Not a tier matter -- the shapes are all in the unit"
            ),
        ),
    )
    predicate_ids = frozenset({"multi_return_timestamp_never_reaches_a_guard"})
    instruction = (
        "Find places where a value is used after the freshness information returned "
        "with it was discarded. Report the function. A caller that checks the "
        "freshness, or one whose source returns none at all, is not an instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        unpacked = [
            d
            for d in parsed.destructurings
            if self._spans(finding, d.site.start_line, d.site.end_line)
        ]
        hosts = [
            function
            for function in parsed.functions
            if self._spans(finding, function.site.start_line, function.site.end_line)
        ]
        if not unpacked:
            unpacked = [
                d
                for d in parsed.destructurings
                if any(
                    function.site.start_line <= d.site.start_line <= function.site.end_line
                    for function in hosts
                )
            ]
        if not unpacked:
            return [
                _reject(
                    "no_multi_return_at_locator",
                    "nothing at the stated location unpacks several values, so there is no "
                    "freshness value that could have been discarded",
                )
            ]

        mentioned = {
            identifier
            for guard in parsed.guards
            for function in hosts
            if function.site.start_line <= guard.site.start_line <= function.site.end_line
            for identifier in guard.identifiers
        }
        # The class is about a *freshness* value, and the conjunction was about
        # any multi-return: fifteen firings over one sample, none of them an
        # oracle -- an `EnumerableMap.tryGet` whose discarded slot is a success
        # flag, an internal `_claimable(...)` discarding three values, a bridge
        # adapter returning an amount and a payload. The evidence layer had the
        # right rule all along and the verdict did not ask for it, so the same
        # test is used here rather than a second one written beside it.
        timed = [
            (declared, name)
            for destructuring in unpacked
            for declared, name in destructuring.bindings
            if looks_like_a_time(declared, name)
        ]
        if not timed:
            return [
                _reject(
                    "no_time_typed_binding_at_locator",
                    "nothing unpacked here is a freshness value by type and name, so a "
                    "discarded binding is a discarded value of some other kind -- a "
                    "success flag, an amount -- and not a discarded freshness claim",
                )
            ]

        failures: list[FailedCheck] = []
        if all(name in mentioned for _, name in timed):
            failures.append(
                _reject(
                    "the_freshness_value_does_reach_a_guard",
                    "every freshness value unpacked here is mentioned in a condition in "
                    "the same function, so the freshness information was not discarded",
                )
            )
        return failures


class ArithmeticRoundingDetector(_SyntacticDetector):
    """Integer division taken before a multiplication that would have kept the precision.

    Built because §4.2's audit split this class three ways where the table had
    merged them. Evaluation order is the parse tree and declared widths are
    declarations; a token's `decimals()` is another contract's storage and is a
    declared indeterminacy rather than a gap this detector can close.
    """

    detector_id = "reference-arithmetic-rounding"
    class_id = VulnerabilityClass.ARITHMETIC_ROUNDING
    api_version = "1.1"

    declared_limits = (
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a subtraction that can underflow, `assetData.totalBidAmout -= amount` -- "
                "an arithmetic defect with no division in it, so the order this detector "
                "is about is not present at all"
            ),
            demonstrated_by=("2024-07-benddao-arithmetic-rounding-0f04d2af",),
            isolated=True,
            unpatched_because=(
                "§4.2 split this class three ways and this detector implements one of "
                "them. Whether a subtraction can underflow is a question about the "
                "values, not about the expression: `a -= b` is the same shape whether "
                "`b <= a` is guaranteed elsewhere or not, and a predicate over the shape "
                "alone would fire on every checked subtraction in the corpus."
            ),
            closed_when=(
                "a predicate for the other two ways the class was split -- an unchecked "
                "subtraction whose operand is not bounded by a guard in the same "
                "function, which is depth-one and needs no tier"
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "the same loss one assignment apart: `daysOld = (block.timestamp - t) / 60 "
                "/ 60 / 24;` and then `daysOld * perfomanceFactor * ...`, where the "
                "division and the multiplication are in two statements joined by a local"
            ),
            demonstrated_by=("2024-07-traitforge-arithmetic-rounding-1800009d",),
            isolated=True,
            unpatched_because=(
                "the predicate is about one expression -- an outer multiplication whose "
                "operand already divided -- and here neither expression has both halves. "
                "Nothing about the shape is missing; the two halves are simply not in the "
                "same tree."
            ),
            closed_when=(
                "a local's definition is followed to its assignment, which the access "
                "control predicates already do at depth one. NOT a tier matter, and worth "
                "saying so: the third time a claim about *why* something was invisible "
                "named the semantic tier, depth-one def-use turned out to be enough"
            ),
        ),
    )
    predicate_ids = frozenset({"division_evaluated_before_multiplication"})
    instruction = (
        "Find expressions that divide before multiplying, discarding precision that "
        "the other order would have kept. Report the expression's line. An expression "
        "that multiplies first, or whose division is exact by construction, is not an "
        "instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        spanned = [
            expression
            for expression in parsed.arithmetic
            if self._spans(finding, expression.site.start_line, expression.site.end_line)
        ]
        if not spanned:
            return [
                _reject(
                    "no_arithmetic_at_locator",
                    "the stated location contains no arithmetic expression",
                )
            ]
        divides_first = [
            expression
            for expression in spanned
            if expression.operator == "*" and "/" in expression.operand_operators
        ]
        if not divides_first:
            return [
                _reject(
                    "nothing_divides_before_multiplying",
                    "no expression here multiplies a value that was already divided, so the "
                    "order this class is about is not present",
                )
            ]
        # The predicate excludes `(a / b) * b` -- rounding down to a multiple of
        # `b`, where the truncation is the point -- and the verdict did not, so
        # it accepted exactly the idiom the evidence layer had been narrowed to
        # reject. `(block.timestamp / DURATION) * DURATION` and
        # `((block.timestamp + MAXTIME) / WEEK) * WEEK` are epoch boundaries, not
        # lost precision. Same split as the oracle verdict, in a second class:
        # the property is the evidence layer's and the decision is here, so the
        # decision has to ask for the property.
        if not any(expression.divides_then_scales for expression in divides_first):
            return [
                _reject(
                    "the_multiplier_is_the_divisor",
                    "every expression here multiplies a divided value by the divisor "
                    "itself, which rounds down to a multiple of it deliberately rather "
                    "than discarding precision the other order would have kept",
                )
            ]
        return []


class ReentrancyDetector(_SyntacticDetector):
    """State written after a language-level external call, in one function.

    Built because a working predicate for this class existed with nothing
    wiring it up -- finished work that ran nowhere, invisible in a score report
    because a class with an unwired predicate shows zero predictions exactly as
    a class with no predicate does. A test now fails at commit time if that
    happens again.

    The single-function scope is the whole of what this sees, and it is declared
    rather than implied: the cross-function shape, where the call is in one
    function and the write in another reached from it, is a call graph over the
    unit and is §4.2's one remaining row for the semantic tier.
    """

    declared_limits = (
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "control leaves through an internal call rather than a language-level "
                "transfer: `buyShareCred(credIdCounter, 1, 0)` is internal and the "
                "external call that can re-enter is two hops below it, while the state "
                "write this class is about -- `credIdCounter += 1` -- is here"
            ),
            demonstrated_by=("2024-08-phi-reentrancy-0398895c",),
            isolated=True,
            unpatched_because=(
                "the predicate is about a transfer visible in the analysed function. "
                "Finding one below an internal call is a reachability question over the "
                "unit's call graph, which is a different search from the one-hop name "
                "lookup the denial-of-service predicate does for appends to a named "
                "array: there the target is one identifier, here it is any of several "
                "transfer forms at unknown depth."
            ),
            closed_when=(
                "a predicate that follows internal calls within the unit to the first "
                "language-level transfer, refusing where a name resolves to more than "
                "one declaration. Not a tier matter -- the calls are all in the file"
            ),
        ),
    )

    detector_id = "reference-reentrancy"
    class_id = VulnerabilityClass.REENTRANCY
    api_version = "1.1"
    predicate_ids = frozenset({"state_write_after_raw_external_call"})
    instruction = (
        "Find places where contract state is written after control has already left "
        "the contract, so a callee can re-enter and observe or act on the stale state. "
        "Report the call site. A call whose caller writes nothing afterwards, or which "
        "is guarded against re-entry, is not an instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        calls = [
            call
            for call in parsed.calls
            if self._spans(finding, call.site.start_line, call.site.end_line)
        ]
        if not calls:
            return [_reject("no_call_at_locator", "the stated location contains no call")]
        transfers = [call for call in calls if call.is_low_level or call.is_value_transfer]
        if not transfers:
            return [
                _reject(
                    "call_is_not_a_language_level_transfer",
                    "no call here hands control to an arbitrary address by the language's "
                    "own means, so re-entry through it is not what this tier can see",
                )
            ]

        # After a *transfer*, not after any call. Quantified over `calls` this
        # accepted a span holding an internal call with a write below it and a
        # low-level call somewhere else entirely -- two conditions met by two
        # sites, which is the same defect the slippage verdict had. The class is
        # a claim about one call and the state written after it.
        after = [
            write
            for write in parsed.writes
            if write.writes_state
            and any(write.site.start_line > call.site.end_line for call in transfers)
        ]
        if not after:
            return [
                _reject(
                    "no_state_written_after_the_call",
                    "state is not written after control leaves, so there is nothing for a "
                    "re-entrant caller to find stale",
                )
            ]
        return []


class SlippageDetector(_SyntacticDetector):
    """A zero minimum passed where a caller should have bounded its loss.

    Built for the same reason as the reentrancy detector: the predicate existed
    and nothing ran it.

    The predicate is deliberately unscoped -- every literal zero passed to
    anything -- because recognising a swap through an aliased import and a
    renamed variable needs a selector, and a selector needs ABI canonicalisation
    this tier does not have (§2.3). Scoping therefore happens here, where a rule
    that rejects is recorded and countable rather than hidden inside a predicate
    that declined to look.
    """

    # What the boundary check cannot separate, recorded here rather than in the
    # declared-limit register because no corpus record demonstrates it (§7.4's
    # completeness bound): a struct construction qualified by the interface that
    # declares the struct -- `IVotingEscrow.Point(0, 0, 0, 0)` -- carries a
    # receiver and constructs a value in memory. Telling that from a member call
    # needs to know the qualifier is a type, and the type is declared in another
    # file, so it is not in this unit's index. An indeterminacy of scope rather
    # than a defect in the check.

    declared_limits = (
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "a bound that is present and unsound: "
                "`melt(revenueToken, debtToken, balance, balance)` passes the input "
                "amount as the minimum, so a bound was written and it cannot bind"
            ),
            demonstrated_by=("alchemix-v2-dao-slippage-e86e1d55",),
            isolated=True,
            unpatched_because=(
                "the predicate names the bound written as zero, which is a shape. A "
                "bound equal to the input is also a shape, and it is a *correct* one "
                "wherever the exchange is meant to be one-for-one -- a stable pair, a "
                "wrapper. Whether this assumption holds is what the report argues about, "
                "and no predicate over the expression decides it."
            ),
            closed_when=(
                "the two sides of the exchange can be told apart -- which token is "
                "being sold and which bought -- so that 'minimum equals input' can be "
                "read as an assumption about their prices rather than as arithmetic"
            ),
        ),
        DeclaredLimit(
            kind=LimitKind.BLINDNESS,
            shape=(
                "an exchange that takes no bound at all: `pool.burn(TICK_LOWER, "
                "TICK_UPPER, liquidity)` returns `(amount0, amount1)` and accepts no "
                "minimum, so the caller's omission is a missing *check on what came "
                "back* rather than a zero passed in"
            ),
            demonstrated_by=("2024-06-vultisig-slippage-55a693c2",),
            isolated=True,
            unpatched_because=(
                "this detector reads the call's arguments, and there is no argument to "
                "read. The property is about the returned values reaching a guard, which "
                "is the oracle detector's shape applied to amounts -- a different "
                "predicate, not a looser version of this one."
            ),
            closed_when=(
                "a predicate for a multi-return whose values reach no condition before "
                "being used, which `multi_return_timestamp_never_reaches_a_guard` "
                "already does for timestamps. Not a tier matter"
            ),
        ),
    )

    detector_id = "reference-slippage"
    class_id = VulnerabilityClass.SLIPPAGE
    api_version = "1.1"
    predicate_ids = frozenset({"call_argument_is_zero_literal"})
    instruction = (
        "Find calls that exchange value where the caller accepts any amount in return, "
        "having passed no lower bound. Report the call site. A call whose minimum is "
        "computed from a quote, or which exchanges nothing, is not an instance."
    )

    def class_checks(
        self, ctx: AnalysisContext, finding: Finding, parsed: Syntax
    ) -> Sequence[FailedCheck]:
        calls = [
            call
            for call in parsed.calls
            if self._spans(finding, call.site.start_line, call.site.end_line)
        ]
        if not calls:
            return [_reject("no_call_at_locator", "the stated location contains no call")]

        # All three conditions below have to hold of **one** call. Written as
        # three independent `any(...)` they held of three different ones: over a
        # whole function, `IFluxToken(FLUX).mergeFlux(_from, _to)` supplied the
        # receiver and the two arguments while `LockedBalance(0, 0, false, 0)`
        # supplied the zero, and the verdict passed on a call that exchanges
        # nothing. The receiver rule was added for exactly that struct
        # construction and did not close it, because the rule was about the
        # *set* of calls rather than about a call.
        if any(
            call.receiver is not None
            and len(call.arguments) >= 2
            and any(argument.is_zero_literal for argument in call.arguments)
            for call in calls
        ):
            return []

        failures: list[FailedCheck] = []
        # An exchange happens across a contract boundary, so the call has a
        # receiver. Without this the class means "passes zero to anything": over
        # one corpus every single firing was a struct construction or an
        # internal call -- `LockedBalance(0, 0, false, 0)`, `_checkpoint(...)` --
        # where the zero is a field initialiser and not a bound on anything.
        # Structural rather than a list of callee names, which no import
        # aliasing survives (§2.3).
        if not any(call.receiver is not None for call in calls):
            failures.append(
                _reject(
                    "call_crosses_no_contract_boundary",
                    "the call has no receiver, so it is an internal call or a struct "
                    "construction rather than an exchange with another party, and a zero "
                    "among its arguments bounds nothing",
                )
            )
        if not any(argument.is_zero_literal for call in calls for argument in call.arguments):
            failures.append(
                _reject(
                    "no_zero_literal_argument",
                    "no argument here is the literal zero, so no bound was written as an "
                    "unbounded one",
                )
            )
        # An exchange takes more than one argument. A single-argument call
        # passing zero is a great many innocent things, and admitting it would
        # make the class mean "passes zero to anything".
        if not any(len(call.arguments) >= 2 for call in calls):
            failures.append(
                _reject(
                    "call_takes_too_few_arguments_to_be_an_exchange",
                    "a call with fewer than two arguments has no separate amount and bound, "
                    "so a zero among them is not an unbounded exchange",
                )
            )
        if not failures:
            # Every condition held, and no call held them together. Reported as
            # its own rejection rather than as silence, because silence here
            # means "accepted" and that was the defect.
            failures.append(
                _reject(
                    "no_one_call_is_an_unbounded_exchange",
                    "a receiver, two arguments and a zero literal are all present at this "
                    "location but not in the same call, so nothing here exchanges value "
                    "without a bound",
                )
            )
        return failures
