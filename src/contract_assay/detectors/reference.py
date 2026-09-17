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
from contract_assay.evidence.predicates import run_all
from contract_assay.evidence.syntax import CHAIN_STATE_MEMBERS, Syntax
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
            (receiver, prop)
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

        # Whether the value is then *used* as randomness rather than as a
        # deadline needs data flow, so it is not checked here. Asserting it from
        # syntax would be a rule that passes its own tests and nothing else.
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
            demonstrated_by="rewardshypervisor-access-control-13849006",
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
            demonstrated_by="rewardshypervisor-access-control-13849006",
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

        failures: list[FailedCheck] = []
        if not any(function.is_externally_reachable for function in hosts):
            failures.append(
                _reject(
                    "host_not_externally_reachable",
                    "the enclosing function is internal or private, so its own reachability "
                    "is not the defect",
                )
            )
        if all(function.modifiers for function in hosts):
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

        writes = [
            write
            for write in parsed.writes
            if write.writes_state
            and any(
                function.site.start_line <= write.site.start_line <= function.site.end_line
                for function in hosts
            )
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
                if call.receiver is not None
                and any(
                    function.site.start_line <= call.site.start_line <= function.site.end_line
                    for function in hosts
                )
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
