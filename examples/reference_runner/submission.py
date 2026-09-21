"""A submission, complete and minimal, in the shape the interface asks for.

Copy this file. It shows every layer of the contract being written by hand --
which is what you do when you can beat the defaults, and **not** what the
contract requires. The smallest working submission is three declarations:

    class MissingOwnerCheck(Detector):
        detector_id = "missing-owner-check"
        class_id = VulnerabilityClass.ACCESS_CONTROL
        api_version = "1.0"

That gets the benchmark's own evidence layer for its class and rejects nothing,
which is a real baseline you can score. Everything below is an override of a
default, so read each part as "here is why you might do better than what you
already get" rather than as an obligation. `docs/api.md` §1 has the table of
what each default is.

Read `docs/api.md` §4 for the rules. What this file shows is the *shape*:

- **Three declarations.** `detector_id`, `class_id`, `api_version`. Missing one
  fails at import, with the field named, rather than partway through a run where
  the failure would read as a defect in your logic.
- **`evidence()` establishes what is true of the source**, deterministically.
  Every item is re-validated by the host, so an `EvidenceRef` that does not
  match the source is not a formatting problem.
- **`plan()` says what to ask.** It does not call a model, and it must not
  contain the source: the contract is a variable the model explores, and pasting
  the file into the prompt makes the task's difficulty a function of the file's
  length. Returning `None` is legitimate and means no model runs -- a purely
  deterministic detector is a first-class citizen here.
- **`verdict()` is where a multi-condition rule is enforceable.** "Exploitable
  only if A and B and C" written into prompt text is enforced by the model's
  attention holding across the whole input; written here, it is `and`. A
  rejection names itself, so the cost of tightening a rule is visible instead of
  being a matter of faith.

The one thing worth internalising before you write your own: **the layer that
decides must ask for the property the layer that observes established.** If
`evidence()` establishes that a function takes a deadline argument, `verdict()`
must ask for *that*, not re-derive it from the finding's text. Six separate bugs
in this project's own reference detectors were that mistake.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from contract_assay.detectors.base import (
    AnalysisContext,
    Detector,
    ModelTaskSpec,
    check_citation,
)
from contract_assay.models import (
    DifficultyLevel,
    EvidenceRef,
    FailedCheck,
    Finding,
    Locator,
    RejectionKind,
    VulnerabilityClass,
)

# A state variable assigned in a function with no guard in it. Deliberately
# crude: the point of the example is the contract, not the analysis.
_ASSIGNS_STATE = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)\s*=\s*[^=]", re.MULTILINE)
_GUARDS = ("require(", "revert", "onlyOwner", "_checkOwner", "msg.sender ==")


class UnguardedStateWrite(Detector):
    """Writes to state in a function that names no guard."""

    detector_id = "example-unguarded-state-write"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = "1.0"
    level = DifficultyLevel.M

    instruction = (
        "The variable `source` holds one Solidity file. Find external or public "
        "functions that write to contract state without checking who called them. "
        "For each one, report the line range of the assignment and quote every "
        "line in that range verbatim -- the quote must be the whole of what the "
        "line range names, and the range must cover at least six tokens, so "
        "include the neighbouring line when the statement is short. Do not "
        "report a function whose body checks the caller, and do not report a "
        "constructor or an initializer guarded against a second call."
    )

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        """Lines that assign to something, and whether a guard appears near them.

        Deterministic and re-validated by the host. This is the observation
        `verdict()` will ask for -- which is the whole reason it is established
        here rather than re-derived there.
        """
        out: list[EvidenceRef] = []
        for match in _ASSIGNS_STATE.finditer(ctx.source):
            line = ctx.source.count("\n", 0, match.start()) + 1
            out.append(
                EvidenceRef(
                    # Named for the PROPERTY established, never for the shape it
                    # was found in. `assignment_without_a_named_guard` is a
                    # property; `regex_matched_an_equals_sign` is one shape of
                    # it, and a second shape would then need a second name --
                    # so counting either one under-reports the property. The
                    # shape belongs in `detail`.
                    predicate="state_assignment_without_a_named_guard",
                    tier=ctx.tier,
                    locator=Locator(file=ctx.path, start_line=line, end_line=line),
                    detail={"target": match.group("name")},
                )
            )
        return out

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        """What to ask. Return `None` and this detector is fully deterministic.

        The instruction never contains the source. `ctx.limits` is what the host
        will hold you to; reading it here is how a harness decides whether it can
        afford to ask at all.
        """
        if not evidence:
            # Nothing to reason about, so nothing to pay a model for. A skipped
            # call is budget left for the next unit rather than a missed finding.
            return None
        return ModelTaskSpec(instruction=self.instruction, max_steps=2)

    def verdict(
        self,
        ctx: AnalysisContext,
        finding: Finding,
        evidence: Sequence[EvidenceRef],
    ) -> Sequence[FailedCheck]:
        """Reject what the class definition does not cover, and name the check.

        Two rejections, and the second is the one worth copying. It asks the
        *evidence* whether an assignment was established at these lines, rather
        than re-reading the finding's quote for one -- the observing layer
        already did that work, and a decision that re-derives it will eventually
        derive it differently.
        """
        rejections: list[FailedCheck] = []

        span = ctx.source.split("\n")[
            max(finding.locator.start_line - 1, 0) : finding.locator.end_line
        ]
        if any(guard in line for line in span for guard in _GUARDS):
            rejections.append(
                FailedCheck(
                    check="guard_named_at_the_cited_lines",
                    kind=RejectionKind.VERDICT,
                    detail="the cited lines check the caller, so the class does not apply",
                )
            )

        established = {
            line
            for ref in evidence
            for line in range(ref.locator.start_line, ref.locator.end_line + 1)
        }
        cited = set(range(finding.locator.start_line, finding.locator.end_line + 1))
        if not (established & cited):
            rejections.append(
                FailedCheck(
                    check="assignment_established_here",
                    kind=RejectionKind.VERDICT,
                    detail="evidence() established no assignment at the cited lines",
                )
            )
        return rejections


def self_check(ctx: AnalysisContext, finding: Finding) -> str | None:
    """What the host will check before your verdict is consulted, runnable here.

    Not part of the interface. It is here because the single most common way a
    submission scores zero is a quote that does not match the source at the
    locator it names -- which the host records as `citation_unverified`, meaning
    the run measured nothing at all. Calling this during development turns that
    into a message you see immediately.

    The mismatch to expect from a model is a *fragment*: asked for the lines of
    an assignment, it returns the assignment and a locator covering the whole
    function. The host wants the two to agree, so either narrow the locator or
    widen the quote -- and the cheapest way to never get this wrong is to slice
    `ctx.source` at the locator you are about to report, which is what the
    bundled `PredicateDetector` does.
    """
    failure = check_citation(ctx, finding)
    return None if failure is None else f"{failure.check}: {failure.detail}"
