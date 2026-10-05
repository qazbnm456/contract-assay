"""A model caller over any OpenAI-compatible endpoint, built on rlm-harness.

This package does not call a model, and that is deliberate rather than
unfinished. A benchmark whose own correctness depended on the thing it measures
could not tell a broken instrument from a weak model, so `contract_assay`
defines what to ask (`Detector.plan`) and never asks it. **The asking is the
consumer's job, and `rlm_caller` below is what a consumer looks like.**

It is a `harness.ModelCaller`, nothing more: `contract-assay run` reads the
corpus, loops over units and detectors, builds each run and writes the JSONL, and
calls this when a detector asks for a model. There is no loop in this file, and
there should not be one in yours. If you are testing a harness of your own, start
from `examples/bring_your_own_harness/` instead: it shows the same seam without a
model library in the way.

Three obligations come with calling a model on a submission's behalf, and
getting any of them wrong produces figures that look fine:

1. **A run must name what produced its findings.** `ModelReply.models` carries
   `ModelUse` entries. The benchmark refuses a run that leaves the producer
   unnamed, because a figure that cannot say what produced it cannot be compared
   with one produced by something else.
2. **A failed call still happened.** Tokens spent on a call that returned
   nothing are spent, so a failure is returned with whatever it cost. A budget
   that counted only successes would let a harness retry without limit.
3. **"We stopped it" and "it found nothing" are different facts.** A failed call
   is `ModelReply(failed=...)`, which the run records as `invalid`, never as
   `clean`.

What this file does *not* do, and a competition host must: meter the calls from
outside the process running the submission, confine that process, and re-check
every citation against its own copy of the source. Those are not omissions in an
example. They are the difference between running your own harness and running
a stranger's.

Usage
-----
    pip install -e . -r examples/reference_runner/requirements.txt
    export RLM_MODEL=qwen2.5-coder:32b              # as the endpoint names it
    export RLM_BASE_URL=http://localhost:11434/v1   # or any OpenAI-compatible endpoint
    export RLM_API_KEY=local

    contract-assay run --manifest examples/reference_runner/manifest.json \\
        --records corpus/records --source-root ./checkout \\
        --model-caller runner:rlm_caller --limit 5 --out runs.jsonl

    contract-assay score runs.jsonl --records corpus/records \\
        --submission-id example-runner --source-root ./checkout --out score.json

`runner:rlm_caller` is a module name, resolved from the working directory and from
the directory of the manifest you pass, which is this one.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, Field

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec
from contract_assay.harness import ModelReply
from contract_assay.models import Finding, Locator, ModelRole, ModelUse


class Proposal(BaseModel):
    """What the model is asked for, and the whole of what it may decide.

    No file and no detector id. Both are known here, both are stamped on
    afterwards, and a model that could name either could file a claim against a
    file it was never given or under a detector nobody declared.
    """

    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    quote: str = Field(min_length=1, description="The exact source text at those lines.")
    reasoning: str = Field(min_length=1)
    contract: str | None = None
    function: str | None = None


class Proposals(BaseModel):
    findings: list[Proposal] = Field(default_factory=list)


def _model_from_the_environment() -> str:
    """The model's name, read when this module is imported rather than per call.

    `ModelCaller` has no model argument and `--model-caller` cannot carry one, so
    the model comes from the environment. Reading it at import is the point: a
    missing value then ends `contract-assay run` with one red line and exit 2,
    instead of every unit coming back `transport_failure`, which reads like a
    harness that measures nothing.
    """
    name = os.environ.get("RLM_MODEL")
    if not name:
        raise RuntimeError(
            "set RLM_MODEL to the model's name as your endpoint calls it "
            "(RLM_BASE_URL and RLM_API_KEY say where it lives)"
        )
    return name


MAIN_MODEL = _model_from_the_environment()
SUB_MODEL = os.environ.get("RLM_SUB_MODEL") or MAIN_MODEL
"""One model is the usual case. A sub-model is recorded as such, so that two rows
that differ only in which helper they called are not mistaken for one."""

MAX_ITERATIONS = int(os.environ.get("RUNNER_MAX_ITERATIONS", "10"))
"""The planner turn budget. Read from the environment so the cost of a sweep can
be changed without editing a harness, which is a property of the run rather than
of the submission."""

_CONFIGURED = False


def setup(*, max_tokens: int, max_calls: int) -> None:
    """Configure rlm-harness once: models from `RLM_MODEL`, endpoint from the environment.

    The split is the thing to copy. `rlm-harness` will read `RLM_MAIN_MODEL` and
    `RLM_SUB_MODEL` if you let it build the config for you, and a runner that
    took the model from there would have two sources of truth for the one value
    a figure is only meaningful beside. So the models come from `RLM_MODEL` and
    the environment supplies **where the model lives**:

        RLM_BASE_URL    any OpenAI-compatible endpoint, hosted or local
        RLM_API_KEY     required by hosted providers; most local servers want
                        any non-empty string
        RLM_ADAPTER     `json` for schema-guided structured output, `chat` for
                        an endpoint with none
        RLM_INTERPRETER where the model's own REPL runs

    Getting this wrong is not a subtle failure, and it is worth knowing the
    shape: omit the base URL and litellm receives a bare model name with no
    provider, which comes back as `LLM Provider NOT provided` on every call.
    Every run is then `invalid`, which reads like a harness that measures
    nothing, and `contract-assay run` prints that cause.

    Called once rather than per call, because `configure` sets process-global
    state. That is safe here for the same reason it is safe in a competition:
    one round, one agreed model, one process. The budgets are the first
    detector's, and a unit's budgets are the same for every detector in a run.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    from rlm_harness import RLMConfig, configure

    configure(
        RLMConfig(
            main_model=MAIN_MODEL,
            sub_model=SUB_MODEL,
            api_key=os.environ.get("RLM_API_KEY") or None,
            base_url=os.environ.get("RLM_BASE_URL") or None,
            adapter=os.environ.get("RLM_ADAPTER", "json"),
            interpreter=os.environ.get("RLM_INTERPRETER", "pyodide"),
            # A per-call ceiling, where the submission's budget is per unit. A
            # reasoning model emits its chain-of-thought before its answer, so
            # this has to hold both or the reply is cut off mid-JSON, which
            # surfaces as a model that cannot follow a schema rather than as a
            # truncation. The unit budget then bounds how many such calls fit.
            max_tokens=max_tokens,
            max_llm_calls=max_calls,
            # The planner's turn budget, and the dominant cost here. A
            # `ModelTaskSpec.max_steps` is per detector while `configure` is
            # process-global, so this caller cannot honour both: a
            # submission's `max_steps` is treated as advisory and this is the
            # ceiling. Said out loud because a harness author reading only the
            # interface would expect their number to be the one in force.
            #
            # Worth knowing before choosing it: an RLM planner exists to explore
            # context too large to prompt with, and one Solidity file is not
            # that. Ten turns over a 300-line contract is mostly overhead, and
            # with a reasoning main model each turn costs its chain-of-thought.
            max_iterations=MAX_ITERATIONS,
        )
    )
    _CONFIGURED = True


def to_findings(
    detector: Detector, ctx: AnalysisContext, proposals: Sequence[Proposal]
) -> tuple[Finding, ...]:
    """The model's proposals as findings, with the file and the detector stamped on."""
    return tuple(
        Finding(
            detector_id=detector.detector_id,
            locator=Locator(
                file=ctx.path,
                start_line=proposal.start_line,
                # The model gave two lines; nothing here can tell which it
                # meant, so a backwards span collapses to its start rather than
                # becoming invalid and being dropped for a reason that reads as
                # the model's fault.
                end_line=max(proposal.end_line, proposal.start_line),
                contract=proposal.contract,
                function=proposal.function,
            ),
            quote=proposal.quote,
            reasoning=proposal.reasoning,
        )
        for proposal in proposals
    )


def models_used(
    usage_data: Mapping[str, Sequence[Mapping[str, Any]]], *, main: str, sub: str
) -> tuple[ModelUse, ...]:
    """What dspy's usage tracker recorded, as the `ModelUse` entries a run names.

    The tracker is keyed by whatever string the language model reports for
    itself, which for an OpenAI-compatible endpoint is usually the configured
    name behind a provider prefix. A key is the sub-model when it is that name,
    bare or prefixed; everything else is the main model, so an unexpected key
    is charged rather than lost.

    Calls the provider reported no usage for are not in the tracker at all, so
    `calls` here can undercount when usage is missing. That is the case the
    live test exists for, and `rlm_caller` keeps a call that was made visible
    even when the tracker saw nothing of it.
    """
    totals: dict[ModelRole, list[int]] = {}
    for key, calls in usage_data.items():
        is_sub = sub != main and (key == sub or key.endswith("/" + sub))
        role = ModelRole.SUB if is_sub else ModelRole.MAIN
        entry = totals.setdefault(role, [0, 0])
        for call in calls:
            entry[0] += 1
            entry[1] += int(call.get("total_tokens") or 0) or (
                int(call.get("prompt_tokens") or 0) + int(call.get("completion_tokens") or 0)
            )
    return tuple(
        ModelUse(
            model_id=sub if role is ModelRole.SUB else main,
            role=role,
            calls=calls,
            tokens=tokens,
        )
        for role, (calls, tokens) in totals.items()
    )


def rlm_caller(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
    """One model call for one detector over one unit: findings, and what it cost.

    Never raises. A transport failure is a reply with `failed` set and whatever
    was spent, because the alternative, letting the exception escape, is a
    run that cannot say what it cost.
    """
    usage: Mapping[str, Sequence[Mapping[str, Any]]] = {}
    attempted = False
    findings: tuple[Finding, ...] = ()
    failed: str | None = None
    started = time.monotonic()
    try:
        import dspy
        from rlm_harness import RLMTask

        setup(max_tokens=ctx.limits.max_tokens, max_calls=ctx.limits.max_model_calls)

        class Detect(RLMTask):  # type: ignore[misc]
            signature = "instruction: str, source: str -> findings: Proposals"
            output_field = "findings"
            output_model = Proposals
            instructions = (
                "Follow the instruction against the source. Report only what the source "
                "supports, quoting the exact text at the lines you cite."
            )

        with dspy.track_usage() as tracker:
            attempted = True
            try:
                result = Detect().run(instruction=spec.instruction, source=ctx.source)
            finally:
                # Read on failure as well: the call happened, and what it spent
                # is spent.
                usage = getattr(tracker, "usage_data", {})
        findings = to_findings(detector, ctx, result.findings)
    except Exception as failure:
        failed = f"{type(failure).__name__}: {failure}"

    models = models_used(usage, main=MAIN_MODEL, sub=SUB_MODEL)
    if not models and attempted:
        # A provider that reports no usage leaves the tracker empty, and a run
        # naming no model is refused. One call, no tokens, is the truthful
        # minimum, and the zero is what the README's first check looks for.
        models = (ModelUse(model_id=MAIN_MODEL, role=ModelRole.MAIN, calls=1, tokens=0),)

    seconds = time.monotonic() - started
    if seconds > ctx.limits.wall_seconds:
        # Not a warning about performance. A round kills a call that overruns, so
        # a harness like this does not score badly: every run of it is killed,
        # which is a different fact and one the author cannot see from a score.
        print(
            f"  {detector.detector_id}: {seconds:.0f}s exceeds the "
            f"{ctx.limits.wall_seconds}s a round allows",
            file=sys.stderr,
        )
    return ModelReply(findings=findings, models=models, failed=failed)
