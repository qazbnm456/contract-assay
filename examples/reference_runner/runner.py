"""A reference runner: the missing half of the benchmark, as a consumer.

This package does not call a model, and that is deliberate rather than
unfinished. A benchmark whose own correctness depended on the thing it measures
could not tell a broken instrument from a weak model, so `contract_assay`
defines what to ask (`Detector.plan`) and never asks it. **The asking is the
consumer's job, and this file is what a consumer looks like.**

It is a reference in the strict sense: it is not the only way to connect, and
nothing here is imported by the package. It exists so that

- an outsider can reproduce a figure rather than take one on trust,
- a submission author can see the whole loop their `Detector` will run inside,
- and the arena (or any other host) has a worked example of the obligations
  that come with calling a model on a submission's behalf.

Three of those obligations are easy to miss, and getting any of them wrong
produces figures that look fine:

1. **A run must name what produced its findings.** Either `models=[ModelUse(…)]`
   or `produced_without_a_model=True`. The benchmark refuses a run that leaves
   the producer unnamed, because a figure that cannot say what produced it
   cannot be compared with one produced by something else.
2. **A failed call still happened.** Tokens spent on a call that returned
   nothing are spent. A budget that counted only successes would let a harness
   retry without limit.
3. **"We stopped it" and "it found nothing" are different facts.** A run cut
   short by a budget or a timeout is `invalid` with a reason, never `clean`.

What this file does *not* do, and a competition host must: meter the calls from
outside the process running the submission, confine that process, and re-check
every citation against its own copy of the source. Those are not omissions in an
example -- they are the difference between running your own harness and running
a stranger's.

Usage
-----
    pip install -e . -r examples/reference_runner/requirements.txt
    export RLM_BASE_URL=http://localhost:11434/v1   # or any OpenAI-compatible endpoint
    export RLM_API_KEY=local

    python examples/reference_runner/runner.py \\
        --records corpus/records --source-root ./checkout \\
        --manifest examples/reference_runner/manifest.json \\
        --model qwen2.5-coder:32b --out runs.jsonl

    contract-assay score runs.jsonl --records corpus/records \\
        --submission-id example-runner --source-root ./checkout \\
        --weights weights.json --predictions-per-unit 3 --out score.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from contract_assay.corpus.records import load_records
from contract_assay.detectors.base import AnalysisContext, Detector, SubmissionLimits
from contract_assay.detectors.loading import (
    MalformedSubmission,
    SubmissionFault,
    SubmissionManifest,
    call_evidence,
    call_plan,
    load_detector,
)
from contract_assay.detectors.runner import run_detector
from contract_assay.models import (
    DetectorRun,
    EvidenceTier,
    Finding,
    InvalidReason,
    Locator,
    ModelRole,
    ModelUse,
    Outcome,
)


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


_CONFIGURED = False


def setup(*, model: str, sub_model: str, max_tokens: int, max_calls: int) -> None:
    """Configure the harness once: models from the caller, endpoint from the environment.

    The split is the thing to copy. `rlm-harness` will read `RLM_MAIN_MODEL` and
    `RLM_SUB_MODEL` if you let it build the config for you, and a runner that
    took the model from there would have two sources of truth for the one value
    a figure is only meaningful beside. So the models come from arguments and
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
    nothing.

    Called once rather than per call, because `configure` sets process-global
    state. That is safe here for the same reason it is safe in a competition:
    one round, one agreed model, one process.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    try:
        from rlm_harness import RLMConfig, configure
    except ImportError:
        print(
            "this runner needs rlm-harness: "
            "pip install -r examples/reference_runner/requirements.txt",
            file=sys.stderr,
        )
        raise

    configure(
        RLMConfig(
            main_model=model,
            sub_model=sub_model,
            api_key=os.environ.get("RLM_API_KEY") or None,
            base_url=os.environ.get("RLM_BASE_URL") or None,
            adapter=os.environ.get("RLM_ADAPTER", "json"),
            interpreter=os.environ.get("RLM_INTERPRETER", "pyodide"),
            # A per-call ceiling, where the submission's budget is per unit. A
            # reasoning model emits its chain-of-thought before its answer, so
            # this has to hold both or the reply is cut off mid-JSON -- which
            # surfaces as a model that cannot follow a schema rather than as a
            # truncation. The unit budget then bounds how many such calls fit.
            max_tokens=max_tokens,
            max_llm_calls=max_calls,
        )
    )
    _CONFIGURED = True


@dataclass(frozen=True, slots=True)
class Unit:
    """One source file of the corpus, as the records' pins name it."""

    source_id: str
    path: str
    source: str


@dataclass(frozen=True, slots=True)
class Answer:
    findings: tuple[Finding, ...]
    tokens: int
    failed: str | None = None


def units_from(records: Path, source_root: Path) -> Iterator[Unit]:
    """Every distinct source unit the corpus points at, once each.

    Once each, because two records in one file are two defects in one unit --
    running the unit twice would give a detector two chances at the same file
    and count its budget twice.
    """
    seen: set[str] = set()
    for record in load_records(records):
        pin = record.pin
        if pin.source_id in seen:
            continue
        seen.add(pin.source_id)
        path = source_root / pin.path
        if not path.is_file():
            print(f"skipping {pin.source_id}: {path} is not in the checkout", file=sys.stderr)
            continue
        yield Unit(source_id=pin.source_id, path=pin.path, source=path.read_text(encoding="utf-8"))


def ask(
    detector: Detector,
    ctx: AnalysisContext,
    instruction: str,
    *,
    model: str,
    sub_model: str,
) -> Answer:
    """One model call, reporting what came back and what it cost.

    Never raises. A transport failure is an empty answer with whatever was
    spent, because the alternative -- letting the exception escape -- ends the
    whole run on one bad call and publishes the submission as having measured
    nothing.
    """
    import dspy
    from rlm_harness import RLMTask

    setup(
        model=model,
        sub_model=sub_model,
        max_tokens=ctx.limits.max_tokens,
        max_calls=ctx.limits.max_model_calls,
    )

    class Detect(RLMTask):  # type: ignore[misc]
        signature = "instruction: str, source: str -> findings: Proposals"
        output_field = "findings"
        output_model = Proposals
        instructions = (
            "Follow the instruction against the source. Report only what the source "
            "supports, quoting the exact text at the lines you cite."
        )

    tokens = 0
    try:
        with dspy.track_usage() as tracker:
            result = Detect().run(instruction=instruction, source=ctx.source)
    except Exception as failure:
        return Answer(findings=(), tokens=0, failed=f"{type(failure).__name__}: {failure}")
    for calls in getattr(tracker, "usage_data", {}).values():
        for call in calls:
            tokens += int(call.get("total_tokens") or 0) or (
                int(call.get("prompt_tokens") or 0) + int(call.get("completion_tokens") or 0)
            )
    return Answer(
        findings=tuple(
            Finding(
                detector_id=detector.detector_id,
                locator=Locator(
                    file=ctx.path,
                    start_line=proposal.start_line,
                    # The model gave two lines; nothing here can tell which it
                    # meant, so a backwards span collapses to its start rather
                    # than becoming invalid and being dropped for a reason that
                    # reads as the model's fault.
                    end_line=max(proposal.end_line, proposal.start_line),
                    contract=proposal.contract,
                    function=proposal.function,
                ),
                quote=proposal.quote,
                reasoning=proposal.reasoning,
            )
            for proposal in result.findings
        ),
        tokens=tokens,
    )


def run_one(
    detector: Detector,
    unit: Unit,
    *,
    model: str,
    sub_model: str,
    wall_seconds: int,
    max_calls: int,
    max_tokens: int,
    predictions_per_unit: int,
) -> DetectorRun:
    """One detector against one unit, as the interface requires it to be run."""
    ctx = AnalysisContext(
        source_id=unit.source_id,
        path=unit.path,
        source=unit.source,
        tier=EvidenceTier.SYNTACTIC,
        level=detector.level,
        limits=SubmissionLimits.for_level(
            detector.level,
            wall_seconds=wall_seconds,
            max_model_calls=max_calls,
            max_tokens=max_tokens,
        ),
    )
    try:
        evidence = call_evidence(detector, ctx)
        spec = call_plan(detector, ctx, evidence)
    except SubmissionFault as fault:
        # Attributed to the stage that raised. A crash recorded without its
        # stage reads as a defect in the detector's logic wherever it surfaces.
        return DetectorRun(
            detector_id=detector.detector_id,
            class_id=detector.class_id,
            source_id=unit.source_id,
            outcome=Outcome.INVALID,
            invalid_reason=fault.invalid_reason,
            evidence_tier=ctx.tier,
            declared_limits=list(detector.declared_limits),
        )

    if spec is None:
        # A deterministic detector. `produced_without_a_model` is a claim, and
        # leaving the producer unnamed is not -- the benchmark refuses the
        # latter, which is why this branch says so explicitly.
        return run_detector(detector, ctx, model_findings=(), produced_without_a_model=False)

    answer = ask(detector, ctx, spec.instruction, model=model, sub_model=sub_model)
    if answer.failed is not None:
        # Printed as well as recorded. `InvalidReason` has five values and none
        # of them says *what* the transport did, so a runner that only set the
        # reason would leave the cause nowhere -- and the first thing anybody
        # does with a run of `transport_failure` is go looking for it. A cause
        # recorded wrongly points investigation away from the fix; a cause
        # dropped points it nowhere.
        print(f"\n{unit.source_id} {detector.detector_id}: {answer.failed}", file=sys.stderr)
        # Charged and invalid. The call happened; it measured nothing.
        return DetectorRun(
            detector_id=detector.detector_id,
            class_id=detector.class_id,
            source_id=unit.source_id,
            outcome=Outcome.INVALID,
            invalid_reason=InvalidReason.TRANSPORT_FAILURE,
            evidence_tier=ctx.tier,
            models=[ModelUse(model_id=model, role=ModelRole.MAIN, calls=1, tokens=answer.tokens)],
            declared_limits=list(detector.declared_limits),
        )

    # Capped here as a courtesy, so a runaway model does not fill a file. The
    # cap that counts is the scorer's `--predictions-per-unit`: it is the only
    # layer that sees a whole submission's runs at once, and a cap applied per
    # run cannot see two detectors for one class using the quota between them.
    return run_detector(
        detector,
        ctx,
        model_findings=answer.findings[:predictions_per_unit],
        models=[ModelUse(model_id=model, role=ModelRole.MAIN, calls=1, tokens=answer.tokens)],
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, action="append", required=True, help="Repeatable.")
    parser.add_argument("--model", required=True, help="The main model, as the endpoint names it.")
    parser.add_argument("--sub-model", default=None)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--wall-seconds", type=int, default=30)
    parser.add_argument("--max-calls", type=int, default=4)
    parser.add_argument("--max-tokens", type=int, default=20_000)
    parser.add_argument("--predictions-per-unit", type=int, default=3)
    parser.add_argument("--limit", type=int, default=0, help="Stop after N units. 0 is all.")
    args = parser.parse_args(argv)

    detectors: list[Detector] = []
    for path in args.manifest:
        manifest = SubmissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
        try:
            detectors.append(load_detector(manifest, search_path=path.parent))
        except MalformedSubmission as bad:
            print(f"{path}: {bad}", file=sys.stderr)
            return 2

    written = 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for index, unit in enumerate(units_from(args.records, args.source_root)):
            if args.limit and index >= args.limit:
                break
            for detector in detectors:
                run = run_one(
                    detector,
                    unit,
                    model=args.model,
                    sub_model=args.sub_model or args.model,
                    wall_seconds=args.wall_seconds,
                    max_calls=args.max_calls,
                    max_tokens=args.max_tokens,
                    predictions_per_unit=args.predictions_per_unit,
                )
                handle.write(json.dumps(run.model_dump(mode="json")) + "\n")
                written += 1
            print(f"{index + 1} unit(s), {written} run(s)", end="\r", file=sys.stderr)

    print(f"\nwrote {args.out}: {written} run(s)", file=sys.stderr)
    print(
        "now score it -- precision waits on adjudication, and the queue is in the", file=sys.stderr
    )
    print("document rather than in this runner:", file=sys.stderr)
    print(
        f"  contract-assay score {args.out} --records {args.records} "
        f"--source-root {args.source_root} --submission-id <id> "
        f"--predictions-per-unit {args.predictions_per_unit} --out score.json",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
