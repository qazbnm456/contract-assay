"""A model caller for any OpenAI-compatible chat endpoint. Standard library only.

Use it to try a detector against a real model with no framework in the way, on
Ollama, LM Studio, vLLM or a hosted provider, or read it as the plainest example
of a `ModelCaller` that talks to a model. It makes one request for each detector
and unit: the detector's `plan()` says what to look for, and this adds the source
and asks for findings back as JSON.

    export BYO_MODEL=qwen2.5-coder:32b                # as your endpoint names it
    export BYO_BASE_URL=http://localhost:11434/v1     # the default, Ollama's address
    export BYO_API_KEY=...                            # only if the endpoint wants one

    contract-assay run --manifest access_control.manifest.json \\
        --records corpus/records --source-root ./checkout \\
        --model-caller byo_openai:call --limit 5 --out runs.jsonl

`BYO_TEMPERATURE` is sent when it is set, for repeatable runs on models that accept
one. The model is read when this module is imported, so a missing `BYO_MODEL` ends
`contract-assay run` with one error line instead of failing every unit.

A harness of your own belongs in `byo_caller.py`, not here: this file calls a
model, and `byo_caller.py` calls your code. Neither enforces the budgets. Both
report what the call cost and warn when it went over.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec, check_citation
from contract_assay.harness import ModelReply
from contract_assay.models import Finding, Locator, ModelRole, ModelUse


def _model_from_the_environment() -> str:
    name = os.environ.get("BYO_MODEL")
    if not name:
        raise RuntimeError(
            "set BYO_MODEL to the model's name as your endpoint calls it "
            "(BYO_BASE_URL says where it lives, BYO_API_KEY unlocks it)"
        )
    return name


MODEL = _model_from_the_environment()
BASE_URL = os.environ.get("BYO_BASE_URL", "http://localhost:11434/v1").rstrip("/")
API_KEY = os.environ.get("BYO_API_KEY", "")
TEMPERATURE = os.environ.get("BYO_TEMPERATURE")

SYSTEM = (
    "You review Solidity source for one class of vulnerability and report only what the "
    "source supports. Reply with one JSON object and nothing else, shaped like "
    '{"findings": [{"start_line": 12, "end_line": 14, "quote": "...", "reasoning": "...", '
    '"contract": "Vault", "function": "withdraw"}]}. Line numbers are the ones printed in '
    "the left margin. `quote` is the exact source text of the lines from start_line to "
    "end_line, copied whole lines at a time and without the margin numbers. Reply "
    '{"findings": []} when there is nothing to report.'
)


def build_messages(spec: ModelTaskSpec, ctx: AnalysisContext) -> list[dict[str, str]]:
    """The two messages sent: the rules of the reply, then the task and the numbered source."""
    numbered = "\n".join(
        f"{number:>5} | {line}" for number, line in enumerate(ctx.source.split("\n"), start=1)
    )
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"{spec.instruction}\n\nSource of {ctx.path}:\n\n{numbered}"},
    ]


def parse_findings(content: str, detector: Detector, ctx: AnalysisContext) -> tuple[Finding, ...]:
    """The findings in a model's reply. Raises ValueError that names what is wrong.

    A malformed finding fails the whole reply. Dropping it would leave a run that
    reads `clean` because the model's output could not be parsed, which is an
    error wearing a measurement's clothes.
    """
    # A reasoning model may print its thinking first, and a chat model may fence its JSON.
    text = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("the reply holds no JSON object")
    try:
        document = json.loads(text[start : end + 1])
    except json.JSONDecodeError as bad:
        raise ValueError(f"the reply is not valid JSON: {bad}") from bad
    rows = document.get("findings") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise ValueError('the reply has no "findings" list')

    findings: list[Finding] = []
    for index, row in enumerate(rows, start=1):
        try:
            first, last = int(row["start_line"]), int(row["end_line"])
            quote, reasoning = str(row["quote"]), str(row["reasoning"])
            findings.append(
                Finding(
                    detector_id=detector.detector_id,
                    locator=Locator(
                        file=ctx.path,
                        start_line=first,
                        # The model gave two lines and nothing says which it meant, so a
                        # backwards span collapses to its start.
                        end_line=max(first, last),
                        contract=row.get("contract") or None,
                        function=row.get("function") or None,
                    ),
                    quote=quote,
                    reasoning=reasoning,
                )
            )
        except (KeyError, TypeError, ValueError) as bad:
            raise ValueError(f"finding {index} is malformed: {type(bad).__name__}: {bad}") from bad
    return tuple(findings)


def _tokens(usage: Any) -> int:
    if not isinstance(usage, dict):
        return 0
    return int(usage.get("total_tokens") or 0) or (
        int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0)
    )


def call(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
    request_body: dict[str, Any] = {"model": MODEL, "messages": build_messages(spec, ctx)}
    if TEMPERATURE is not None:
        request_body["temperature"] = float(TEMPERATURE)
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    request = urllib.request.Request(
        f"{BASE_URL}/chat/completions",
        data=json.dumps(request_body).encode("utf-8"),
        headers=headers,
    )

    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=ctx.limits.wall_seconds) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as failure:
        # The server answered, so the call happened, and what it cost is unknown.
        detail = failure.read().decode("utf-8", "replace").strip().replace("\n", " ")[:200]
        used = (ModelUse(model_id=MODEL, role=ModelRole.MAIN, calls=1, tokens=0),)
        return ModelReply(failed=f"HTTP {failure.code} from {BASE_URL}: {detail}", models=used)
    except Exception as failure:
        # Nothing reached the model: a refused connection, a timeout, a reply that is not JSON.
        return ModelReply(failed=f"{type(failure).__name__}: {failure}")

    tokens = _tokens(payload.get("usage"))
    models = (ModelUse(model_id=MODEL, role=ModelRole.MAIN, calls=1, tokens=tokens),)
    seconds = time.monotonic() - started
    for limit, spent, name in (
        (ctx.limits.max_tokens, tokens, "tokens"),
        (ctx.limits.wall_seconds, seconds, "seconds"),
    ):
        if spent > limit:
            # Not enforced here or by `run`. A competition host meters from outside.
            print(
                f"  {ctx.path}: {spent:.0f} {name} exceeds the {limit} a round allows",
                file=sys.stderr,
            )

    try:
        content = payload["choices"][0]["message"]["content"]
        findings = parse_findings(content, detector, ctx)
    except (KeyError, IndexError, TypeError, ValueError) as bad:
        return ModelReply(failed=f"{type(bad).__name__}: {bad}", models=models)

    for finding in findings:
        failure = check_citation(ctx, finding)
        if failure is not None:
            # Reported and still returned: the benchmark records a claim it cannot check
            # as `invalid`, and dropping it would turn that into `clean`.
            print(
                f"  {ctx.path}:{finding.locator.start_line}-{finding.locator.end_line}: the "
                "quote is not whole lines of the source at that range "
                f"({failure.detail or failure.check})",
                file=sys.stderr,
            )
    return ModelReply(findings=findings, models=models)
