"""The one test a model is needed for, and the only thing it establishes.

Excluded from the default gate (`pytest -m offline`), because a test that needs
a provider is a test that fails for reasons unrelated to the code. Run it
deliberately:

    pip install -e . -r examples/reference_runner/requirements.txt
    export RLM_BASE_URL=http://localhost:11434/v1
    export RLM_API_KEY=local
    CONTRACT_ASSAY_LIVE_MODEL=qwen2.5-coder:32b pytest -m live

What it checks is not a score. Two things a misconfigured endpoint gets wrong
**while appearing to work**, both of which make a working harness look like one
that finds nothing:

1. **Usage is reported.** A provider that returns no token counts meters every
   run at zero, and every budget built on that is decoration. Nothing else in
   the system can notice.
2. **The model quotes rather than paraphrases.** A quote that is not at the
   locator fails the citation check, and the run comes back `invalid` -- which
   means it measured nothing, not that it was wrong.

Everything else about the caller is established offline, without a model, in
`tests/unit/test_reference_runner_caller.py`, and the detector in
`tests/unit/test_example_submission.py`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from contract_assay.detectors.base import AnalysisContext, SubmissionLimits, check_citation
from contract_assay.detectors.loading import SubmissionManifest, load_detector
from contract_assay.harness import SourceUnit, run_submission
from contract_assay.models import CitationStatus, DifficultyLevel, EvidenceTier, Outcome

pytestmark = pytest.mark.live

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "reference_runner"
VAULT = """\
contract Vault {
    address owner;

    function setOwner(address who) external {
        owner = who;
    }
}
"""


@pytest.fixture(scope="module")
def runner():  # type: ignore[no-untyped-def]
    pytest.importorskip("rlm_harness", reason="pip install -r requirements.txt in the example")
    if not (os.environ.get("RLM_BASE_URL") or os.environ.get("ANTHROPIC_API_KEY")):
        pytest.skip("set RLM_BASE_URL (or an API key) to run the live test")
    # The caller reads its model when it is imported, so the test names it first.
    os.environ.setdefault("RLM_MODEL", model_name())
    sys.path.insert(0, str(EXAMPLE))
    try:
        import runner as module
    finally:
        sys.path.remove(str(EXAMPLE))
    return module


@pytest.fixture(scope="module")
def detector():  # type: ignore[no-untyped-def]
    manifest = SubmissionManifest.model_validate_json(
        (EXAMPLE / "manifest.json").read_text(encoding="utf-8")
    )
    return load_detector(manifest, search_path=EXAMPLE)


def a_context() -> AnalysisContext:
    return AnalysisContext(
        source_id="commit:vault@aaa:src/Vault.sol",
        path="src/Vault.sol",
        source=VAULT,
        tier=EvidenceTier.SYNTACTIC,
        level=DifficultyLevel.M,
        limits=SubmissionLimits.for_level(
            DifficultyLevel.M, wall_seconds=60, max_model_calls=4, max_tokens=20_000
        ),
    )


def model_name() -> str:
    return os.environ.get("CONTRACT_ASSAY_LIVE_MODEL", "claude-sonnet-5")


def a_unit() -> SourceUnit:
    return SourceUnit(
        source_id="commit:vault@aaa:src/Vault.sol", path="src/Vault.sol", source=VAULT
    )


class TestTheEndpointIsWiredUp:
    def test_one_unit_produces_a_metered_run(self, runner, detector) -> None:  # type: ignore[no-untyped-def]
        [run] = run_submission([detector], [a_unit()], model=runner.rlm_caller)

        # The run has to name what produced it, whatever it concluded. A figure
        # that cannot say what produced it cannot be compared with one produced
        # by something else.
        assert run.models or run.produced_without_a_model

        if run.outcome is Outcome.INVALID:
            pytest.fail(f"the call failed: {run.invalid_reason}")

        # (1) Usage reported. Nothing else in the system can notice a provider
        # that returns none -- it would meter every submission at zero.
        assert run.models, "no model recorded: the call did not happen"
        assert run.models[0].tokens > 0, (
            "the endpoint reported no token usage. Every budget in a round is "
            "built on this number; with zero, they are all decoration"
        )

    def test_a_returned_finding_quotes_the_source(self, runner, detector) -> None:  # type: ignore[no-untyped-def]
        ctx = a_context()
        spec = detector.plan(ctx, detector.evidence(ctx))
        reply = runner.rlm_caller(detector, spec, ctx)
        if reply.failed is not None:
            pytest.fail(f"the call failed: {reply.failed}")
        if not reply.findings:
            pytest.skip(
                "the model reported nothing on this file, which is a result rather "
                "than a wiring problem -- rerun against a file it does report on"
            )
        # (2) Quoted, not paraphrased. A paraphrase fails the citation check and
        # the run comes back `invalid`: it measured nothing, which is a different
        # fact from being wrong and reads like a harness that finds nothing.
        failures = [check_citation(ctx, finding) for finding in reply.findings]
        assert any(failure is None for failure in failures), (
            "every finding failed its citation check. The model is paraphrasing "
            "rather than quoting; try RLM_ADAPTER=json, or a larger model"
        )

    def test_the_run_verifies_end_to_end(self, runner, detector) -> None:  # type: ignore[no-untyped-def]
        [run] = run_submission([detector], [a_unit()], model=runner.rlm_caller)
        if run.outcome is Outcome.INVALID:
            pytest.fail(f"the call failed: {run.invalid_reason}")
        # Whatever it concluded, the record has to be internally consistent: a
        # verified finding means the quote was found at the locator, and the
        # outcome follows from the findings rather than from the model's say-so.
        verified = [f for f in run.findings if f.status is CitationStatus.VERIFIED]
        assert (run.outcome is Outcome.VULNERABLE) == bool(verified)
