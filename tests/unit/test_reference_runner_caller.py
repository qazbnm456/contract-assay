"""The rlm-harness caller, with the model library replaced by a fake.

`tests/live/` needs an endpoint and checks the two things a misconfigured one
gets wrong. Everything that is the caller's own is checked here, offline: the
conversion of a proposal into a finding, the metering, and the three ways a call
can end. `dspy` and `rlm_harness` are stood in for by modules registered for the
length of one test, so nothing here imports a provider.

The runner is loaded from its file under a name of this test's own. Its module
name is `runner` for a user, which is too generic to import by name in a suite
that loads other examples.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from contract_assay.detectors import API_VERSION, Detector
from contract_assay.detectors.base import AnalysisContext, ModelTaskSpec, SubmissionLimits
from contract_assay.harness import SourceUnit, run_submission
from contract_assay.models import (
    EvidenceTier,
    InvalidReason,
    ModelRole,
    Outcome,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline

RUNNER = Path(__file__).resolve().parents[2] / "examples" / "reference_runner" / "runner.py"
VAULT = """\
contract Vault {
    address owner;

    function setOwner(address who) external {
        owner = who;
    }
}
"""


class Asks(Detector):
    detector_id = "asks-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION

    def plan(self, ctx: AnalysisContext, evidence: Any) -> ModelTaskSpec | None:
        return ModelTaskSpec(instruction="look for a guardless setter")


def a_unit() -> SourceUnit:
    return SourceUnit(
        source_id="commit:vault@aaa:src/Vault.sol", path="src/Vault.sol", source=VAULT
    )


def a_context() -> AnalysisContext:
    return AnalysisContext(
        source_id=a_unit().source_id,
        path=a_unit().path,
        source=VAULT,
        tier=EvidenceTier.SYNTACTIC,
        level=Asks().level,
        limits=SubmissionLimits.for_level(
            Asks().level, wall_seconds=30, max_model_calls=4, max_tokens=20_000
        ),
    )


def load(monkeypatch: pytest.MonkeyPatch, **env: str) -> ModuleType:
    for name in ("RLM_MODEL", "RLM_SUB_MODEL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    spec = importlib.util.spec_from_file_location("reference_runner_under_test", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs, as an import would: pydantic resolves the
    # postponed annotations of `Proposals` through `sys.modules`.
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


class Fake:
    """What `dspy` and `rlm_harness` do, as far as the caller can see.

    `answer` is what `RLMTask.run` returns, or an exception it raises, and `usage`
    is what the tracker holds afterwards.
    """

    def __init__(
        self, *, answer: Any = None, usage: dict[str, list[dict[str, int]]] | None = None
    ) -> None:
        self.answer = answer
        self.usage = usage or {}
        self.configured: list[Any] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self

        class Tracker:
            usage_data = fake.usage

        @contextmanager
        def track_usage() -> Iterator[Tracker]:
            yield Tracker()

        class RLMTask:
            def run(self, **_: Any) -> Any:
                if isinstance(fake.answer, Exception):
                    raise fake.answer
                return fake.answer

        monkeypatch.setitem(sys.modules, "dspy", SimpleNamespace(track_usage=track_usage))
        monkeypatch.setitem(
            sys.modules,
            "rlm_harness",
            SimpleNamespace(
                RLMTask=RLMTask,
                RLMConfig=lambda **kwargs: SimpleNamespace(**kwargs),
                configure=fake.configured.append,
            ),
        )


def proposals(module: ModuleType, *rows: tuple[int, int, str]) -> Any:
    return module.Proposals(
        findings=[
            module.Proposal(start_line=a, end_line=b, quote=quote, reasoning="because")
            for a, b, quote in rows
        ]
    )


SET_OWNER = "    function setOwner(address who) external {\n        owner = who;"


class TestTheModelComesFromTheEnvironment:
    def test_a_missing_model_ends_the_import_with_one_clear_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Otherwise every unit comes back `transport_failure` and the run reads
        # like a harness that measures nothing. As an import error it is what
        # `contract-assay run` prints as one red line and exit 2.
        with pytest.raises(RuntimeError, match="RLM_MODEL"):
            load(monkeypatch)

    def test_the_sub_model_defaults_to_the_main_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = load(monkeypatch, RLM_MODEL="m")
        assert (module.MAIN_MODEL, module.SUB_MODEL) == ("m", "m")


class TestMetering:
    def test_tokens_and_calls_are_summed_per_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = load(monkeypatch, RLM_MODEL="big", RLM_SUB_MODEL="small")
        used = module.models_used(
            {
                "openai/big": [
                    {"total_tokens": 100},
                    {"prompt_tokens": 20, "completion_tokens": 5},
                ],
                "openai/small": [{"total_tokens": 7}],
            },
            main="big",
            sub="small",
        )
        by_role = {u.role: u for u in used}
        assert (by_role[ModelRole.MAIN].calls, by_role[ModelRole.MAIN].tokens) == (2, 125)
        assert (by_role[ModelRole.SUB].calls, by_role[ModelRole.SUB].tokens) == (1, 7)
        assert by_role[ModelRole.SUB].model_id == "small"

    def test_an_unrecognised_key_is_charged_to_the_main_model_and_not_lost(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = load(monkeypatch, RLM_MODEL="big", RLM_SUB_MODEL="small")
        [used] = module.models_used(
            {"something-else": [{"total_tokens": 3}]}, main="big", sub="small"
        )
        assert (used.role, used.model_id, used.tokens) == (ModelRole.MAIN, "big", 3)

    def test_one_model_in_both_roles_is_one_main_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = load(monkeypatch, RLM_MODEL="m")
        [used] = module.models_used(
            {"m": [{"total_tokens": 4}], "openai/m": [{"total_tokens": 5}]}, main="m", sub="m"
        )
        assert (used.role, used.calls, used.tokens) == (ModelRole.MAIN, 2, 9)


class TestTheCall:
    def test_a_proposal_becomes_a_verified_finding_and_the_run_names_its_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = load(monkeypatch, RLM_MODEL="m")
        Fake(
            answer=SimpleNamespace(findings=proposals(module, (4, 5, SET_OWNER)).findings),
            usage={"m": [{"total_tokens": 42}]},
        ).install(monkeypatch)
        [run] = run_submission([Asks()], [a_unit()], model=module.rlm_caller)
        assert run.outcome is Outcome.VULNERABLE
        assert [(u.model_id, u.role, u.calls, u.tokens) for u in run.models] == [
            ("m", ModelRole.MAIN, 1, 42)
        ]

    def test_a_backwards_span_collapses_to_its_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = load(monkeypatch, RLM_MODEL="m")
        [finding] = module.to_findings(Asks(), a_context(), proposals(module, (5, 4, "x")).findings)
        assert (finding.locator.start_line, finding.locator.end_line) == (5, 5)
        assert finding.detector_id == "asks-access-control"
        assert finding.locator.file == "src/Vault.sol"

    def test_a_failure_is_a_value_that_keeps_what_the_call_spent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A budget that counted only successes would let a harness retry without
        # limit, so the tokens a failed call used are on the reply.
        module = load(monkeypatch, RLM_MODEL="m")
        Fake(answer=TimeoutError("endpoint timed out"), usage={"m": [{"total_tokens": 9}]}).install(
            monkeypatch
        )
        reply = module.rlm_caller(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert reply.failed == "TimeoutError: endpoint timed out"
        assert [u.tokens for u in reply.models] == [9]
        [run] = run_submission([Asks()], [a_unit()], model=module.rlm_caller)
        assert run.invalid_reason is InvalidReason.TRANSPORT_FAILURE

    def test_a_provider_that_reports_no_usage_still_names_one_call_and_zero_tokens(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The first thing the README tells a newcomer to check is a non-zero token
        # count. A run that names no model is refused, and one that invented a
        # count would hide the very misconfiguration the check is for.
        module = load(monkeypatch, RLM_MODEL="m")
        Fake(answer=SimpleNamespace(findings=[]), usage={}).install(monkeypatch)
        reply = module.rlm_caller(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert reply.failed is None
        assert [(u.calls, u.tokens) for u in reply.models] == [(1, 0)]

    def test_a_missing_model_library_is_a_failed_call_and_not_a_traceback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = load(monkeypatch, RLM_MODEL="m")
        monkeypatch.setitem(sys.modules, "dspy", None)  # `import dspy` raises ImportError
        reply = module.rlm_caller(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert reply.failed is not None and "dspy" in reply.failed
        assert reply.models == ()

    def test_a_call_over_the_wall_clock_is_said_out_loud(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        module = load(monkeypatch, RLM_MODEL="m")
        Fake(answer=SimpleNamespace(findings=[]), usage={"m": [{"total_tokens": 1}]}).install(
            monkeypatch
        )
        ticks = iter([0.0, 31.0])
        monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
        module.rlm_caller(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert "exceeds the 30s a round allows" in capsys.readouterr().err
