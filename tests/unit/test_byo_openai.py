"""The standard-library model caller, against a fake endpoint on localhost.

Nothing here reaches a model or the network. A server on a free local port plays
the endpoint, so the request the caller sends and every way the answer can go
wrong are checked for real, over HTTP, and nothing is mocked inside the caller.

The module is loaded from its file under a name of this test's own, with the
environment set first, because it reads its model when it is imported.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
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

CALLER = (
    Path(__file__).resolve().parents[2] / "examples" / "bring_your_own_harness" / "byo_openai.py"
)
VAULT = """\
contract Vault {
    address owner;

    function setOwner(address who) external {
        owner = who;
    }
}
"""
SET_OWNER = "    function setOwner(address who) external {\n        owner = who;"


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


class Endpoint:
    """What the fake server answers, and what it was asked."""

    def __init__(self) -> None:
        self.status = 200
        self.body: Any = {}
        self.requests: list[dict[str, Any]] = []
        self.headers: list[Any] = []

    def reply(self, content: str, *, usage: dict[str, int] | None = None) -> None:
        self.status = 200
        self.body = {"choices": [{"message": {"content": content}}], "usage": usage or {}}


@contextmanager
def serving(endpoint: Endpoint) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            endpoint.requests.append(json.loads(self.rfile.read(length)))
            endpoint.headers.append(self.headers)
            raw = endpoint.body if isinstance(endpoint.body, str) else json.dumps(endpoint.body)
            self.send_response(endpoint.status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw.encode("utf-8"))

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1"
    finally:
        server.shutdown()
        server.server_close()


def load(
    monkeypatch: pytest.MonkeyPatch, base_url: str = "http://127.0.0.1:9/v1", **env: str
) -> ModuleType:
    for name in ("BYO_MODEL", "BYO_BASE_URL", "BYO_API_KEY", "BYO_TEMPERATURE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BYO_MODEL", "m")
    monkeypatch.setenv("BYO_BASE_URL", base_url)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    spec = importlib.util.spec_from_file_location("byo_openai_under_test", CALLER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def one_finding(first: int = 4, last: int = 5, quote: str = SET_OWNER) -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "start_line": first,
                    "end_line": last,
                    "quote": quote,
                    "reasoning": "anyone can take ownership",
                    "contract": "Vault",
                    "function": "setOwner",
                }
            ]
        }
    )


class TestTheEnvironment:
    def test_a_missing_model_ends_the_import_with_one_clear_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("BYO_MODEL", raising=False)
        spec = importlib.util.spec_from_file_location("byo_openai_no_model", CALLER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, module)
        with pytest.raises(RuntimeError, match="BYO_MODEL"):
            spec.loader.exec_module(module)


class TestTheRequest:
    def test_it_sends_the_instruction_the_numbered_source_and_the_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.reply('{"findings": []}')
        with serving(endpoint) as url:
            module = load(monkeypatch, url)
            module.call(
                Asks(), ModelTaskSpec(instruction="look for a guardless setter"), a_context()
            )
        [request] = endpoint.requests
        assert request["model"] == "m"
        user = request["messages"][1]["content"]
        assert "look for a guardless setter" in user
        assert "    4 |     function setOwner(address who) external {" in user
        assert "temperature" not in request

    def test_a_key_is_sent_only_when_there_is_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        endpoint = Endpoint()
        endpoint.reply('{"findings": []}')
        with serving(endpoint) as url:
            module = load(monkeypatch, url, BYO_API_KEY="secret", BYO_TEMPERATURE="0")
            module.call(Asks(), ModelTaskSpec(instruction="x"), a_context())
            bare = load(monkeypatch, url)
            bare.call(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert endpoint.headers[0]["Authorization"] == "Bearer secret"
        assert endpoint.requests[0]["temperature"] == 0.0
        assert endpoint.headers[1]["Authorization"] is None


class TestTheAnswer:
    def test_a_finding_is_verified_and_the_run_names_the_model_and_its_tokens(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.reply(one_finding(), usage={"total_tokens": 321})
        with serving(endpoint) as url:
            module = load(monkeypatch, url)
            [run] = run_submission([Asks()], [a_unit()], model=module.call)
        assert run.outcome is Outcome.VULNERABLE
        assert [(u.model_id, u.role, u.calls, u.tokens) for u in run.models] == [
            ("m", ModelRole.MAIN, 1, 321)
        ]
        assert run.findings[0].finding.locator.function == "setOwner"

    def test_tokens_fall_back_to_prompt_plus_completion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.reply('{"findings": []}', usage={"prompt_tokens": 100, "completion_tokens": 20})
        with serving(endpoint) as url:
            reply = load(monkeypatch, url).call(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert [u.tokens for u in reply.models] == [120]

    def test_thinking_and_a_code_fence_around_the_json_are_tolerated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.reply("<think>maybe {not json}</think>\n```json\n" + one_finding() + "\n```")
        with serving(endpoint) as url:
            reply = load(monkeypatch, url).call(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert reply.failed is None and len(reply.findings) == 1

    def test_a_backwards_span_collapses_to_its_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        endpoint = Endpoint()
        endpoint.reply(one_finding(first=5, last=4, quote="        owner = who;"))
        with serving(endpoint) as url:
            reply = load(monkeypatch, url).call(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert (reply.findings[0].locator.start_line, reply.findings[0].locator.end_line) == (5, 5)

    def test_nothing_to_report_is_a_clean_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        endpoint = Endpoint()
        endpoint.reply('{"findings": []}', usage={"total_tokens": 5})
        with serving(endpoint) as url:
            [run] = run_submission([Asks()], [a_unit()], model=load(monkeypatch, url).call)
        assert run.outcome is Outcome.CLEAN


class TestEveryWayItCanGoWrongIsAValueWithACause:
    def failed(self, monkeypatch: pytest.MonkeyPatch, endpoint: Endpoint) -> Any:
        with serving(endpoint) as url:
            return load(monkeypatch, url).call(Asks(), ModelTaskSpec(instruction="x"), a_context())

    def test_an_http_error_names_the_status_and_still_counts_the_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.status, endpoint.body = 429, {"error": "rate limited"}
        reply = self.failed(monkeypatch, endpoint)
        assert reply.failed is not None and reply.failed.startswith("HTTP 429")
        assert "rate limited" in reply.failed
        assert [(u.calls, u.tokens) for u in reply.models] == [(1, 0)]

    def test_a_refused_connection_names_the_cause_and_charges_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Port 9 is the discard service, which nothing listens on locally.
        reply = load(monkeypatch).call(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert reply.failed is not None and "URLError" in reply.failed
        assert reply.models == ()

    @pytest.mark.parametrize(
        ("content", "fragment"),
        [
            ("I could not find anything.", "no JSON object"),
            ("{not json}", "not valid JSON"),
            ('{"issues": []}', '"findings" list'),
            ('{"findings": [{"start_line": 1}]}', "finding 1 is malformed"),
            (
                '{"findings": [{"start_line": 0, "end_line": 1, "quote": "x", "reasoning": "y"}]}',
                "finding 1 is malformed",
            ),
        ],
    )
    def test_an_unusable_answer_fails_the_call_with_what_was_wrong_and_keeps_the_cost(
        self, monkeypatch: pytest.MonkeyPatch, content: str, fragment: str
    ) -> None:
        # Dropping the bad finding would leave a run that reads `clean` because the
        # output could not be parsed.
        endpoint = Endpoint()
        endpoint.reply(content, usage={"total_tokens": 7})
        reply = self.failed(monkeypatch, endpoint)
        assert reply.failed is not None and fragment in reply.failed
        assert [u.tokens for u in reply.models] == [7]

    def test_a_reply_that_is_not_a_chat_completion_fails_the_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.body = {"unexpected": True}
        reply = self.failed(monkeypatch, endpoint)
        assert reply.failed is not None and "KeyError" in reply.failed

    def test_through_run_submission_it_is_an_invalid_run_with_the_cause_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = Endpoint()
        endpoint.status, endpoint.body = 500, {"error": "boom"}
        causes: list[str] = []
        with serving(endpoint) as url:
            [run] = run_submission(
                [Asks()],
                [a_unit()],
                model=load(monkeypatch, url).call,
                on_failure=lambda unit, detector, cause: causes.append(cause),
            )
        assert run.invalid_reason is InvalidReason.TRANSPORT_FAILURE
        assert causes and causes[0].startswith("HTTP 500")


class TestACitationThatDoesNotHold:
    def test_it_is_reported_and_still_returned_so_the_run_is_invalid_and_not_clean(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        endpoint = Endpoint()
        endpoint.reply(
            one_finding(quote="function setOwner(address who"), usage={"total_tokens": 9}
        )
        with serving(endpoint) as url:
            [run] = run_submission([Asks()], [a_unit()], model=load(monkeypatch, url).call)
        assert run.outcome is Outcome.INVALID
        assert run.invalid_reason is InvalidReason.CITATION_UNVERIFIED
        assert "src/Vault.sol:4-5" in capsys.readouterr().err

    def test_a_call_over_the_token_budget_is_said_out_loud(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        endpoint = Endpoint()
        endpoint.reply('{"findings": []}', usage={"total_tokens": 20_001})
        with serving(endpoint) as url:
            load(monkeypatch, url).call(Asks(), ModelTaskSpec(instruction="x"), a_context())
        assert "exceeds the 20000 a round allows" in capsys.readouterr().err
