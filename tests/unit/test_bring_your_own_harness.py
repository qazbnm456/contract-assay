"""The adapter template, driven the way a newcomer drives it.

`examples/bring_your_own_harness/` is the documented path for somebody testing
their own harness, so it is tested as that path: every manifest through the real
loader, the caller through `run_submission`, and each of the four things its
docstring says are not obvious. A template that rots is worse than none -- it is
copied, and what is copied is the rot.

The example's modules are named `byo_*` and imported by name, as a user's own
would be, so nothing here can collide with `test_example_submission.py`, which
imports the other example as `submission`.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest
from typer.testing import CliRunner

from contract_assay.cli import app
from contract_assay.detectors import API_VERSION, Detector
from contract_assay.detectors.base import AnalysisContext, SubmissionLimits
from contract_assay.detectors.loading import SubmissionManifest, load_detector
from contract_assay.harness import SourceUnit, run_submission
from contract_assay.models import (
    CitationStatus,
    DetectorRun,
    EvidenceTier,
    InvalidReason,
    Outcome,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "bring_your_own_harness"
WALLET = """\
contract Wallet {
    address owner;

    function transferTo(address payable to, uint256 amount) external {
        require(tx.origin == owner);
        to.transfer(amount);
    }
}
"""


def a_unit(name: str = "Wallet") -> SourceUnit:
    return SourceUnit(
        source_id=f"commit:{name}@aaa:src/{name}.sol",
        path=f"src/{name}.sol",
        source=WALLET.replace("Wallet", name),
    )


@pytest.fixture
def byo(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """`byo_caller`, with the memo of the last unit cleared."""
    sys.path.insert(0, str(EXAMPLE))
    try:
        import byo_caller
        import byo_detectors  # noqa: F401
    finally:
        sys.path.remove(str(EXAMPLE))
    monkeypatch.setattr(byo_caller, "_last_source_id", None)
    monkeypatch.setattr(byo_caller, "_last", None)
    return byo_caller


def all_detectors() -> list[Detector]:
    detectors: list[Detector] = []
    for path in sorted(EXAMPLE.glob("*.manifest.json")):
        manifest = SubmissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
        detectors.append(load_detector(manifest, search_path=EXAMPLE))
    return detectors


class TestTheManifests:
    def test_there_is_one_per_class_and_each_resolves(self) -> None:
        detectors = all_detectors()
        assert {d.class_id for d in detectors} == set(VulnerabilityClass)
        assert len({d.detector_id for d in detectors}) == len(VulnerabilityClass)

    @pytest.mark.parametrize(
        "path",
        sorted(EXAMPLE.glob("*.manifest.json")),
        ids=lambda p: p.name.removesuffix(".manifest.json"),
    )
    def test_a_manifest_is_named_for_the_class_it_loads(self, path: Path) -> None:
        manifest = SubmissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
        assert load_detector(
            manifest, search_path=EXAMPLE
        ).class_id.value == path.name.removesuffix(".manifest.json")
        assert manifest.api_version == API_VERSION


class TestTheAdapter:
    def test_the_stand_in_is_found_verified_and_filed_under_the_right_class(
        self, byo: ModuleType
    ) -> None:
        runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call))
        by_class = {run.class_id: run for run in runs}
        assert len(runs) == len(VulnerabilityClass)
        hit = by_class[VulnerabilityClass.ACCESS_CONTROL]
        assert hit.outcome is Outcome.VULNERABLE
        assert [f.status for f in hit.findings] == [CitationStatus.VERIFIED]
        assert hit.findings[0].finding.quote.strip() == "require(tx.origin == owner);"
        # Every other class is a real `clean`, not an error wearing one.
        others = [
            run for cls, run in by_class.items() if cls is not VulnerabilityClass.ACCESS_CONTROL
        ]
        assert {run.outcome for run in others} == {Outcome.CLEAN}

    def test_the_harness_runs_once_per_unit_and_is_charged_once(
        self, byo: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The loop is units outside, detectors inside: without the memo a harness
        # covering nine classes is called nine times over the same file, and
        # without attributing the cost once the metering says it was.
        calls: list[str] = []
        real = byo.analyze

        def counting(source: str):  # type: ignore[no-untyped-def]
            calls.append(source)
            return replace(real(source), model_id="m", calls=3, tokens=900)

        monkeypatch.setattr(byo, "analyze", counting)
        runs = list(run_submission(all_detectors(), [a_unit("A"), a_unit("B")], model=byo.call))
        assert len(calls) == 2
        assert sum(m.calls for run in runs for m in run.models) == 6
        assert sum(m.tokens for run in runs for m in run.models) == 1800
        # Every run names what produced it, including the ones charged nothing.
        assert all(run.models for run in runs)

    def test_a_claim_with_no_class_is_dropped_and_named_not_misfiled(
        self,
        byo: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Dropping is right, since the claim cannot be scored. Dropping in silence
        # is not: a misspelt key made every run `clean` with nothing printed.
        real = byo.analyze

        def unmapped(source: str):  # type: ignore[no-untyped-def]
            analysis = real(source)
            return replace(
                analysis,
                claims=tuple(
                    replace(c, category="a-category-nobody-mapped") for c in analysis.claims
                ),
            )

        monkeypatch.setattr(byo, "analyze", unmapped)
        runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call))
        assert {run.outcome for run in runs} == {Outcome.CLEAN}
        err = capsys.readouterr().err
        assert "'a-category-nobody-mapped'" in err
        # Once per unit, and not once for each of the nine detectors.
        assert err.count("a-category-nobody-mapped") == 1

    def test_a_claim_that_fails_its_citation_is_reported_and_still_returned(
        self,
        byo: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Returned, because the benchmark records an unverifiable claim as `invalid`
        # and dropping it here would turn that into `clean`.
        real = byo.analyze

        def half_a_line(source: str):  # type: ignore[no-untyped-def]
            analysis = real(source)
            return replace(
                analysis,
                claims=tuple(replace(c, quote="require(tx.origin") for c in analysis.claims),
            )

        monkeypatch.setattr(byo, "analyze", half_a_line)
        runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call))
        hit = next(run for run in runs if run.class_id is VulnerabilityClass.ACCESS_CONTROL)
        assert hit.outcome is Outcome.INVALID
        assert hit.invalid_reason is InvalidReason.CITATION_UNVERIFIED
        assert "src/Wallet.sol:5-5" in capsys.readouterr().err

    def test_a_second_sweep_over_the_same_unit_runs_the_harness_again(
        self, byo: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The memo keeps one unit, and a detector asking twice for it means a new
        # sweep: reusing the first sweep's result would report zero tokens for it.
        calls: list[str] = []
        real = byo.analyze

        def counting(source: str):  # type: ignore[no-untyped-def]
            calls.append(source)
            return replace(real(source), model_id="m", calls=1, tokens=900)

        monkeypatch.setattr(byo, "analyze", counting)
        for _ in range(2):
            runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call))
            assert sum(m.tokens for run in runs for m in run.models) == 900
        assert len(calls) == 2

    def test_a_failing_harness_is_one_invalid_run_per_class_with_its_cause(
        self, byo: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[int] = []

        def boom(source: str):  # type: ignore[no-untyped-def]
            attempts.append(1)
            raise RuntimeError("boom")

        monkeypatch.setattr(byo, "analyze", boom)
        causes: list[str] = []
        runs: Sequence[DetectorRun] = list(
            run_submission(
                all_detectors(),
                [a_unit()],
                model=byo.call,
                on_failure=lambda unit, detector, cause: causes.append(cause),
            )
        )
        assert {run.invalid_reason for run in runs} == {InvalidReason.TRANSPORT_FAILURE}
        assert causes == ["RuntimeError: boom"] * len(VulnerabilityClass)
        assert len(attempts) == 1


class TestAHarnessThatWorksOneClassAtATime:
    """`call_per_class`: each detector's class and instruction go to the harness, in turn."""

    def test_the_harness_is_asked_once_for_each_class_with_that_classs_instruction(
        self, byo: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[tuple[str, str]] = []
        real = byo.analyze_class

        def recording(source: str, class_id: str, instruction: str):  # type: ignore[no-untyped-def]
            asked.append((class_id, instruction))
            return real(source, class_id, instruction)

        monkeypatch.setattr(byo, "analyze_class", recording)
        runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call_per_class))
        assert sorted(c for c, _ in asked) == sorted(c.value for c in VulnerabilityClass)
        # What each detector's `plan()` said is what its class was asked.
        assert all(instruction for _, instruction in asked)
        assert len({instruction for _, instruction in asked}) == len(VulnerabilityClass)
        hit = next(run for run in runs if run.class_id is VulnerabilityClass.ACCESS_CONTROL)
        assert hit.outcome is Outcome.VULNERABLE
        assert [f.status for f in hit.findings] == [CitationStatus.VERIFIED]
        assert {run.outcome for run in runs if run is not hit} == {Outcome.CLEAN}

    def test_each_call_is_charged_what_it_cost(
        self, byo: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Nothing is shared between detectors here, so nothing is charged once for all.
        real = byo.analyze_class

        def costly(source: str, class_id: str, instruction: str):  # type: ignore[no-untyped-def]
            return replace(real(source, class_id, instruction), model_id="m", calls=2, tokens=100)

        monkeypatch.setattr(byo, "analyze_class", costly)
        runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call_per_class))
        assert sum(m.calls for run in runs for m in run.models) == 2 * len(VulnerabilityClass)
        assert sum(m.tokens for run in runs for m in run.models) == 100 * len(VulnerabilityClass)

    def test_a_failure_is_one_invalid_run_with_its_cause_for_that_class_only(
        self, byo: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = byo.analyze_class

        def flaky(source: str, class_id: str, instruction: str):  # type: ignore[no-untyped-def]
            if class_id == "reentrancy":
                raise RuntimeError("the reentrancy skill timed out")
            return real(source, class_id, instruction)

        monkeypatch.setattr(byo, "analyze_class", flaky)
        causes: list[str] = []
        runs = list(
            run_submission(
                all_detectors(),
                [a_unit()],
                model=byo.call_per_class,
                on_failure=lambda unit, detector, cause: causes.append(cause),
            )
        )
        invalid = [run for run in runs if run.outcome is Outcome.INVALID]
        assert [run.class_id for run in invalid] == [VulnerabilityClass.REENTRANCY]
        assert causes == ["RuntimeError: the reentrancy skill timed out"]
        assert any(run.outcome is Outcome.VULNERABLE for run in runs)

    def test_a_claim_that_fails_its_citation_is_reported_and_still_returned(
        self,
        byo: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        real = byo.analyze_class

        def half_a_line(source: str, class_id: str, instruction: str):  # type: ignore[no-untyped-def]
            found = real(source, class_id, instruction)
            return replace(
                found, claims=tuple(replace(c, quote="require(tx.origin") for c in found.claims)
            )

        monkeypatch.setattr(byo, "analyze_class", half_a_line)
        runs = list(run_submission(all_detectors(), [a_unit()], model=byo.call_per_class))
        hit = next(run for run in runs if run.class_id is VulnerabilityClass.ACCESS_CONTROL)
        assert hit.invalid_reason is InvalidReason.CITATION_UNVERIFIED
        assert "src/Wallet.sol:5-5" in capsys.readouterr().err


class TestTheCommandAsItIsDocumented:
    """`contract-assay run` with the example's own manifests, from a directory that is not its own.

    The loader looks for a manifest's detector module in the manifest's directory
    only, so the command works when the manifests sit beside the modules and fails
    with `No module named 'byo_detectors'` when they do not. Other tests here
    import the example's modules, and `load_detector` leaves their directory on
    `sys.path`, so this one removes both before it runs the command. Without that
    it passes whatever the layout is.
    """

    def a_checkout(self, root: Path) -> None:
        (root / "src").mkdir()
        (root / "src" / "Wallet.sol").write_text(WALLET, encoding="utf-8")
        (root / "records").mkdir()
        (root / "records" / "wallet.json").write_text(
            json.dumps(
                {
                    "record_id": "wallet-access-control-1",
                    "split": "public",
                    "pin": {
                        "kind": "commit",
                        "repo_url": "https://github.com/example/wallet",
                        "commit": "a" * 40,
                        "path": "src/Wallet.sol",
                        "sha256": hashlib.sha256(WALLET.encode()).hexdigest(),
                    },
                    "locator": {
                        "file": "src/Wallet.sol",
                        "contract": "Wallet",
                        "function": "transferTo",
                        "start_line": 4,
                        "end_line": 7,
                    },
                    "population": "audit_review",
                    "locator_provenance": "stated",
                    "classes": ["access_control"],
                    "provenance": {
                        "platform": "example-platform",
                        "report_url": "https://example.invalid/report/1",
                    },
                }
            ),
            encoding="utf-8",
        )

    def test_the_documented_command_runs_and_the_stand_in_is_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.a_checkout(tmp_path)
        monkeypatch.chdir(tmp_path)
        for name in ("byo_caller", "byo_detectors", "byo_harness"):
            monkeypatch.delitem(sys.modules, name, raising=False)
        monkeypatch.setattr(
            sys, "path", [p for p in sys.path if Path(p or ".").resolve() != EXAMPLE.resolve()]
        )
        out = tmp_path / "runs.jsonl"
        result = CliRunner().invoke(
            app,
            [
                "run",
                "--manifest",
                str(EXAMPLE / "access_control.manifest.json"),
                "--manifest",
                str(EXAMPLE / "reentrancy.manifest.json"),
                "--records",
                str(tmp_path / "records"),
                "--source-root",
                str(tmp_path),
                "--model-caller",
                "byo_caller:call",
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "never called" not in result.output
        assert "invalid" not in result.output
        runs = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        assert {run["class_id"]: run["outcome"] for run in runs} == {
            "access_control": "vulnerable",
            "reentrancy": "clean",
        }
        assert all(run["models"] for run in runs)


class TestThePlanIsWhatMakesTheModelRun:
    def test_three_declarations_never_reach_the_adapter(self, byo: ModuleType) -> None:
        # The first mistake a newcomer makes, and silent: every run `clean`, no
        # error, `models` empty. `byo_detectors` says so in its docstring, and
        # `contract-assay run` warns; this pins the behaviour both rely on.
        class ThreeDeclarations(Detector):
            detector_id = "three-declarations"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

        def never(detector, spec, ctx: AnalysisContext):  # type: ignore[no-untyped-def]
            raise AssertionError("a detector whose plan() is None must not ask for a model")

        [run] = run_submission([ThreeDeclarations()], [a_unit()], model=never)
        assert run.outcome is Outcome.CLEAN
        assert run.models == []
        assert not run.produced_without_a_model

    def test_the_example_detectors_do_ask(self) -> None:
        for detector in all_detectors():
            ctx = AnalysisContext(
                source_id=a_unit().source_id,
                path=a_unit().path,
                source=WALLET,
                tier=EvidenceTier.SYNTACTIC,
                level=detector.level,
                limits=SubmissionLimits.for_level(
                    detector.level, wall_seconds=30, max_model_calls=4, max_tokens=20_000
                ),
            )
            spec = detector.plan(ctx, ())
            assert spec is not None and spec.instruction
            # The contract is a variable the model explores; it is never pasted in.
            assert WALLET not in spec.instruction


def test_the_manifests_are_valid_json_with_one_entry_point_each() -> None:
    for path in EXAMPLE.glob("*.manifest.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert set(document) == {"submission_id", "api_version", "entry_point", "author"}
