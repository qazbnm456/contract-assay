"""The defaults, the deterministic baseline, and the loop between them.

These cover the two claims `docs/api.md` §1 makes that nothing used to check:
that three declarations are a complete submission, and that a detector running
no model can report something. The second was false for as long as `propose()`
did not exist -- findings reached a run only through the host's model call, so a
deterministic detector could report nothing but `clean` while the documents
called static analysis this benchmark's own control group.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from contract_assay.corpus.records import (
    CommitPin,
    CorpusRecord,
    CorpusSplit,
    Population,
    Provenance,
)
from contract_assay.detectors import API_VERSION, Detector, PredicateDetector
from contract_assay.detectors.base import AnalysisContext, ModelTaskSpec, SubmissionLimits
from contract_assay.harness import (
    ModelReply,
    SourceUnit,
    load_caller,
    run_submission,
    units_from,
)
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
    CitationStatus,
    EvidenceRef,
    EvidenceTier,
    FailedCheck,
    Finding,
    InvalidReason,
    Locator,
    ModelRole,
    ModelUse,
    Outcome,
    RejectionKind,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline

PATH = "src/Vault.sol"
VAULT = """\
contract Vault {
    address owner;
    uint256 total;

    function setOwner(address who) external {
        owner = who;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        total = total - amount;
    }
}
"""


def a_unit() -> SourceUnit:
    return SourceUnit(source_id="commit:vault@aaa:" + PATH, path=PATH, source=VAULT)


def a_context(detector: Detector) -> AnalysisContext:
    return AnalysisContext(
        source_id=a_unit().source_id,
        path=PATH,
        source=VAULT,
        tier=EvidenceTier.SYNTACTIC,
        level=detector.level,
        limits=SubmissionLimits.for_level(
            detector.level, wall_seconds=30, max_model_calls=4, max_tokens=20_000
        ),
    )


class Minimal(Detector):
    detector_id = "minimal-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION


class Baseline(PredicateDetector):
    detector_id = "baseline-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION


class TestThreeDeclarationsAreASubmission:
    def test_a_detector_with_no_methods_instantiates_and_runs(self) -> None:
        # `docs/api.md` §1 promises this. Nothing checked it before.
        runs = list(run_submission([Minimal()], [a_unit()]))
        assert len(runs) == 1
        assert runs[0].outcome in {Outcome.CLEAN, Outcome.VULNERABLE}

    def test_the_default_evidence_is_the_benchmarks_own(self) -> None:
        # The point of the default: two submissions differ by what they
        # conclude, not by who wrote the better parser query.
        evidence = Minimal().evidence(a_context(Minimal()))
        assert evidence, "the default evidence layer established nothing on a guardless setter"
        assert all(ref.locator.file == PATH for ref in evidence)
        assert {ref.predicate for ref in evidence} == {
            "state_change_reachable_without_modifier_or_sender_reference"
        }

    def test_the_default_asserts_nothing(self) -> None:
        # An evidence item is a precondition, not a claim. A default that turned
        # every one into a finding would make every model-driven detector start
        # claiming its own preconditions.
        detector = Minimal()
        ctx = a_context(detector)
        assert detector.propose(ctx, detector.evidence(ctx)) == ()

    def test_the_default_verdict_rejects_nothing(self) -> None:
        detector = Minimal()
        ctx = a_context(detector)
        finding = Finding(
            detector_id=detector.detector_id,
            locator=Locator(
                file=PATH, contract="Vault", function="setOwner", start_line=6, end_line=6
            ),
            quote="        owner = who;",
            reasoning="anyone can take ownership",
        )
        assert list(detector.verdict(ctx, finding, [])) == []


class TestTheDeterministicBaselineCanActuallyReport:
    def test_a_predicate_detector_produces_verified_findings_with_no_model(self) -> None:
        # The claim that was false until `propose()` existed.
        runs = list(run_submission([Baseline()], [a_unit()]))
        assert len(runs) == 1
        run = runs[0]
        assert run.outcome is Outcome.VULNERABLE
        assert run.findings, "a static-analysis submission reported nothing"
        assert all(f.status is CitationStatus.VERIFIED for f in run.findings)

    def test_its_citations_pass_by_construction(self) -> None:
        # It quotes the source at the evidence item's own locator, so a
        # deterministic finding has no excuse for failing the citation check.
        run = next(iter(run_submission([Baseline()], [a_unit()])))
        assert not any(f.has_citation_failure for f in run.findings)

    def test_it_names_code_as_its_producer(self) -> None:
        # Set by the runner, which is the only layer that knows `propose()` was
        # called -- so a host cannot forget what it was never asked.
        run = next(iter(run_submission([Baseline()], [a_unit()])))
        assert run.produced_without_a_model is True
        assert run.models == []

    def test_a_proposed_finding_is_still_subject_to_the_verdict(self) -> None:
        # No exemption for being cheap to produce.
        class Fussy(PredicateDetector):
            detector_id = "fussy-access-control"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def verdict(
                self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
            ) -> Sequence[FailedCheck]:
                return [FailedCheck(check="never_accept", kind=RejectionKind.VERDICT)]

        run = next(iter(run_submission([Fussy()], [a_unit()])))
        assert run.outcome is Outcome.CLEAN
        assert [c.check for f in run.findings for c in f.failed_checks] == ["never_accept"]

    def test_a_proposed_finding_whose_quote_is_wrong_is_caught(self) -> None:
        # The citation check is the host's and runs first, whoever produced the
        # finding.
        class Liar(Detector):
            detector_id = "liar-access-control"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def propose(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> Sequence[Finding]:
                return [
                    Finding(
                        detector_id=self.detector_id,
                        locator=Locator(
                            file=PATH,
                            contract="Vault",
                            function="setOwner",
                            start_line=6,
                            end_line=6,
                        ),
                        quote="owner = msg.sender;",
                        reasoning="not what the source says",
                    )
                ]

        run = next(iter(run_submission([Liar()], [a_unit()])))
        assert run.outcome is Outcome.INVALID
        assert run.invalid_reason is InvalidReason.CITATION_UNVERIFIED


class TestTheLoop:
    def test_a_model_caller_supplies_findings_and_names_itself(self) -> None:
        class Planner(Detector):
            detector_id = "planner-access-control"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def plan(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> ModelTaskSpec | None:
                return ModelTaskSpec(instruction="look for a guardless setter")

        def caller(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
            return ModelReply(
                findings=(
                    Finding(
                        detector_id=detector.detector_id,
                        locator=Locator(
                            file=PATH,
                            contract="Vault",
                            function="setOwner",
                            start_line=5,
                            end_line=6,
                        ),
                        quote="    function setOwner(address who) external {\n        owner = who;",
                        reasoning="anyone can take ownership",
                    ),
                ),
                models=(ModelUse(model_id="m", role=ModelRole.MAIN, calls=1, tokens=42),),
            )

        run = next(iter(run_submission([Planner()], [a_unit()], model=caller)))
        assert run.outcome is Outcome.VULNERABLE
        assert [u.tokens for u in run.models] == [42]

    def test_it_hands_over_only_what_the_scorer_will_count(self) -> None:
        # Otherwise a submission emits everything, the scorer charges for all of
        # it in this loop's own unit order, and the cap's own defence -- "the
        # order is the submission's own, so spending slots on guesses is its
        # choice" -- describes a choice the documented workflow never offered. A
        # review reverted this default to `None` and the whole suite stayed
        # green, which is why the assertion is here and not only in the scorer's.
        class Planner(Detector):
            detector_id = "planner-capped"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def plan(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> ModelTaskSpec | None:
                return ModelTaskSpec(instruction="look for a guardless setter")

        def caller(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
            return ModelReply(
                findings=tuple(
                    Finding(
                        detector_id=detector.detector_id,
                        locator=Locator(file=PATH, start_line=5, end_line=6),
                        quote="    function setOwner(address who) external {\n        owner = who;",
                        reasoning=f"claim {index}",
                    )
                    for index in range(DEFAULT_PREDICTIONS_PER_UNIT + 3)
                ),
                models=(ModelUse(model_id="m", role=ModelRole.MAIN, calls=1, tokens=1),),
            )

        run = next(iter(run_submission([Planner()], [a_unit()], model=caller)))
        assert len(run.findings) == DEFAULT_PREDICTIONS_PER_UNIT

    def test_a_failed_call_is_invalid_and_keeps_its_cost(self) -> None:
        # A call that happened and returned nothing still cost tokens, and the
        # run measured nothing rather than finding nothing.
        class Planner(Detector):
            detector_id = "planner-2"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def plan(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> ModelTaskSpec | None:
                return ModelTaskSpec(instruction="ask")

        def caller(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
            return ModelReply(
                models=(ModelUse(model_id="m", role=ModelRole.MAIN, calls=1, tokens=7),),
                failed="TimeoutError: the endpoint did not answer",
            )

        run = next(iter(run_submission([Planner()], [a_unit()], model=caller)))
        assert run.outcome is Outcome.INVALID
        assert run.invalid_reason is InvalidReason.TRANSPORT_FAILURE
        assert [u.tokens for u in run.models] == [7]

    def test_a_planned_call_the_host_never_made_is_not_a_measurement(self) -> None:
        # This test previously asserted the opposite -- `Outcome.CLEAN` -- and so
        # locked in the founding conflation this package refuses one layer down:
        # a real-looking zero attributed to the detector, indistinguishable
        # afterwards from having looked and found nothing. A review caught both
        # the behaviour and the test blessing it.
        class Planner(Detector):
            detector_id = "planner-3"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def plan(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> ModelTaskSpec | None:
                return ModelTaskSpec(instruction="ask")

        run = next(iter(run_submission([Planner()], [a_unit()])))
        assert run.outcome is Outcome.INVALID
        assert run.invalid_reason is InvalidReason.MODEL_NOT_PERMITTED
        assert run.outcome.is_measurement is False

    def test_a_detector_that_plans_nothing_is_still_a_clean_measurement(self) -> None:
        # The other half: a detector that asked for no model measured the unit.
        run = next(iter(run_submission([Minimal()], [a_unit()])))
        assert run.outcome is Outcome.CLEAN
        assert run.models == []

    def test_a_caller_that_raises_costs_one_unit_and_not_the_sweep(self) -> None:
        # `ModelReply` states that a failed call is a value and never an
        # exception, then asserted that about third-party code while enforcing it
        # nowhere. Every real HTTP client raises.
        class Planner(Detector):
            detector_id = "planner-4"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def plan(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> ModelTaskSpec | None:
                return ModelTaskSpec(instruction="ask")

        def caller(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
            raise ConnectionResetError("the endpoint hung up")

        runs = list(run_submission([Planner()], [a_unit(), a_unit()], model=caller))
        assert len(runs) == 2, "the sweep ended instead of costing one unit"
        assert all(r.invalid_reason is InvalidReason.TRANSPORT_FAILURE for r in runs)

    def test_a_detector_may_both_propose_and_call_a_model(self) -> None:
        # This crashed: `DetectorRun` forbade naming two producers, and the
        # refusal was an uncaught ValidationError that ended the whole sweep.
        class Hybrid(PredicateDetector):
            detector_id = "hybrid-access-control"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

            def plan(
                self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]
            ) -> ModelTaskSpec | None:
                return ModelTaskSpec(instruction="ask")

        def caller(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
            return ModelReply(
                findings=(
                    Finding(
                        detector_id=detector.detector_id,
                        locator=Locator(
                            file=PATH,
                            contract="Vault",
                            function="withdraw",
                            start_line=11,
                            end_line=11,
                        ),
                        quote="        total = total - amount;",
                        reasoning="the model's own claim",
                    ),
                ),
                models=(ModelUse(model_id="m", role=ModelRole.MAIN, calls=1, tokens=5),),
            )

        run = next(iter(run_submission([Hybrid()], [a_unit()], model=caller)))
        assert run.models, "the model it called is unnamed"
        assert run.produced_without_a_model is True, "the code that proposed is unnamed"
        assert len(run.findings) >= 2


class TestReadingTheCorpus:
    def a_record(self, path: str, record_id: str) -> CorpusRecord:
        return CorpusRecord.model_validate(
            {
                "record_id": record_id,
                "population": Population.AUDIT_REVIEW,
                "split": CorpusSplit.PUBLIC,
                "pin": CommitPin(
                    repo_url="https://github.com/example/vault", commit="a" * 40, path=path
                ),
                "locator": Locator(
                    file=path, contract="Vault", function="setOwner", start_line=5, end_line=6
                ),
                "locator_provenance": "stated",
                "classes": [VulnerabilityClass.ACCESS_CONTROL],
                "provenance": Provenance(platform="example", report_url="https://x/1"),
            }
        )

    def test_one_file_holding_several_records_is_one_unit(self, tmp_path: Path) -> None:
        # Two records in one file are two defects in one unit. Running it twice
        # would give a detector two attempts and count its budget twice.
        (tmp_path / "src").mkdir()
        (tmp_path / PATH).write_text(VAULT, encoding="utf-8")
        records = [self.a_record(PATH, f"vault-access-control-{n}") for n in (1, 2, 3)]
        units, missing = units_from(records, tmp_path)
        assert len(units) == 1
        assert missing == []

    def test_a_unit_absent_from_the_checkout_is_returned_not_logged(self, tmp_path: Path) -> None:
        # It scores as a submission that missed it, so a caller that ignores
        # this list reports recall over a subset nobody chose.
        units, missing = units_from([self.a_record(PATH, "vault-access-control-1")], tmp_path)
        assert units == []
        assert len(missing) == 1


class TestTheCallerIsResolvedLikeASubmission:
    def test_a_dotted_path_resolves(self) -> None:
        assert load_caller("contract_assay.harness:units_from") is units_from

    @pytest.mark.parametrize("bad", ["nocolon", ":missing", "contract_assay.harness:", ""])
    def test_a_malformed_spec_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match=r"module\.path:function"):
            load_caller(bad)

    def test_a_name_that_is_not_callable_is_refused(self) -> None:
        with pytest.raises(ValueError, match="does not name a callable"):
            load_caller("contract_assay.harness:__all__")

    def test_an_unimportable_module_says_so(self) -> None:
        with pytest.raises(ValueError, match="importing"):
            load_caller("no_such_module_anywhere:thing")
