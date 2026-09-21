"""The public detector interface, and the boundary it is trusted across.

Two properties dominate this file. The interface must refuse a submission it
cannot run *before* running any of it, and it must refuse to believe anything a
submission returns. Both are only interesting against hostile input, so most of
what follows is hostile input.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import ValidationError

from contract_assay.detectors.base import (
    API_VERSION,
    AnalysisContext,
    ClassificationClaim,
    Detector,
    LabelSpaceSpec,
    ModelTaskSpec,
    SubmissionLimits,
    TaskOutput,
    check_citation,
    gate,
    is_compatible,
    validate_claim,
)
from contract_assay.detectors.loading import (
    IncompatibleSubmission,
    MalformedSubmission,
    SubmissionFault,
    SubmissionManifest,
    call_classify,
    call_evidence,
    call_plan,
    call_verdict,
    load_detector,
)
from contract_assay.detectors.reference import (
    AccessControlDetector,
    ArithmeticRoundingDetector,
    DenialOfServiceDetector,
    OracleIntegrityDetector,
    ReentrancyDetector,
    SlippageDetector,
)
from contract_assay.models import (
    Determination,
    DifficultyLevel,
    EvidenceRef,
    EvidenceTier,
    FailedCheck,
    Finding,
    InvalidReason,
    LimitKind,
    Locator,
    RejectionKind,
    SkipReason,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline


VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
    }
}
"""

LABELS = LabelSpaceSpec(
    name="example-space",
    version="1",
    tags={"reentrancy": ["classic", "cross-function"], "access-control": []},
    severities=["low", "medium", "high"],
)


def a_locator(**over: object) -> Locator:
    base: dict[str, object] = {"file": "src/Vault.sol", "start_line": 5, "end_line": 7}
    return Locator(**{**base, **over})  # type: ignore[arg-type]


def a_finding(**over: object) -> Finding:
    base: dict[str, object] = {
        "detector_id": "example",
        "locator": a_locator(),
        "quote": "payable(msg.sender).transfer(amount);",
        "reasoning": "State is written after the external call.",
    }
    return Finding(**{**base, **over})  # type: ignore[arg-type]


def a_context(**over: object) -> AnalysisContext:
    base: dict[str, object] = {
        "source_id": "vault@abc:src/Vault.sol",
        "path": "src/Vault.sol",
        "source": VAULT,
        "tier": EvidenceTier.SYNTACTIC,
        "level": DifficultyLevel.M,
        "limits": SubmissionLimits.for_level(
            DifficultyLevel.M, wall_seconds=60, max_model_calls=4, max_tokens=8_000
        ),
    }
    return AnalysisContext(**{**base, **over})  # type: ignore[arg-type]


class Ok(Detector):
    """A minimal well-behaved detector."""

    detector_id = "ok"
    class_id = VulnerabilityClass.REENTRANCY
    api_version = API_VERSION

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        return []

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        return []


class Rogue(Detector):
    """A detector whose every method misbehaves, configurably."""

    detector_id = "rogue"
    class_id = VulnerabilityClass.REENTRANCY
    api_version = API_VERSION

    def __init__(self, payload: Any = None, *, boom: str = "") -> None:
        self.payload = payload
        self.boom = boom

    def _answer(self, stage: str) -> Any:
        if self.boom == stage:
            raise RuntimeError(f"exploded in {stage}")
        return self.payload

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        return self._answer("evidence")  # type: ignore[no-any-return]

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        return self._answer("plan")  # type: ignore[no-any-return]

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        return self._answer("verdict")  # type: ignore[no-any-return]

    def classify(
        self, ctx: AnalysisContext, findings: Sequence[Finding]
    ) -> Sequence[ClassificationClaim]:
        return self._answer("classify")  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------


class TestCompatibility:
    @pytest.mark.parametrize("declared", ["1.0", "1.4", "1.99"])
    def test_same_major_is_compatible(self, declared: str) -> None:
        assert is_compatible(declared)

    @pytest.mark.parametrize("declared", ["0.9", "2.0", "11.0"])
    def test_different_major_is_not(self, declared: str) -> None:
        assert not is_compatible(declared)

    def test_a_newer_minor_is_accepted(self) -> None:
        # Minor versions only add fields, so a submission written against a newer
        # minor reads nothing this host cannot give it. Refusing would strand
        # submissions over a difference that cannot affect them.
        major = API_VERSION.split(".", 1)[0]
        assert is_compatible(f"{major}.9999")

    def test_a_non_string_version_is_not_compatible_rather_than_an_error(self) -> None:
        # Reached when a submission sets the attribute to something odd after the
        # class body has already passed the definition-time check.
        assert not is_compatible(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


class TestSubmissionLimits:
    def test_escalation_is_closed_at_level_s(self) -> None:
        limits = SubmissionLimits.for_level(
            DifficultyLevel.S, wall_seconds=30, max_model_calls=1, max_tokens=100
        )
        assert not limits.escalation_allowed

    @pytest.mark.parametrize("level", [DifficultyLevel.M, DifficultyLevel.Q])
    def test_escalation_is_open_above_s(self, level: DifficultyLevel) -> None:
        limits = SubmissionLimits.for_level(
            level, wall_seconds=30, max_model_calls=1, max_tokens=100
        )
        assert limits.escalation_allowed

    def test_a_run_must_be_given_some_wall_clock(self) -> None:
        with pytest.raises(ValidationError):
            SubmissionLimits(
                wall_seconds=0, max_model_calls=1, max_tokens=1, escalation_allowed=False
            )


# ---------------------------------------------------------------------------
# Label spaces are data
# ---------------------------------------------------------------------------


class TestLabelSpaceSpec:
    def test_a_blank_tag_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be blank"):
            LabelSpaceSpec(name="x", version="1", tags={"  ": []}, severities=["low"])

    def test_a_blank_severity_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be blank"):
            LabelSpaceSpec(name="x", version="1", tags={"a": []}, severities=[" "])

    def test_duplicate_severities_are_rejected(self) -> None:
        # Two identical labels make a scored severity ambiguous for no benefit.
        with pytest.raises(ValidationError, match="must be distinct"):
            LabelSpaceSpec(name="x", version="1", tags={"a": []}, severities=["low", "low"])

    def test_an_empty_label_space_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LabelSpaceSpec(name="x", version="1", tags={}, severities=["low"])
        with pytest.raises(ValidationError):
            LabelSpaceSpec(name="x", version="1", tags={"a": []}, severities=[])


class TestValidateClaim:
    def _claim(self, **over: object) -> ClassificationClaim:
        base: dict[str, object] = {
            "tag": "reentrancy",
            "subtag": "classic",
            "severity": "high",
            "description": "Withdraw calls out before writing state.",
        }
        return ClassificationClaim(**{**base, **over})  # type: ignore[arg-type]

    def test_a_well_formed_claim_has_no_problems(self) -> None:
        assert validate_claim(self._claim(), LABELS) == []

    def test_an_unknown_tag_is_reported(self) -> None:
        problems = validate_claim(self._claim(tag="nonsense", subtag=None), LABELS)
        assert any("tag 'nonsense'" in p for p in problems)

    def test_a_subtag_outside_its_tag_is_reported(self) -> None:
        problems = validate_claim(self._claim(subtag="unrelated"), LABELS)
        assert any("subtag 'unrelated'" in p for p in problems)

    def test_a_tag_with_subtags_requires_one(self) -> None:
        problems = validate_claim(self._claim(subtag=None), LABELS)
        assert any("requires a subtag" in p for p in problems)

    def test_a_tag_without_subtags_accepts_none(self) -> None:
        assert validate_claim(self._claim(tag="access-control", subtag=None), LABELS) == []

    def test_an_unknown_severity_is_reported(self) -> None:
        problems = validate_claim(self._claim(severity="catastrophic"), LABELS)
        assert any("severity 'catastrophic'" in p for p in problems)

    def test_every_problem_is_reported_not_just_the_first(self) -> None:
        # An author fixing three fields should learn all three in one run rather
        # than discovering them over three submissions.
        problems = validate_claim(
            self._claim(tag="nonsense", subtag=None, severity="catastrophic"), LABELS
        )
        assert len(problems) == 2

    def test_a_description_has_an_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            self._claim(description="x" * 5_000)


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


class TestGate:
    def test_a_contract_is_admitted(self) -> None:
        assert gate(VAULT) is None

    @pytest.mark.parametrize(
        "source",
        [
            "library Math { function add(uint a) internal pure returns (uint) { return a; } }",
            "interface IVault { function withdraw(uint256) external; }",
        ],
    )
    def test_libraries_and_interfaces_are_admitted(self, source: str) -> None:
        assert gate(source) is None

    def test_unreadable_source_is_skipped_as_unparseable(self) -> None:
        assert gate("}{ not solidity ][") is SkipReason.UNPARSEABLE

    def test_empty_source_is_skipped_as_unparseable(self) -> None:
        assert gate("   \n  ") is SkipReason.UNPARSEABLE

    def test_a_file_declaring_no_type_is_skipped(self) -> None:
        source = (
            "pragma solidity ^0.8.20;\n"
            "function helper(uint256 x) pure returns (uint256) { return x + 1; }\n"
        )
        assert gate(source) is SkipReason.NO_CONTRACT_DECLARATION

    def test_the_gate_is_not_a_detector_method(self) -> None:
        # A per-detector skip is indistinguishable in the record from a detector
        # that looked and found nothing, which would let a submission convert
        # misses into exclusions.
        assert not hasattr(Ok(), "gate")


# ---------------------------------------------------------------------------
# Declaring a detector
# ---------------------------------------------------------------------------


class TestDetectorDeclaration:
    def test_a_well_formed_detector_declares_itself(self) -> None:
        assert Ok().detector_id == "ok"
        assert Ok().level is DifficultyLevel.M

    def test_level_is_derived_from_the_class_not_declared(self) -> None:
        # Two independent fields would permit a detector claiming one class and
        # the difficulty grade of another.
        assert not hasattr(Ok, "level_override")
        assert Ok().level is VulnerabilityClass.REENTRANCY.level

    @pytest.mark.parametrize("missing", ["detector_id", "class_id", "api_version"])
    def test_a_partial_declaration_fails_at_definition_time(self, missing: str) -> None:
        # Declaring some but not all is the actual mistake, and the message names
        # what is absent so the author does not have to guess.
        body: dict[str, Any] = {
            "detector_id": "x",
            "class_id": VulnerabilityClass.REENTRANCY,
            "api_version": API_VERSION,
            "evidence": lambda self, ctx: [],
            "verdict": lambda self, ctx, f, e: [],
        }
        del body[missing]
        with pytest.raises(TypeError, match=f"but not {missing}"):
            type("Broken", (Detector,), body)

    def test_a_shared_base_declaring_none_of_them_is_allowed(self) -> None:
        # A base that implements both methods and leaves the declarations to its
        # subclasses has no abstract methods left, so an abstractness test alone
        # would demand a detector_id it has no business owning -- pushing authors
        # into inventing a fake one, which is what the check exists to prevent.
        class SharedBase(Detector):
            def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
                return []

            def verdict(
                self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
            ) -> Sequence[FailedCheck]:
                return []

        class Leaf(SharedBase):
            detector_id = "leaf"
            class_id = VulnerabilityClass.REENTRANCY
            api_version = API_VERSION

        assert Leaf().detector_id == "leaf"
        assert getattr(SharedBase, "detector_id", None) is None

    def test_an_incompatible_version_fails_at_definition_time(self) -> None:
        with pytest.raises(TypeError, match="incompatible"):
            type(
                "FromTheFuture",
                (Detector,),
                {
                    "detector_id": "x",
                    "class_id": VulnerabilityClass.REENTRANCY,
                    "api_version": "99.0",
                    "evidence": lambda self, ctx: [],
                    "verdict": lambda self, ctx, f, e: [],
                },
            )

    def test_an_intermediate_class_need_not_declare_anything(self) -> None:
        # A shared base that subclasses complete is normal. Forcing it to invent
        # a detector_id would push authors into declaring a fake one.
        #
        # It is exempt by declaring none of the three fields, not by being
        # abstract: `evidence` and `verdict` have defaults now, so this base has
        # no abstract methods left for the other exemption to see.
        class Partial(Detector):
            def verdict(
                self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
            ) -> Sequence[FailedCheck]:
                return []

        assert Partial.__abstractmethods__ == frozenset()
        assert getattr(Partial, "detector_id", None) is None

    def test_an_intermediate_with_its_own_abstract_method_is_exempt_too(self) -> None:
        # The other exemption, which now fires only for a hierarchy that
        # introduced abstractness itself. Kept because a submission may.
        from abc import abstractmethod

        class Shared(Detector):
            @abstractmethod
            def house_rule(self) -> str: ...

        assert Shared.__abstractmethods__ == frozenset({"house_rule"})

    def test_a_detector_runs_no_model_by_default(self) -> None:
        # A purely deterministic detector is first-class: static analysers are the
        # baseline, and an interface that could not express one could not express
        # its own control group.
        assert Ok().plan(a_context(), []) is None

    def test_a_detector_claims_no_labels_by_default(self) -> None:
        assert Ok().classify(a_context(), []) == ()


class TestAnalysisContext:
    def test_classification_is_expected_only_when_a_label_space_is_given(self) -> None:
        assert not a_context().classification_expected
        assert a_context(labels=LABELS).classification_expected

    def test_context_refuses_unknown_fields(self) -> None:
        # An extra key means the caller and this type disagree about the contract.
        with pytest.raises(ValidationError):
            a_context(surprise="?")


# ---------------------------------------------------------------------------
# Manifests are readable without executing anything
# ---------------------------------------------------------------------------


class TestSubmissionManifest:
    def _manifest(self, **over: object) -> SubmissionManifest:
        base: dict[str, object] = {
            "submission_id": "team-alpha",
            "api_version": API_VERSION,
            "entry_point": "pkg.mod:MyDetector",
        }
        return SubmissionManifest(**{**base, **over})  # type: ignore[arg-type]

    def test_a_well_formed_manifest_splits_into_module_and_class(self) -> None:
        manifest = self._manifest()
        assert manifest.module_path == "pkg.mod"
        assert manifest.class_name == "MyDetector"

    @pytest.mark.parametrize(
        "entry_point",
        ["no-colon-here", ":MyDetector", "pkg.mod:", "pkg.mod", " :", "pkg mod:X"],
    )
    def test_a_malformed_entry_point_is_rejected(self, entry_point: str) -> None:
        with pytest.raises(ValidationError):
            self._manifest(entry_point=entry_point)

    def test_a_non_identifier_class_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not a valid class name"):
            self._manifest(entry_point="pkg.mod:Not A Name")

    @pytest.mark.parametrize("version", ["1", "1.0.0", "v1.0", ""])
    def test_an_unparseable_api_version_is_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            self._manifest(api_version=version)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_imports() -> Iterator[None]:
    """Keep module loading in these tests from leaking into the rest of the run."""
    path, modules = list(sys.path), set(sys.modules)
    try:
        yield
    finally:
        sys.path[:] = path
        for name in set(sys.modules) - modules:
            del sys.modules[name]


def write_submission(root: Path, name: str, body: str) -> Path:
    path = root / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return path


GOOD_SUBMISSION = f"""
from collections.abc import Sequence

from contract_assay.detectors.base import API_VERSION, Detector
from contract_assay.models import VulnerabilityClass

class MyDetector(Detector):
    detector_id = "mine"
    class_id = VulnerabilityClass.{VulnerabilityClass.ACCESS_CONTROL.name}
    api_version = API_VERSION

    def evidence(self, ctx):
        return []

    def verdict(self, ctx, finding, evidence):
        return []
"""


@pytest.mark.usefixtures("isolated_imports")
class TestLoadDetector:
    def _manifest(self, module: str, cls: str = "MyDetector", **over: object) -> SubmissionManifest:
        base: dict[str, object] = {
            "submission_id": "team-alpha",
            "api_version": API_VERSION,
            "entry_point": f"{module}:{cls}",
        }
        return SubmissionManifest(**{**base, **over})  # type: ignore[arg-type]

    def test_a_well_formed_submission_loads(self, tmp_path: Path) -> None:
        write_submission(tmp_path, "sub_good", GOOD_SUBMISSION)
        detector = load_detector(self._manifest("sub_good"), search_path=tmp_path)
        assert detector.detector_id == "mine"
        assert detector.class_id is VulnerabilityClass.ACCESS_CONTROL

    def test_an_incompatible_version_is_refused_before_the_module_is_imported(
        self, tmp_path: Path
    ) -> None:
        # The order is the point. Importing first lets an incompatible submission
        # run its module body before being turned away -- and the module body is
        # the part you wanted to decide about. Pointing at a module that would
        # fail loudly on import proves the import never happened.
        write_submission(tmp_path, "sub_bomb", "raise SystemExit('module body ran')\n")
        with pytest.raises(IncompatibleSubmission):
            load_detector(self._manifest("sub_bomb", api_version="99.0"), search_path=tmp_path)

    def test_a_missing_module_is_a_malformed_submission(self, tmp_path: Path) -> None:
        with pytest.raises(MalformedSubmission, match="failed"):
            load_detector(self._manifest("sub_absent"), search_path=tmp_path)

    def test_a_module_that_raises_on_import_is_reported_not_propagated(
        self, tmp_path: Path
    ) -> None:
        # Deliberately not an ImportError: a submission's module body is arbitrary
        # code and can fail in any way at all.
        write_submission(tmp_path, "sub_raises", "raise ValueError('bad module')\n")
        with pytest.raises(MalformedSubmission, match="ValueError"):
            load_detector(self._manifest("sub_raises"), search_path=tmp_path)

    def test_a_module_without_the_declared_class_is_refused(self, tmp_path: Path) -> None:
        write_submission(tmp_path, "sub_empty", "x = 1\n")
        with pytest.raises(MalformedSubmission, match="declares no"):
            load_detector(self._manifest("sub_empty"), search_path=tmp_path)

    def test_something_that_is_not_a_detector_is_refused(self, tmp_path: Path) -> None:
        write_submission(tmp_path, "sub_notadetector", "MyDetector = 42\n")
        with pytest.raises(MalformedSubmission, match="not a Detector subclass"):
            load_detector(self._manifest("sub_notadetector"), search_path=tmp_path)

    def test_a_constructor_that_raises_is_refused(self, tmp_path: Path) -> None:
        body = (
            GOOD_SUBMISSION
            + """
    def __init__(self):
        raise RuntimeError("no")
"""
        )
        write_submission(tmp_path, "sub_badinit", body)
        with pytest.raises(MalformedSubmission, match="instantiating"):
            load_detector(self._manifest("sub_badinit"), search_path=tmp_path)

    def test_a_version_swapped_after_the_class_body_is_still_caught(self, tmp_path: Path) -> None:
        # The definition-time check cannot see an assignment made afterwards, so
        # the loader re-reads the attribute from the class it actually got.
        body = GOOD_SUBMISSION + '\nMyDetector.api_version = "99.0"\n'
        write_submission(tmp_path, "sub_swapped", body)
        with pytest.raises(IncompatibleSubmission, match=r"99\.0"):
            load_detector(self._manifest("sub_swapped"), search_path=tmp_path)

    def test_loading_without_a_search_path_uses_the_existing_import_system(self) -> None:
        manifest = self._manifest("tests.unit.test_detectors", "Ok")
        assert load_detector(manifest).detector_id == "ok"


# ---------------------------------------------------------------------------
# Believing nothing the submission returns
# ---------------------------------------------------------------------------


class TestCallEvidence:
    def test_valid_evidence_passes_through(self) -> None:
        ref = EvidenceRef(
            predicate="state_write_after_call",
            tier=EvidenceTier.SYNTACTIC,
            locator=a_locator(),
        )
        assert call_evidence(Rogue([ref]), a_context()) == [ref]

    def test_evidence_given_as_plain_dicts_is_coerced(self) -> None:
        raw = {
            "predicate": "state_write_after_call",
            "tier": "syntactic",
            "locator": {"file": "src/Vault.sol", "start_line": 5, "end_line": 7},
        }
        [ref] = call_evidence(Rogue([raw]), a_context())
        assert ref.predicate == "state_write_after_call"

    def test_none_is_refused_rather_than_read_as_nothing(self) -> None:
        with pytest.raises(SubmissionFault, match="returned None"):
            call_evidence(Rogue(None), a_context())

    def test_a_string_is_refused_even_though_it_iterates(self) -> None:
        # str is a Sequence, so a returned string would otherwise decompose into
        # characters and fail one layer deeper with an unrecognisable message.
        with pytest.raises(SubmissionFault, match="returned str"):
            call_evidence(Rogue("oops"), a_context())

    @pytest.mark.parametrize("payload", [42, {"a": 1}, object()])
    def test_a_non_sequence_is_refused(self, payload: Any) -> None:
        with pytest.raises(SubmissionFault, match="not a sequence"):
            call_evidence(Rogue(payload), a_context())

    def test_an_invalid_item_names_its_position(self) -> None:
        with pytest.raises(SubmissionFault, match=r"evidence\[1\]"):
            call_evidence(
                Rogue(
                    [
                        {
                            "predicate": "p",
                            "tier": "syntactic",
                            "locator": {"file": "f", "start_line": 1, "end_line": 1},
                        },
                        {"predicate": ""},
                    ]
                ),
                a_context(),
            )

    def test_a_raising_detector_becomes_a_fault_naming_the_stage(self) -> None:
        with pytest.raises(SubmissionFault, match=r"evidence: raised RuntimeError"):
            call_evidence(Rogue(boom="evidence"), a_context())

    def test_a_fault_is_a_schema_violation_not_a_clean_result(self) -> None:
        with pytest.raises(SubmissionFault) as caught:
            call_evidence(Rogue(None), a_context())
        assert caught.value.invalid_reason is InvalidReason.SCHEMA_VIOLATION
        assert caught.value.stage == "evidence"


class TestCallVerdict:
    def test_no_rejections_means_the_finding_stands(self) -> None:
        assert call_verdict(Ok(), a_context(), a_finding(), []) == []

    def test_a_named_rejection_passes_through_with_its_kind(self) -> None:
        check = FailedCheck(check="quote_mismatch", kind=RejectionKind.CITATION, detail="no match")
        [got] = call_verdict(Rogue([check]), a_context(), a_finding(), [])
        assert got.kind is RejectionKind.CITATION

    def test_none_is_refused_so_a_broken_verdict_cannot_accept_everything(self) -> None:
        # The charitable reading of None is "no rejections", which would make a
        # verdict() that falls off its exception path accept every finding handed
        # to it -- scoring a submission's bug as a detection.
        with pytest.raises(SubmissionFault, match="returned None"):
            call_verdict(Rogue(None), a_context(), a_finding(), [])

    def test_a_rejection_without_a_kind_is_refused(self) -> None:
        # A bare label cannot distinguish a judgement from an error, which is
        # exactly the conflation the type system exists to prevent.
        with pytest.raises(SubmissionFault, match="failed_checks"):
            call_verdict(Rogue([{"check": "something"}]), a_context(), a_finding(), [])

    def test_a_raising_verdict_names_its_stage(self) -> None:
        with pytest.raises(SubmissionFault, match=r"^verdict:"):
            call_verdict(Rogue(boom="verdict"), a_context(), a_finding(), [])


class TestCallPlan:
    def test_none_means_no_model_runs(self) -> None:
        assert call_plan(Rogue(None), a_context(), []) is None

    def test_a_spec_passes_through(self) -> None:
        spec = ModelTaskSpec(instruction="Look for reentrancy.", expects=TaskOutput.BOTH)
        assert call_plan(Rogue(spec), a_context(), []) == spec

    def test_a_spec_given_as_a_dict_is_coerced(self) -> None:
        got = call_plan(Rogue({"instruction": "Look."}), a_context(), [])
        assert got is not None
        assert got.expects is TaskOutput.FINDINGS

    def test_garbage_is_refused(self) -> None:
        with pytest.raises(SubmissionFault, match="not a ModelTaskSpec"):
            call_plan(Rogue({"instruction": ""}), a_context(), [])

    def test_a_raising_plan_names_its_stage(self) -> None:
        with pytest.raises(SubmissionFault, match=r"^plan:"):
            call_plan(Rogue(boom="plan"), a_context(), [])


class TestCallClassify:
    def _claim(self, **over: object) -> ClassificationClaim:
        base: dict[str, object] = {
            "tag": "reentrancy",
            "subtag": "classic",
            "severity": "high",
            "description": "Calls out before writing state.",
        }
        return ClassificationClaim(**{**base, **over})  # type: ignore[arg-type]

    def test_valid_claims_pass_through(self) -> None:
        claim = self._claim()
        assert call_classify(Rogue([claim]), a_context(labels=LABELS), []) == [claim]

    def test_a_claim_outside_the_label_space_is_kept_not_dropped(self) -> None:
        # Dropping it would reward invalid output: an unusable claim that
        # disappears costs nothing, while the same claim retained carries the
        # false-positive penalty it earned.
        claim = self._claim(tag="not-a-real-tag", subtag=None)
        assert call_classify(Rogue([claim]), a_context(labels=LABELS), []) == [claim]
        assert validate_claim(claim, LABELS) != []

    def test_a_structurally_invalid_claim_is_refused(self) -> None:
        with pytest.raises(SubmissionFault, match="claims"):
            call_classify(Rogue([{"tag": "reentrancy"}]), a_context(labels=LABELS), [])

    def test_a_raising_classify_names_its_stage(self) -> None:
        with pytest.raises(SubmissionFault, match=r"^classify:"):
            call_classify(Rogue(boom="classify"), a_context(labels=LABELS), [])

    def test_a_fault_raised_by_the_detector_itself_is_not_rewrapped(self) -> None:
        class Faulty(Ok):
            detector_id = "faulty"

            def classify(
                self, ctx: AnalysisContext, findings: Sequence[Finding]
            ) -> Sequence[ClassificationClaim]:
                raise SubmissionFault("classify", "already precise")

        with pytest.raises(SubmissionFault, match="already precise"):
            call_classify(Faulty(), a_context(labels=LABELS), [])


@pytest.mark.usefixtures("isolated_imports")
class TestASharedBaseIsNotAnEntryPoint:
    def test_pointing_a_manifest_at_a_base_is_refused(self, tmp_path: Path) -> None:
        # `__init_subclass__` lets an undeclared base through precisely because it
        # is not meant to be an entry point, so the loader has to be the one that
        # says so -- otherwise reading `api_version` off it raises AttributeError
        # and a malformed submission arrives as a crash.
        body = """
from collections.abc import Sequence

from contract_assay.detectors.base import Detector

class SharedBase(Detector):
    def evidence(self, ctx):
        return []

    def verdict(self, ctx, finding, evidence):
        return []
"""
        write_submission(tmp_path, "sub_base_only", body)
        manifest = SubmissionManifest(
            submission_id="team-alpha",
            api_version=API_VERSION,
            entry_point="sub_base_only:SharedBase",
        )
        with pytest.raises(MalformedSubmission, match="shared base rather than a detector"):
            load_detector(manifest, search_path=tmp_path)

    def test_an_attribute_deleted_after_definition_is_caught(self, tmp_path: Path) -> None:
        body = GOOD_SUBMISSION + "\ndel MyDetector.detector_id\n"
        write_submission(tmp_path, "sub_deleted", body)
        manifest = SubmissionManifest(
            submission_id="team-alpha",
            api_version=API_VERSION,
            entry_point="sub_deleted:MyDetector",
        )
        with pytest.raises(MalformedSubmission, match="declares no detector_id"):
            load_detector(manifest, search_path=tmp_path)


class TestCitationIsReVerifiedByTheHarness:
    """Re-verification is harness-owned, always runs, and is never a judgement.

    The data contract says a finding is re-verified against source
    unconditionally, every run. That sentence is false if each submission has to
    remember to do it, and a submission that omitted the check would have its
    unverifiable claims accepted -- the overridable-gate hole with a different
    label.
    """

    SOURCE = """\
contract Vault {
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
    }

    function other() external {
        payable(msg.sender).transfer(1);
    }
}
"""

    def _ctx(self) -> AnalysisContext:
        return a_context(source=self.SOURCE, path="src/Vault.sol")

    def _finding(self, quote: str, start: int, end: int) -> Finding:
        return a_finding(
            quote=quote,
            locator=a_locator(file="src/Vault.sol", start_line=start, end_line=end),
        )

    def test_a_quote_matching_its_locator_passes(self) -> None:
        assert (
            check_citation(
                self._ctx(), self._finding("payable(msg.sender).transfer(amount);", 3, 3)
            )
            is None
        )

    def test_indentation_is_not_semantic(self) -> None:
        # A model reproducing a line with its indentation shifted has still
        # quoted the code. Demanding byte-exact whitespace would reject true
        # findings for a reason unrelated to whether they are true, which is a
        # wrong skip paid for in recall.
        quoted = "         payable(msg.sender).transfer(amount);   "
        assert check_citation(self._ctx(), self._finding(quoted, 3, 3)) is None

    def test_blank_lines_are_ignored(self) -> None:
        quoted = "\n\npayable(msg.sender).transfer(amount);\n\n"
        assert check_citation(self._ctx(), self._finding(quoted, 3, 3)) is None

    def test_a_multi_line_quote_matches_its_span(self) -> None:
        quoted = (
            "function withdraw(uint256 amount) external {\npayable(msg.sender).transfer(amount);\n}"
        )
        assert check_citation(self._ctx(), self._finding(quoted, 2, 4)) is None

    def test_real_code_at_the_wrong_place_is_distinguished(self) -> None:
        # The two failures mean different things about the detector: one quoted
        # real code and pointed at the wrong place, the other quoted code that is
        # not in the file at all.
        failure = check_citation(
            self._ctx(), self._finding("payable(msg.sender).transfer(amount);", 7, 7)
        )
        assert failure is not None
        assert failure.check == "citation_quote_elsewhere_in_file"

    def test_a_quote_absent_from_the_file_is_reported(self) -> None:
        failure = check_citation(self._ctx(), self._finding("selfdestruct(owner);", 3, 3))
        assert failure is not None
        assert failure.check == "citation_quote_absent_from_source"

    def test_a_span_past_the_end_of_the_source_is_reported(self) -> None:
        failure = check_citation(self._ctx(), self._finding("anything", 99, 99))
        assert failure is not None
        assert failure.check == "citation_span_out_of_range"

    def test_a_quote_that_is_only_whitespace_is_reported(self) -> None:
        failure = check_citation(self._ctx(), self._finding("   \n\t ", 3, 3))
        assert failure is not None
        assert failure.check == "citation_quote_absent_from_source"

    @pytest.mark.parametrize(
        "quote",
        ["selfdestruct(owner);", "   \n ", "payable(msg.sender).transfer(amount);"],
    )
    def test_every_failure_is_a_citation_never_a_verdict(self, quote: str) -> None:
        # A finding whose quote is not where it says establishes nothing about
        # whether the class is present there. Recording it as a verdict would
        # make the run `clean` -- asserting "nothing here" on the strength of a
        # broken citation.
        failure = check_citation(self._ctx(), self._finding(quote, 7, 7))
        assert failure is None or failure.kind is RejectionKind.CITATION

    def test_the_check_is_not_a_detector_method(self) -> None:
        # Same reasoning as the gate: a submission that could skip it would have
        # its unverifiable claims accepted.
        assert not hasattr(Ok(), "check_citation")


class TestTheDeclaredLimitsAreCheckable:
    """Each entry names a record, which is what makes it a proof.

    Three states are exercised here rather than two. A limit that was declared
    and has since been closed; a limit still open; and the control that stops
    "silent" from meaning "this predicate never works". A demonstrated limit
    needs a demonstrated sighting beside it or it proves nothing.

    Fixtures are hand-written and reproduce the *shape*: no third-party source
    is vendored here.
    """

    BASE = """contract R {{
    address public owner;
    mapping(address => uint256) public shares;

    function deposit(uint256 amount, address from, address to) external {{
{guard}
{effect}
    }}
}}
"""
    GUARD = "        require(IVisor(from).owner() == msg.sender);"
    WRITE = "        shares[to] += amount;"
    EXTERNAL = "        v.mint(to, amount);"

    def _evidence(self, *, guard: bool, external: bool) -> list[EvidenceRef]:
        source = self.BASE.format(
            guard=self.GUARD if guard else "",
            effect=self.EXTERNAL if external else self.WRITE,
        )
        return list(AccessControlDetector().evidence(a_context(source=source, path="src/R.sol")))

    def _predicates(self, *, guard: bool, external: bool) -> list[str]:
        return sorted(
            e.predicate for e in self._evidence(guard=guard, external=external) if e.is_established
        )

    def test_the_unguarded_case_is_the_control(self) -> None:
        # Without it, "silent" would not distinguish a limit from a predicate
        # that never fires.
        assert self._predicates(guard=False, external=False) == [
            "state_change_reachable_without_modifier_or_sender_reference"
        ]

    def test_an_unsound_guard_is_now_seen(self) -> None:
        # The limit that was declared and is now closed. The neighbouring
        # predicate is still silenced by the msg.sender mention -- which is why
        # this needed its own predicate rather than a tightening.
        assert self._predicates(guard=True, external=False) == [
            "authorisation_reads_its_answer_from_caller_supplied_address"
        ]

    def test_an_external_effect_is_still_reported_as_indeterminate(self) -> None:
        # The limit that is still open. Reported rather than silent, because the
        # silence meant both "no state change here" and "the change happens
        # where I cannot see", and only the first is a fact about this code.
        assert self._predicates(guard=False, external=True) == []
        [entry] = self._evidence(guard=False, external=True)
        assert entry.determination is Determination.INDETERMINATE
        assert "not in the analysed unit" in (entry.indeterminate_because or "")

    def test_the_record_shape_is_seen_and_still_undecided(self) -> None:
        # Both at once, which is the corpus record's own shape: the guard is now
        # established evidence, and whether there is state to protect remains
        # undecided. `isolated=False` said exactly this would happen.
        evidence = self._evidence(guard=True, external=True)
        assert [e.predicate for e in evidence if e.is_established] == [
            "authorisation_reads_its_answer_from_caller_supplied_address"
        ]
        assert any(not e.is_established for e in evidence)

    def test_the_closed_entry_records_that_its_prediction_was_wrong(self) -> None:
        # The prediction and the outcome sit side by side, and the pair is the
        # record of the error: it said the semantic tier, and no tier was needed.
        closed = [b for b in AccessControlDetector().declared_limits if b.closed_by]
        assert len(closed) == 1
        assert "semantic tier" in closed[0].closed_when
        assert "was not needed" in closed[0].closed_by  # type: ignore[operator]

    def test_every_open_entry_says_what_would_close_it(self) -> None:
        # It was one entry, and asserting the count made the test about the
        # register's size rather than its contents. A second opened when the
        # verdict started declining every function that reads `msg.sender`:
        # that narrowing is what keeps permissionless-by-design functions out of
        # the pool, and its price is every record whose guard is present and
        # wrong. What is worth pinning is that each entry says what closes it,
        # and that the indeterminacy names a reason other than the tier.
        open_limits = [b for b in AccessControlDetector().declared_limits if not b.closed_by]
        assert open_limits
        assert all(entry.closed_when.strip() for entry in open_limits)
        [indeterminacy] = [b for b in open_limits if b.kind is LimitKind.INDETERMINACY]
        assert "NOT the semantic tier" in indeterminacy.closed_when

    DETECTORS_WITH_LIMITS: ClassVar[list[type]] = [
        AccessControlDetector,
        ArithmeticRoundingDetector,
        DenialOfServiceDetector,
        OracleIntegrityDetector,
        ReentrancyDetector,
        SlippageDetector,
    ]

    @pytest.mark.parametrize("detector", DETECTORS_WITH_LIMITS)
    def test_every_entry_names_a_reason_and_a_record(self, detector: type) -> None:
        for entry in detector().declared_limits:
            assert entry.unpatched_because.strip()
            assert entry.demonstrated_by
            assert all(record_id.strip() for record_id in entry.demonstrated_by)
            assert entry.closed_when.strip()

    @pytest.mark.parametrize("detector", DETECTORS_WITH_LIMITS)
    def test_every_named_record_exists(self, detector: type) -> None:
        # What makes a claimed limit checkable rather than an opinion: the
        # records can be fetched and the detector run against them. A limit
        # naming a record that does not exist cannot be falsified, and it would
        # still take a miss out of the unexplained count.
        held = {path.stem for path in Path("corpus/records").glob("*.json")}
        for entry in detector().declared_limits:
            for record_id in entry.demonstrated_by:
                assert record_id in held, f"{record_id} is not in the corpus"
