"""The example submission, checked against the contract it is a template for.

A template that does not satisfy the interface is worse than no template: it
teaches the wrong shape and the mistake is discovered by whoever copied it. So
the example is loaded through the *real* loader here, not imported, and run
through the real phases.

The runner itself is not tested here -- it needs a model. `tests/live/` has that
one, excluded from the default gate.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from contract_assay.detectors.base import AnalysisContext, SubmissionLimits, check_citation
from contract_assay.detectors.loading import (
    SubmissionManifest,
    call_evidence,
    call_plan,
    load_detector,
)
from contract_assay.detectors.runner import run_detector
from contract_assay.models import (
    CitationStatus,
    DifficultyLevel,
    EvidenceTier,
    Finding,
    Locator,
    Outcome,
    VulnerabilityClass,
)

pytestmark = pytest.mark.offline

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "reference_runner"
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


@pytest.fixture(scope="module")
def detector():  # type: ignore[no-untyped-def]
    manifest = SubmissionManifest.model_validate_json(
        (EXAMPLE / "manifest.json").read_text(encoding="utf-8")
    )
    return load_detector(manifest, search_path=EXAMPLE)


def a_context() -> AnalysisContext:
    return AnalysisContext(
        source_id="commit:vault@aaa:src/Vault.sol",
        path=PATH,
        source=VAULT,
        tier=EvidenceTier.SYNTACTIC,
        level=DifficultyLevel.M,
        limits=SubmissionLimits.for_level(
            DifficultyLevel.M, wall_seconds=30, max_model_calls=4, max_tokens=20_000
        ),
    )


class TestItSatisfiesTheContract:
    def test_it_loads_through_the_real_loader(self, detector) -> None:  # type: ignore[no-untyped-def]
        # Not imported. A manifest that resolves in a test and not through the
        # loader is a template that fails on upload.
        assert detector.detector_id == "example-unguarded-state-write"
        assert detector.class_id is VulnerabilityClass.ACCESS_CONTROL
        assert detector.api_version == "1.0"

    def test_evidence_names_the_property_it_establishes(self, detector) -> None:  # type: ignore[no-untyped-def]
        evidence = call_evidence(detector, a_context())
        assert evidence
        # Named for the property, never for the shape it was found in: a second
        # shape of one property would otherwise need a second name, and counting
        # either would under-report the property.
        assert {ref.predicate for ref in evidence} == {"state_assignment_without_a_named_guard"}
        assert all(ref.locator.file == PATH for ref in evidence)

    def test_plan_asks_for_nothing_when_there_is_nothing_to_reason_about(self, detector) -> None:  # type: ignore[no-untyped-def]
        # A skipped call is budget left for the next unit rather than a missed
        # finding, and `None` is a legitimate answer the interface documents.
        empty = a_context().model_copy(update={"source": "// nothing here\n"})
        assert call_plan(detector, empty, call_evidence(detector, empty)) is None

    def test_the_instruction_never_carries_the_source(self, detector) -> None:  # type: ignore[no-untyped-def]
        # Pasting the file in makes the task's difficulty a function of the
        # file's length, which is the one thing the interface forbids here.
        ctx = a_context()
        spec = call_plan(detector, ctx, call_evidence(detector, ctx))
        assert spec is not None
        assert "contract Vault" not in spec.instruction


class TestTheVerdictAsksTheEvidence:
    def a_finding(self, start: int, end: int, quote: str) -> Finding:
        return Finding(
            detector_id="example-unguarded-state-write",
            locator=Locator(file=PATH, start_line=start, end_line=end),
            quote=quote,
            reasoning="anyone can take ownership",
        )

    def test_an_unguarded_write_stands(self, detector) -> None:  # type: ignore[no-untyped-def]
        ctx = a_context()
        run = run_detector(
            detector,
            ctx,
            # The quote is every line the locator names: `owner = who;` alone
            # is four tokens, and a span that short is not citable.
            model_findings=[
                self.a_finding(
                    5, 6, "function setOwner(address who) external {\n        owner = who;"
                )
            ],
            produced_without_a_model=True,
        )
        assert run.outcome is Outcome.VULNERABLE
        assert run.findings[0].status is CitationStatus.VERIFIED

    def test_a_guarded_write_is_rejected_by_name(self, detector) -> None:  # type: ignore[no-untyped-def]
        ctx = a_context()
        run = run_detector(
            detector,
            ctx,
            model_findings=[
                self.a_finding(
                    10,
                    11,
                    'require(msg.sender == owner, "not owner");\n        total = total - amount;',
                )
            ],
            produced_without_a_model=True,
        )
        assert run.outcome is Outcome.CLEAN
        assert [c.check for c in run.findings[0].failed_checks] == [
            "guard_named_at_the_cited_lines"
        ]

    def test_a_location_the_evidence_never_established_is_rejected(self, detector) -> None:  # type: ignore[no-untyped-def]
        # The template's own demonstration of the rule the project learned six
        # times: the layer that decides asks the layer that observes, rather
        # than re-deriving the observation.
        ctx = a_context()
        run = run_detector(
            detector,
            ctx,
            model_findings=[self.a_finding(1, 2, "contract Vault {\n    address owner;")],
            produced_without_a_model=True,
        )
        assert "assignment_established_here" in [c.check for c in run.findings[0].failed_checks]


class TestTheSelfCheckIsTheOneWorthCopying:
    def test_it_catches_a_quote_that_is_not_there(self) -> None:
        # The single most common way a submission scores zero: the run comes
        # back `invalid`, meaning it measured nothing, which reads like a
        # harness that found nothing.
        sys.path.insert(0, str(EXAMPLE))
        try:
            import submission
        finally:
            sys.path.remove(str(EXAMPLE))
        ctx = a_context()
        bad = Finding(
            detector_id="example-unguarded-state-write",
            locator=Locator(file=PATH, start_line=5, end_line=6),
            quote="owner = msg.sender;",
            reasoning="paraphrased rather than quoted",
        )
        assert submission.self_check(ctx, bad) is not None
        # And a quote that is real but is only part of the span it declared: the
        # forgery that closed was a submitter declaring the span the corpus
        # published and hiding a guessable fragment inside it.
        fragment = bad.model_copy(update={"quote": "owner = who;"})
        assert submission.self_check(ctx, fragment) is not None
        good = bad.model_copy(
            update={"quote": "function setOwner(address who) external {\n        owner = who;"}
        )
        assert submission.self_check(ctx, good) is None
        assert check_citation(ctx, good) is None
