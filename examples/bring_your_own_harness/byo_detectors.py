"""One detector per class, each of which asks for the model.

A `Detector` is a vulnerability class plus what to ask about it. The benchmark
scores per class, so a harness that covers several classes is several detectors
and `SubmissionManifest` names exactly one entry point, so there is one manifest
for each (`<class>.manifest.json`). Keep the manifests for the classes your
harness covers.

`plan()` is what makes the model run. Its default returns `None`, which
means "no model", and a detector with three declarations and nothing else never
calls your adapter at all: every run comes back `clean`, with no error. That is
the commonest first mistake, and `contract-assay run` warns when it sees it.

Do not use the benchmark's reference detectors as the vehicle for your model.
Their `verdict()` rejects findings on their own rules, and their declared
limits are attached to your score. A bare `Detector` rejects nothing beyond the
citation check, which is the host's and always runs.

The instructions say what to look for and never contain the source: the model
explores the file, and pasting it in makes the task's difficulty a function of
its length.
"""

from __future__ import annotations

from collections.abc import Sequence

from contract_assay.detectors import API_VERSION, Detector
from contract_assay.detectors.base import AnalysisContext, ModelTaskSpec
from contract_assay.models import EvidenceRef, VulnerabilityClass

INSTRUCTIONS: dict[VulnerabilityClass, str] = {
    VulnerabilityClass.ACCESS_CONTROL: (
        "Find functions that change privileged state or move value without checking who is calling."
    ),
    VulnerabilityClass.ORACLE_INTEGRITY: (
        "Find places where a price or other outside value is trusted without a freshness, "
        "bounds or source check."
    ),
    VulnerabilityClass.SLIPPAGE: (
        "Find swaps or trades that accept any output amount or take no deadline."
    ),
    VulnerabilityClass.FLASHLOAN_MANIPULATION: (
        "Find logic whose result can be moved inside one transaction by borrowing, "
        "trading and repaying."
    ),
    VulnerabilityClass.REENTRANCY: (
        "Find external calls made before the state they depend on is updated."
    ),
    VulnerabilityClass.UNCHECKED_EXTERNAL_CALL: (
        "Find low-level calls or transfers whose failure is ignored."
    ),
    VulnerabilityClass.DENIAL_OF_SERVICE: (
        "Find loops or payments that one participant can make fail, or grow without bound, "
        "for everybody else."
    ),
    VulnerabilityClass.ARITHMETIC_ROUNDING: (
        "Find divisions and conversions whose rounding direction lets a caller gain or lose value."
    ),
    VulnerabilityClass.INSECURE_RANDOMNESS: (
        "Find randomness derived from values a caller or validator can predict or influence."
    ),
}


class _AsksTheModel(Detector):
    """Declares none of the three, which marks it as a base and not an entry point."""

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        return ModelTaskSpec(instruction=INSTRUCTIONS[self.class_id])


class AccessControl(_AsksTheModel):
    detector_id = "byo-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION


class OracleIntegrity(_AsksTheModel):
    detector_id = "byo-oracle-integrity"
    class_id = VulnerabilityClass.ORACLE_INTEGRITY
    api_version = API_VERSION


class Slippage(_AsksTheModel):
    detector_id = "byo-slippage"
    class_id = VulnerabilityClass.SLIPPAGE
    api_version = API_VERSION


class FlashloanManipulation(_AsksTheModel):
    detector_id = "byo-flashloan-manipulation"
    class_id = VulnerabilityClass.FLASHLOAN_MANIPULATION
    api_version = API_VERSION


class Reentrancy(_AsksTheModel):
    detector_id = "byo-reentrancy"
    class_id = VulnerabilityClass.REENTRANCY
    api_version = API_VERSION


class UncheckedExternalCall(_AsksTheModel):
    detector_id = "byo-unchecked-external-call"
    class_id = VulnerabilityClass.UNCHECKED_EXTERNAL_CALL
    api_version = API_VERSION


class DenialOfService(_AsksTheModel):
    detector_id = "byo-denial-of-service"
    class_id = VulnerabilityClass.DENIAL_OF_SERVICE
    api_version = API_VERSION


class ArithmeticRounding(_AsksTheModel):
    detector_id = "byo-arithmetic-rounding"
    class_id = VulnerabilityClass.ARITHMETIC_ROUNDING
    api_version = API_VERSION


class InsecureRandomness(_AsksTheModel):
    detector_id = "byo-insecure-randomness"
    class_id = VulnerabilityClass.INSECURE_RANDOMNESS
    api_version = API_VERSION
