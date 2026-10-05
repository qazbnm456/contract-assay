"""The smallest working submission: three declarations and no model.

A detector declares which class it is about, what it is called, and which
interface version it was written against. Everything else is a default. This one
gets the benchmark's own evidence layer for the class, asserts one finding at each
place a predicate fires, quotes the source at that place, and calls no model, so
`contract-assay run` accepts it with no `--model-caller`.

It is a real baseline and a weak detector. Beating it takes being more selective,
not finding more, and `submission.py` beside it shows each layer written out by
hand for when you can.
"""

from __future__ import annotations

from contract_assay.detectors import API_VERSION, PredicateDetector
from contract_assay.models import VulnerabilityClass


class Baseline(PredicateDetector):
    detector_id = "baseline-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION
