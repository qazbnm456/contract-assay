"""harvest → normalize → verify, with no network and no toolchain.

The unit suites check each stage. This checks that the three compose into
records the verifier will admit, and that the accounting survives the whole
way: a candidate lost at any stage stays attributable to its class, and a
number quoted at the end can say what it is a number over.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from contract_assay.corpus.harvest import (
    Candidate,
    DraftRecord,
    RawReport,
    Skip,
    SkipCause,
    harvest,
)
from contract_assay.corpus.normalize import NormalizeCause, normalize
from contract_assay.corpus.records import CorpusSplit, LocatorProvenance, Provenance
from contract_assay.corpus.verify import verify_all
from contract_assay.models import VulnerabilityClass

pytestmark = pytest.mark.offline

SHA = "a" * 40
FIX_SHA = "b" * 40

VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address owner;
    mapping(address => uint256) balances;

    function setOwner(address o) external {
        owner = o;
    }

    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }

    function swap(uint256 a) external {}

    function swap(uint256 a, address to) external {}
}
"""


class MiniAdapter:
    """Reads a two-line-per-finding format, so the fixtures stay legible."""

    platform = "example"

    def candidates(self, report: RawReport) -> Sequence[Candidate]:
        found: list[Candidate] = []
        for line in report.body.strip().splitlines():
            ident, label, _location = (part.strip() for part in line.split("|"))
            mapped = {
                "access_control": VulnerabilityClass.ACCESS_CONTROL,
                "reentrancy": VulnerabilityClass.REENTRANCY,
                "slippage": VulnerabilityClass.SLIPPAGE,
                "arithmetic": VulnerabilityClass.ARITHMETIC_ROUNDING,
            }.get(label)
            found.append(
                Candidate(
                    candidate_id=ident,
                    classes=(mapped,) if mapped else (),
                    raw_labels=(label,),
                )
            )
        return found

    def extract(self, report: RawReport, candidate: Candidate) -> DraftRecord | Skip:
        line = next(
            line
            for line in report.body.strip().splitlines()
            if line.split("|")[0].strip() == candidate.candidate_id
        )
        _ident, _label, location = (part.strip() for part in line.split("|"))
        if not candidate.classes:
            return Skip(SkipCause.UNMAPPED_CLASS, _label)
        if location == "-":
            return Skip(SkipCause.NO_LOCATION, "described only in prose")

        contract, _, rest = location.partition(".")
        function, _, span = rest.partition("@")
        start, end = (int(span.split("-")[0]), int(span.split("-")[1])) if span else (None, None)
        return DraftRecord(
            candidate_id=candidate.candidate_id,
            repo_url="https://github.com/example/vault",
            commit=SHA,
            path="src/Vault.sol",
            contract=contract,
            function=function,
            start_line=start,
            end_line=end,
            classes=candidate.classes,
            provenance=Provenance(
                platform=report.platform,
                report_url=report.report_url,
                reported_severity="high",
                fix_commit=FIX_SHA,
            ),
        )


REPORT = RawReport(
    platform="example",
    report_url="https://example.invalid/report/1",
    body="""\
H-01 | access_control | Vault.setOwner
H-02 | reentrancy     | Vault.withdraw@12-15
H-03 | slippage       | Vault.swap
H-04 | arithmetic     | -
L-01 | gas            | Vault.setOwner
""",
)
"""One of each shape: prose-located, permalinked, overloaded, unlocatable, unmapped."""


def resolver(source: str | None = VAULT):  # type: ignore[no-untyped-def]
    def _resolve(repo_url: str, commit: str, path: str) -> str | None:
        return source

    return _resolve


def pipeline(source: str | None = VAULT):  # type: ignore[no-untyped-def]
    harvested = harvest(MiniAdapter(), [REPORT])
    normalized = normalize(harvested.drafts, resolver(source), split=CorpusSplit.PUBLIC)
    verified = verify_all(list(normalized.records), resolver(source))
    return harvested, normalized, verified


class TestTheStagesCompose:
    def test_records_survive_to_verification(self) -> None:
        _harvested, normalized, verified = pipeline()
        assert normalized.records
        assert len(verified.admitted) == len(normalized.records)
        assert verified.rejected == ()

    def test_one_candidate_of_each_shape_ends_where_it_should(self) -> None:
        harvested, normalized, verified = pipeline()
        # Five candidates: two skipped at harvest, one lost at normalize to the
        # overloaded name, two admitted.
        assert harvested.candidates == 5
        assert {s.skip.cause for s in harvested.skipped} == {
            SkipCause.UNMAPPED_CLASS,
            SkipCause.NO_LOCATION,
        }
        assert normalized.by_cause == {NormalizeCause.FUNCTION_AMBIGUOUS: 1}
        assert {r.locator.function for r in verified.admitted} == {"setOwner", "withdraw"}

    def test_both_locator_provenances_arrive_and_stay_distinguishable(self) -> None:
        _harvested, _normalized, verified = pipeline()
        assert verified.admitted_by_locator_provenance == {
            LocatorProvenance.DERIVED: 1,
            LocatorProvenance.STATED: 1,
        }

    def test_a_post_fix_pair_is_available_for_every_record(self) -> None:
        # §6.4 needs a fix commit to run the pair-differential, so the adapter
        # carrying it through is part of the contract rather than a nicety.
        _harvested, normalized, _verified = pipeline()
        assert all(r.provenance.fix_commit == FIX_SHA for r in normalized.records)


class TestAccountingSurvivesTheWholePipeline:
    def test_every_candidate_is_accounted_for_at_some_stage(self) -> None:
        harvested, normalized, verified = pipeline()
        accounted = (
            len(harvested.skipped)
            + len(normalized.skipped)
            + len(verified.admitted)
            + len(verified.rejected)
        )
        assert accounted == harvested.candidates

    def test_a_loss_stays_attributable_to_its_class_at_each_stage(self) -> None:
        # The property the whole design rests on: a class-resolved loss is a
        # diagnosis, where an aggregate loss is only a magnitude.
        harvested, normalized, _verified = pipeline()
        assert harvested.skipped_by_class == {VulnerabilityClass.ARITHMETIC_ROUNDING: 1}
        assert normalized.skipped_by_class == {VulnerabilityClass.SLIPPAGE: 1}

    def test_the_class_distribution_that_survives_is_visibly_not_the_real_one(self) -> None:
        harvested, normalized, _verified = pipeline()
        assert harvested.skip_rate_for(VulnerabilityClass.ARITHMETIC_ROUNDING) == 1.0
        assert normalized.loss_rate_for(VulnerabilityClass.SLIPPAGE) == 1.0
        assert harvested.skip_rate_for(VulnerabilityClass.ACCESS_CONTROL) == 0.0

    def test_every_stage_can_state_what_its_numbers_are_over(self) -> None:
        harvested, normalized, verified = pipeline()
        assert "never recognised as a finding is absent" in harvested.yield_statement()
        assert "cannot cross-check" in normalized.statement()
        assert "describes the admitted records only" in verified.sampling_statement()


class TestTheWholePipelineSurvivesBadInput:
    @pytest.mark.parametrize("source", [None, "   ", "}{ not solidity ][", "contract C {}"])
    def test_nothing_raises_and_nothing_is_silently_dropped(self, source: str | None) -> None:
        harvested, normalized, verified = pipeline(source)
        accounted = (
            len(harvested.skipped)
            + len(normalized.skipped)
            + len(verified.admitted)
            + len(verified.rejected)
        )
        assert accounted == harvested.candidates
        for record in verified.admitted:
            assert record.pin.sha256 is not None
            assert record.locator_provenance is not None
