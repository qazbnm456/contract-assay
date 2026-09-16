"""The Code4rena adapter.

Every fixture here is written by hand. No real report text is vendored: report
prose is somebody else's writing, and embedding it would attach its terms to an
MIT release for the same reason the corpus stores pointers rather than source.
The structure below mirrors the real format; the words do not come from it.

The adapter was separately validated against six published reports outside the
tree, and the numbers that produced are recorded in the commit that added it.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.adapters.code4rena import (
    Code4renaAdapter,
    Code4renaEnumerator,
)
from contract_assay.corpus.harvest import DraftRecord, RawReport, Skip, SkipCause, harvest
from contract_assay.models import VulnerabilityClass

pytestmark = pytest.mark.offline

SHA = "f" * 40
REPO = "https://github.com/code-423n4/2099-01-example"


def a_report(body: str) -> RawReport:
    return RawReport(
        platform="code4rena",
        report_url="https://code4rena.com/reports/2099-01-example",
        body=body,
    )


WELL_FORMED = a_report(
    f"""\
# Overview
## About C4

# High Risk Findings (1)
## [[H-01] Reentrancy lets a caller drain the vault](https://example.invalid/issues/1)
*Submitted by someone*

### Lines of code

<{REPO}/blob/{SHA}/src/Vault.sol#L20-L28>

### Impact
The balance is written after the transfer.

# Medium Risk Findings (1)
## [[M-01] Stale price feed is accepted without a freshness check](https://example.invalid/issues/2)
*Submitted by someone else*

### Lines of code

<{REPO}/blob/{SHA}/src/Oracle.sol#L44>

### Impact
An old answer is treated as current.

# Low Risk and Non-Critical Issues
## [01] Consider renaming a variable
"""
)


class TestEnumeration:
    """Enumeration sets the denominator of every rate derived from it."""

    def test_the_declared_counts_are_read_from_the_report(self) -> None:
        assert Code4renaEnumerator().declared_counts(WELL_FORMED.body) == {
            "High": 1,
            "Medium": 1,
        }

    def test_excluded_categories_are_not_counted(self) -> None:
        # Low-risk, QA, gas and informational sections are out of scope by
        # design, so the denominator is "findings in the accepted categories".
        # Stating that is what makes the exclusion reviewable.
        assert "Low" not in Code4renaEnumerator().declared_counts(WELL_FORMED.body)
        assert Code4renaEnumerator().declared_total(WELL_FORMED.body) == 2

    def test_findings_are_enumerated_with_their_severity_and_issue(self) -> None:
        [high, medium] = Code4renaEnumerator().findings(WELL_FORMED.body)
        assert (high.ident, high.severity) == ("H-01", "high")
        assert (medium.ident, medium.severity) == ("M-01", "medium")
        assert high.issue_url == "https://example.invalid/issues/1"

    def test_a_finding_body_stops_at_the_next_finding(self) -> None:
        [high, _medium] = Code4renaEnumerator().findings(WELL_FORMED.body)
        assert "balance is written after" in high.body
        assert "Stale price feed" not in high.body

    def test_low_risk_entries_are_not_enumerated_as_findings(self) -> None:
        idents = [f.ident for f in Code4renaEnumerator().findings(WELL_FORMED.body)]
        assert idents == ["H-01", "M-01"]


class TestTheDenominatorComesFromOutsideTheAdapter:
    """An enumerator that quietly skipped sections would flatter its own yield."""

    def test_agreement_with_the_report_is_reported_as_confirmed(self) -> None:
        basis = Code4renaEnumerator().enumeration_basis(WELL_FORMED.body)
        assert basis.startswith("externally confirmed")
        assert "2 enumerated, 2 declared" in basis

    def test_a_disagreement_is_reported_as_a_mismatch_not_smoothed_over(self) -> None:
        # The declared count says three and the report contains two, so every
        # rate derived from this enumeration is suspect and says so.
        body = WELL_FORMED.body.replace("High Risk Findings (1)", "High Risk Findings (2)")
        basis = Code4renaEnumerator().enumeration_basis(body)
        assert basis.startswith("MISMATCH")
        assert "suspect" in basis

    def test_a_report_declaring_nothing_is_reported_as_self_declared(self) -> None:
        # The honest fallback: the denominator is the adapter's own judgement and
        # a reader should know that before quoting a rate built on it.
        body = WELL_FORMED.body.replace(" Risk Findings (1)", " Risk Findings")
        assert Code4renaEnumerator().enumeration_basis(body).startswith("self-declared")
        assert Code4renaEnumerator().declared_total(body) is None


class TestExtraction:
    def test_a_lines_of_code_section_gives_a_stated_span(self) -> None:
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        assert len(result.drafts) == 2
        reentrancy = next(d for d in result.drafts if d.path.endswith("Vault.sol"))
        assert (reentrancy.start_line, reentrancy.end_line) == (20, 28)
        assert reentrancy.commit == SHA
        assert reentrancy.repo_url == REPO
        assert reentrancy.classes == (VulnerabilityClass.REENTRANCY,)

    def test_a_single_line_permalink_becomes_a_one_line_span(self) -> None:
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        oracle = next(d for d in result.drafts if d.path.endswith("Oracle.sol"))
        assert (oracle.start_line, oracle.end_line) == (44, 44)

    def test_severity_is_kept_as_provenance_not_as_a_class(self) -> None:
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        assert {d.provenance.reported_severity for d in result.drafts} == {"high", "medium"}

    def test_the_issue_url_is_preferred_over_the_report_url(self) -> None:
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        assert all("issues/" in d.provenance.report_url for d in result.drafts)


class TestAPermalinkIsNotAutomaticallyALocation:
    """Proof-of-concept sections cite freely, and those lines are not the defect."""

    MANY_LINKS = a_report(
        f"""\
# High Risk Findings (1)
## [[H-01] Reentrancy in the withdrawal path](https://example.invalid/issues/1)

### Proof of Concept
See <{REPO}/blob/{SHA}/src/Vault.sol#L20>, then
<{REPO}/blob/{SHA}/src/Vault.sol#L44>, and also
<{REPO}/blob/{SHA}/src/Token.sol#L9>.
"""
    )

    def test_several_distinct_citations_state_no_location(self) -> None:
        # One observed real finding carried 36 permalinks, none of which was the
        # defect. Taking the first would produce a confidently wrong record.
        result = harvest(Code4renaAdapter(), [self.MANY_LINKS])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}

    def test_one_repeated_citation_does_state_a_location(self) -> None:
        body = self.MANY_LINKS.body.replace("Vault.sol#L44", "Vault.sol#L20").replace(
            "Token.sol#L9", "Vault.sol#L20"
        )
        result = harvest(Code4renaAdapter(), [a_report(body)])
        [draft] = result.drafts
        assert (draft.path, draft.start_line) == ("src/Vault.sol", 20)

    def test_a_lines_of_code_section_wins_over_a_noisy_body(self) -> None:
        stated = (
            f"### Lines of code\n\n<{REPO}/blob/{SHA}/src/Vault.sol#L100-L110>\n\n"
            "### Proof of Concept"
        )
        body = self.MANY_LINKS.body.replace("### Proof of Concept", stated)
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert (draft.start_line, draft.end_line) == (100, 110)

    def test_a_non_solidity_citation_is_refused(self) -> None:
        body = f"""\
# High Risk Findings (1)
## [[H-01] Reentrancy in the withdrawal path](https://example.invalid/issues/1)

### Lines of code

<{REPO}/blob/{SHA}/README.md#L276>
"""
        result = harvest(Code4renaAdapter(), [a_report(body)])
        assert result.by_cause == {SkipCause.NO_FILE_PATH: 1}


class TestClassMapping:
    """Code4rena publishes no vulnerability taxonomy, only severity."""

    @pytest.mark.parametrize(
        ("title", "expected"),
        [
            ("Reentrancy in withdraw", VulnerabilityClass.REENTRANCY),
            ("Missing access control on setOwner", VulnerabilityClass.ACCESS_CONTROL),
            ("Stale price feed accepted", VulnerabilityClass.ORACLE_INTEGRITY),
            ("Rounding down favours the caller", VulnerabilityClass.ARITHMETIC_ROUNDING),
            ("Griefing via unbounded loop", VulnerabilityClass.DENIAL_OF_SERVICE),
            ("Swap accepts zero slippage bound", VulnerabilityClass.SLIPPAGE),
        ],
    )
    def test_titles_naming_a_class_are_mapped(
        self, title: str, expected: VulnerabilityClass
    ) -> None:
        body = f"""\
# High Risk Findings (1)
## [[H-01] {title}](https://example.invalid/issues/1)

### Lines of code

<{REPO}/blob/{SHA}/src/Vault.sol#L20>
"""
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert draft.classes == (expected,)

    def test_a_protocol_logic_title_maps_to_nothing_and_is_skipped(self) -> None:
        # Not a defect in the table: most accepted contest findings are
        # protocol-specific logic errors rather than instances of a generic
        # vulnerability class. Skipping them is what turns "how much of this
        # platform do the nine classes cover" into a reported number.
        body = f"""\
# High Risk Findings (1)
## [[H-01] Incorrect queued withdrawal accounting deflates reported TVL](https://example.invalid/issues/1)

### Lines of code

<{REPO}/blob/{SHA}/src/Vault.sol#L20>
"""
        result = harvest(Code4renaAdapter(), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.UNMAPPED_CLASS: 1}
        assert result.unclassified_skips == 1

    def test_only_one_class_is_assigned_from_a_title(self) -> None:
        # Multi-labelling is permitted for records because one location can host
        # several classes. A title matching two words is a different claim, and
        # putting that much confidence in a keyword table is not warranted.
        body = f"""\
# High Risk Findings (1)
## [[H-01] Reentrancy allows an oracle price feed to be manipulated](https://example.invalid/issues/1)

### Lines of code

<{REPO}/blob/{SHA}/src/Vault.sol#L20>
"""
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert len(draft.classes) == 1


class TestTheAdapterSurvivesOddReports:
    @pytest.mark.parametrize(
        "body",
        [
            "",
            "# Overview\nnothing here",
            "# High Risk Findings (3)\n",
            "## [[H-01] no closing bracket\n",
            "# High Risk Findings (1)\n## [[H-01] Reentrancy](url)\n",
        ],
    )
    def test_nothing_raises_and_the_accounting_holds(self, body: str) -> None:
        adapter = Code4renaAdapter()
        report = a_report(body)
        enumerated = len(adapter.candidates(report))
        result = harvest(adapter, [report])
        assert result.candidates == enumerated
        assert len(result.drafts) + len(result.skipped) == enumerated

    def test_a_candidate_whose_finding_vanishes_is_a_malformed_report(self) -> None:
        # Reachable only if enumeration and extraction disagree, which would be a
        # defect in the adapter rather than in the report -- reported as such
        # instead of crashing.
        adapter = Code4renaAdapter()
        from contract_assay.corpus.harvest import Candidate

        outcome = adapter.extract(WELL_FORMED, Candidate(candidate_id="H-99"))
        assert isinstance(outcome, Skip)
        assert outcome.cause is SkipCause.MALFORMED_REPORT

    def test_a_well_formed_report_yields_drafts_that_normalize_would_accept(self) -> None:
        for draft in harvest(Code4renaAdapter(), [WELL_FORMED]).drafts:
            assert isinstance(draft, DraftRecord)
            assert draft.has_stated_span
