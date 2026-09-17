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
SCOPE_SHA = "a" * 40


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

    def test_a_single_line_permalink_becomes_an_anchor_not_a_span(self) -> None:
        # `#L44` says the defect is at line 44 and nothing about where it ends,
        # so treating it as a one-line span would assert more than the report
        # did. It becomes an anchor, widened later to its declaration.
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        oracle = next(d for d in result.drafts if d.path.endswith("Oracle.sol"))
        assert oracle.anchor_line == 44
        assert not oracle.has_stated_span
        assert oracle.has_anchor

    def test_a_ranged_permalink_stays_a_stated_span(self) -> None:
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        vault = next(d for d in result.drafts if d.path.endswith("Vault.sol"))
        assert (vault.start_line, vault.end_line) == (20, 28)
        assert vault.has_stated_span
        assert not vault.has_anchor

    def test_the_two_kinds_are_counted_apart(self) -> None:
        result = harvest(Code4renaAdapter(), [WELL_FORMED])
        assert result.anchored_drafts == 1
        assert result.derived_span_drafts == 0

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
        assert (draft.path, draft.anchor_line) == ("src/Vault.sol", 20)

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
            assert draft.has_stated_span or draft.has_anchor


class TestLineNumberedExcerpts:
    """The best location signal the format offers, and the only one with a quote.

    The platform's submission tooling emits excerpts headed by the file they came
    from and prefixed with line numbers. Measured over six published reports it
    appears in about one accepted finding in nine -- a minority convention rather
    than the format, and the only signal that arrives with source text attached,
    which can be checked against the pinned file.
    """

    EXCERPT = a_report(
        f"""\
# Scope
Audited at <{REPO}/blob/{SHA}/README.md#L1>.

# High Risk Findings (1)
## [[H-01] Reentrancy in the withdrawal path](https://example.invalid/issues/1)

### Vulnerability details

```solidity
File: src/Vault.sol
120:   function withdraw(uint256 amount) external {{
121:     payable(msg.sender).transfer(amount);
122:     balances[msg.sender] -= amount;
123:   }}
```
"""
    )

    def test_the_path_comes_from_the_excerpt_and_the_location_from_its_text(self) -> None:
        # The numbers are not a location. One published excerpt read
        # `503: function erc20TransferOutBidAmountToLiqudity(...)` and that
        # declaration sits at 496 in the pinned file, with 503 inside the next
        # function -- and every check downstream passed, because the function
        # was derived from the span and so agreed with itself. The text is what
        # can be found in the source or refused.
        [draft] = harvest(Code4renaAdapter(), [self.EXCERPT]).drafts
        assert draft.path == "src/Vault.sol"
        assert draft.has_stated_span is False
        assert draft.quoted_source is not None
        assert "function withdraw(uint256 amount) external {" in draft.quoted_source
        assert "120:" not in draft.quoted_source

    def test_the_commit_comes_from_the_contest_not_the_finding(self) -> None:
        # A commit identifies the snapshot under audit, so any permalink in the
        # report establishes it. A *location* is specific to one finding and
        # cannot be borrowed the same way.
        [draft] = harvest(Code4renaAdapter(), [self.EXCERPT]).drafts
        assert draft.commit == SHA
        assert draft.repo_url == REPO

    def test_the_most_cited_snapshot_wins_over_a_stray_link(self) -> None:
        other = "b" * 40
        body = self.EXCERPT.body.replace(
            "# High Risk Findings (1)",
            f"Unrelated: <https://github.com/someone/else/blob/{other}/x.sol#L1>\n"
            f"Also <{REPO}/blob/{SHA}/src/Other.sol#L2>\n\n# High Risk Findings (1)",
        )
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert draft.commit == SHA

    def test_a_report_with_no_permalink_anywhere_cannot_be_pinned(self) -> None:
        body = self.EXCERPT.body.replace(
            f"Audited at <{REPO}/blob/{SHA}/README.md#L1>.", "Audited at the tagged release."
        )
        result = harvest(Code4renaAdapter(), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}

    def test_an_excerpt_beats_a_function_named_in_prose(self) -> None:
        # Both signals are present. The excerpt quotes source, which locates a
        # span exactly, where a name in prose has to be resolved and may not be
        # the site the finding is about.
        body = self.EXCERPT.body.replace(
            "### Vulnerability details",
            "### Vulnerability details\n\nThe bug is in `Vault.somethingElse()`.",
        )
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert draft.quoted_source is not None
        assert "balances[msg.sender] -= amount;" in draft.quoted_source
        assert draft.function != "somethingElse"

    def test_several_quoted_regions_have_not_said_which_is_the_site(self) -> None:
        # Of four such findings in one sample, three quoted a helper or an
        # explanatory call first and the defect later. Taking the first block
        # picked the wrong one three times out of four.
        body = self.EXCERPT.body.replace(
            "```\n",
            "```\n\nand also\n\n```solidity\nFile: src/Other.sol\n"
            "40:   function totalAssets() external view returns (uint256) {\n"
            "41:     return asset.balanceOf(address(this));\n"
            "42:   }\n```\n",
            1,
        )
        result = harvest(Code4renaAdapter(), [a_report(body)])
        # No excerpt, no citation of its own and nothing quoted outside the
        # blocks, so this falls to the named-function route and is lost there.
        assert result.drafts == ()
        assert set(result.by_cause) <= {SkipCause.NO_LOCATION}

    def test_a_block_quoting_the_harness_is_not_a_second_region(self) -> None:
        # A proof of concept exercises the defect rather than containing it, so
        # a test file beside the real one leaves the real one determinate.
        body = self.EXCERPT.body.replace(
            "```\n",
            "```\n\nProof of concept:\n\n```solidity\nFile: test/Vault.t.sol\n"
            "10:   function test_withdraw() public {\n"
            "11:     vault.withdraw(1 ether);\n"
            "12:   }\n```\n",
            1,
        )
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert draft.path == "src/Vault.sol"

    def test_an_excerpt_with_no_line_numbers_is_not_a_location(self) -> None:
        body = self.EXCERPT.body.replace("120:   ", "").replace("121:     ", "")
        result = harvest(Code4renaAdapter(), [a_report(body)])
        assert all(d.has_stated_span is False for d in result.drafts)


class TestFallingBackToANamedFunction:
    """Generous extraction, strict resolution: the §2.2 asymmetry, third outing."""

    NAMED = a_report(
        f"""\
# High Risk Findings (1)
## [[H-01] Reentrancy in `Vault.withdraw()`](https://example.invalid/issues/1)

### Impact
See <{REPO}/blob/{SHA}/src/Vault.sol#L10> and <{REPO}/blob/{SHA}/src/Vault.sol#L90>.
"""
    )

    def test_one_cited_file_plus_a_named_function_is_enough(self) -> None:
        # Two lines cited in one file states no span, but the file plus a name
        # the prose gives is enough for normalize to resolve -- and if the name
        # does not resolve there, the draft is lost and counted.
        [draft] = harvest(Code4renaAdapter(), [self.NAMED]).drafts
        assert draft.path == "src/Vault.sol"
        assert (draft.contract, draft.function) == ("Vault", "withdraw")
        assert not draft.has_stated_span and not draft.has_anchor

    def test_an_unqualified_call_gives_a_function_without_a_contract(self) -> None:
        body = self.NAMED.body.replace("`Vault.withdraw()`", "`withdraw()`")
        [draft] = harvest(Code4renaAdapter(), [a_report(body)]).drafts
        assert (draft.contract, draft.function) == (None, "withdraw")

    def test_a_cited_file_with_no_named_function_is_a_loss(self) -> None:
        body = self.NAMED.body.replace("in `Vault.withdraw()`", "somewhere")
        result = harvest(Code4renaAdapter(), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}

    def test_several_cited_files_state_no_location_even_with_a_name(self) -> None:
        body = self.NAMED.body.replace("src/Vault.sol#L90", "src/Token.sol#L90")
        result = harvest(Code4renaAdapter(), [a_report(body)])
        assert result.drafts == ()
        assert result.by_cause == {SkipCause.NO_LOCATION: 1}


class TestOnlyTheCodeUnderReview:
    """A citation outside the reviewed repository has not located a defect in it.

    A report cites a dependency to show what the reviewed code was derived from
    or ought to have done. The first run of the quote route pinned a record to
    an upstream library for a finding about a port of it, which is a defect
    attributed to a third party the report never claimed was defective.
    """

    SCOPE = "\n".join(
        f"https://github.com/code-423n4/2024-08-x/blob/{'a' * 40}/src/Vault{n}.sol#L{n}"
        for n in range(1, 8)
    )

    def _body(self, citation: str) -> str:
        return (
            "# Overview\n\n" + self.SCOPE + "\n\n# High Risk Findings (1)\n\n"
            "## [[H-01] Reentrancy in the withdrawal path](https://github.com/x/y/issues/1)\n\n"
            f"{citation}\n\n```solidity\n"
            "    function withdraw(uint256 amount) external {\n"
            "        payable(msg.sender).transfer(amount);\n"
            "        balances[msg.sender] -= amount;\n"
            "    }\n```\n"
        )

    def _extract(self, citation: str):  # type: ignore[no-untyped-def]
        report = a_report(self._body(citation))
        adapter = Code4renaAdapter()
        [candidate] = adapter.candidates(report)
        return adapter.extract(report, candidate)

    def test_the_reviewed_repository_is_read_from_the_whole_report(self) -> None:
        # Within one finding a dependency can easily be cited more often than
        # the code under review, which is how the bad record was made.
        outcome = self._extract(
            f"https://github.com/code-423n4/2024-08-x/blob/{'a' * 40}/src/Vault1.sol#L10-L14"
        )
        assert isinstance(outcome, DraftRecord)
        assert outcome.repo_url == "https://github.com/code-423n4/2024-08-x"

    def test_a_citation_elsewhere_is_refused_with_its_own_cause(self) -> None:
        # Not `no_file_path`: the fix is to read the report's scope, not to
        # parse a path better.
        outcome = self._extract(
            f"https://github.com/Uniswap/v3-core/blob/{'b' * 40}/contracts/Position.sol#L61-L76"
        )
        assert isinstance(outcome, Skip)
        assert outcome.cause is SkipCause.CITES_ANOTHER_REPOSITORY

    def test_a_sole_citation_elsewhere_does_not_slip_past_as_a_file(self) -> None:
        # The check had to hold in three places and held in two, so a finding
        # whose single Solidity citation was a dependency went through as "the
        # one file it cites". The candidate set is now restricted once.
        outcome = self._extract(
            f"https://github.com/Uniswap/v3-core/blob/{'b' * 40}/contracts/Position.sol"
        )
        assert isinstance(outcome, Skip)
        assert outcome.cause in (
            SkipCause.CITES_ANOTHER_REPOSITORY,
            SkipCause.NO_LOCATION,
        )


class TestWhichCommitTheRecordRestsOn:
    """A recovered commit is an assumption, and only the recovered ones made it.

    Rewriting a moving ref to the commit the report states erases the evidence
    that the ref ever moved: the rewritten citation is pinned, and both callers
    asked exactly that. So every draft came out labelled the wrong way round --
    findings that pinned their own commit were published as resting on a
    recovery, and the recovered ones as stated outright -- and the label is not
    an internal detail but `pin.resolved_from`, which is what a report
    stratifies on to say how much of the corpus rests on an inference.
    """

    OTHER = SCOPE_SHA
    SCOPE = "\n".join(f"<{REPO}/blob/{SCOPE_SHA}/src/Scope{n}.sol#L{n}>" for n in range(1, 9))

    def _draft(self, citation: str, *, scope: str | None = None) -> DraftRecord | Skip:
        body = (
            "# Overview\n\n" + (self.SCOPE if scope is None else scope) + "\n\n"
            "# High Risk Findings (1)\n\n"
            "## [[H-01] Reentrancy lets a caller drain the vault](https://x.invalid/issues/1)\n\n"
            "### Lines of code\n\n"
            f"{citation}\n\n"
            "### Impact\nThe balance is written after the transfer.\n"
        )
        report = a_report(body)
        adapter = Code4renaAdapter()
        [candidate] = adapter.candidates(report)
        return adapter.extract(report, candidate)

    def test_a_finding_that_pins_its_own_commit_rests_on_nothing(self) -> None:
        outcome = self._draft(f"<{REPO}/blob/{SHA}/src/Vault.sol#L20-L28>")
        assert isinstance(outcome, DraftRecord)
        assert outcome.commit == SHA
        assert outcome.commit_resolved_from is None

    def test_a_moving_ref_takes_the_commit_the_report_states_and_says_so(self) -> None:
        outcome = self._draft(f"<{REPO}/blob/main/src/Vault.sol#L20-L28>")
        assert isinstance(outcome, DraftRecord)
        # The report's own citations of this repository name one commit, so the
        # line numbers can be read against it -- on the assumption that the
        # branch was there when they were written, which the finding never said.
        assert outcome.commit == self.OTHER
        assert outcome.commit_resolved_from is not None
        assert "most often" in outcome.commit_resolved_from

    def test_a_moving_ref_with_no_commit_to_recover_is_refused_for_that(self) -> None:
        outcome = self._draft(f"<{REPO}/blob/main/src/Vault.sol#L20-L28>", scope="")
        assert isinstance(outcome, Skip)
        assert outcome.cause is SkipCause.NO_COMMIT

    def test_a_finding_citing_nothing_is_refused_for_that_and_not_for_a_path(self) -> None:
        outcome = self._draft("The withdrawal path is reentrant.")
        assert isinstance(outcome, Skip)
        assert outcome.cause is SkipCause.NO_LOCATION
        assert "cites no source location" in outcome.detail
