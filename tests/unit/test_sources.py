"""Reshaping a consolidated judging README into the reports an adapter reads.

The module exists because Sherlock changed a layout, not a format: the same
findings, the same `###` sections, the same permalinks, presented as one file
per contest instead of one file per issue. So these tests are about the two
differences that stop the existing adapter from reading it -- a title carrying
an `Issue M-1: ` prefix, and no bare severity line -- and about not inventing
anything while fixing them.

The severity line's *position* is tested rather than just its presence.
`SherlockAdapter` finds severity with an unanchored multiline search, so a body
that happens to contain a line reading `Medium` would otherwise decide the
finding's severity, and a reshape that appended the real one would be overridden
by whichever came first in the text.
"""

from __future__ import annotations

import json

import pytest

from contract_assay.corpus.adapters.code4rena import Code4renaEnumerator
from contract_assay.corpus.adapters.markdown import contest_snapshot, reviewed_repository
from contract_assay.corpus.adapters.sherlock import SherlockAdapter, SherlockEnumerator
from contract_assay.corpus.harvest import harvest
from contract_assay.corpus.sources import (
    code4rena_report,
    dominant_commits,
    rsc_payload,
    rsc_text_blob,
    sections_of_sherlock_judging,
    split_sherlock_judging,
)

pytestmark = pytest.mark.offline

REPO = "https://github.com/sherlock-audit/2025-07-cap-judging"
SOURCE = "https://github.com/sherlock-audit/2025-07-cap"
SHA = "2bd34fa369d36af8ecc377090d3292ea74ccc669"
OTHER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def a_section(
    *,
    label: str = "M-1",
    title: str = "Liquidation can be extended by resetting the start",
    issue: int = 145,
    found_by: str | None = "Bigsam, dobrevaleri, silver\\_eth",
    root_cause: str = f"{SOURCE}/blob/{SHA}/cap-contracts/contracts/Lender.sol#L88-L89",
    extra: str = "",
) -> str:
    """One section of a consolidated README.

    `found_by=None` and `issue=0` omit those parts, rather than a caller
    deleting them from the result with `str.replace` -- the trailing space on
    the real `Source:` line makes that surgery silently miss, which it did.
    """
    source = f"Source: {REPO}/issues/{issue} \n" if issue else ""
    attribution = f"## Found by \n{found_by}\n" if found_by is not None else ""
    return f"""# Issue {label}: {title}

{source}
{attribution}
### Summary

The health check closes the liquidation before the delegation is slashed.

### Root Cause

```solidity
if (health >= 1e27) _closeLiquidation($, params.agent);
```
{root_cause}

### Impact

An agent stays liquidatable.
{extra}
"""


class TestReadingTheSections:
    def test_a_section_becomes_one_issue_with_its_parts_lifted_out(self) -> None:
        (section,) = sections_of_sherlock_judging(a_section())
        assert section.severity == "Medium"
        assert section.number == 1
        assert section.title == "Liquidation can be extended by resetting the start"
        assert section.source_url == f"{REPO}/issues/145"
        assert section.handles == ("Bigsam", "dobrevaleri", "silver_eth")
        assert section.label == "M-1"
        # The body starts at the first `###`, so the consolidation's framing is
        # not left inside a section the adapter reads by heading.
        assert section.body.startswith("### Summary")
        assert "Found by" not in section.body
        assert "Source:" not in section.body

    def test_high_and_medium_both_read(self) -> None:
        readme = a_section(label="H-3") + a_section(label="M-7", issue=200)
        first, second = sections_of_sherlock_judging(readme)
        assert (first.severity, first.number) == ("High", 3)
        assert (second.severity, second.number) == ("Medium", 7)

    def test_a_section_stops_at_the_next_heading(self) -> None:
        """The marker goes in the SECOND section, which is the direction that bites.

        Written the other way round first -- a marker in section one, asserted
        absent from section two -- and that passes even if every section runs to
        the end of the file, because section one's text is behind section two's
        heading either way. The loss that matters is one finding's body carrying
        the next finding's location.
        """
        readme = a_section(label="M-1") + a_section(
            label="M-2", issue=2, extra="\nONLY IN THE SECOND\n"
        )
        first, second = sections_of_sherlock_judging(readme)
        assert "ONLY IN THE SECOND" in second.body
        assert "ONLY IN THE SECOND" not in first.body
        assert "Issue M-2" not in first.body

    def test_the_last_section_runs_to_the_end_of_the_file(self) -> None:
        (section,) = sections_of_sherlock_judging(a_section(extra="\nTHE VERY END\n"))
        assert "THE VERY END" in section.body

    def test_a_readme_with_no_issue_heading_yields_nothing(self) -> None:
        """Not one section made of the whole file.

        The old layout and an unpublished judging repository both look like
        this, and a section invented from the whole file would put one finding's
        location on another finding.
        """
        assert sections_of_sherlock_judging("# Audit Report\n\nNothing here.\n") == []
        assert sections_of_sherlock_judging("") == []

    def test_a_missing_found_by_is_empty_rather_than_an_error(self) -> None:
        (section,) = sections_of_sherlock_judging(a_section(found_by=None))
        assert section.handles == ()

    def test_a_missing_source_line_is_none(self) -> None:
        (section,) = sections_of_sherlock_judging(a_section(issue=0))
        assert section.source_url is None

    def test_a_heading_inside_a_code_fence_is_still_a_heading(self) -> None:
        """Known, and left alone.

        A `# Issue M-2: ...` line inside a fenced block would split a section.
        No observed README does it, and the alternative -- tracking fence state
        -- would make the splitter a markdown parser to guard against something
        that has not happened. Recorded here so that if it ever does, the test
        names the decision rather than the behaviour looking accidental.
        """
        readme = a_section(extra="\n```\n# Issue M-9: not really a finding\n```\n")
        assert [s.label for s in sections_of_sherlock_judging(readme)] == ["M-1", "M-9"]


class TestTheReshapedBody:
    def test_the_adapter_reads_what_this_produces(self) -> None:
        (report,) = split_sherlock_judging(a_section(), repo_url=REPO)
        issue = SherlockEnumerator().issue(report.body)
        assert issue is not None
        assert issue.severity == "medium"
        assert issue.title == "Liquidation can be extended by resetting the start"
        assert issue.root_cause is not None
        assert SHA in issue.root_cause

    def test_the_title_loses_the_issue_prefix(self) -> None:
        (report,) = split_sherlock_judging(a_section(label="H-12"), repo_url=REPO)
        issue = SherlockEnumerator().issue(report.body)
        assert issue is not None
        assert not issue.title.startswith("Issue")
        assert "H-12" not in issue.title

    def test_the_real_severity_wins_over_one_in_the_prose(self) -> None:
        """The reason the severity line is emitted first.

        `_SEVERITY` is an unanchored multiline search. A body with a line
        reading `High` -- a severity discussion, a table cell -- would otherwise
        set the finding's severity, and `High` and `Medium` are not
        interchangeable: the adapter accepts both, but the record carries the
        one it read.
        """
        readme = a_section(label="M-1", extra="\nSeverity assessment:\n\nHigh\n")
        (report,) = split_sherlock_judging(readme, repo_url=REPO)
        issue = SherlockEnumerator().issue(report.body)
        assert issue is not None
        assert issue.severity == "medium"

    def test_the_report_url_is_the_consolidated_issue(self) -> None:
        (report,) = split_sherlock_judging(a_section(issue=77), repo_url=REPO)
        assert report.report_url == f"{REPO}/issues/77"

    def test_a_section_with_no_source_still_gets_a_distinct_url(self) -> None:
        """Two such sections must not collapse onto one candidate id."""
        readme = a_section(label="M-1", issue=0) + a_section(label="M-2", issue=0)
        first, second = split_sherlock_judging(readme, repo_url=REPO)
        assert first.report_url != second.report_url
        assert first.report_url == f"{REPO}#M-1"

    def test_the_platform_and_date_are_carried(self) -> None:
        (report,) = split_sherlock_judging(a_section(), repo_url=REPO, published="2025-07-07")
        assert report.platform == "sherlock"
        assert report.published == "2025-07-07"

    def test_no_date_is_none_rather_than_today(self) -> None:
        (report,) = split_sherlock_judging(a_section(), repo_url=REPO)
        assert report.published is None

    def test_a_section_with_no_handles_says_so_rather_than_being_blank(self) -> None:
        (report,) = split_sherlock_judging(a_section(found_by=None), repo_url=REPO)
        assert report.body.startswith("unattributed\n")
        # And the severity is still the second stanza, so the adapter reads it.
        issue = SherlockEnumerator().issue(report.body)
        assert issue is not None and issue.severity == "medium"

    def test_the_whole_pipeline_produces_a_draft(self) -> None:
        """The point of the module, asserted through `harvest` rather than beside it."""
        readme = a_section(title="Lender DoS if all asset is borrowed", label="M-3", issue=150)
        reports = split_sherlock_judging(readme, repo_url=REPO, published="2025-07-07")
        report = harvest(SherlockAdapter(), reports)
        assert report.candidates == 1
        assert len(report.drafts) == 1
        draft = report.drafts[0]
        assert draft.candidate_id == f"{REPO}/issues/150"
        assert draft.commit == SHA
        assert draft.path == "cap-contracts/contracts/Lender.sol"


class TestDominantCommits:
    def test_the_most_cited_commit_per_repository_wins(self) -> None:
        text = "\n".join(
            [
                f"{SOURCE}/blob/{SHA}/a.sol#L1",
                f"{SOURCE}/blob/{SHA}/b.sol#L2",
                f"{SOURCE}/blob/{OTHER}/c.sol#L3",
            ]
        )
        assert dominant_commits([text]) == {SOURCE: SHA}

    def test_a_branch_reference_is_not_counted(self) -> None:
        """Otherwise `main` wins by appearing everywhere.

        And the commit it resolves to is whatever it points at today, which is
        the recovery `SherlockAdapter` refuses because it rests on no assumption
        anybody can write down.
        """
        text = "\n".join([f"{SOURCE}/blob/main/a.sol#L1"] * 5 + [f"{SOURCE}/blob/{SHA}/b.sol#L2"])
        assert dominant_commits([text]) == {SOURCE: SHA}

    def test_no_pinned_citation_means_no_entry_rather_than_a_guess(self) -> None:
        assert dominant_commits([f"{SOURCE}/blob/main/a.sol#L1"]) == {}
        assert dominant_commits([""]) == {}

    def test_repositories_are_counted_apart(self) -> None:
        other_repo = "https://github.com/example/other"
        text = f"{SOURCE}/blob/{SHA}/a.sol#L1\n{other_repo}/blob/{OTHER}/b.sol#L2"
        assert dominant_commits([text]) == {SOURCE: SHA, other_repo: OTHER}

    def test_a_tie_is_broken_deterministically(self) -> None:
        """Two runs over one contest have to agree, so the order is stated.

        A tie means the contest cited two commits equally often and neither is
        more the reviewed state than the other. The pin records which
        assumption was made either way; what must not happen is the answer
        changing between runs.
        """
        text = f"{SOURCE}/blob/{SHA}/a.sol#L1\n{SOURCE}/blob/{OTHER}/b.sol#L2"
        assert dominant_commits([text]) == {SOURCE: min(SHA, OTHER)}
        reversed_text = f"{SOURCE}/blob/{OTHER}/b.sol#L2\n{SOURCE}/blob/{SHA}/a.sol#L1"
        assert dominant_commits([reversed_text]) == {SOURCE: min(SHA, OTHER)}

    def test_several_texts_are_counted_together(self) -> None:
        assert dominant_commits(
            [f"{SOURCE}/blob/{SHA}/a.sol#L1", f"{SOURCE}/blob/{SHA}/b.sol#L2"]
        ) == {SOURCE: SHA}


# --------------------------------------------------------------------------
# Code4rena: the report is a web page now
# --------------------------------------------------------------------------

C4 = "https://github.com/code-423n4/2025-03-silo-finance"
SUBMISSION = "https://code4rena.com/audits/2025-03-silo-finance/submissions/F-17"


def a_page(report_html: str, *, duplicate: bool = True) -> str:
    """A Next.js page carrying `report_html` as a length-prefixed RSC blob.

    Duplicated by default because a real page carries the report twice -- once
    for the server render and once in the client payload -- and a converter that
    concatenated both would emit every finding twice.
    """
    blob = f"16:T{len(report_html):x},{report_html}"
    stream = blob + (f"1c:T{len(report_html):x},{report_html}" if duplicate else "")
    return (
        f"<html><body><script>self.__next_f.push([1,{json.dumps(stream)}])</script></body></html>"
    )


def a_report(*, findings: int = 1, declared: int | None = None) -> str:
    heading = declared if declared is not None else findings
    body = "".join(
        f'<h2 id="m-{n:02d}-x" style="position:relative;">'
        f'<a href="#m-{n:02d}-x" aria-label="permalink" class="anchor before">'
        f'<svg aria-hidden="true"><path d="M4 9h1v1H4"></path></svg></a>'
        f'<a href="{SUBMISSION}">[M-{n:02d}] A finding about maxDeposit</a></h2>\n'
        f'<p><em>Submitted by <a href="{SUBMISSION}">warden</a></em></p>\n'
        f'<p><a href="{C4}/blob/{SHA}/silo-vaults/contracts/SiloVault.sol#L136-L150">'
        f"SiloVault.sol#L136-L150</a></p>\n"
        f"<p>The supply function ignores maxDeposit &amp; reverts.</p>\n"
        f'<pre><code class="language-solidity">'
        f'<span class="grvsc-line"><span class="grvsc-source">'
        f"function supply(uint256 assets) internal {{</span></span>\n"
        f"</code></pre>\n"
        for n in range(1, findings + 1)
    )
    return (
        '<h1 id="overview" style="position:relative;">Overview</h1>\n'
        f'<h1 id="medium">Medium Risk Findings ({heading})</h1>\n{body}'
    )


class TestTheCode4renaPage:
    def test_the_adapter_reads_what_the_converter_produces(self) -> None:
        markdown = code4rena_report(a_page(a_report(findings=2)))
        assert markdown is not None
        enumerator = Code4renaEnumerator()
        assert enumerator.declared_total(markdown) == 2
        found = enumerator.findings(markdown)
        assert len(found) == 2
        assert found[0].title == "A finding about maxDeposit"
        assert found[0].issue_url == SUBMISSION

    def test_the_report_is_not_emitted_twice(self) -> None:
        """A real page carries it twice; two of every finding would double a corpus."""
        once = code4rena_report(a_page(a_report(findings=3), duplicate=False))
        twice = code4rena_report(a_page(a_report(findings=3), duplicate=True))
        assert once == twice
        assert twice is not None
        assert twice.count("[M-01]") == 1

    def test_the_headings_self_anchor_is_dropped(self) -> None:
        """Left in, its `href="#m-01-x"` becomes the finding's link."""
        markdown = code4rena_report(a_page(a_report()))
        assert markdown is not None
        assert "#m-01-x" not in markdown
        assert f"## [[M-01] A finding about maxDeposit]({SUBMISSION})" in markdown

    def test_the_permalink_survives_for_the_helpers_that_need_it(self) -> None:
        markdown = code4rena_report(a_page(a_report()))
        assert markdown is not None
        assert reviewed_repository(markdown) == C4
        assert contest_snapshot(markdown) == (C4, SHA)

    def test_a_code_block_becomes_a_fence_with_its_spans_flattened(self) -> None:
        markdown = code4rena_report(a_page(a_report()))
        assert markdown is not None
        assert "```" in markdown
        assert "grvsc" not in markdown
        assert "function supply(uint256 assets) internal {" in markdown

    def test_a_code_blocks_content_is_not_reinterpreted_as_markup(self) -> None:
        """The reason the fence's content is flattened before the link pass.

        The outer tag strip would remove the tag either way, so this looked
        redundant until a code block held an `<a>`: without the inner flatten,
        the link pass rewrites it as a markdown link *inside* a fence, and a
        fenced block is meant to be source rather than markup.
        """
        report = (
            '<h1 id="m">Medium Risk Findings (1)</h1>\n'
            '<h2 id="m-01-x"><a href="' + SUBMISSION + '">[M-01] A finding</a></h2>\n'
            "<pre><code>// see "
            '<a href="https://example.invalid/doc">the docs</a>'
            " for why\nuint256 x = 1;</code></pre>\n"
        )
        markdown = code4rena_report(a_page(report, duplicate=False))
        assert markdown is not None
        fence = markdown.split("```")[1]
        assert "the docs" in fence
        assert "](https://example.invalid/doc)" not in fence
        assert "<a href" not in fence

    def test_entities_are_unescaped(self) -> None:
        markdown = code4rena_report(a_page(a_report()))
        assert markdown is not None
        assert "maxDeposit & reverts" in markdown
        assert "&amp;" not in markdown

    def test_a_page_with_no_report_is_none_rather_than_empty(self) -> None:
        """Empty markdown would report zero findings for a contest that has some."""
        assert code4rena_report("<html><body>not a report</body></html>") is None
        assert code4rena_report(a_page("<p>no findings here</p>")) is None

    def test_a_blob_without_a_heading_is_not_a_report(self) -> None:
        """The table of contents mentions `Risk Findings` too, and is not the report."""
        toc = '<ul><li><a href="#medium-risk-findings-6">Medium Risk Findings (6)</a></li></ul>'
        assert code4rena_report(a_page(toc)) is None

    def test_the_longest_matching_blob_wins_over_the_contents(self) -> None:
        toc = '<ul><li><a href="#m">Medium Risk Findings (1)</a></li></ul>'
        page = a_page(toc + a_report(), duplicate=False)
        markdown = code4rena_report(page)
        assert markdown is not None
        assert Code4renaEnumerator().declared_total(markdown) == 1

    def test_a_declared_count_that_disagrees_is_reported_not_corrected(self) -> None:
        """Observed: `2025-11-merkl` declares 4 medium findings and publishes 3.

        The converter does not reconcile them. The adapter's external count is
        the check that catches a conversion dropping a finding, and silently
        making the two agree would disable it.
        """
        markdown = code4rena_report(a_page(a_report(findings=3, declared=4)))
        assert markdown is not None
        enumerator = Code4renaEnumerator()
        assert enumerator.declared_total(markdown) == 4
        assert len(enumerator.findings(markdown)) == 3

    def test_a_blob_is_sliced_by_its_declared_length(self) -> None:
        """Not by looking for where it ends, which nothing in the stream marks."""
        report = a_report()
        trailing = "TRAILING STREAM DATA"
        page = (
            "<script>"
            + f"self.__next_f.push([1,{json.dumps(f'16:T{len(report):x},{report}{trailing}')}])"
            + "</script>"
        )
        markdown = code4rena_report(page)
        assert markdown is not None
        assert trailing not in markdown

    def test_the_payload_is_json_decoded_rather_than_unescaped_by_hand(self) -> None:
        """The stream carries `\\u003c` for every `<`."""
        report = a_report()
        escaped = json.dumps(f"16:T{len(report):x},{report}").replace("<", "\\u003c")
        page = f"<script>self.__next_f.push([1,{escaped}])</script>"
        markdown = code4rena_report(page)
        assert markdown is not None
        assert "[M-01]" in markdown


class TestTheRscHelpers:
    def test_a_page_with_no_push_calls_falls_back_to_its_own_text(self) -> None:
        """A server-rendered page with the report in the HTML still converts."""
        assert rsc_payload("<html>nothing</html>") == ""
        report = a_report()
        plain = f"<html>16:T{len(report):x},{report}</html>"
        markdown = code4rena_report(plain)
        assert markdown is not None
        assert "[M-01]" in markdown

    def test_no_blob_containing_the_marker_is_none(self) -> None:
        assert rsc_text_blob("14:T5,hello", containing="absent") is None
