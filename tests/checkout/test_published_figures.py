"""Every figure the docstrings publish, asserted against a real checkout.

**Why this file exists.** Eight review rounds found, every time, a figure
re-measured on one side of a comparison and not the other: the honest ceiling
published three ways, a before/after pair drawn from two submission files, a
table whose `equality` column came from one checkout and its `now` column from
another. The generator was structural -- these numbers live in prose, their two
halves live in different sentences, and nothing recomputed either. A reviewer
re-derived them by hand each round and the next commit moved one again.

So the numbers are a test. Each assertion names where the figure is published,
and a figure that moves now fails here instead of being found by reading.

`checkout`-marked, because it needs the source the corpus pins. The offline gate
has none; `.github/workflows/ci.yml`'s `figures` job fetches one and runs this,
so the marker is a gate and not a decoration. Locally:

    contract-assay fetch corpus/records --source-root ./checkout
    pytest -m checkout
"""

from __future__ import annotations

import collections
import os
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

import pytest

from contract_assay.cli import _local_resolver
from contract_assay.corpus.records import CorpusRecord, load_records
from contract_assay.detectors.base import (
    _MINIMUM_QUOTE_TOKENS,
    _names_something_of_its_own,
    _tokens,
)
from contract_assay.models import (
    MAX_QUOTE_CHARS,
    CitationStatus,
    DetectorRun,
    EvidenceTier,
    Finding,
    Locator,
    Outcome,
    VerifiedFinding,
    VulnerabilityClass,
)
from contract_assay.report.scoring import MatchStrength, score

pytestmark = pytest.mark.checkout

ROOT = Path(__file__).resolve().parents[2]
CHECKOUT = Path(os.environ.get("CONTRACT_ASSAY_CHECKOUT", ROOT / "checkout"))


@pytest.fixture(scope="module")
def resolve():  # type: ignore[no-untyped-def]
    if not CHECKOUT.is_dir():
        pytest.skip(
            f"no checkout at {CHECKOUT}; run "
            "`contract-assay fetch corpus/records --source-root ./checkout` "
            "or set CONTRACT_ASSAY_CHECKOUT"
        )
    return _local_resolver(CHECKOUT)


@pytest.fixture(scope="module")
def records() -> list[CorpusRecord]:
    return list(load_records(ROOT / "corpus" / "records"))


@pytest.fixture(scope="module")
def positives(records: Sequence[CorpusRecord]) -> list[CorpusRecord]:
    return [r for r in records if r.is_positive and r.locator is not None]


def _micro(report, floor: MatchStrength = MatchStrength.FUNCTION) -> tuple[int, int]:  # type: ignore[no-untyped-def]
    """Matched at or above `floor`, over records. The figure the docs quote."""
    hits = sum(
        count
        for cls in report.by_class.values()
        for strength, count in cls.by_strength.items()
        if strength.rank >= floor.rank
    )
    return hits, sum(cls.records for cls in report.by_class.values())


def _runs(findings: dict[tuple[str, VulnerabilityClass], list[VerifiedFinding]]):  # type: ignore[no-untyped-def]
    return [
        DetectorRun(
            detector_id="figures",
            class_id=cls,
            source_id=source_id,
            outcome=Outcome.VULNERABLE,
            evidence_tier=EvidenceTier.SYNTACTIC,
            findings=tuple(found),
            produced_without_a_model=True,
        )
        for (source_id, cls), found in findings.items()
        if found
    ]


def _citable(text: str) -> bool:
    tokens = _tokens(text)
    return len(tokens) >= _MINIMUM_QUOTE_TOKENS and _names_something_of_its_own(tokens)


def _submission(  # type: ignore[no-untyped-def]
    positives, resolve, *, shape: str, above: int = 0, below: int = 0
):
    """One honest submission per shape, built the way a submitter would."""
    found: dict[tuple[str, VulnerabilityClass], list[VerifiedFinding]] = collections.defaultdict(
        list
    )
    skipped: list[str] = []
    for record in positives:
        source = resolve(record.pin)
        if source is None:
            skipped.append(record.record_id)
            continue
        lines = source.split("\n")
        locator = record.locator
        if locator.end_line > len(lines):
            skipped.append(record.record_id)
            continue
        if shape == "whole-span":
            kept: list[str] = []
            for line in lines[locator.start_line - 1 : locator.end_line]:
                if len("\n".join([*kept, line])) > MAX_QUOTE_CHARS:
                    break
                kept.append(line)
            if not kept or not "\n".join(kept).strip():
                skipped.append(record.record_id)
                continue
            start, end, quote = (
                locator.start_line,
                locator.start_line + len(kept) - 1,
                "\n".join(kept),
            )
        else:
            anchor = record.anchor_line or locator.start_line
            last = anchor if shape == "one-line" else min(anchor + 4, locator.end_line)
            picked = None
            for end_line in range(anchor, last + 1):
                candidate = "\n".join(lines[anchor - 1 : end_line])
                if len(candidate) > MAX_QUOTE_CHARS:
                    break
                if _citable(candidate):
                    picked = (anchor, end_line, candidate)
                    break
            if picked is None:
                skipped.append(record.record_id)
                continue
            start, end, quote = picked
        declared = Locator(
            file=locator.file,
            contract=locator.contract,
            function=locator.function,
            start_line=max(1, start - above),
            end_line=min(end + below, len(lines)),
        )
        for cls in record.classes:
            found[(record.pin.source_id, cls)].append(
                VerifiedFinding(
                    finding=Finding(
                        detector_id="figures",
                        locator=declared,
                        quote=quote,
                        reasoning="the figure this file pins",
                    ),
                    status=CitationStatus.VERIFIED,
                )
            )
    return _runs(found), skipped


class TestTheDigestMeansOneThing:
    """`fetch` compares bytes; the gates compare the text the resolver returned.

    Two domains for "the digest of this file", and they agree on this corpus by
    measurement rather than by construction: the text digest is over a lenient
    decode, which is not injective over bytes, so a file carrying an invalid
    UTF-8 sequence would be `verified` by `fetch` and rejected by `verify`. The
    text domain is the definition -- it identifies the text the scorer analyses,
    which is what the locators index -- and this asserts the two have not
    diverged.
    """

    def test_the_byte_digest_and_the_text_digest_agree(self, records, resolve) -> None:  # type: ignore[no-untyped-def]
        # `resolve` is requested for its skip guard, not its value: without it
        # this test alone reported a missing checkout as the byte digest and
        # the text digest disagreeing, while its ten siblings skipped and named
        # the fetch command.
        import hashlib

        from contract_assay.corpus.fetch import checkout_file

        assert resolve is not None

        checked = 0
        for record in records:
            found = checkout_file(CHECKOUT, record.pin)
            if found is None or record.pin.sha256 is None:
                continue
            raw = found.read_bytes()
            text = raw.decode("utf-8", errors="replace")
            assert hashlib.sha256(raw).hexdigest() == record.pin.sha256, record.record_id
            assert hashlib.sha256(text.encode("utf-8")).hexdigest() == record.pin.sha256, (
                record.record_id
            )
            checked += 1
        assert checked >= 140


class TestTheHonestCeiling:
    """`report.scoring.recheck_citations`, `docs/api.md` §1, `README.md`."""

    def test_quoting_the_whole_recorded_span(self, positives, resolve, records) -> None:  # type: ignore[no-untyped-def]
        runs, _ = _submission(positives, resolve, shape="whole-span")
        report = score(runs, records, resolve)
        assert _micro(report) == (469, 471)
        by_class = {cls.value: score_.precision() for cls, score_ in report.by_class.items()}
        assert by_class["access_control"] == pytest.approx(0.9836, abs=5e-5)
        assert all(
            value == pytest.approx(1.0)
            for name, value in by_class.items()
            if name != "access_control" and value is not None
        )


class TestLocatorSlopIsFree:
    """`detectors.base.cited_lines`'s honest table, and `docs/api.md`.

    Seven shapes, one figure. The rule this pins is that a correct quote is not
    punished for a locator a line or five wide in any direction -- which is what
    the span-equality rule broke, at 0.9908 -> 0.0759.
    """

    @pytest.mark.parametrize(
        ("above", "below"),
        [(0, 0), (0, 1), (0, 5), (1, 0), (5, 0), (1, 1), (5, 5)],
    )
    def test_one_statement_quoted_at_a_wider_locator(  # type: ignore[no-untyped-def]
        self, positives, resolve, records, above: int, below: int
    ) -> None:
        runs, _ = _submission(positives, resolve, shape="statement", above=above, below=below)
        report = score(runs, records, resolve)
        assert _micro(report) == (467, 471)


class TestWhatTheTokenFloorCosts:
    """`detectors.base._MINIMUM_QUOTE_TOKENS` and `docs/api.md`'s floor note."""

    def test_a_submitter_confined_to_its_anchor_line(self, positives, resolve, records) -> None:  # type: ignore[no-untyped-def]
        runs, skipped = _submission(positives, resolve, shape="one-line")
        report = score(runs, records, resolve)
        assert _micro(report) == (344, 471)
        # 127 records missed, and the docstring's arithmetic is that one of them
        # is not an anchor-line refusal at all: its source resolves from no
        # public coordinates. An earlier version of that sentence closed the
        # arithmetic by inventing a fourth category.
        assert len(skipped) == 127
        unresolvable = [r.record_id for r in positives if resolve(r.pin) is None]
        assert len(unresolvable) == 1
        assert len(set(skipped) - set(unresolvable)) == 126

    def test_the_floor_is_the_dominant_refusal_and_the_clause_is_not(  # type: ignore[no-untyped-def]
        self, positives, resolve
    ) -> None:
        floor = clause = 0
        for record in positives:
            source = resolve(record.pin)
            if source is None:
                continue
            lines = source.split("\n")
            if record.locator.end_line > len(lines):
                continue
            anchor = record.anchor_line or record.locator.start_line
            tokens = _tokens(lines[anchor - 1])
            if len(tokens) < _MINIMUM_QUOTE_TOKENS:
                floor += 1
            elif not _names_something_of_its_own(tokens):
                clause += 1
        assert (floor, clause) == (123, 3)


class TestAForgedCheckoutIsARefusal:
    """`report.scoring.VerifiedSource` and `docs/api.md`'s `--source-root` note.

    Forged source for every unit, and quotes that are real lines *of the
    forgery*: the digest gate refuses every one, so the figure is a refusal
    with a count rather than a number about the wrong bytes.
    """

    def test_every_citation_on_forged_source_is_unchecked(
        self, positives, resolve, records
    ) -> None:  # type: ignore[no-untyped-def]
        def forged(pin):  # type: ignore[no-untyped-def]
            text = resolve(pin)
            return None if text is None else text + "\n// planted\n"

        runs, _ = _submission(positives, forged, shape="whole-span")
        report = score(runs, records, forged)
        assert _micro(report) == (0, 471)
        assert report.unchecked_citations == report.stale_citations == 470


class TestTheShapesTheRuleRefuses:
    """`docs/api.md`'s "Shapes this refuses": how many records each shape reaches.

    Non-adjacent lines need three non-blank lines in the span; an interior
    comment is a comment-only line strictly between its first and last
    non-blank lines.
    """

    def test_how_many_spans_each_shape_reaches(self, positives, resolve) -> None:  # type: ignore[no-untyped-def]
        def is_comment(line: str) -> bool:
            return line.startswith(("//", "/*", "*"))

        non_adjacent = interior_comment = resolvable = 0
        for record in positives:
            source = resolve(record.pin)
            if source is None:
                continue
            lines = source.split("\n")
            if record.locator.end_line > len(lines):
                continue
            resolvable += 1
            span = lines[record.locator.start_line - 1 : record.locator.end_line]
            code = [line.strip() for line in span if line.strip()]
            non_adjacent += len(code) >= 3
            interior_comment += any(is_comment(line) for line in code[1:-1])
        assert (len(positives), non_adjacent) == (471, 449)
        assert (resolvable, interior_comment) == (470, 207)


class TestTheBaselineThreeDeclarationsBuy:
    """`detectors.base.PredicateDetector`, `docs/api.md` §1 and `README.md`.

    The baseline the docs tell an entrant to beat, run the way `contract-assay
    run` runs it: every unit the records pin, no model. Once published at 97
    predictions and 0.27, then 34 against 55 records; the corpus grew under the
    second figure and nothing re-ran it.
    """

    def test_the_access_control_baseline(self, records, resolve) -> None:  # type: ignore[no-untyped-def]
        from contract_assay.detectors import API_VERSION, PredicateDetector
        from contract_assay.harness import run_submission, units_from

        class Baseline(PredicateDetector):
            detector_id = "baseline-access-control"
            class_id = VulnerabilityClass.ACCESS_CONTROL
            api_version = API_VERSION

        units, missing = units_from(records, CHECKOUT)
        assert len(missing) == 1
        report = score(list(run_submission([Baseline()], units)), records, resolve)
        cls = report.by_class[VulnerabilityClass.ACCESS_CONTROL]
        assert (cls.predictions, cls.records) == (41, 62)
        # Recall at the function floor, the one the docs quote: 6 of 62.
        assert cls.recall() == pytest.approx(6 / 62)


class TestTheProseQuotesTheseFigures:
    """The literals above, counted in the prose that publishes them.

    Pinning the figures in this file closed one half of the generator: a figure
    that moves fails a test. The other half stayed open -- a review changed
    `micro recall 0.9954` to `0.9977` in one docstring and every gate passed,
    because the prose is coupled to these literals by convention. So the
    coupling is a test too, and it counts rather than searches: presence alone
    passed the same mutation, because the figure still appeared elsewhere in
    the file.

    A count is deliberately brittle. If you add a sentence that mentions one of
    these figures, the number here moves with it -- which is the point: every
    edit to a published figure's prose is then a deliberate one.
    """

    # Current figures (0.9958, 0.9836, 0.9915, 0.7304) over the 471 located
    # positives, and the ones measured on the 435-record corpus (0.9954,
    # 0.9815, 0.9908, 0.7149), which stay where a comparison was drawn and are
    # labelled as such. Both are counted: a historical figure quietly "updated"
    # would be the mixed-checkout table again.
    PUBLISHED: ClassVar[dict[str, dict[str, int]]] = {
        "src/contract_assay/report/scoring.py": {
            "0.9908": 3,
            "0.9958": 1,
            "0.9836": 1,
            "0.9915": 1,
        },
        "src/contract_assay/detectors/base.py": {
            "0.9954": 4,
            "0.9908": 10,
            "0.9958": 1,
            "0.9915": 3,
            "0.7304": 1,
        },
        "docs/api.md": {
            "0.9958": 1,
            "0.9836": 1,
            "0.9915": 4,
            "0.7304": 1,
            "41 access-control predictions": 1,
            "470 citations reported unchecked": 1,
            "**449 of 471**": 1,
            "**207 of\n470**": 1,
        },
        "README.md": {"0.9958": 1, "41 access-control predictions": 1},
        "results/README.md": {"0.9958": 1},
    }

    @pytest.mark.parametrize("relative", sorted(PUBLISHED))
    def test_each_figure_this_file_pins_is_quoted_the_same_number_of_times(
        self, relative: str
    ) -> None:
        body = (ROOT / relative).read_text(encoding="utf-8")
        counted = {figure: body.count(figure) for figure in self.PUBLISHED[relative]}
        assert counted == self.PUBLISHED[relative], (
            f"{relative}'s published figures moved. If a measurement changed, the "
            "assertions above should have failed first; if you added or removed a "
            "mention, update the count here in the same commit"
        )
