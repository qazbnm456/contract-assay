"""Command line entry point.

Only the commands that are actually implemented appear here. A CLI that
advertises subcommands it cannot run is worse than a short one: it reports a
project's intentions as though they were its capabilities.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from contract_assay import __version__
from contract_assay.corpus.fetch import (
    checkout_file,
    fetch_pins,
    fetch_records,
    urllib_fetcher,
)
from contract_assay.corpus.records import CorpusRecord, SourcePin, load_records
from contract_assay.corpus.units import read_manifest, unit_manifest
from contract_assay.corpus.verify import verify_all
from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec
from contract_assay.detectors.loading import (
    MalformedSubmission,
    SubmissionManifest,
    load_detector,
)
from contract_assay.evidence.solidity import index_source
from contract_assay.harness import (
    ModelCaller,
    ModelReply,
    SourceUnit,
    load_caller,
    run_submission,
    units_from,
    units_from_pins,
)
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
    DetectorRun,
    DifficultyLevel,
    InvalidReason,
    Outcome,
    VulnerabilityClass,
)
from contract_assay.report.leaderboard import Measure, leaderboard, score_submission
from contract_assay.report.scoring import score
from contract_assay.report.wire import leaderboard_document, score_document
from contract_assay.results import compare, load_pointers

app = typer.Typer(
    name="contract-assay",
    help="Benchmark infrastructure for LLM smart contract auditing.",
    no_args_is_help=True,
    add_completion=False,
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"contract-assay {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = False,
) -> None:
    """Benchmark infrastructure for LLM smart contract auditing."""


def _source_from_manifest(root: Path, pin: SourcePin) -> str | None:
    """Verified source for an address pin, from a manifest laid out by chain.

    `<root>/<chain_id>/<address>.json`, holding `{"sources": {key: content}}` --
    the shape a verification repository answers with. A manifest rather than a
    directory tree because that is what the thing being represented *is*: a set
    of named files, whose names are import specifiers rather than paths. Writing
    them into directories would make `path` joinable by accident and lose the
    distinction the pin exists to carry.
    """
    if pin.kind != "address":
        return None
    manifest = root / str(pin.chain_id) / f"{pin.address}.json"
    if not manifest.is_file():
        return None
    try:
        sources = json.loads(manifest.read_text(encoding="utf-8")).get("sources", {})
    except (json.JSONDecodeError, OSError):
        return None
    entry = sources.get(pin.path)
    if isinstance(entry, dict):
        entry = entry.get("content")
    return entry if isinstance(entry, str) else None


def _local_resolver(root: Path):  # type: ignore[no-untyped-def]
    """Resolve pinned paths against a checkout on disk.

    Resolves whatever is there, digest or no digest, and that is deliberate:
    `verify` distinguishes `digest_mismatch` from `source_unresolvable`, and a
    resolver that returned `None` for a mismatch would collapse the two -- a
    cause recorded wrongly points investigation away from the fix. The digest is
    enforced where the trust boundary is, in `report.scoring.VerifiedSource`,
    which every byte consumer inside one `score` draws from -- the path a third
    party's submission travels.

    Verification against a working tree, not a fetched commit: it cannot confirm
    that the bytes belong to the pinned commit, only that the record is coherent
    against what is here.
    """

    def resolve(pin: SourcePin) -> str | None:
        # `path` is a key into the pinned unit, and only some kinds of unit are
        # directories. Verified source arrives as a *map* of import-style names
        # to contents -- `@openzeppelin/contracts/token/ERC20/ERC20.sol` and the
        # like -- which look exactly like repository paths and join to nothing.
        # Joining a key to a root because it looked like a path reads the wrong
        # file, or no file, and says nothing about why; so the pin is asked, and
        # the two kinds are read from the two shapes they actually have.
        if pin.is_filesystem_path:
            # `checkout_file` knows the revision names `fetch` writes and
            # prefers one only when its bytes match the pin, which is the same
            # rule `harness.units_from` now applies. One function, because the
            # two of them disagreeing is how a unit the checkout held came back
            # reported as missing.
            candidate = checkout_file(root, pin)
            if candidate is None:
                return None
            return candidate.read_text(encoding="utf-8", errors="replace")
        return _source_from_manifest(root, pin)

    return resolve


@app.command("verify")
def verify_command(
    records: Annotated[
        Path,
        typer.Argument(exists=True, help="A corpus record JSON file, or a directory of them."),
    ],
    source_root: Annotated[
        Path,
        typer.Option(
            "--source-root", exists=True, file_okay=False, help="Checkout to verify against."
        ),
    ],
    write_digests: Annotated[
        bool,
        typer.Option("--write-digests", help="Write computed digests back to admitted records."),
    ] = False,
) -> None:
    """Check corpus records against source, and report what was rejected and why."""
    paths = sorted(records.glob("*.json")) if records.is_dir() else [records]
    if not paths:
        typer.secho(f"no record files under {records}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    parsed: list[CorpusRecord] = []
    for path in paths:
        try:
            parsed.append(CorpusRecord.model_validate_json(path.read_text(encoding="utf-8")))
        except ValidationError as exc:
            typer.secho(f"{path.name}: malformed record", fg=typer.colors.RED, err=True)
            typer.echo(f"  {exc.error_count()} problem(s); first: {exc.errors()[0]['msg']}")
            raise typer.Exit(1) from exc

    report = verify_all(parsed, _local_resolver(source_root))

    for result in report.rejected:
        typer.secho(f"  rejected  {result}", fg=typer.colors.RED, err=True)
    for record in report.admitted:
        typer.secho(f"  admitted  {record.record_id}", fg=typer.colors.GREEN, err=True)

    if write_digests:
        by_id = {r.record_id: r for r in report.admitted}
        for path in paths:
            record_id = json.loads(path.read_text(encoding="utf-8"))["record_id"]
            if updated := by_id.get(record_id):
                path.write_text(updated.model_dump_json(indent=2) + "\n", encoding="utf-8")

    # Printed on every run, including a clean one. What the corpus is a sample of
    # is a property of the corpus, not a warning about this invocation, and a
    # statement that only appears on failure is one nobody reads.
    typer.echo(f"\n{report.sampling_statement()}")
    if report.rejected:
        raise typer.Exit(1)


@app.command("declarations")
def declarations_command(
    source: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="A .sol file.")],
) -> None:
    """List what a Solidity file declares, and on which lines.

    The same index the verifier uses, exposed so that a rejected record can be
    diagnosed without guessing at what the file actually contains.
    """
    index = index_source(source.read_text(encoding="utf-8", errors="replace"))
    if not index.parsed:
        typer.secho("no declarations could be read from this file", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    for decl in index.declarations:
        scope = f"{decl.parent}." if decl.parent else ""
        names = "/".join(decl.names)
        # Parameter types are shown for anything function-like, because a name on
        # its own does not identify an overloaded function -- and diagnosing a
        # record rejected as ambiguous is exactly what this command is for.
        if not decl.kind.is_type:
            names += f"({','.join(decl.parameter_types)})"
        typer.echo(
            f"  {decl.start_line:>5}-{decl.end_line:<5} {decl.kind.value:<20} {scope}{names}"
        )


def _records_from(directory: Path) -> list[CorpusRecord]:
    """The public loader, with the CLI's own exit on top of it.

    The reading and validating live in `corpus.records` so that a consumer
    outside this package gets the same behaviour; what belongs here is only the
    decision to stop the process, which a library has no business making.
    """
    try:
        return load_records(directory)
    except ValueError as invalid:
        typer.secho(str(invalid), fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from invalid


def _runs_from(path: Path) -> list[DetectorRun]:
    """A submission's output, one `DetectorRun` document per line.

    JSON Lines rather than one array, because a harness writes runs as it
    finishes units and a truncated array is unreadable where a truncated stream
    is short. A malformed line stops the load rather than being skipped: a
    scoring run that silently dropped part of a submission would report its
    recall as the submission's.
    """
    runs: list[DetectorRun] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            runs.append(DetectorRun.model_validate_json(line))
        except ValidationError as invalid:
            typer.secho(
                f"{path.name}:{number}: {invalid.error_count()} problems",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1) from invalid
    return runs


def _weights_from(path: Path | None) -> dict[DifficultyLevel, float]:
    """The exercise's difficulty weighting, which this engine does not supply.

    Absent, the per-class figures are still reported and the aggregate is
    refused with that as its stated reason. A default here would be this
    project asserting what the exercise values, which is the caller's to say.
    """
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    weights: dict[DifficultyLevel, float] = {}
    for key, value in raw.items():
        try:
            weights[DifficultyLevel(key)] = float(value)
        except (ValueError, TypeError) as bad:
            typer.secho(
                f"{path.name}: {key!r} is not a difficulty level", fg=typer.colors.RED, err=True
            )
            raise typer.Exit(1) from bad
    return weights


def _class_weights_from(path: Path | None) -> dict[VulnerabilityClass, float] | None:
    """A weight per vulnerability class, when the exercise measured one.

    `None` rather than `{}` when absent, because the two mean different things
    to the scorer: `None` is "weight by difficulty level", and an empty mapping
    is "weight by class, and name no class" -- which covers nothing and refuses
    every total. Returning the second for a missing file would turn a forgotten
    flag into a board with no rows and a reason nobody would connect to it.
    """
    if path is None:
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    weights: dict[VulnerabilityClass, float] = {}
    for key, value in raw.items():
        try:
            weights[VulnerabilityClass(key)] = float(value)
        except (ValueError, TypeError) as bad:
            typer.secho(
                f"{path.name}: {key!r} is not a vulnerability class",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1) from bad
    return weights


@app.command("fetch")
def fetch_command(
    source_root: Annotated[
        Path, typer.Option("--source-root", help="Where the checkout is built.")
    ],
    records: Annotated[
        Path | None,
        typer.Argument(exists=True, help="Corpus record file or directory."),
    ] = None,
    workers: Annotated[int, typer.Option("--workers", min=1, max=32)] = 8,
    units: Annotated[
        Path | None,
        typer.Option(
            "--units",
            exists=True,
            dir_okay=False,
            help="A unit manifest, for a split whose records you do not have.",
        ),
    ] = None,
) -> None:
    """Build a source checkout from the records' pins, verifying every digest.

    `verify` and `score` both need a checkout, and until this existed nobody
    outside this repository could build one -- the pins were a promise of
    reproducibility that could not be collected.

    A file whose digest does not match its pin is **not written**, and the
    reason is the one failure here with no symptom: its record's locators index
    lines that have moved, so a score over it would be a real number about the
    wrong source.
    """
    if (records is None) == (units is None):
        typer.secho(
            "pass exactly one of a records path (you hold the answers) or --units "
            "(you were given a manifest)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)
    if units is not None:
        try:
            pins = read_manifest(units.read_text(encoding="utf-8"))
        except (OSError, ValueError) as bad:
            typer.secho(f"{units}: {bad}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from bad
        report = fetch_pins(list(pins), source_root, workers=workers, fetch=urllib_fetcher())
    else:
        assert records is not None
        report = fetch_records(
            _records_from(records), source_root, workers=workers, fetch=urllib_fetcher()
        )
    for outcome in report.by_state("mismatched") + report.by_state("unavailable"):
        typer.secho(
            f"  {outcome.state:<12} {outcome.path}: {outcome.detail}", fg=typer.colors.RED, err=True
        )
    typer.echo(report.statement())
    # Non-zero unless every pin a repository *can* serve is usable. `usable`
    # alone exited 0 as soon as one file landed, whatever fraction failed --
    # measured, 1 of 2 pins gave exit 0 -- so a CI step could not tell a
    # complete checkout from a mostly empty one. A pin a repository cannot
    # serve at all is expected and does not count against it: one record here
    # pins verified source for a deployed address, which is why `verify` reports
    # 477 of 478 and this command still exits 0 on a good fetch.
    expected_gaps = sum(
        1 for outcome in report.by_state("unavailable") if "chain explorer" in outcome.detail
    )
    if report.usable + expected_gaps < len(report.outcomes):
        raise typer.Exit(1)


@app.command("units")
def units_command(
    records: Annotated[
        Path,
        typer.Argument(exists=True, help="Corpus record file or directory."),
    ],
    out: Annotated[
        Path | None, typer.Option("--out", help="Where the manifest is written.")
    ] = None,
) -> None:
    """Publish a split's units without its answers, as a manifest.

    What a **held-out** split gives a participant. A record carries the answer
    -- its locator says where the defect is, and its classes say what kind --
    so a holdout cannot be handed out as records. The manifest is the pins and
    nothing else: enough to fetch the source, name a unit, and produce runs a
    scorer can match.

    `run --units` takes the result. Scoring still happens against the records,
    which stay with whoever holds them.
    """
    document = unit_manifest(_records_from(records))
    text = json.dumps(document, indent=1) + "\n"
    if out is None:
        typer.echo(text)
        return
    out.write_text(text, encoding="utf-8")
    typer.echo(f"wrote {out}: {len(document['units'])} unit(s), pins only")


@app.command("run")
def run_command(
    manifest: Annotated[
        list[Path],
        typer.Option(
            "--manifest", exists=True, dir_okay=False, help="Submission manifest. Repeatable."
        ),
    ],
    source_root: Annotated[
        Path,
        typer.Option("--source-root", exists=True, file_okay=False, help="Checkout to read."),
    ],
    out: Annotated[Path, typer.Option("--out", help="Where the runs are written, as JSON Lines.")],
    records: Annotated[
        Path | None,
        typer.Option("--records", exists=True, help="Corpus record file or directory."),
    ] = None,
    units: Annotated[
        Path | None,
        typer.Option(
            "--units",
            exists=True,
            dir_okay=False,
            help="A unit manifest, for a split whose records you do not have.",
        ),
    ] = None,
    model_caller: Annotated[
        str | None,
        typer.Option(
            "--model-caller",
            help="`module.path:function` returning a `harness.ModelReply`. Left out, no "
            "model is called -- which is a real submission, not a degraded one.",
        ),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", min=0, help="Stop after N units. 0 is all.")] = 0,
    wall_seconds: Annotated[int, typer.Option("--wall-seconds", min=1)] = 30,
    max_calls: Annotated[int, typer.Option("--max-calls", min=0)] = 4,
    max_tokens: Annotated[int, typer.Option("--max-tokens", min=0)] = 20_000,
    predictions_per_unit: Annotated[
        int,
        typer.Option(
            "--predictions-per-unit",
            min=1,
            help="Hand the benchmark at most this many model findings per unit per class, "
            "in the order your detectors returned them. The default is what `score` will "
            "count, so what you submit is what gets scored.",
        ),
    ] = DEFAULT_PREDICTIONS_PER_UNIT,
) -> None:
    """Run one or more detectors over the corpus and write the runs.

    The loop between "a submission exists" and "it can be scored". Until this
    existed every consumer wrote it, and the first two both got the same two
    things wrong: reading the corpus, and naming what produced a finding.

    **No model is called unless you name a caller.** A deterministic run is a
    real submission and this benchmark's own control group, so it is the default
    rather than a fallback. A model is your code, resolved from an import path
    the way a submission is -- this package imports no provider, because an
    instrument whose correctness depended on the thing it measures could not
    tell a broken instrument from a weak model.
    """
    detectors: list[Detector] = []
    for path in manifest:
        try:
            declared = SubmissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
        except ValidationError as malformed:
            # The boundary in `run_cli` catches this too, and cannot name the
            # file: several `--manifest` flags are allowed, so "1 validation
            # error for SubmissionManifest" leaves the operator to guess which
            # one. `verify` has named its file for every malformed record since
            # it was written.
            problems = malformed.errors()
            first = problems[0]["msg"] if problems else str(malformed)
            typer.secho(f"{path.name}: {first}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from malformed
        try:
            detectors.append(load_detector(declared, search_path=path.parent))
        except MalformedSubmission as bad:
            typer.secho(f"{path}: {bad}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from bad

    caller: ModelCaller | None = None
    # Counted, because `Detector.plan()` returns `None` by default and `None`
    # means "no model". A caller named against detectors that never ask for one
    # is a run in which the caller was never called -- every run `clean`, no
    # warning, and the figures read as a harness that finds nothing.
    invocations = 0
    if model_caller is not None:
        try:
            named = load_caller(model_caller, search_path=Path.cwd())
        except ValueError as bad:
            typer.secho(str(bad), fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from bad

        def counted(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
            nonlocal invocations
            invocations += 1
            return named(detector, spec, ctx)

        caller = counted

    # Exactly one. Both would be two answers to "which units", and a caller
    # that passed both has a belief about which wins that this command should
    # not confirm by picking. Neither is the missing-argument case typer used
    # to report for `--records` alone.
    if (records is None) == (units is None):
        typer.secho(
            "pass exactly one of --records (you hold the answers) or --units "
            "(you were given a manifest)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)
    if units is not None:
        try:
            pins = read_manifest(units.read_text(encoding="utf-8"))
        except (OSError, ValueError) as bad:
            typer.secho(f"{units}: {bad}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1) from bad
        analysed, missing = units_from_pins(pins, source_root)
    else:
        assert records is not None
        analysed, missing = units_from(_records_from(records), source_root)
    if missing:
        # Said out loud, never counted over. A unit absent from a checkout
        # scores as a submission that missed it.
        typer.secho(
            f"{len(missing)} unit(s) are not in {source_root} and were not run; "
            "`contract-assay fetch` builds the checkout. Figures from this run are "
            "over the analysed that are present.",
            fg=typer.colors.YELLOW,
        )
    if not analysed:
        typer.secho(f"no source units found under {source_root}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    if limit:
        analysed = analysed[:limit]

    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    outcomes: Counter[Outcome] = Counter()
    causes: Counter[InvalidReason] = Counter()
    failures: Counter[str] = Counter()

    def note_failure(unit: SourceUnit, detector: Detector, cause: str) -> None:
        # A run records *that* a call failed and not what the transport did, so
        # the cause is kept here and printed once the sweep ends.
        failures[" ".join(cause.split())[:300]] += 1

    with out.open("w", encoding="utf-8") as handle:
        for run in run_submission(
            detectors,
            analysed,
            model=caller,
            wall_seconds=wall_seconds,
            max_calls=max_calls,
            max_tokens=max_tokens,
            predictions_per_unit=predictions_per_unit,
            on_unit=lambda i, u: typer.echo(f"  [{i + 1}/{len(analysed)}] {u.path}", err=True),
            on_failure=note_failure,
        ):
            # Flushed per run, so a sweep that dies at unit 90 of 141 leaves 90
            # analysed of runs behind it rather than nothing.
            handle.write(json.dumps(run.model_dump(mode="json")) + "\n")
            handle.flush()
            written += 1
            outcomes[run.outcome] += 1
            if run.invalid_reason is not None:
                causes[run.invalid_reason] += 1

    typer.echo(f"wrote {out}: {written} run(s) over {len(analysed)} unit(s)")
    # **The losses, not just the count.** A sweep that wrote 140 runs of which
    # 130 were invalid printed the same line as one that worked, and the first
    # thing a newcomer does is read that line and believe it. Measured: a
    # detector that asks for a model, run without `--model-caller`, produces 130
    # of 140 invalid, and nothing said so until the score document reported
    # every class empty.
    broken = outcomes[Outcome.INVALID] + outcomes[Outcome.SKIPPED]
    if broken:
        typer.secho(
            f"  {outcomes[Outcome.INVALID]} invalid and {outcomes[Outcome.SKIPPED]} skipped: "
            "these measure nothing and score as misses.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        for cause, count in causes.most_common():
            typer.secho(f"    {count:>4}  {cause.value}", fg=typer.colors.YELLOW, err=True)
        for cause_text, count in failures.most_common(3):
            typer.secho(
                f"    model call failed ({count}x): {cause_text}",
                fg=typer.colors.YELLOW,
                err=True,
            )
        if causes.get(InvalidReason.MODEL_NOT_PERMITTED):
            # The one cause a newcomer hits first and cannot act on from its
            # name alone: the detector asked for a model and none was named.
            typer.secho(
                "    A detector asked for a model and none was named. Pass "
                "--model-caller module.path:function, or submit a deterministic "
                "harness on purpose.",
                fg=typer.colors.YELLOW,
                err=True,
            )
    if model_caller is not None and invocations == 0:
        typer.secho(
            f"  --model-caller {model_caller} was never called: no detector's plan() "
            "returned a ModelTaskSpec, and the default returns None, which means no "
            "model. These runs measure the detectors alone.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if records is not None:
        typer.echo(
            f"  contract-assay score {out} --records {records} --source-root {source_root} "
            "--submission-id <id> --out score.json"
        )
    else:
        # **Not the same next step.** A manifest run has no records to score
        # against -- that is what a holdout is -- and printing the score command
        # with `--records None` in it sends a participant to run something that
        # cannot work, at the moment they are most likely to copy a line
        # verbatim.
        typer.echo(
            f"  {out} is what you submit. Scoring it needs the records, which the "
            "exercise holds; score against the public split to measure yourself."
        )


@app.command("results")
def results_command(
    directory: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Directory of result pointers."),
    ] = Path("results"),
) -> None:
    """Compare published results, and refuse the comparisons that are not one.

    This repository publishes no ranking of its own. A result lives wherever its
    author put it and what lands here is a pointer to it -- because a leaderboard
    in a benchmark's own repository makes its maintainers the adjudicators of
    their own instrument, which is the thing this project already refuses one
    level down: a detector's author cannot adjudicate its own predictions.

    Results measured against different corpus digests, engine versions, floors,
    weightings or caps are grouped apart rather than put in one column.
    """
    try:
        pointers = load_pointers(directory)
    except ValueError as invalid:
        typer.secho(str(invalid), fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from invalid

    comparison = compare(pointers)
    groups = comparison.comparable
    for index, group in enumerate(groups, start=1):
        typer.echo("")
        if len(groups) > 1:
            # Labelled, because two unlabelled blocks each restarting at `1.`
            # read as one list with a spacing hiccup -- which is the "two
            # incomparable figures in one column" failure this command exists
            # to refuse, reintroduced in its own rendering.
            first = group[0]
            typer.secho(
                f"  group {index} of {len(groups)} -- not comparable with the others "
                f"(engine {first.engine_version}, corpus {first.corpus_digest[:12]}, "
                f"floor {first.strength_floor}, cap {first.predictions_per_unit}, "
                f"model {first.main_model or 'deterministic'}, "
                # `weights` too, or two groups split only by weighting print
                # byte-identical labels -- a label that exists to say why the
                # groups differ, saying nothing that differs.
                f"weights {json.dumps(first.weights, sort_keys=True)})",
                fg=typer.colors.YELLOW,
            )
        for place, pointer in enumerate(group, start=1):
            if pointer.total is None:
                typer.echo(
                    f"  --  {pointer.submission_id:<28} {pointer.published_by:<20} "
                    f"no total: {pointer.unavailable}"
                )
            else:
                typer.echo(
                    f"  {place:>2}. {pointer.submission_id:<28} {pointer.published_by:<20} "
                    f"{pointer.total:.4f}  {pointer.main_model or 'deterministic'}"
                )
    typer.echo("")
    typer.echo(comparison.statement())


@app.command("score")
def score_command(
    runs: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="A submission's runs, one JSON per line."),
    ],
    records: Annotated[
        Path, typer.Option("--records", exists=True, help="Corpus record file or directory.")
    ],
    submission_id: Annotated[
        str, typer.Option("--submission-id", help="Identifies this submission in the document.")
    ],
    source_root: Annotated[
        Path,
        typer.Option(
            "--source-root",
            exists=True,
            file_okay=False,
            help="Checkout to read source from. Required: every figure rests on re-reading "
            "the quotes, and `contract-assay fetch` builds it.",
        ),
    ],
    weights: Annotated[
        Path | None,
        typer.Option("--weights", exists=True, dir_okay=False, help="Difficulty weights, as JSON."),
    ] = None,
    class_weights: Annotated[
        Path | None,
        typer.Option(
            "--class-weights",
            exists=True,
            dir_okay=False,
            help="A weight per class, as JSON. Replaces --weights when given, and must "
            "name every class scored.",
        ),
    ] = None,
    predictions_per_unit: Annotated[
        int,
        typer.Option(
            "--predictions-per-unit",
            min=1,
            help="Score at most this many findings per source unit per class, in the order "
            "returned, whether or not their citations held. The default is the most "
            "records any one unit-class pair holds, so a perfect submission is never "
            "capped and an unbounded pool cannot buy recall with volume.",
        ),
    ] = DEFAULT_PREDICTIONS_PER_UNIT,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the document here instead of stdout.")
    ] = None,
) -> None:
    """Score one submission's runs against the corpus and emit a JSON document.

    The document is the boundary a submission surface is built on: every figure
    carries its own absence and reason, so a caller cannot render a refusal as a
    zero, and the adjudication queue is carried in full so that "precision is
    unlicensed" is a list of work rather than a verdict.
    """
    # Required rather than optional, because it stopped being an enhancement.
    # The scorer re-reads every quote the submission marked verified, and
    # without source it can establish none of them -- so `score` with no
    # checkout used to return figures and now correctly returns nothing. An
    # option that is optional and useless is worse than one that is required.
    # Both weightings first, before the corpus and the runs are read. Parsing
    # them at the point of use put a mistyped class name after the whole scoring
    # run, which is the same late-refusal `--rank-on` had one command over: the
    # cheapest check to make reported last.
    weighting = _weights_from(weights)
    by_class = _class_weights_from(class_weights)
    resolve = _local_resolver(source_root)
    held = _records_from(records)
    report = score(_runs_from(runs), held, resolve, predictions_per_unit=predictions_per_unit)
    submission = score_submission(
        submission_id,
        report,
        weights=weighting,
        class_weights=by_class,
    )
    document = json.dumps(score_document(submission, held), indent=1, ensure_ascii=False)
    if out is None:
        typer.echo(document)
        return
    out.write_text(document + "\n", encoding="utf-8")
    queued = len(report.unjudged)
    typer.echo(f"wrote {out} -- {queued} prediction(s) await adjudication before precision exists")
    unrun = sorted(cls.value for cls, s in report.by_class.items() if s.records and s.nothing_ran)
    if unrun:
        # Its recall is 0.0 and reads like a result. Nothing ran for it, which is the
        # first thing a newcomer covering some of the classes needs to be told.
        typer.secho(
            f"  {len(unrun)} class(es) with records had no run from any detector "
            f"({', '.join(unrun)}): their recall is 0.0 because nothing ran, not because "
            "anything was measured.",
            fg=typer.colors.YELLOW,
            err=True,
        )


@app.command("rank")
def rank_command(
    submissions: Annotated[
        list[str],
        typer.Option(
            "--submission",
            help="One submission, as `id=path/to/runs.jsonl`. Repeat for each. Giving one "
            "id more than once is one submission measured more than once: its row is "
            "ranked on the mean total, with each total and the spread published.",
        ),
    ],
    records: Annotated[
        Path, typer.Option("--records", exists=True, help="Corpus record file or directory.")
    ],
    source_root: Annotated[
        Path,
        typer.Option(
            "--source-root",
            exists=True,
            file_okay=False,
            help="Checkout the quotes are re-read against. Required, as it is for `score`: "
            "without it a submission's claims cannot be checked and its class reads as "
            "'claimed nothing'.",
        ),
    ],
    weights: Annotated[
        Path | None,
        typer.Option("--weights", exists=True, dir_okay=False, help="Difficulty weights, as JSON."),
    ] = None,
    predictions_per_unit: Annotated[
        int,
        typer.Option(
            "--predictions-per-unit",
            min=1,
            help="Score at most this many findings per source unit per class, in the order "
            "returned, whether or not their citations held. The default is the most "
            "records any one unit-class pair holds, so a perfect submission is never "
            "capped and an unbounded pool cannot buy recall with volume.",
        ),
    ] = DEFAULT_PREDICTIONS_PER_UNIT,
    baseline: Annotated[
        str | None,
        typer.Option(
            "--baseline",
            help="The main model the exercise agreed on. Rows run under anything else "
            "are listed apart rather than ranked.",
        ),
    ] = None,
    any_model: Annotated[
        bool,
        typer.Option(
            "--any-model",
            help="Rank rows whatever main model they ran under; the board says so. "
            "Not with --baseline.",
        ),
    ] = False,
    over: Annotated[
        list[str] | None,
        typer.Option(
            "--over",
            help="A class the ranking covers. Repeat for each; omitted, every class "
            "the reports share is required.",
        ),
    ] = None,
    class_weights: Annotated[
        Path | None,
        typer.Option(
            "--class-weights",
            exists=True,
            dir_okay=False,
            help="A weight per class, as JSON. Replaces --weights when given, and "
            "must name every class being ranked.",
        ),
    ] = None,
    rank_on: Annotated[
        str,
        typer.Option(
            "--rank-on",
            help="Which per-class figure to rank on: f1, or bpref. An f1 board needs "
            "every prediction adjudicated; a bpref board does not.",
        ),
    ] = Measure.F1.value,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the leaderboard here instead of stdout.")
    ] = None,
) -> None:
    """Rank what can be ranked, and list the rest with the reason.

    Takes each submission's *runs* rather than its score document, because a
    leaderboard assembled from figures cannot check that they were computed
    against the same corpus -- and two submissions scored against different
    ground truth are not comparable however similar the numbers look. Scoring
    them here, against one corpus and one weighting, is what makes the row
    comparison mean anything.

    **One verified read per submission, not one per ranking.** `score` runs once
    per submission and each run builds its own reader, so a checkout that
    changes between rows gives those rows different bytes. Nothing downstream
    detects it: a result's corpus digest is over the *records*, not over the
    resolved sources. Rank from a checkout nobody is writing to.
    """
    # First, before anything is read. A mistyped flag costs nothing to detect
    # and everything to detect late: loading a corpus and every submission's
    # runs before saying "that is not a measure" spends a minute to report a
    # typo, and does it after the operator has walked away.
    try:
        measure = Measure(rank_on)
    except ValueError:
        typer.secho(
            f"--rank-on takes one of {', '.join(m.value for m in Measure)}, not {rank_on!r}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(2) from None
    if any_model and baseline is not None:
        typer.secho(
            "--any-model and --baseline are two answers to one question; give one",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    # Stated, not inferred. Omitted, `leaderboard` requires every class the
    # submissions share, which is the safe default and rarely the intended one:
    # an exercise ranks on the classes it says it ranks on, and a mean over
    # whichever classes happened to have figures ranks a submission on its
    # corpus's readiness instead of on itself.
    wanted: list[VulnerabilityClass] | None = None
    if over:
        wanted = []
        for name in over:
            try:
                wanted.append(VulnerabilityClass(name))
            except ValueError as unknown:
                typer.secho(f"{name!r} is not a vulnerability class", fg=typer.colors.RED, err=True)
                raise typer.Exit(1) from unknown
    weighting = _weights_from(weights)
    by_class = _class_weights_from(class_weights)
    held = _records_from(records)
    resolve = _local_resolver(source_root)
    scores = []
    documents: dict[str, dict[str, object]] = {}
    for entry in submissions:
        submission_id, separator, runs_path = entry.partition("=")
        if not separator or not submission_id:
            typer.secho(f"{entry!r} is not `id=path`", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        path = Path(runs_path)
        if not path.is_file():
            typer.secho(f"{runs_path} is not a readable runs file", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        report = score(_runs_from(path), held, resolve, predictions_per_unit=predictions_per_unit)
        submission = score_submission(
            submission_id,
            report,
            weights=weighting,
            class_weights=by_class,
            measure=measure,
        )
        scores.append(submission)
        # The first measurement's, matching the row's `score`.
        documents.setdefault(submission_id, score_document(submission, held))
    board = leaderboard(scores, baseline=baseline, over=wanted, any_model=any_model)
    document = json.dumps(
        leaderboard_document(board, held, documents=documents, baseline=baseline),
        indent=1,
        ensure_ascii=False,
    )
    if out is None:
        typer.echo(document)
        return
    out.write_text(document + "\n", encoding="utf-8")
    typer.echo(f"wrote {out} -- {board.statement()}")


def run_cli() -> int:
    """The console script. One exception boundary for the whole CLI.

    There was none at this edge -- no `except OSError`, no `except Exception`,
    no excepthook -- and an operational review found six documented paths that
    ended in a bare pydantic or I/O traceback: a malformed `--manifest` (five
    shapes, and the filename never named), an unreadable file in the checkout,
    an unwritable `--source-root`, a full filesystem, `--out` naming a
    directory, and a `--model-caller` returning the wrong type. Each was one
    handler away, and each earlier fix added one handler.

    A `ValidationError` from a hand-edited JSON file and an `OSError` from a
    filesystem are things an operator did, not defects in this package: one
    line naming the cause, exit 1. Everything else propagates, because a defect
    in here should look like one.
    """
    try:
        app()
    except SystemExit as exit_code:  # typer's own, including --help and Exit
        return int(exit_code.code or 0)
    except (ValidationError, json.JSONDecodeError) as malformed:
        lines = str(malformed).splitlines()
        typer.secho(lines[0] if lines else str(malformed), fg=typer.colors.RED, err=True)
        typer.secho(
            "this file is not the shape the command expects; `--help` names what it takes",
            fg=typer.colors.RED,
            err=True,
        )
        return 1
    except OSError as failed:
        named = getattr(failed, "filename", None)
        typer.secho(
            f"{named or 'a file'}: {failed.strerror or failed}", fg=typer.colors.RED, err=True
        )
        return 1
    return 0
