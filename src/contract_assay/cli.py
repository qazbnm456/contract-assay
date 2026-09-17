"""Command line entry point.

Only the commands that are actually implemented appear here. A CLI that
advertises subcommands it cannot run is worse than a short one: it reports a
project's intentions as though they were its capabilities.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from contract_assay import __version__
from contract_assay.corpus.records import CorpusRecord, SourcePin, load_records
from contract_assay.corpus.verify import verify_all
from contract_assay.evidence.solidity import index_source
from contract_assay.models import DetectorRun, DifficultyLevel, VulnerabilityClass
from contract_assay.report.leaderboard import leaderboard, score_submission
from contract_assay.report.scoring import score
from contract_assay.report.wire import leaderboard_document, score_document

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

    Verification against a working tree, not a fetched commit: it cannot confirm
    that the bytes belong to the pinned commit, only that the record is coherent
    against what is here. Adequate for authoring records; not a substitute for
    fetch-based verification once that exists.
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
            candidate = root / pin.path
            if not candidate.is_file():
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
        typer.secho(f"no record files under {records}", fg=typer.colors.RED)
        raise typer.Exit(1)

    parsed: list[CorpusRecord] = []
    for path in paths:
        try:
            parsed.append(CorpusRecord.model_validate_json(path.read_text(encoding="utf-8")))
        except ValidationError as exc:
            typer.secho(f"{path.name}: malformed record", fg=typer.colors.RED)
            typer.echo(f"  {exc.error_count()} problem(s); first: {exc.errors()[0]['msg']}")
            raise typer.Exit(1) from exc

    report = verify_all(parsed, _local_resolver(source_root))

    for result in report.rejected:
        typer.secho(f"  rejected  {result}", fg=typer.colors.RED)
    for record in report.admitted:
        typer.secho(f"  admitted  {record.record_id}", fg=typer.colors.GREEN)

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
        typer.secho("no declarations could be read from this file", fg=typer.colors.RED)
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
        typer.secho(str(invalid), fg=typer.colors.RED)
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
                f"{path.name}:{number}: {invalid.error_count()} problems", fg=typer.colors.RED
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
            typer.secho(f"{path.name}: {key!r} is not a difficulty level", fg=typer.colors.RED)
            raise typer.Exit(1) from bad
    return weights


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
        Path | None,
        typer.Option(
            "--source-root",
            exists=True,
            file_okay=False,
            help="Checkout to read source from, enabling function-strength matching.",
        ),
    ] = None,
    weights: Annotated[
        Path | None,
        typer.Option("--weights", exists=True, dir_okay=False, help="Difficulty weights, as JSON."),
    ] = None,
    predictions_per_unit: Annotated[
        int | None,
        typer.Option(
            "--predictions-per-unit",
            min=1,
            help="Score at most this many verified findings per source unit per class, in "
            "the order returned. Left out, nothing is capped -- a cap states how much "
            "adjudication an exercise will fund, which is the exercise's to state.",
        ),
    ] = None,
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
    resolve = _local_resolver(source_root) if source_root is not None else None
    held = _records_from(records)
    report = score(_runs_from(runs), held, resolve, predictions_per_unit=predictions_per_unit)
    submission = score_submission(submission_id, report, weights=_weights_from(weights))
    document = json.dumps(score_document(submission, held), indent=1, ensure_ascii=False)
    if out is None:
        typer.echo(document)
        return
    out.write_text(document + "\n", encoding="utf-8")
    queued = len(report.unjudged)
    typer.echo(f"wrote {out} -- {queued} prediction(s) await adjudication before precision exists")


@app.command("rank")
def rank_command(
    submissions: Annotated[
        list[str],
        typer.Option(
            "--submission",
            help="One submission, as `id=path/to/runs.jsonl`. Repeat for each.",
        ),
    ],
    records: Annotated[
        Path, typer.Option("--records", exists=True, help="Corpus record file or directory.")
    ],
    source_root: Annotated[
        Path | None,
        typer.Option("--source-root", exists=True, file_okay=False, help="Checkout for source."),
    ] = None,
    weights: Annotated[
        Path | None,
        typer.Option("--weights", exists=True, dir_okay=False, help="Difficulty weights, as JSON."),
    ] = None,
    predictions_per_unit: Annotated[
        int | None,
        typer.Option(
            "--predictions-per-unit",
            min=1,
            help="Score at most this many verified findings per source unit per class, in "
            "the order returned. Left out, nothing is capped -- a cap states how much "
            "adjudication an exercise will fund, which is the exercise's to state.",
        ),
    ] = None,
    baseline: Annotated[
        str | None,
        typer.Option(
            "--baseline",
            help="The main model the exercise agreed on. Rows run under anything else "
            "are listed apart rather than ranked.",
        ),
    ] = None,
    over: Annotated[
        list[str] | None,
        typer.Option(
            "--over",
            help="A class the ranking covers. Repeat for each; omitted, every class "
            "the reports share is required.",
        ),
    ] = None,
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
    """
    held = _records_from(records)
    resolve = _local_resolver(source_root) if source_root is not None else None
    weighting = _weights_from(weights)
    scores = []
    documents: dict[str, dict[str, object]] = {}
    for entry in submissions:
        submission_id, separator, runs_path = entry.partition("=")
        if not separator or not submission_id:
            typer.secho(f"{entry!r} is not `id=path`", fg=typer.colors.RED)
            raise typer.Exit(1)
        path = Path(runs_path)
        if not path.is_file():
            typer.secho(f"{runs_path} is not a readable runs file", fg=typer.colors.RED)
            raise typer.Exit(1)
        report = score(_runs_from(path), held, resolve, predictions_per_unit=predictions_per_unit)
        submission = score_submission(submission_id, report, weights=weighting)
        scores.append(submission)
        documents[submission_id] = score_document(submission, held)
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
                typer.secho(f"{name!r} is not a vulnerability class", fg=typer.colors.RED)
                raise typer.Exit(1) from unknown
    board = leaderboard(scores, baseline=baseline, over=wanted)
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
