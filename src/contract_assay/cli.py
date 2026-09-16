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
from contract_assay.corpus.records import CorpusRecord, SourcePin
from contract_assay.corpus.verify import verify_all
from contract_assay.evidence.solidity import index_source

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


def _local_resolver(root: Path):  # type: ignore[no-untyped-def]
    """Resolve pinned paths against a checkout on disk.

    Verification against a working tree, not a fetched commit: it cannot confirm
    that the bytes belong to the pinned commit, only that the record is coherent
    against what is here. Adequate for authoring records; not a substitute for
    fetch-based verification once that exists.
    """

    def resolve(pin: SourcePin) -> str | None:
        # `path` is a key into the pinned unit, and only some kinds of unit are
        # directories. Verified source arrives keyed by import-style names --
        # `@openzeppelin/contracts/token/ERC20/ERC20.sol` and the like -- which
        # look exactly like repository paths and join to nothing. Joining a key
        # to a root because it looked like a path reads the wrong file, or no
        # file, and says nothing about why; so the pin is asked instead.
        if not pin.is_filesystem_path:
            return None
        candidate = root / pin.path
        if not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8", errors="replace")

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
