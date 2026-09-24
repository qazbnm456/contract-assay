# contract-assay

A benchmark that scores smart-contract vulnerability detectors against a corpus of located, digest-pinned records, and ranks them without inventing a figure it cannot measure.

## Setup and the gate

```console
$ pip install -e . --group dev          # needs pip >= 25.1
$ ruff check . && ruff format --check . && mypy && mypy tools
$ pytest -m offline --cov=contract_assay --cov-fail-under=90
$ contract-assay results results
```

That is what CI runs first. Its other jobs need `contract-assay fetch corpus/records --source-root ./checkout`, then `pytest -m checkout`. Read the real exit code of each command; do not pipe a gate into `tail`.

A change is done when the local gate and the remote CI run are both green.

## Rules that are easy to break

- **An absent figure is a reason, never a number.** Code that cannot compute a figure returns the sentence saying why; it does not return 0 or rank the row last.
- **No third-party report text in the repository**, including tests and fixtures. A record states its claim in its own words and cites its source by URL.
- **The version lives only in `__version__`.** A bump also updates `CITATION.cff`. Any change to what `score` or `rank` writes is a bump, because `engine_version` is part of what makes two results comparable.
- **Published figures are tested.** A scoring change that moves a number in the docs must update the checkout tests and the counts CI checks, in the same change.
- `contract-assay verify` exits 1 on the shipped corpus by design (one record pins a deployed address). The gate is "no new rejection", not exit 0.

## Where to read more

- Why the scoring works the way it does: `docs/design.md` (long; search it, don't read it whole).
- The CLI and the documents it writes: `docs/api.md`.
- Adding or changing a record: `docs/contributing.md` and `docs/curation.md`.
