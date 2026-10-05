# Contributing

The bar, the record format and what each kind of contribution has to establish are in **[docs/contributing.md](docs/contributing.md)**. This file exists so that the link is where a contributor looks for it.

Three things worth knowing before you start:

- **A record is a claim with a reproducible basis**, not a link to a report. It pins the bytes by digest, it locates the defect by file, contract, function and line span, and it says where its locator came from. A record that cannot be verified against the pinned source is refused by `contract-assay verify`.
- **No report prose is vendored.** A record cites its source by URL and states the claim in its own words; the third party's writing stays theirs.
- **The figures in `results/` are self-reported.** `results/README.md` says what a pointer does and does not establish before it says how to add one.

Run the gate the same way CI does. CI runs everything down to `pytest`; the two commands after the blank line need a checkout and are yours to run before proposing a record.

```console
$ python -m pip install --upgrade pip      # `--group` needs pip >= 25.1
$ pip install -e . --group dev
$ ruff check . && ruff format --check . && mypy && mypy tools
$ pytest -m offline --cov=contract_assay --cov-fail-under=90
$ contract-assay results results

$ contract-assay fetch corpus/records --source-root ./checkout
$ contract-assay verify corpus/records --source-root ./checkout
$ pytest -m checkout        # the figures the docs publish, over that checkout
```

`verify` **exits 1 on the shipped corpus** and that is not a failure you have caused: 477 of 478 records are admitted and the last one pins verified source for a deployed address, which no repository checkout can hold. The gate is that your change adds no *new* rejection: run it before and after. `./checkout` is 174 files and is already in `.gitignore`.
