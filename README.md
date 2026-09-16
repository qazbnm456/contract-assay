# contract-assay

Benchmark infrastructure for LLM smart contract auditing.

An assay measures what a sample actually contains. This one measures what a
detector actually finds — at which function, on which line, provably — rather
than whether it said something somewhere in a repository that happened to be
labelled vulnerable.

> **Status: early construction.** Built so far: the data contract, the corpus
> record schema and its verifier, the syntactic analysis backend, and a CLI for
> authoring and checking records. Not yet built: detectors, the predicate
> library, the compiled analysis backend, corpus harvesting, and scoring. Nothing
> here can measure a model yet. `docs/design.md` carries a per-component status
> table.

## Why this exists

Benchmarks for LLM vulnerability detection tend to score at the wrong
granularity. If a run counts as a hit whenever a model reports *anything* in a
repository carrying the right label, then a model pointing at the wrong
function in the wrong file scores identically to one that found the bug. The
resulting numbers are not wrong so much as unrelated to the question.

Three commitments follow from that, and they shape every type in this codebase:

**A finding is a citation.** It carries a file, a contract, a function, a line
span, and the exact source text at that span. After the model returns, every
finding is re-read against the source and compared — unconditionally, every
run. A finding that cannot be re-verified is recorded as `unverified`. It is
neither silently dropped nor silently believed.

**Evidence is deterministic and independent of the verdict.** Structural facts
about the code are established before any model runs. A model may decline to
report, or report wrongly; it cannot remove an evidence item from the record. A
verdict asserted against the evidence is visible as exactly that.

Those facts come from a parser, never a text match. A comment mentioning a
function is not a declaration of it, and a matcher that cannot tell the
difference will certify a location containing no code while rejecting
constructors — which carry neither the `function` keyword nor a visibility
modifier, and host a large share of the access-control defects worth measuring.

**Failures are not measurements.** A schema violation, an exhausted budget, a
transport error and an unparseable source are four different things, and none of
them is "the model found nothing". Only `vulnerable` and `clean` enter a
confusion matrix; everything else is reported separately, as harness health.

The same distinction runs one level deeper. A predicate that applies its rule
and concludes "not an instance" has *measured* something, and the run is `clean`.
A claim that could not be checked against the source has measured nothing, and
the run is `invalid`. Recorded as a bare list of failed check names the two are
indistinguishable, so each rejection carries its kind, and a run cannot be
`clean` over a finding nobody could check.

Severity is deliberately absent from the model's output contract. It is a value
judgement, not an observation; detectors are asked only for facts they can
point at. Severity assigned by the original auditors travels with corpus
records as provenance and is never mixed with anything a model produced.

## Design

Each detector is a Python class in three layers:

| Layer | Runs | Produces |
| --- | --- | --- |
| `evidence()` | Always, before any model | Deterministic structural facts, with locations |
| `task` | The model, in a sandbox | Findings, with citations — the contract is a variable it explores, not text pasted into a prompt |
| `verdict()` | Always, after the model | Accept or reject, naming every predicate that rejected |

Gate predicates are lenient by construction: when in doubt they admit the
source. A wasted model call costs a fraction of a cent; a wrong skip costs a
true positive. Verdict predicates are strict — but a rejection must name
itself, so strictness stays tunable instead of becoming an invisible recall
sink.

Analysis runs on a compiled backend where the source builds, and degrades to a
syntactic one where it does not. The tier travels with every result, because a
`clean` verdict reached without data flow is a weaker claim than one reached
with it, and the two must never be averaged together.

Built on [rlm-harness](https://github.com/qazbnm456/rlm-harness).

## Development

```bash
pip install -e . --group dev

ruff check . && ruff format --check .
mypy
pytest -m offline
```

The offline suite runs with no model, no network and no toolchain. It is the
gate on every push, along with lint, formatting, strict type checking and a
coverage floor.

Two commands are available today:

```bash
contract-assay declarations src/Vault.sol          # what a file declares, and where
contract-assay verify corpus/records/ --source-root .
```

## Licence

MIT. See [LICENSE](LICENSE).
