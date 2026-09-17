# contract-assay

Benchmark infrastructure for LLM smart contract auditing.

An assay measures what a sample actually contains. This one measures what a
detector actually finds — at which function, on which line, provably — rather
than whether it said something somewhere in a repository that happened to be
labelled vulnerable.

> **Status: usable, narrow, and honest about which.** Built: the data contract,
> the corpus pipeline (harvest accounting, normalize, verify), adapters for
> three audit platforms, a corpus of 442 verified records across nine classes,
> the syntactic analysis backend and its shape queries, the public detector
> interface with its loader and runner, the predicate library, eight reference
> detectors, scoring with its stratifications and refusals, a leaderboard, and
> the JSON documents a consumer is built on. Not built: the compiled analysis
> backend, the classification-only track, and synthetic variants.
> `docs/design.md` carries a per-component status table.
>
> What that buys and does not: every figure a score needs except precision is
> produced today. Precision needs each prediction judged, and a prediction made
> by an instrument its own author would adjudicate cannot license one -- so the
> reference detectors' recall is measured (0.80 down to 0.00 by class) and their
> precision waits on a judge who did not write them.
>
> **What produced the predictions that recall was measured over.** This package
> calls no model. `Detector.plan()` says what to ask and nothing here asks it,
> so the findings those figures were computed over were written by a person
> reading each contract against the detector's own contract. The matching
> arithmetic is the real one, over real corpus records at real locations; what it
> measures is *what these detectors' predicates admit at those locations*, not
> what a model behind them scores. Those are different numbers and only the
> second is a model's.
>
> `examples/reference_runner/` is how the second one is produced, by anybody,
> including against a local endpoint. It is deliberately outside the package:
> an instrument whose own correctness depended on the thing it measures could
> not tell a broken instrument from a weak model.

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

Severity is absent from a located finding. Asked how bad a defect is, a model
states a value judgement as an observation, and nothing can check it; detectors
are asked only for facts they can point at. Reproducing a severity that a named
auditor recorded is a different claim, because it has a ground truth to be wrong
about — that one lives on the classification track, is scored against the
severity the original report assigned, and is never mixed into located results.

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

The detector interface is a public API. A submission is a `Detector` subclass
loaded from a declared entry point and run under isolation, and nothing it
returns is taken on trust: every value is re-validated, and anything unusable is
recorded as a harness failure rather than as the absence of a finding.
[docs/api.md](docs/api.md) states the compatibility surface and what running
under isolation asks of a submission.

## Connecting a model

This package does not call one, and installing it gets you no model library.
`examples/reference_runner/` is a worked consumer built on
[rlm-harness](https://github.com/qazbnm456/rlm-harness): copy `submission.py` to
start a detector of your own, and run `runner.py` against any
OpenAI-compatible endpoint -- hosted or local -- to produce runs this engine can
score.

`pytest -m live` is the one test that needs a model. It establishes the two
things a misconfigured endpoint gets wrong while appearing to work: that usage
is reported at all, and that the model quotes rather than paraphrases. Every
other test in this repository runs with no model and no network.

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

Four commands:

```bash
contract-assay declarations src/Vault.sol          # what a file declares, and where
contract-assay verify corpus/records/ --source-root .
contract-assay score runs.jsonl --records corpus/records --submission-id team-a \
    --source-root ./checkout --weights weights.json --out team-a.json
contract-assay rank --submission team-a=team-a-runs.jsonl \
    --records corpus/records --weights weights.json --baseline the-agreed-model
```

## What this is, and what depends on it

An independent benchmark, meant to be depended on and contributed to. It holds
the corpus, the interface, the scorer and the refusals that keep its figures
honest. It does **not** hold a competition: collecting submissions, holding a
deadline, adjudicating a pool and publishing results are a consumer's
business, and a consumer's rules and infrastructure belong in that consumer's
own project with this one as a dependency. `docs/design.md` §8 states the
boundary and why it is worth holding.

[docs/contributing.md](docs/contributing.md) says what can be contributed --
records, adapters, detectors, classes -- and what review asks of each.

## Licence

MIT. See [LICENSE](LICENSE).
