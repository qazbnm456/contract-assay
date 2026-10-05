# contract-assay

Benchmark infrastructure for LLM smart contract auditing.

An assay measures what a sample actually contains. This one measures what a detector actually finds (at which function, on which line, provably) rather than whether it said something somewhere in a repository that happened to be labelled vulnerable.

> **Status: usable, narrow, and honest about which.** Built: the data contract, the corpus pipeline (harvest accounting, normalize, verify), adapters for three audit platforms, a corpus of 478 verified records across nine classes, the syntactic analysis backend and its shape queries, the public detector interface with its loader and runner, the predicate library, eight reference detectors, scoring with its stratifications and refusals, a leaderboard, and the JSON documents a consumer is built on. Not built: the compiled analysis backend, the classification-only track, and synthetic variants. `docs/design.md` carries a per-component status table.
>
> What that buys and does not: every figure a score needs except precision is produced today. Precision needs each prediction judged, and a prediction made by an instrument its own author would adjudicate cannot license one -- so the reference detectors' recall is measured (0.80 down to 0.00 by class) and their precision waits on a judge who did not write them.
>
> **What produced the predictions that recall was measured over.** This package calls no model. `Detector.plan()` says what to ask and nothing here asks it, so the findings those figures were computed over were written by a person reading each contract against the detector's own contract. The matching arithmetic is the real one, over real corpus records at real locations; what it measures is *what these detectors' predicates admit at those locations*, not what a model behind them scores. Those are different numbers and only the second is a model's.
>
> `examples/bring_your_own_harness/` is how the second one is produced, by anybody, including against a local endpoint. It is deliberately outside the package: an instrument whose own correctness depended on the thing it measures could not tell a broken instrument from a weak model.

## Why this exists

Benchmarks for LLM vulnerability detection tend to score at the wrong granularity. If a run counts as a hit whenever a model reports *anything* in a repository carrying the right label, then a model pointing at the wrong function in the wrong file scores identically to one that found the bug. The resulting numbers are not wrong so much as unrelated to the question.

Three commitments follow from that, and they shape every type in this codebase:

**A finding is a citation.** It carries a file, a contract, a function, a line span, and the exact source text at that span. After the model returns, every finding is re-read against the source and compared, unconditionally, every run. A finding that cannot be re-verified is recorded as `unverified`. It is neither silently dropped nor silently believed.

**Evidence is deterministic and independent of the verdict.** Structural facts about the code are established before any model runs. A model may decline to report, or report wrongly; it cannot remove an evidence item from the record. A verdict asserted against the evidence is visible as exactly that.

Those facts come from a parser, never a text match. A comment mentioning a function is not a declaration of it, and a matcher that cannot tell the difference will certify a location containing no code while rejecting constructors, which carry neither the `function` keyword nor a visibility modifier, and host a large share of the access-control defects worth measuring.

**Failures are not measurements.** A schema violation, an exhausted budget, a transport error and an unparseable source are four different things, and none of them is "the model found nothing". Only `vulnerable` and `clean` enter a confusion matrix; everything else is reported separately, as harness health.

The same distinction runs one level deeper. A predicate that applies its rule and concludes "not an instance" has *measured* something, and the run is `clean`. A claim that could not be checked against the source has measured nothing, and the run is `invalid`. Recorded as a bare list of failed check names the two are indistinguishable, so each rejection carries its kind, and a run cannot be `clean` over a finding nobody could check.

Severity is absent from a located finding. Asked how bad a defect is, a model states a value judgement as an observation, and nothing can check it; detectors are asked only for facts they can point at. Reproducing a severity that a named auditor recorded is a different claim, because it has a ground truth to be wrong about. That one lives on the classification track, is scored against the severity the original report assigned, and is never mixed into located results.

## Design

Each detector is a Python class in three layers:

| Layer | Runs | Produces |
| --- | --- | --- |
| `evidence()` | Always, before any model | Deterministic structural facts, with locations |
| `task` | The model, in a sandbox | Findings, with citations: the contract is a variable it explores, not text pasted into a prompt |
| `verdict()` | Always, after the model | Accept or reject, naming every predicate that rejected |

Gate predicates are lenient by construction: when in doubt they admit the source. A wasted model call costs a fraction of a cent; a wrong skip costs a true positive. Verdict predicates are strict, but a rejection must name itself, so strictness stays tunable instead of becoming an invisible recall sink.

Analysis runs on a compiled backend where the source builds, and degrades to a syntactic one where it does not. The tier travels with every result, because a `clean` verdict reached without data flow is a weaker claim than one reached with it, and the two must never be averaged together.

The detector interface is a public API. A submission is a `Detector` subclass loaded from a declared entry point and run under isolation, and nothing it returns is taken on trust: every value is re-validated, and anything unusable is recorded as a harness failure rather than as the absence of a finding. [docs/api.md](docs/api.md) states the compatibility surface and what running under isolation asks of a submission.

## What a figure over this corpus is

**Self-reported.** The corpus is public and every record publishes its full locator (file, contract, function, start and end line) and `contract-assay fetch` builds the scorer's checkout from the same public coordinates you have. So a script that quotes the real span at each published locator scores **micro recall 0.9958** without finding anything, and the citation check cannot tell that apart from a detector that did. Measured, not hypothesised.

That is a property of publishing the answers, not a defect in the checking, and it is the same trade SWE-bench and HumanEval make. It means a figure here is a real measurement **of an honest submission**, which is what a development benchmark is for, and it is not evidence against a motivated one. A competitive ranking needs records whose locators are not published; that is what `assay-arena` exists for. `docs/api.md` §1 has the numbers, including what a submission that opens no source file can still score: **0.24** over these records and **0.07** over records it has not seen, or 0.43 and 0.07, the same attack grouped to favour the first figure. The first figure is a measure of how hard somebody worked at this corpus; the second is what the same method gets on a corpus it has not read.

## Using it

The corpus lives in this repository, so the flow below starts from a clone. The engine is not on PyPI yet, so install it from the clone; when it is published, `pip install contract-assay` will get you the engine alone: the 478 records under `corpus/records` and the pointers under `results/` are not in the wheel, and a `--records` path is how you point the engine at them (or at your own).

```console
$ cd contract-assay          # your clone of this repository
$ pip install -e .

$ contract-assay fetch corpus/records --source-root ./checkout
174 of 175 pinned file(s) available. 174 matched their recorded digest. ...

$ contract-assay run --manifest my-detector.json --records corpus/records \
    --source-root ./checkout --out runs.jsonl
# `my-detector.json` is your manifest -- `examples/reference_detector/manifest.json`
# is one to copy. Do not also use that name for `--out` below.

$ contract-assay score runs.jsonl --records corpus/records \
    --submission-id my-detector --source-root ./checkout --out my-score.json

$ contract-assay results        # compare with what others have published
```

That gives you per-class recall and a refused aggregate, and the refusal names its two reasons: this engine ships no difficulty weighting, because a weighting states what an exercise values, and precision does not exist for a class until its predictions have been adjudicated. Add `--weights your-weights.json` when you have decided what yours are: `docs/api.md` §6 has the shape and the argument.

A submission is three declarations. This is the whole of it:

```python
from contract_assay.detectors import API_VERSION, PredicateDetector
from contract_assay.models import VulnerabilityClass


class Baseline(PredicateDetector):
    detector_id = "baseline-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION
```

That is a static-analysis baseline with no model in it: this benchmark's own predicates for the class, asserted as findings, citing the source at each one's own locator. On the public split it makes 41 access-control predictions against 62 records and recalls 0.10. It is a real number and a weak detector: **you beat it by being more selective, not by finding more.** `docs/api.md` §1 has the five layers and what each default does, and `examples/reference_detector/submission.py` writes every one of them by hand.

No model is called unless you name one (`--model-caller module:function`) and a detector asks for one, because `plan()` returns `None` by default, which means no model. This package imports no provider. An instrument whose own correctness depended on the thing it measures could not tell a broken instrument from a weak model.

`results/` holds pointers to published results, not a ranking. A leaderboard in a benchmark's own repository makes its maintainers the adjudicators of their own instrument, which this project refuses one level down too: a detector's author cannot adjudicate its own predictions.

## Connecting a model

This package does not call a model, and installing it gets you no model library. A model is a function you supply, and `contract-assay run` calls it:

```text
your harness -> a ModelCaller -> contract-assay run -> runs.jsonl -> contract-assay score
```

If you are testing a harness of your own, start from `examples/bring_your_own_harness/`. It holds an adapter with no dependency, a detector for each of the nine classes, and a README on the mistakes that raise no error: a detector that never asks for a model, a harness called once per class instead of once per file, and a cost counted once per class. The same directory has `byo_openai.py`, a caller for any OpenAI-compatible endpoint that uses only the standard library, for trying a detector against a model on Ollama, vLLM or a hosted provider. Use whichever framework you already have, because neither example contains a loop and yours should not either. The contract for both is in `docs/api.md` section 8.

## Development

```bash
pip install -e . --group dev

ruff check . && ruff format --check . && mypy && mypy tools
pytest -m offline --cov=contract_assay --cov-fail-under=90
contract-assay results results
```

The offline suite runs with no model, no network and no toolchain. It is the gate on every push, along with lint, formatting, strict type checking and a coverage floor.

Four commands:

```bash
contract-assay declarations src/Vault.sol          # what a file declares, and where
contract-assay verify corpus/records/ --source-root ./checkout
contract-assay score runs.jsonl --records corpus/records --submission-id team-a \
    --source-root ./checkout --weights weights.json --out team-a.json
contract-assay rank --submission team-a=team-a-runs.jsonl \
    --records corpus/records --source-root ./checkout \
    --weights your-weights.json --baseline the-agreed-model
```

## What this is, and what depends on it

An independent benchmark, meant to be depended on and contributed to. It holds the corpus, the interface, the scorer and the refusals that keep its figures honest. It does **not** hold a competition: collecting submissions, holding a deadline, adjudicating a pool and publishing results are a consumer's business, and a consumer's rules and infrastructure belong in that consumer's own project with this one as a dependency. `docs/design.md` §8 states the boundary and why it is worth holding.

[docs/contributing.md](docs/contributing.md) says what can be contributed -- records, adapters, detectors, classes -- and what review asks of each.

## Licence, citing, reporting

MIT. See [LICENSE](LICENSE).

Citing a figure measured with this benchmark: [CITATION.cff](CITATION.cff), and say which corpus commit you measured against: the records, their locators and the pinned sources all move between releases.

A way to make an unverifiable claim score is a vulnerability in this project, not a bug report: [SECURITY.md](SECURITY.md).
