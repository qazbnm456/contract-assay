# A reference runner

`contract_assay` does not call a model. This does.

The separation is the design rather than an unfinished edge. An instrument whose
own correctness depended on the thing it measures could not tell a broken
instrument from a weak model — so the package defines *what to ask*
(`Detector.plan`) and never asks it, and every test in it runs with no model and
no network. This directory is the other half: a worked consumer, so that the
figures the benchmark reports can be reproduced by somebody who did not write
it.

Nothing here is imported by the package. `pip install contract-assay` gets you
no model library, by design.

## What is in here

| File | What it is for |
| --- | --- |
| `submission.py` | a complete, minimal `Detector` — **copy this to start your own** |
| `manifest.json` | what a submission declares about itself before its code runs |
| `runner.py` | the loop: evidence → plan → model → verdict → JSONL |
| `requirements.txt` | what the example needs and the package does not |

## Running it

```console
$ pip install -e . -r examples/reference_runner/requirements.txt
$ export RLM_BASE_URL=http://localhost:11434/v1     # any OpenAI-compatible endpoint
$ export RLM_API_KEY=local

$ python examples/reference_runner/runner.py \
    --records corpus/records --source-root ./checkout \
    --manifest examples/reference_runner/manifest.json \
    --model qwen2.5-coder:32b --limit 5 --out runs.jsonl

$ contract-assay score runs.jsonl --records corpus/records \
    --submission-id example-runner --source-root ./checkout \
    --predictions-per-unit 3 --out score.json
```

Start with `--limit 5`. What you are checking on the first run is not a score,
it is two things a misconfigured endpoint gets wrong **while appearing to
work**:

- **a non-zero token count** in the score document's `models` — a provider that
  reports no usage meters every run at zero, and every budget built on that is
  decoration;
- **a quote that is whole lines of the span its locator names** — a model that
  paraphrases, or that returns half a line, fails its citation check on every
  claim, and the runs come back `invalid` rather than wrong. That reads like a
  harness that finds nothing. Slice `ctx.source` by line at the locator you are
  about to report and the two cannot disagree.

`submission.py` has a `self_check()` for exactly the second one, callable during
development so you see it immediately rather than in a score.

Any endpoint works: Ollama, LM Studio, vLLM, or a hosted provider. The model's
name is whatever that endpoint calls it.

## If you are writing a submission for a competition

Read `submission.py` first. It is the whole contract in one file, and the
comments say why each part exists rather than what it does.

Then read `runner.py` for the loop your detector will run inside — and read what
it says it **does not** do. A competition host meters your calls from outside
your process, confines that process, and re-checks every citation against its
own copy of the source. None of that changes what you write; all of it changes
what happens when you get it wrong:

| If your harness | this runner | a competition host |
| --- | --- | --- |
| exceeds its token budget | keeps going | refuses the call; the run is `invalid` |
| marks its own finding verified | believes it | re-checks it against the host's source |
| reports 50 predictions for one unit | writes 50 | scores the first *n*, publishes the rest as capped |
| crashes | one `invalid` run | one `invalid` run per declared detector, with the cause |

The rule underneath all four: **anything a host can establish for itself, it
will.** The part of your submission that no other layer can produce is the
detectors' own judgement — `evidence()` and `verdict()` — and that is where the
work is worth putting.

## What a figure from this is, and is not

It is a measurement of *one model behind these detectors*, on the split you
pointed it at, with a stated cap and weighting. It is not "the model's score on
this benchmark", and the score document says why: precision does not exist for a
class until every prediction in it has been adjudicated, and the document
carries that queue rather than a number in its place.

Nobody should adjudicate predictions made by an instrument they wrote. If you
run this and want a precision figure out of it, the queue is work for somebody
else.
