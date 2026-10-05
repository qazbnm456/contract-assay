# A reference submission

`submission.py` is a complete `Detector` with every layer written by hand, and `manifest.json` is what a submission declares about itself before its code runs. Read the detector to see what each layer is for, and copy it when you want a starting point that does more than the three declarations the interface asks for.

Nothing here is imported by the package, and nothing here calls a model on its own. The package defines what to ask (`Detector.plan`) and never asks it, so that an instrument whose correctness depended on the thing it measures cannot mistake a broken instrument for a weak model. A model is a function you supply to `contract-assay run`, and `examples/bring_your_own_harness/` has two: an adapter for a harness of your own, and `byo_openai.py` for any OpenAI-compatible endpoint.

## What is in here

| File | What it is for |
| --- | --- |
| `submission.py` | A `Detector` with `evidence()`, `plan()` and `verdict()` all written out, and a `self_check()` for the quotes it reports. |
| `manifest.json` | The manifest that names it. |

## Running it against a model

The detector asks for a model, so `run` needs a caller. `byo_openai.py` is one that works with Ollama, LM Studio, vLLM or a hosted provider, and `PYTHONPATH` lets `run` find it from here.

```console
$ pip install -e .
$ contract-assay fetch corpus/records --source-root ./checkout

$ export BYO_MODEL=qwen2.5-coder:32b                # the name your endpoint gives the model
$ export BYO_BASE_URL=http://localhost:11434/v1     # the default, Ollama's address

$ PYTHONPATH=examples/bring_your_own_harness contract-assay run \
    --manifest examples/reference_runner/manifest.json \
    --records corpus/records --source-root ./checkout \
    --model-caller byo_openai:call --limit 5 --out runs.jsonl

$ contract-assay score runs.jsonl --records corpus/records \
    --submission-id example-submission --source-root ./checkout --out score.json
```

Start with `--limit 5`. The first run checks two things a misconfigured endpoint gets wrong while appearing to work, and the score is not one of them: a non-zero token count in the `models` section of the score document, and a quote that is whole lines of the span its locator names. `examples/bring_your_own_harness/README.md` says what each failure looks like. `submission.py` has a `self_check()` for the second, and you can call it during development to see the problem before it shows up in a score.

## If you are writing a submission for a competition

Read `submission.py` first. It is the whole contract in one file, and its comments say why each part exists. Then read what `contract-assay run` does and does not do, because a competition host does the rest from outside your process: it meters your calls, confines the process, and re-checks every citation against its own copy of the source. None of that changes what you write. All of it changes what happens when you get it wrong.

| If your harness | `contract-assay run` | a competition host |
| --- | --- | --- |
| exceeds its token budget | keeps going and records the figures you report | refuses the call, and the run is `invalid` |
| reports 50 findings for one unit | hands on the first 9 | scores the first n and publishes the rest as capped |
| raises while being called | records an `invalid` run for each call that raised and prints the cause | records one `invalid` run per declared detector, with the cause |

The rule underneath all three is that anything a host can establish for itself, it will. The part of your submission that no other layer can produce is the detectors' own judgement, `evidence()` and `verdict()`, and that is where the work is worth putting.

## What a figure from this is

It measures one model behind these detectors, on the split you pointed it at, with a stated cap and weighting, and it should not be quoted as the model's score on the benchmark. The score document gives the reason: precision does not exist for a class until every prediction in it has been adjudicated, and the document carries that queue instead of a number in its place.

Nobody should adjudicate predictions made by an instrument they wrote. If you run this and want a precision figure out of it, the queue is work for somebody else.
