# A reference runner

`contract_assay` does not call a model. This directory does, so that the figures the benchmark reports can be reproduced by somebody who did not write it.

The separation is the design. An instrument whose own correctness depended on the thing it measures could not tell a broken instrument from a weak model, so the package defines what to ask (`Detector.plan`) and never asks it, and every test in it runs with no model and no network. Nothing here is imported by the package, and `pip install contract-assay` gets you no model library.

The runner is a model caller. `contract-assay run` reads the corpus, loops over units and detectors, and writes the runs, and `runner.py` supplies the one function it calls when a detector asks for a model. If you are testing a harness of your own, start from `examples/bring_your_own_harness/`, which shows the same seam without a model library in the way.

## What is in here

| File | What it is for |
| --- | --- |
| `submission.py` | A complete `Detector` with every layer written by hand. Read it to see what each layer is for. |
| `manifest.json` | What a submission declares about itself before its code runs. |
| `runner.py` | `rlm_caller`, a model caller over any OpenAI-compatible endpoint, built on rlm-harness. |
| `requirements.txt` | What the example needs and the package does not. |

## Running it

```console
$ pip install -e . -r examples/reference_runner/requirements.txt
$ export RLM_MODEL=qwen2.5-coder:32b                # the name your endpoint gives the model
$ export RLM_BASE_URL=http://localhost:11434/v1     # any OpenAI-compatible endpoint
$ export RLM_API_KEY=local

$ contract-assay run --manifest examples/reference_runner/manifest.json \
    --records corpus/records --source-root ./checkout \
    --model-caller runner:rlm_caller --limit 5 --out runs.jsonl

$ contract-assay score runs.jsonl --records corpus/records \
    --submission-id example-runner --source-root ./checkout --out score.json
```

`ModelCaller` takes no model argument, so the model comes from `RLM_MODEL`, and `RLM_SUB_MODEL` names a helper model when there is one. The module reads them when it is imported, which means a missing value ends the command with one error line instead of failing every unit. Any endpoint works: Ollama, LM Studio, vLLM or a hosted provider.

Start with `--limit 5`. The first run checks two things a misconfigured endpoint gets wrong while appearing to work, and the score is not one of them. The first is a non-zero token count in the `models` section of the score document, because a provider that reports no usage meters every run at zero, and every budget built on that is decoration. The second is a quote that is whole lines of the span its locator names, because a model that paraphrases, or returns half a line, fails its citation check on every claim and the runs come back `invalid`. Slice `ctx.source` by line at the locator you are about to report and the two cannot disagree. `submission.py` has a `self_check()` for exactly this, and you can call it during development to see the problem before it shows up in a score.

When a call fails, `contract-assay run` prints the cause, such as a missing provider or a timeout, next to the count of invalid runs. When a call takes longer than `--wall-seconds`, the caller prints that as well, because a round kills a call that overruns.

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
