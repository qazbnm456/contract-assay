# Bring your own harness

This directory is the shortest path from a vulnerability-detection harness you built to a score on this benchmark. It needs nothing beyond `contract_assay`, and it runs end to end before you have connected anything.

Your harness stays yours. The benchmark reads the corpus, calls your code once per source file, checks every citation against the source, and writes the runs. You supply one function that turns a call into your harness's findings, and you do not write a loop.

```text
your harness -> byo_caller.call -> contract-assay run -> runs.jsonl -> contract-assay score
```

## What is here

| File | What it is for |
| --- | --- |
| `byo_harness.py` | A stand-in for your harness. Replace `analyze` and leave the rest. |
| `byo_caller.py` | The adapter. `call` is what `contract-assay run` calls when a detector asks for a model. |
| `byo_detectors.py` | One detector per vulnerability class, each of which asks for the model. |
| `byo_openai.py` | A second caller, for trying a detector against any OpenAI-compatible endpoint with no framework. |
| `<class>.manifest.json` | A manifest naming the detector for one class. A manifest holds a single entry point, so there is one per class. |

## Run it

The stand-in flags `tx.origin` and nothing else, so its score will be close to zero. That is the expected result, and it shows that the whole path works before you change anything.

```console
$ pip install -e .
$ contract-assay fetch corpus/records --source-root ./checkout

$ contract-assay run \
    --manifest examples/bring_your_own_harness/access_control.manifest.json \
    --records corpus/records --source-root ./checkout \
    --model-caller byo_caller:call --limit 5 --out runs.jsonl

$ contract-assay score runs.jsonl --records corpus/records \
    --submission-id my-harness --source-root ./checkout --out score.json
```

Pass `--manifest` once for each class your harness covers. `byo_caller:call` is a module name: the loader looks for it in the working directory and in the directory of each manifest, and it looks for a manifest's detector module in that manifest's directory, so keep the manifests, `byo_detectors.py` and `byo_caller.py` together and the command works from anywhere.

## Connect your harness

Replace the body of `analyze` in `byo_harness.py` with a call into your harness. It takes one source file as a string and returns an `Analysis`: the claims your harness made, the name of the model behind them, and what the analysis cost. Raise an exception when it fails, and the adapter records the failure instead of guessing. `analyze` does not have to be a library call: a harness that is a coding agent, such as Claude Code or Codex with your skills, fits by being started as a subprocess from `analyze` with the source, and its answer parsed into claims. Name the model it used in `model_id`, and report the calls and tokens it spent, or leave them at zero when the tool does not say, since a host that sees zero knows the figures were never reported.

Each claim needs a line range and a quote, and the quote must be whole lines of the source at that range. A paraphrase, or half a line, fails the citation check, and the run comes back `invalid` instead of wrong, which reads like a harness that finds nothing. Slice the source by line at the range you are about to report and compare it with the quote. The adapter also runs `check_citation` from `contract_assay.detectors.base`, the comparison the benchmark itself makes, on every claim it returns and prints the ones that fail, so you see the cause of an `invalid` run before you read a score. It returns those claims anyway, because dropping a claim that fails its check would turn an `invalid` run into a `clean` one.

The benchmark has nine fixed classes and your harness has its own categories. `CATEGORY_TO_CLASS` in `byo_caller.py` maps one onto the other, and a claim whose category is not in it is dropped, because a finding carries no class of its own and cannot be scored without one. The adapter prints the category it dropped, so a misspelt key does not turn every run into `clean` without a word. Keep the manifests for the classes your harness covers and delete the rest.

## Report what the analysis cost

`contract-assay run` states the three budgets, `--wall-seconds`, `--max-calls` and `--max-tokens`, and passes them to your code. It does not enforce them, so the only source for what you spent is the `calls` and `tokens` your harness reports, and every budget in a competition is built on those numbers. The adapter prints a warning when the figures exceed the limits, which is the earliest you will hear of it.

Once your harness is connected, open `score.json` after the first run and read `models`. A token count of zero means the figures were never reported, whatever the score says. The stand-in reports zeros on purpose, so the first run you make before connecting anything shows zero too.

## Why the adapter is shaped this way

The loop runs every detector over one unit before it moves to the next, so a harness covering nine classes would be called nine times on the same file. The adapter runs it once per unit and gives each detector the claims that belong to its class. It charges the cost to the first detector and reports zero for the rest, because charging every detector would multiply what you spent by the number of classes.

A failure is returned as `ModelReply(failed=...)` and never raised. The run is then `invalid` with the cause printed, which is a different fact from finding nothing. If you know what the failed call cost, name it in `models`.

## When nothing is called

A detector's `plan()` returns `None` by default, and `None` means no model. A detector with three declarations and no `plan()` never reaches your adapter, and every run comes back `clean` with no error. `byo_detectors.py` overrides `plan()`, and `contract-assay run` says so when `--model-caller` is named and no detector asked for a model.

A class you ran no detector for is not hidden. `score` lists every class that has records and shows `recall` 0.0 for the ones you skipped, and it also prints their names when it finishes and marks each `nothing_ran` in the document, so a zero from no detector is not mistaken for a zero from a detector that found nothing.

## If your harness is an analyzer and not a model

A harness that makes no model call belongs in `Detector.propose()`, which returns findings the detector asserts from the source alone. Leave `plan()` returning `None` and pass no `--model-caller`. The runs are then recorded as produced without a model, which is true of them. Routing the same engine through `ModelReply` would put its name in `score.json` as the model, and that is wrong for something that is not one.

## Try a detector against a model endpoint

`byo_openai.py` is the other direction. Your harness is the thing being measured in the sections above, and here a detector is, with a model behind it. It makes one request to any OpenAI-compatible chat endpoint for each detector and unit, adds the numbered source to the detector's instruction, and reads findings back as JSON. It needs only the standard library, so it works the same on Ollama, LM Studio, vLLM or a hosted provider, and it is the plainest example of a `ModelCaller` that talks to a model.

```console
$ export BYO_MODEL=qwen2.5-coder:32b              # the name your endpoint gives the model
$ export BYO_BASE_URL=http://localhost:11434/v1   # the default, Ollama's address
$ export BYO_API_KEY=...                          # only if the endpoint wants one

$ contract-assay run \
    --manifest examples/bring_your_own_harness/access_control.manifest.json \
    --records corpus/records --source-root ./checkout \
    --model-caller byo_openai:call --limit 5 --out runs.jsonl
```

Start with `--limit 5`, because the first run checks two things a misconfigured endpoint gets wrong while appearing to work. A token count of zero in the `models` section of the score document means the provider reports no usage, and every budget built on that number is decoration. A run that comes back `invalid` on every unit usually means the model paraphrases its quotes, and the line `run` prints for each failed citation shows what it returned. A larger model, or `BYO_TEMPERATURE=0` for models that accept it, is the usual fix.

When a call fails, `contract-assay run` prints the cause beside the count of invalid runs: an HTTP status and the start of the server's message, a refused connection, or the part of the reply that could not be used. A reply with one malformed finding fails the whole call. Dropping that finding would leave a run that reads `clean` because the output could not be parsed.

## What this path does not do

`contract-assay run` does not confine your process, and it checks citations against the file your own process also read. A competition host meters your calls from outside, confines the process, and re-checks every citation against its own copy of the source, so a harness that passes here can still be refused there for exceeding a budget. None of that changes what you write.

