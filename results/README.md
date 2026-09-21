# Published results

This directory holds **pointers** to results, not results, and no ranking.

## Why it is shaped this way

A leaderboard in a benchmark's own repository makes its maintainers the
adjudicators of their own instrument. This project already refuses that one
level down — a detector's author cannot adjudicate its own predictions, because
precision would then be 1 by construction — and the same argument applies to the
benchmark's authors and the benchmark's own ranking.

So your result lives wherever you put it: a repository, a paper, a post. What
lands here is a small JSON file naming what you measured, where the document is,
and who published it. Every field in it comes out of the score document the
engine wrote, so a pointer either matches the document it points at or it does
not.

## Adding one

1. Score your submission, and put the document somewhere fetchable.

   ```console
   $ contract-assay run --manifest my.json --records corpus/records \
       --source-root ./checkout --out runs.jsonl
   $ contract-assay score runs.jsonl --records corpus/records \
       --submission-id my-detector --source-root ./checkout \
       --weights weights.json --out my-detector.json
   ```

2. Build the pointer from the document rather than by hand — a pointer typed out
   is a number somebody typed:

   ```python
   import json
   from contract_assay.results import pointer_from_document

   pointer = pointer_from_document(
       json.load(open("my-detector.json")),
       published_by="Your name or lab",
       document_url="https://example.org/my-detector.json",
   )
   open("results/my-detector.json", "w").write(pointer.model_dump_json(indent=1))
   ```

3. Open a pull request with that one file. Nothing else.

## Reading them

```console
$ contract-assay results
```

It groups results by **what they were measured against** and compares only
within a group. Two results disagree about any of `engine_version`,
`corpus_digest`, `strength_floor`, `weights`, `predictions_per_unit` or
`main_model` and they are not two measurements of the same thing — the commonest reason two
leaderboards disagree is not a scoring change but a corpus that grew.

A result whose document **refused** to compute a total is listed after the
ranked ones and marked with the document's own sentence. It is not sorted to the
bottom: ordering it below a ranked result asserts a comparison nobody measured,
and the usual cause is work the exercise owes — unadjudicated predictions, or a
class the corpus does not cover — rather than anything the submission did.

## What a pointer may not do

A deterministic submission is grouped apart from a model-backed one for the
same reason, which is `main_model` being part of the basis: it was measured
under different conditions, and that is not a worse result, it is a different
question.

- **Report a total the document did not.** A null total carries the document's
  own `unavailable` sentence, and a pointer with one and not the other is
  refused at load.
- **Stand in for the document.** No copy is kept here. A copy is a second thing
  to keep in step with the original, and the original is the one carrying the
  digest.
