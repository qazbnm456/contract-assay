# Published results

This directory holds **pointers** to results, not results, and no ranking.

**Every number here is self-reported, and the corpus it is over is public.** Each record publishes its full locator, so a script that quotes the real span at each one scores micro recall 0.9958 having found nothing, and a submission that opens no source file at all can reach 0.24 over these records, and 0.07 over records it has not seen. What a pointer establishes is that somebody published a document and stood behind it; what it does not establish is that the figure came from an analysis. Read a row as a claim by its author, ranked against nobody. `docs/api.md` §1 has the measurements and `CorpusSplit.PRIVATE_HOLDOUT` is where a figure that does not have this property would have to come from.

## Why it is shaped this way

A leaderboard in a benchmark's own repository makes its maintainers the adjudicators of their own instrument. This project already refuses that one level down (a detector's author cannot adjudicate its own predictions, because precision would then be 1 by construction) and the same argument applies to the benchmark's authors and the benchmark's own ranking.

So your result lives wherever you put it: a repository, a paper, a post. What lands here is a small JSON file naming what you measured, where the document is, and who published it. Every field in it comes out of the score document the engine wrote, so a pointer either matches the document it points at or it does not.

## Adding one

1. Score your submission, and put the document somewhere fetchable.

   ```console
   $ contract-assay run --manifest my.json --records corpus/records \
       --source-root ./checkout --out runs.jsonl
   $ contract-assay score runs.jsonl --records corpus/records \
       --submission-id my-detector --source-root ./checkout \
       --weights your-weights.json --out my-detector.json
   ```

   The weighting is yours to supply and this repository ships none: it states what an exercise values, and `docs/api.md` §6 has the shape. Without it the per-class figures still appear and the aggregate is refused, with that as its stated reason.

2. Build the pointer from the document rather than by hand; a pointer typed out is a number somebody typed:

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

It groups results by **what they were measured against** and compares only within a group. Two results disagree about any of `engine_version`, `corpus_digest`, `strength_floor`, `weights`, `class_weights`, `predictions_per_unit`, `main_model` or `units_scored` and they are not two measurements of the same thing. The commonest reason two leaderboards disagree is not a scoring change but a corpus that grew.

A result whose document **refused** to compute a total is listed after the ranked ones and marked with the document's own sentence. It is not sorted to the bottom: ordering it below a ranked result asserts a comparison nobody measured, and the usual cause is work the exercise owes (unadjudicated predictions, or a class the corpus does not cover) rather than anything the submission did.

## What a pointer may not do

A deterministic submission is grouped apart from a model-backed one for the same reason, which is `main_model` being part of the basis: it was measured under different conditions, and that is not a worse result, it is a different question.

- **Report a total the document did not.** A null total carries the document's own `unavailable` sentence, and a pointer with one and not the other is refused at load.
- **Stand in for the document.** No copy is kept here. A copy is a second thing to keep in step with the original, and the original is the one carrying the digest.
