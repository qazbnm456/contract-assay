# Contributing

Four things can be contributed, and they have different bars because they carry
different risks. A wrong record poisons every score computed against it; a
wrong detector costs one number. The bars below follow from that asymmetry
rather than from how hard each is to write.

Read `docs/design.md` §1.3 first. The rules there are the review standard, and
the shortest of them is the one most often skipped: **a rule is an instruction
to go and look, not a conclusion to cite.**

## 1. A corpus record

The highest bar, and the only one where the reviewer will re-derive your work.

```console
$ contract-assay verify corpus/records/your-record.json --source-root ./checkout
$ contract-assay verify corpus/records --source-root ./checkout   # the whole corpus
```

What a record must survive:

- **Verification.** The commit resolves, the digest matches, the span is inside
  the file, and the named contract and function are declared *within the span*.
  A record that cannot be verified is not admitted, whatever its provenance.
- **The locator is one function.** A span covering two declarations names
  neither and is refused; so is a record whose prose names a function the span
  does not contain. Both were found in published records rather than in tests.
- **No duplicate.** `verify` reports records describing a defect another record
  already describes (`defect_key`), because a duplicate halves the recall its
  location can show. Fold before submitting.
- **Notes say what settled it.** For an adjudicated negative this is not
  optional: name the fact in the source that decided it, and say what the record
  does *not* cover.

What a record must not do:

- **Do not fill in a label the report did not state.** `asserted_labels` is what
  the *report* claimed, and it is what lets verification cross-check a locator.
  Adding a name the report never gave makes a weak record look strong and
  nothing downstream can detect it.
- **Do not adjudicate a prediction from an instrument you wrote** as an
  instance. See `docs/curation.md`; as a non-instance it is ordinary curation.

Records are pointers, never source. No report prose is vendored anywhere in this
repository, including in tests: report text is somebody else's writing and
embedding it would attach its terms to an MIT release.

## 2. A platform adapter

An adapter turns one platform's reports into drafts. Three exist
(`corpus/adapters/`), and the shape is fixed by the protocol in
`corpus/harvest.py`:

- `candidates(report)` enumerates what the report claims, **before** anything is
  resolved. Every candidate gets exactly one recorded outcome, so a candidate
  dropped silently is indistinguishable from one that was never there -- which
  is the accounting this two-phase split exists to make impossible.
- `extract(report, candidate)` returns a draft or a `Skip` **with a cause**. The
  cause is load-bearing: a finding citing a dependency, one citing a Markdown
  file and one citing nothing need three different fixes, and reporting all
  three as `no_location` sends the next person to the wrong place.
- Fetching stays out. Reports arrive as `RawReport`; a resolver is injected. It
  is what keeps the whole stage runnable in the offline gate.

Before adding a rule to an adapter, measure it. Every narrowing in the three
existing adapters carries the count that justified it, and several of them
replaced a rule that had looked obviously right: the excerpt route trusted the
line numbers its own excerpts carried until one turned out to be seven lines off
the file it quoted.

Reuse before re-deriving. `corpus/adapters/markdown.py` holds what is not
platform knowledge -- permalinks, quoted source, sections, and the
dominant-citation commit recovery. A rule written twice is a rule honoured once;
that happened four times in this codebase and each instance cost a measurable
number of records.

## 3. A detector

The lowest bar to contribute and the easiest to get subtly wrong. Read
`docs/api.md` for the interface and the checklist.

The mistake to know about in advance, because it was made in five of the eight
reference detectors: **the layer that decides must ask for the property the
layer that observes established.** `evidence()` runs predicates and `verdict()`
re-derives the class's rules from the source -- deliberately, so a model can
score for a defect no predicate can see. But *re-deriving* is not *re-deriving
the same thing*, and a narrowing written into a predicate after a measurement
protects nothing until the verdict asks for it too. Where one test serves both,
make it one function called from both places.

Two more, both from measurement:

- **A class about one site is checked at one site.** Conditions quantified over
  a *set* of calls or functions will be satisfied by different members of it. A
  receiver here, two arguments there and a zero literal somewhere else is not an
  unbounded exchange.
- **Declare what you cannot see.** A `DeclaredLimit` names the shape, the
  records it hides, why it is not patched, and what would close it. It is
  checkable -- run the detector against the records it names -- and a score
  reports how many misses no limit accounts for, so declaring reads better than
  not declaring.

## 4. A class

The nine classes are OWASP-derived patterns, and adding a tenth is a change to
what the benchmark measures. It needs: a definition that says what is and is not
an instance, at least ten corpus records (below that the report refuses to draw
conclusions from the figure), and a statement of what a detector for it would
have to establish. Two OWASP entries were deliberately not adopted -- logic
errors and missing input validation -- because a residual category cannot be
detected or graded, and 66% of real audit findings mapping to none of the nine
is a *measurement* this project reports rather than a gap it papers over.

## Running the pipeline

```console
$ pytest -m offline                       # the gate: no network, no fixtures from reports
$ pytest                                  # everything
$ ruff check . && ruff format --check . && mypy
```

Harvesting is driven from outside the repository, because fetching is an
outward-facing action with its own licensing and rate-limit questions:
`harvest(adapter, reports)` takes reports you supply, `normalize(drafts,
resolve, ...)` takes a resolver you supply, and `verify_all(records, resolve)`
checks the result. `docs/api.md` §8 shows the two commands a consumer runs.

## What review asks

1. What did you measure, and what number changed?
2. What would have caught this if it had been wrong?
3. What does this refuse to state, and does the refusal read better than a
   default would?

A change that improves a figure by loosening what counts is the failure this
project is most exposed to, because it looks like progress in every report.

## The corpus is public, all of it

Every record ships `split: public` and there is no withheld slice. A public
benchmark has a public corpus -- contamination is answered by disclosure and by
**growth**, and growth is what an adapter contribution is for. `docs/design.md`
carries the measurement behind that decision, including what splitting this
corpus would cost in class coverage.

If you are running a competition rather than measuring a harness, you need a
holdout and it is yours to curate: records from reports your entrants have not
seen, in their own directory, marked `private_holdout`, never committed here.
