# The detector API

What you implement to submit a detector, what this project promises not to
break, and what it checks before believing anything your code returns.

Everything here concerns `contract_assay.detectors`. If this document and the
code disagree, one of them is a bug — see `docs/design.md` for the same rule
applied to the rest of the system.

## 1. A detector in three layers

A detector answers one question about one Solidity source unit: does an instance
of a particular vulnerability class exist, and *where*.

**The smallest complete submission is three declarations:**

```python
from contract_assay.detectors import API_VERSION, PredicateDetector
from contract_assay.models import VulnerabilityClass


class Baseline(PredicateDetector):
    detector_id = "baseline-access-control"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION
```

That is a **static-analysis baseline with no model in it**: this benchmark's own
predicates for the class, asserted as findings, quoting the source at each one's
own locator so its citations pass by construction. Measured on the public split
it reports 34 access-control predictions against 55 records and recalls 0.11.

That figure was published as 97 predictions and 0.27 for two commits. It was
wrong, and how it was wrong is worth keeping: `propose()` lifted **every**
evidence item, including the ones the predicate marked `indeterminate` -- the
three-valued answer this system exists to keep apart from "absent". Roughly two
thirds of the baseline's predictions were the evidence layer's own disclaimers
republished as claims, each carrying a `reasoning` string asserting the property
the item had declined to establish. A review found it; the fix is one
`if not ref.is_established: continue`.

It is a real number, and it is not a strong detector. Its predicates establish
that a *shape* is present, and a shape is not a defect — it names many more
locations than hold defects, and the adjudication queue it produces is the
honest cost of that. **You beat it by being more selective, not by finding
more.**

Subclass `Detector` instead and you get the same defaults minus the assertion:
it runs, it produces well-formed runs, and it claims nothing. That is the right
base for a submission whose job is to filter a model's output rather than to
assert from source.

The reason these defaults exist is about what a comparison measures. A benchmark
for vulnerability detection is meant to compare judgement about
vulnerabilities. If every entrant must first write its own parser queries, then
two figures differ partly because one entrant wrote better tree-sitter code, and
that second variable sits inside every comparison this project publishes.
Shipping the analysis holds it constant.

So `contract_assay.evidence` is public, and it is the same code the reference
detectors use:

```python
from contract_assay.evidence import Syntax, run_all

parsed = Syntax.of(ctx.source)  # functions, calls, writes, guards,
# loops, arithmetic, member_reads
refs = run_all(parsed, ctx.path, classes=[VulnerabilityClass.REENTRANCY])
```

Every site carries `start_line`, `end_line`, `host` (contract and function) and
`text` — the **exact** source it spans — plus `site.locator(path)` in the shape a
`Finding` wants. Quote `site.text` *at* `site.locator(path)`: a finding's quote
is re-read against the source unconditionally and has to be whole lines of the
span the locator names, so a pair that came from the same site passes by
construction. A quote typed from memory, or one that starts mid-line, fails —
and a failed citation reads as a detector that found nothing rather than one
that was wrong.

Override a layer when you can establish something the default cannot. The layers
run in a fixed order:

| Order | Layer | Model? | Default if you write nothing |
| --- | --- | --- | --- |
| 1 | `evidence(ctx)` | never | this benchmark's predicates for your class |
| 2 | `propose(ctx, evidence)` | never | nothing — `PredicateDetector` asserts one finding per evidence item |
| 3 | `plan(ctx, evidence)` → the model | optional | no model is called |
| 4 | `verdict(ctx, finding, evidence)` | never | rejects nothing |
| 5 | `classify(ctx, findings)` | never | returns nothing (classification mode only) |

`propose()` is what makes a deterministic submission able to report anything at
all. Before it existed, findings reached a run only through the host's model
call, so a detector with `plan()` returning `None` could report nothing but
`clean` — while this document called static analysis the benchmark's own control
group. A proposed finding is trusted no more than a model's: same citation
check, in the same order, then the same `verdict()`.

**A detector that runs no model is a first-class submission**, and now
demonstrably so rather than only in principle.

### What a figure over the published corpus is

**Self-reported.** Read this before you publish one, and before you read
somebody else's.

The scorer re-reads every quote you mark verified, against its own copy of the
source, and refuses a submission that is incoherent: a quote that is not whole
lines of the span it declared, a quote too short to establish anything, a
locator naming a file other than the unit it declares, or source whose digest
disagrees with the record's pin.

How far that goes, measured over the whole corpus rather than argued. Every
dictionary family is at zero: a 181-entry dictionary of generic Solidity idioms
sprayed at every published locator (once **0.913**), generic mid-line runs of
six or more tokens (once **0.126**), lines of nothing but braces and keywords
(once 0.0138). What is **not** at zero is an attack built on what the corpus
publishes: the record gives you the function's *name*, so `function {F}()
external {` is the right text for a zero-argument function's declaration line.
The strongest such submission measured — whole lines built from a fixed generic
vocabulary, declared over windows derived from the published line numbers —
scores **0.2161**.

**That 0.2161 is in-sample, and the held-out figure for the same method is
0.0414.** A blind attack is a list of guesses, and every list measured here was
chosen by its yield over the same 435 records it was then scored on.
Cross-fitted — rank the guesses on half the corpus, score the other half — the
family drops to 0.0414. Use the in-sample number to ask how much a *published*
corpus leaks to somebody willing to fit it; use the held-out one to ask what a
submission gets on records it has not seen. A competition is the second
question, and `assay-arena` answers it with records whose locators are not
published.

Read both as measurements and not as bounds. This check has been rewritten five
times, the first three published as zeroes, and every one of them was exceeded
by the next review. The size of what is left is clearest from the other side: a
submitter who could name **one real line** of each published span would score
0.9885. The whole defence is that it cannot name one.

What is **not** closed, and cannot be: this corpus publishes the full locator --
file, contract, function, start and end line -- and `contract-assay fetch`
builds the scorer's checkout from the same public coordinates you have. So a
script that quotes the real span at each published locator scores **micro recall
0.9931**, with precision 0.9815 in access control, 0.9947 in denial of service
and 1.0 in the rest. Measured, not hypothesised. (Not 1.0 anywhere near
everywhere, and no submission gets a clean sheet of counters: one positive
record's source resolves from no public coordinates and one more resolves to
bytes whose digest disagrees with its pin, so the best possible submission still
reports an unchecked citation.)

That is a property of publishing the answer, not a defect in the checking. It
means:

- A figure here is a real measurement **of an honest submission**, which is what
  a development benchmark is for, and what you should use it as.
- It is **not evidence** against a motivated one, and a public leaderboard built
  on it ranks willingness to copy.
- A competitive ranking needs records whose locators are not published. That is
  `CorpusSplit.PRIVATE_HOLDOUT`, curated by whoever runs the competition from
  reports the entrants have not seen — see `assay-arena`'s `docs/operations.md`
  step 3. It is deliberately not a slice of this corpus: `docs/design.md` has the
  measurement showing what carving one would cost.

The corpus stays wholly public because that is what a benchmark is for. The
consequence for rankings is stated here rather than hidden behind a check that
cannot carry it.

### Who judges, and why `verdict()` is not self-judging

Worth being exact about, because the shape invites the opposite reading. Four
things decide a score and **a submission can influence none of them**:

| Decided by | What | Overridable? |
| --- | --- | --- |
| `check_citation` | whether the quote is really at the cited lines | no — the host's, runs before any verdict |
| `gate` | whether a unit may be skipped at all | no |
| the scorer | whether a prediction matches a ground-truth record, and at what strength | no — a submission never sees the records |
| the scorer | recall, precision, F1, the aggregate | no |

A proposed finding gets no exemption from any of them. It is cheaper to produce
than a model's and is checked identically.

`verdict()` can do exactly one thing: **discard your own findings.** It cannot
make the corpus agree with one. Rejecting a true finding costs you recall and
buys you precision, which is the trade a detector exists to make — and every
rejection is recorded by name, so the cost of each rule of yours is a number
rather than a matter of faith.

### `evidence()` — deterministic facts

Structural observations, each with a location. It must not consult a model, the
network, or the clock. The reason is a guarantee the whole benchmark rests on:
evidence is recorded *whatever the model concludes*. A model may decline to
report, or report wrongly; it cannot remove an evidence item. A verdict asserted
against the evidence is therefore visible as exactly that.

Name a predicate for the **property** it establishes, not for the form in which
you found it. `oracle_price_read_without_staleness_check` is a property;
`chainlink_latest_round_data_unchecked` is one shape of it, and the second shape
then needs a second name, so neither name counts the property.

An `EvidenceRef` carries two payloads, and putting a value in the wrong one is a
silent scoring bug rather than a style slip:

- `detail` is **compared**. Every value in it must be stable under any edit that
  preserves the property — argument indices, literal values, statement ordering,
  and language builtins such as `block.timestamp`, which no author can rename.
- `diagnostic` is **never compared**. Local identifiers go here: state variable
  names, parameter names, helper names. Renaming any of them preserves
  behaviour, so a comparison would report a difference where nothing changed.

Put the unstable values in `diagnostic` rather than dropping them. Evidence a
human cannot read is evidence nobody trusts.

Two habits that will cost you accuracy if you ignore them:

- **Test shapes, not names.** Identifiers are chosen by whoever wrote the
  contract and can be changed without changing behaviour. A predicate keyed on a
  parameter being called `amountOutMin` measures naming habits. Ask instead
  whether the argument in that position is a literal zero, or a parameter never
  read anywhere else in the function.
- **Do not case-fold identifiers.** Solidity is case-sensitive. `owner` and
  `Owner` are different symbols, and folding them manufactures matches the
  compiler would never make.

### `verdict()` — strict, and it must say why

Return the checks that reject a finding; an empty sequence means it stands.

Be strict here. Rejecting when unsure is affordable *because every rejection is
recorded*: a rejected finding is retained with `status=unverified` and the list
of checks that rejected it, so the recall cost of each rule stays visible.

Each `FailedCheck` carries a `RejectionKind`, and getting it wrong corrupts the
scoring of your submission in a way no aggregate will reveal:

| `RejectionKind` | Means | The run becomes |
| --- | --- | --- |
| `VERDICT` | you applied a rule and the claim did not meet it | a measurement — `clean` |
| `CITATION` | the claim could not be checked against source at all | not a measurement — `invalid` |

Returning an error as a judgement converts infrastructure failures into model
conclusions. Returning a judgement as an error throws away a measurement you
earned.

### What you do *not* control

**Citation re-verification.** After your `verdict()` returns, the harness
re-reads the source at each finding's locator and compares it to the finding's
`quote`. It runs for every finding on every run, you cannot skip it, and there is
no method to override — the data contract says a finding is re-verified
unconditionally, and that is only true if the harness owns it.

Every failure is a `CITATION` rejection, so the run becomes `invalid` rather than
`clean`. A finding whose quote is not where it says establishes nothing about
whether the class is present at that location.

The comparison policy is fixed by the harness and identical for every
submission, so that two detectors reporting the same defect cannot get different
outcomes from how they happened to format a string:

- Leading and trailing whitespace is stripped **per line**, and blank lines are
  ignored. Indentation is not semantic; a quote reproduced with its indentation
  shifted has still quoted the code.
- Both sides are split into tokens — an identifier, a number, or one other
  character — and compared as token sequences. So whitespace *between* tokens
  does not matter either: `total-=amount;` and `total -= amount ;` are the same
  quote. Note that a multi-character operator is two tokens here, which is why
  the floor below is six and not five.
- **The quote must be whole lines of the source, contiguous, inside the span
  your locator declares.** It need not be all of the span — a locator a line or
  two wider than the lines you quoted is fine, which is the common case for a
  finding about a function — but it must not start or stop mid-line. A
  mid-line fragment is refused because that is where a blind guess lives:
  `for (uint256 i = 0; i <` is ten tokens, generic, and inside hundreds of
  spans, and a rule that accepted it scored 0.126 over the whole corpus reading
  no source.
- **A quote must carry at least six tokens, one of them naming something the
  language does not supply.** Below that it is a line anybody can type —
  `} else {`, `msg.sender,`, `) internal {` — and a line of nothing but braces
  and keywords, `} } return false; }`, is six tokens of the same thing: a review
  scored 0.0138 over the whole corpus out of lines of that shape. One variable,
  function or type name of your file's own is enough. Quote the neighbouring
  line as well when your statement is short.
- **Your prediction is scored at the lines your quote matched**, not at the span
  you declared. So locator slop is free in every direction — measured over the
  whole corpus, an honest submission scores the same 0.9862 with its locator
  exact, one line wider, five wider, wider above, or wider on both sides — and
  a wide span does not launder a quote into a function it is not in: a quote
  matched in another function is a file match, not a function one. It is not
  *nothing*, either, and an earlier version of this page claimed it was: a blind
  submission gains about 0.05 in-sample from widening, most of it upward,
  because widening upward pulls the function's own declaration line into the
  pool. The report counts how many of your predictions were moved, and how many
  landed in a callable your locator did not name.
- The lines have to be in the file's own order, and contiguous in it. Blank
  lines are dropped on both sides, so a blank line between two quoted lines does
  not matter; a line of *code* between them does.
- A quote that is blank once normalised is a failure, not a pass.

Five failures are distinguished, because they say different things about a
detector: `citation_span_out_of_range`, `citation_quote_is_not_substantive`
(below the floor), `citation_quote_is_not_whole_lines` (real text at the right
place, starting or stopping mid-line), `citation_quote_elsewhere_in_file` (real
code, wrong place) and `citation_quote_absent_from_source`. The scorer adds two
of its own: `citation_file_is_not_the_units_file` and `citation_unchecked`, the
second meaning it had no source it could trust and therefore established
nothing.

**Shapes this refuses, with what they cost.** A quote assembled from
non-adjacent lines — a model reporting a function by its three interesting lines
— is refused outright, and **416 of 435** records could take that shape, so a
submission built that way scores zero rather than less. Dropping an interior
comment line and quoting the code around it is the same refusal, and **196 of
434** spans contain an interior comment. Blank lines are the exception: they are
dropped on both sides, so a blank line inside your quote is fine. Quote
contiguous lines, comments included, or narrow the locator to a run that has
none.

**The cheapest way to satisfy all of this** is to build the quote by slicing the
source at the locator you are about to report, which is what the bundled
`PredicateDetector` does. `self_check()` in `examples/reference_runner/
submission.py` runs the host's check during development so a mismatch is a
message you see immediately rather than a run that scored zero.

**Skipping.** There is no `gate()` method to override. Whether a source unit is
passed over is decided by `detectors.gate`, outside your submission, and it
blocks only where there is provably nothing to read — the file does not parse, or
it declares no contract, library or interface. A per-detector skip would be
indistinguishable in the record from a detector that looked and found nothing, so
the interface does not offer one.

**Escalation.** `ctx.limits.escalation_allowed` tells you whether a larger model
may be requested. It is closed at difficulty `S` and open above it, and every
escalation is recorded along with whether it changed the verdict.

## 2. What you are given

All inputs arrive in one frozen `AnalysisContext`:

| Field | What it is |
| --- | --- |
| `source_id`, `path` | identity of the unit under analysis |
| `source` | the Solidity source |
| `tier` | `semantic` or `syntactic` — the strongest backend that could read it |
| `level` | difficulty grade of your class, `S`/`M`/`Q` |
| `limits` | wall clock, model calls, tokens, whether escalation is open |
| `facts` | evidence the harness computed before you ran |
| `labels` | a label taxonomy, or `None` outside classification mode |

Read `facts` instead of recomputing. It matters most at the `semantic` tier:
those facts may not be recomputable inside the sandbox at all, because the
compiler and its dependency resolution live outside it.

`tier` is never absent. A unit no backend could read is skipped before any
detector sees it.

## 3. Classification mode

When `ctx.labels` is set, `classify()` is called and may return
`ClassificationClaim`s: a tag, an optional subtag, a severity, and a prose
description. These are *repository-level* claims — no file, no function, no line.

They are kept off `Finding` deliberately. A `Finding` carries a locator and a
quote, so it can be checked against source and refuted. "This repository has a
high-severity access-control bug" carries neither and cannot be. Merging the two
would let an unfalsifiable claim inherit the credibility of a verified one.

**Severity appears here and nowhere else.** `Finding` has no severity field and
will not gain one. Reproducing a severity a named auditor recorded is a claim
with a ground truth to be wrong about; inventing one is a value judgement
dressed as an observation.

The taxonomy arrives as data in `LabelSpaceSpec`, supplied by whoever runs the
exercise. Use `validate_claim(claim, spec)` to check your claims yourself — it
returns every problem, not the first. A claim whose tag falls outside the label
space is **not** dropped: it is retained and counts against you as a false
positive. Dropping it would make invalid output free.

## 4. Submitting

A submission is a module plus a manifest. The manifest declares the entry point
rather than the package registering itself on import, because the only way to
learn what a self-registering package contains is to execute it — which is the
thing to be decided *before* doing.

```json
{
  "submission_id": "team-alpha",
  "api_version": "1.0",
  "entry_point": "my_submission.detectors:MissingOwnerCheck",
  "author": "Team Alpha"
}
```

### Constraints your code must live within

Submissions run as untrusted code under external isolation. Assume all of:

- **No network egress** except the configured model endpoint. Nothing else
  resolves.
- **Enforced wall clock, token and call budgets.** `ctx.limits` tells you the
  allowance. Exceeding it stops the run from outside; it is not a soft limit you
  may overshoot.
- **No import-time work.** Your module body should define classes and return.
  Work done at import happens before anything can supervise it, and a module that
  fails on import is reported as a malformed submission with no chance to run.
- **One submission per process.** Do not rely on state surviving between units,
  and do not manipulate `sys.path` or `sys.modules`.
- **Bounded text.** `Finding.reasoning` is capped at 2,000 characters,
  `Finding.quote` at 4,000, and `ClassificationClaim.description` at 1,000.
  Exceeding a cap invalidates the finding. The caps are generous for honest
  output; they exist because an unbounded string returned from a sandbox is a
  channel out of it.

## 5. Nothing you return is taken on trust

The interface describes what your methods return. Across this boundary that is a
claim, and it is checked -- with one exactness worth stating, because this
paragraph read as a stronger promise than the code makes. Every returned value
is validated against its model, and anything
unusable becomes `Outcome.INVALID` with `InvalidReason.SCHEMA_VIOLATION` —
reported as harness health, never entering a confusion matrix, and never recorded
as `clean`.

Specifically:

- Returning `None` where a sequence belongs is an error, **including from
  `verdict()`**. The charitable reading — "no rejections" — would mean a
  `verdict()` that falls off an exception path accepts every finding it is given.
- Returning a `str` is an error, even though strings iterate.
- Raising is an error, and is reported against the stage that raised
  (`evidence`, `plan`, `verdict`, `classify`) so the failure is attributable.
- Items are validated individually, and the failure names the position.

`plan()` is the one place `None` is a legitimate answer; it means no model runs.

## 6. Versioning and what is promised

`API_VERSION` is `major.minor`.

- **Same major ⇒ compatible.** A submission declaring a newer *minor* than the
  host still runs: minor versions only add, so the fields it does not know about
  are ones it never reads.
- **Different major ⇒ refused**, before your module is imported. That order is
  deliberate: importing first would let an incompatible submission execute its
  module body before being turned away.

### The compatibility surface

Covered by the commitment: every name exported from
`contract_assay.detectors.__all__`, the fields of `AnalysisContext`,
`SubmissionLimits`, `LabelSpaceSpec`, `ModelTaskSpec` and
`ClassificationClaim`, the members of `TaskOutput`, and the `Detector` method
signatures. Also the types these reuse from `contract_assay.models`:
`EvidenceRef`, `Finding`, `FailedCheck`, `RejectionKind`, `Locator`,
`EvidenceTier`, `DifficultyLevel` and `VulnerabilityClass`.

`API_VERSION` is `1.1`. The move from `1.0` added `EvidenceRef.diagnostic`,
which is exactly the kind of change a minor version is for: a submission written
against `1.0` never reads the field and runs unchanged.

Not covered: anything prefixed with an underscore, anything under
`contract_assay.corpus`, and the harness internals that call these methods.

Within a major version, this project will add fields and enum members but will
not remove or rename them, will not change a method signature, and will not
tighten an existing validation rule. Inputs travel in `AnalysisContext` precisely
so that new capabilities can arrive as fields rather than as parameters — adding
a parameter to `evidence()` would break every submission ever written.

Adding an enum member is a minor change, so do not write exhaustive matches over
`TaskOutput` or `VulnerabilityClass` without a default branch.

### One thing this module does not provide

It does not sandbox anything. `load_detector` imports a module, and importing a
module runs its top-level code in that process. Container isolation, egress
denial, timeouts and token accounting are infrastructure outside this package.
The manifest exists so that infrastructure can decide what to run before running
it. `SubmissionLimits` tells a detector its allowance; a detector that ignores
it is stopped from outside, or not at all.

## 7. Checklist

- [ ] `detector_id`, `class_id` and `api_version` declared — missing any fails at
      class definition, not mid-run.
- [ ] `evidence()` consults no model, network or clock.
- [ ] Predicates test shapes, not identifier names; no case-folding.
- [ ] Every `FailedCheck` carries the `RejectionKind` that matches what happened.
- [ ] No sequence-returning method can return `None`, on any path.
- [ ] Module body does no work.
- [ ] Text fields fit their caps.
- [ ] `validate_claim` is clean for every claim, if you classify.

## 8. Running submissions, and the documents that come out

This section is for whoever *runs* the exercise rather than whoever writes a
detector: a marking script, a queue worker, a web front end. The scoring engine
is here, and a surface built on it should call it rather than reimplement any
part of it — §7.6's refusals are one `or 0` away from becoming defaults, and the
loss shows up in the cell a reader believes.

### The model is yours to name

`plan()` says what to ask; the model is called **outside** the detector, by you.
That is what lets an exercise put every submission through one agreed model. It
also means the engine cannot observe which model ran, so you tell it:

```python
run = run_detector(
    detector,
    ctx,
    model_findings=findings_the_model_returned,
    models=[ModelUse(model_id="the-agreed-model", role=ModelRole.MAIN, calls=1, tokens=812)],
)
```

A harness that produced findings without any model says so explicitly:

```python
run = run_detector(
    detector, ctx, model_findings=deterministic_findings, produced_without_a_model=True
)
```

Findings with neither raise. "No model is named" and "no model ran" are
different claims, and only one of them supports a comparison against a
baseline; a run that says nothing would leave a leaderboard reporting an unknown
model as the agreed one.

Sub-models are declared the same way with `role=ModelRole.SUB`. They do not
block a comparison — which helpers a harness calls is part of what the exercise
compares — and their calls and tokens count against the same budgets.

### Two commands

Runs are JSON Lines, one `DetectorRun` per line, because a harness writes them
as units finish and a truncated stream is still readable where a truncated array
is not. A malformed line stops the load rather than being skipped: a scoring run
that silently dropped part of a submission would report its own recall as the
submission's.

```console
$ contract-assay score runs.jsonl \
    --records corpus/records --submission-id team-alpha \
    --source-root ./checkout --weights weights.json --out team-alpha.json
wrote team-alpha.json -- 110 prediction(s) await adjudication before precision exists

$ contract-assay rank \
    --submission team-alpha=team-alpha-runs.jsonl \
    --submission team-beta=team-beta-runs.jsonl \
    --records corpus/records --source-root ./checkout \
    --weights weights.json --baseline the-agreed-model --out board.json
```

`rank` takes each submission's *runs*, not its score document, so that every row
is computed against one corpus with one weighting in one invocation. A
leaderboard assembled from figures cannot check that they were.

`--over` names the classes the ranking covers, and is the exercise's statement
rather than something to infer. Omitted, every class the submissions share must
have an F1 — safe, and rarely what was meant: a mean over whichever classes
happened to have figures ranks a submission on its corpus's readiness instead of
on itself. One class whose pool is fully judged is a real ranking; eight classes
where one is waiting on adjudication is no ranking at all.

`--weights` is yours to supply — the engine ships none, because a weighting
states what the exercise values. Without it the per-class figures are still
reported and the aggregate is refused, with that as its stated reason.

`--predictions-per-unit` is **not** that kind of parameter, and it has a
default: nine, the most records any single unit-class pair in the corpus holds,
so a perfect submission is never capped. It scores at most that many findings
per source unit per class, in the order the runs returned them — counting the
ones whose citations failed, because a refused citation is still a claim you
made about a location — and reports the rest as `capped_predictions`.

Two reasons, and the second is why it is a default rather than an option.
**Precision waits on adjudication and adjudication is somebody's afternoon**: a
submission that proposed every declaration in every file would buy itself an
unbounded amount of that. And **recall over an unbounded pool is not a
measurement**: precision waits, recall does not, so without a cap a submission
can buy recall with volume nobody has judged yet. A review did exactly that —
668,655 quotes over 435 records, per-class recall published, precision
unlicensed in all nine classes. Raise it if your exercise funds more
adjudication; it is one of the six fields two results must share before they
compare, so a figure computed under a different cap will not be ranked against
one computed under this one. The CLI types the option as an integer, so there is
no way to ask this surface for an uncapped figure; `score(..., predictions_per_
unit=None)` in the Python API still does that, for tooling that wants the whole
pool.

The quota is per *unit*, and a unit is the pinned file across revisions — not
the `source_id`, which carries the commit. The corpus pins eight paths at two
commits each, and a quota on `source_id` gave the records on those paths
eighteen guesses instead of nine.

Two things about where it is enforced. It is enforced **here**, at scoring,
because this is the only layer that sees a whole submission's runs at once — a
cap applied per run cannot see that two detectors for one class already used the
quota between them, and a cap applied by whatever *ran* the submission is a cap
inside the process running the code it limits. And the order is the submission's
own: a harness that puts its best finding first is making exactly the choice the
cap asks it to make, so re-ranking for it would take the choice away and then
charge it for the result.

`rank` declines to rank rows scored under different caps, for the same reason it
declines rows under different baseline models: their precisions are over
different pools.

### Calling the model

This package does not. `plan()` states what to ask and nothing here asks it, so
a consumer supplies the model — and `examples/reference_runner/` is a worked one,
on any OpenAI-compatible endpoint.

Three obligations come with calling a model on a submission's behalf, and each
one produces figures that look fine when it is skipped:

1. **A run must name what produced its findings.** `models=[ModelUse(…)]`, or
   `produced_without_a_model=True`. A run that leaves the producer unnamed is
   refused: a figure that cannot say what produced it cannot be compared with
   one produced by something else.
2. **A failed call still happened.** Tokens spent on a call that returned
   nothing are spent, and a budget counting only successes lets a harness retry
   without limit.
3. **"We stopped it" and "it found nothing" are different facts.** A run cut
   short by a budget or a timeout is `invalid` with a reason, never `clean`.

A host running *someone else's* harness owes three more, and none of them change
what a submission author writes: meter the calls from outside the process
running the submission, confine that process, and re-check every citation
against the host's own copy of the source. `check_citation` is exported for the
third.

### What the documents guarantee

Both documents carry `schema_version`, `engine_version` and a `corpus` digest
over every record's identity and verified bytes. Two rows with different digests
were not measured against the same ground truth.

Every measurement is `{"value": …, "unavailable": …}`:

```json
{
  "class": "access_control",
  "records": 6, "predictions": 66, "matched": 5,
  "recall": {"value": 0.83, "unavailable": null},
  "precision": {"value": null, "unavailable": "59 of its predictions are not yet adjudicated"},
  "f1": {"value": null, "unavailable": "..."},
  "below_minimum": true
}
```

A `null` value always has a reason beside it. **Render the value and you print
an empty cell; default it and you have published a number this engine refused to
state.**

`adjudication_queue` lists every prediction nothing in the corpus judges, with
its unit, detector and line range. Precision waits on that list, and the list is
the exercise's own work rather than a defect in the submission — which is also
why the count in it agrees with the sentence in `precision.unavailable`.

`unrankable` rows carry two different kinds of "cannot": `reasons` is per class,
for figures the corpus or the submission cannot yet support, and `incomparable`
is set when the figures exist and the comparison does not — a different baseline
model, none named, or two. An unrankable row is not a worse one, and placing it
last would assert a comparison nobody measured.
