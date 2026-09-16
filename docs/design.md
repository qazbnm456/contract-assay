# Design

How contract-assay is built, and why each piece is shaped the way it is. This
document is the contract between the docs and the code: if they disagree, one of
them is a bug.

## 1. What is being measured

A detector is a program that reads Solidity and claims a vulnerability of a
particular class exists at a particular place. The benchmark asks one question
about such a program:

> When it fires, is it right about *where*? When it stays silent, was there
> nothing there?

Everything below follows from taking that question literally.

### 1.1 Why location is the whole problem

A benchmark that scores at repository granularity — "did the detector say
anything about a repository we labelled vulnerable?" — cannot distinguish a
detector that found the bug from one that flagged an unrelated function three
files away. Both score as hits. The resulting precision and recall describe
something, but not detection.

So a finding must carry a location, and the location must be checked. An
unchecked location field is worse than none: it lends precision to a number that
does not have it.

### 1.2 Why failures must be separable

A run can end in more ways than "found" and "not found". The model can emit
something the schema rejects. The budget can run out. The sandbox can die. The
source may not parse. A corpus path may be missing.

Every one of those, recorded as "not found", becomes a false negative — and a
false-negative count blended from five causes cannot be attributed to any of
them. Tuning against it is guesswork.

`Outcome` therefore has four members, of which two are measurements
(`vulnerable`, `clean`) and two are not (`invalid`, `skipped`). The latter must
state a cause and are reported as harness health, separately, always.

That split is not enough on its own. A finding can be turned away for two very
different reasons, and the difference decides what the whole run is:

| Rejection | Meaning | The run is |
| --- | --- | --- |
| `verdict` | A predicate applied its rule and concluded this is not an instance | a measurement — `clean` |
| `citation` | The claim could not be checked against the source at all | not a measurement — `invalid` |

Recorded as a bare list of strings, the second is indistinguishable from the
first, and an error quietly becomes a judgement. `FailedCheck` therefore carries
a `RejectionKind`, and `DetectorRun` refuses to be `clean` over a finding nobody
could check.

## 2. Detector anatomy

Each detector is a Python class in three layers. The split exists because the
three layers have different failure characteristics and must be tuned against
different objectives.

```
┌─ evidence() ──────────────── deterministic, no model, always runs
│    Structural facts about the code, each with a location.
│    Cannot be influenced by anything the model later says.
│
├─ task (RLMTask) ──────────── the model, in a sandbox
│    The contract is a variable it explores, not text pasted into a prompt.
│    Produces Findings carrying citations.
│
└─ verdict() ───────────────── deterministic, always runs
     Accepts or rejects each finding, naming every predicate that rejected.
```

### 2.1 Evidence is independent of the verdict

`evidence()` runs first and its output is recorded whatever the model concludes.
A model may decline to report, or report wrongly; it cannot remove an evidence
item. A verdict asserted against the evidence is visible as exactly that, which
is a signal worth having.

This is also what makes multi-condition rules enforceable. A rule of the form
"this is only exploitable if A and B and C hold" is a conjunction. Expressed as
prose inside a long prompt, its enforcement depends on the model's attention
holding across the whole input. Expressed in `verdict()`, it is `and`.

### 2.2 Gate predicates are lenient; verdict predicates are strict

These two kinds of predicate look alike and must be tuned in opposite
directions, because their errors cost different things.

| | Decides | Bias | On failure |
| --- | --- | --- | --- |
| **Gate** | whether to run the model at all | **lenient** — admit when unsure | admit |
| **Verdict** | whether a finding stands | **strict** — reject when unsure | reject, and name the predicate |

A wasted model call costs a fraction of a cent. A wrong skip costs a true
positive, silently, and nothing in the output will ever indicate it happened.
So gates block only on conditions that are *provably* empty: the unit declares
no contract, or neither analysis backend can read it. "This looks unpromising"
is never a reason.

Strictness on the verdict side is safe only because rejections are recorded. A
rejected finding is retained with `status=unverified` and the list of predicates
that rejected it, so the recall cost of every rule is a number someone can look
at and argue with.

### 2.3 Predicates work on shapes, not names

Identifiers are attacker-controlled and author-controlled; shapes are not. A
predicate should not ask whether a parameter is called `amountOutMin`. It should
ask whether the second positional argument of a call whose selector is in the
swap set is a literal zero or a parameter never referenced elsewhere in the
function body.

Corollaries:

- Do not case-fold Solidity identifiers. The language is case-sensitive and
  `owner` and `Owner` are different symbols; folding manufactures false matches.
- Prefer 4-byte selectors over name matching for known primitives. The selector
  is the keccak prefix of the canonical signature: exact, free to compute, and
  immune to renaming.
- Use a trie for large synonym sets (router interfaces, oracle interfaces,
  vault entry points) rather than alternating regex.

## 3. Evidence tiers

Analysis runs on the strongest backend that can read the source, and records
which one it used.

| Tier | Backend | Provides | When |
| --- | --- | --- | --- |
| `semantic` | compiled IR | def-use chains, control flow, call graph | source builds |
| `syntactic` | parser only | syntax tree; no types, no data flow | source does not build |

A compilation failure degrades to the syntactic tier. It is **not** a skip.
Large DeFi protocols have the most elaborate build setups and also host the
hardest vulnerability classes; skipping what does not build would
systematically exclude the cases that matter most, and the resulting benchmark
would measure the easy half of the problem while claiming to measure the whole.

Only when *both* tiers fail is the source skipped, with
`skip_reason=unparseable`.

The tier travels with every result. A `clean` verdict reached without data flow
is a weaker claim than one reached with it, and reports must never average the
two together.

## 4. Vulnerability classes

Nine classes, derived from two public sources: the OWASP Smart Contract Top 10
for naming and incident-oriented grouping, and the EEA EthTrust Security Levels
Specification for per-requirement verifiability and a difficulty grade.

| # | `class_id` | OWASP | Level |
| --- | --- | --- | --- |
| 1 | `access_control` | SC01 | M |
| 2 | `oracle_integrity` | SC02 | Q |
| 3 | `slippage` | — | Q |
| 4 | `flashloan_manipulation` | SC07 | Q |
| 5 | `reentrancy` | SC05 | M |
| 6 | `unchecked_external_call` | SC06 | S |
| 7 | `denial_of_service` | SC10 | M |
| 8 | `arithmetic_rounding` | SC08 | Q |
| 9 | `insecure_randomness` | SC09 | M |

Instances of several of these span levels; the grade recorded is the **deepest**
one, because it decides whether the detector may reach for the escape hatch and
under-grading would close it on exactly the cases that need it. One grade per
class, held in `VulnerabilityClass.level` and derived wherever difficulty is
needed — storing it a second time alongside would permit a record that claims a
class and contradicts its grade, with nothing able to say which to believe. Every
row above is pinned by a test, so drift between this table and the code fails CI
rather than going unnoticed.

EthTrust requirements are referenced by identifier only. No specification text
is reproduced in this project.

### 4.1 Difficulty levels are a reporting axis

`S` means static analysis is expected to catch it. `M` means manual review or
stronger assumptions. `Q` means business-logic understanding is required.

A single aggregate score averages classes that static tooling has handled for a
decade with classes it cannot reach in principle, and the resulting number
answers no question anyone has. Reported per level it answers the one that
matters: does the model earn its keep where deterministic tooling cannot follow?

A detector losing to a static analyser on an `S` class is a clear negative
result. The `Q` classes are where the approach is either worth something or
isn't.

### 4.2 Analysis depth required, by class

Which backend each class needs. This drives implementation order: classes
reachable at the syntactic tier can be built and tested before the compiled
backend is wired up.

| Class | Needs | Syntactic tier sufficient? |
| --- | --- | --- |
| `unchecked_external_call` | shallow def-use | mostly |
| `insecure_randomness` | shallow def-use | mostly |
| `access_control` | modifiers, visibility | partly |
| `slippage` | def-use through call arguments | no |
| `oracle_integrity` | def-use into guards | no |
| `denial_of_service` | storage/dynamic array types | no |
| `arithmetic_rounding` | types, decimals, evaluation order | no |
| `reentrancy` | control flow + state-write ordering | no |
| `flashloan_manipulation` | interprocedural reachability | no |

## 5. Escalation

The working model is small. A larger model is available as a metered escape
hatch, and every escalation is recorded with whether it moved the verdict.

| Level | Working model | Escalation |
| --- | --- | --- |
| `S` | deterministic-led, model reviews | closed |
| `M` | small model | permitted, reason recorded |
| `Q` | small model attempts first | expected |

Recording escalations turns "how much did the large model contribute?" into two
measurable numbers per level: escalation rate, and verdict-flip rate given
escalation. Without the record, that question can only be answered by assertion.

## 6. Corpus

### 6.1 Storage is by reference

Corpus records store *pointers*, never vendored third-party source.

| Tracked in this repository | Fetched at run time |
| --- | --- |
| repo URL, commit SHA | contract source |
| file path, contract, function, line span | audit report text |
| class labels, difficulty level | |
| provenance: report URL, auditor-assigned severity | |
| fix commit SHA, where public | |

Three reasons, all load-bearing: the annotation set is the only original work
here and can carry this project's licence cleanly; no third-party code is
redistributed, so no third-party licence attaches; and pinning commit SHAs makes
the corpus reproducible.

The digest is what makes the third one true, so `verify` writes it onto every
record it admits. A record carrying no digest would be admitted today against
one file and tomorrow against different bytes, and nothing would notice; a
reproducibility guarantee that depends on an author remembering to fill a field
is not a guarantee.

Auditor-assigned severity is *provenance* — a fact about what the original
report said. It is never mixed with anything a model produced, and no model in
this system is asked to produce a severity at all.

### 6.2 Negative samples, three kinds

A benchmark with weak negatives measures nothing. All three kinds are required:

1. **Post-fix** — the same repository at the fix commit. The strongest control:
   everything is identical except the bug.
2. **Cross-class** — a repository vulnerable to class Y but clean for class X.
   Forces a detector to distinguish "has a bug" from "has *this* bug", which a
   flat corpus never tests.
3. **Confirmed clean** — manually verified.

Each kind has to carry what makes it that kind, or it decays into the weakest
one. A cross-class negative must name the class it *is* vulnerable to: without
that it is an ordinary clean sample, and the hard negative it was collected to
provide does not exist. A confirmed-clean negative must record how it was
confirmed, because "someone checked" is neither reviewable nor reproducible. A
post-fix negative must be pinned to the fix commit — pinned to the vulnerable
one it would score the defect absent while measuring the code that contains it.
All three are enforced at construction.

The second kind is the reason all nine classes are built together rather than
one at a time. It also yields two measurements a single-class corpus cannot
produce: cross-class false-positive rate, and detector overlap.

### 6.3 Pipeline

```
harvest  ──▶  normalize  ──▶  verify  ──▶  corpus/records/*.json
```

- **harvest** — pull findings from public audit platforms into draft records.
- **normalize** — resolve locations, pin commit SHAs, map to `class_id`.
- **verify** — check every record against reality: the commit resolves, the
  digest matches, the span lies inside the file, and the named function and
  contract are declared where the record says — the function *within the span*,
  and inside the named contract rather than merely somewhere in the file.
  **Verification failure rejects the record.**

Declaration checks go through a parser, never a text match. A comment mentioning
a function is not a declaration of it, and a matcher that cannot tell the
difference certifies locations containing no code while rejecting constructors,
which carry neither the `function` keyword nor a visibility modifier — removing
most access-control annotations from the corpus while the totals still look
healthy.

A file that cannot be parsed is rejected here, which is the opposite of what
§3 does during analysis, and deliberately so. "I could not read this" is not
evidence that a record is sound: in analysis a weaker answer is still an answer,
whereas an unverified record poisons everything scored against it.

The pipeline is code, not a manual process, because nine classes make the
annotation volume large enough that adding a class must be data work rather than
engineering work.

### 6.4 Pair-differential scoring

For any record with a fix commit, the detector runs against both versions. The
result that counts:

> fires on the vulnerable version **and** stays silent on the fixed version.

Firing on both is not a detection — it is a detector that reacts to the shape of
the code rather than the defect. A flat confusion matrix cannot see the
difference; this can.

## 7. Scoring

The scorer is a separate component and does not run inside the harness. Trace
capture and scoring are deliberately different jobs: the run records what
happened, scoring interprets it, and interpretation changes more often than
capture does.

A prediction matches a ground-truth finding when the class matches and the
locations overlap. Location match is reported at three strengths so that
disagreement is legible rather than hidden in a threshold:

| Strength | Condition |
| --- | --- |
| exact | same file, same function, line spans overlap |
| function | same file, same function |
| file | same file only |

Reports are stratified by difficulty level and by evidence tier, and state
counts of `invalid` and `skipped` alongside — never folded in.

Sampling is an explicit parameter of a benchmark run, and metrics are reported
at the corpus's real class prevalence. Forcing a balanced sample produces
numbers that describe no population and cannot be compared across classes.

## 8. Layout and status

Status is stated per component because a design document that describes planned
work in the present tense reports intentions as capabilities.

| Component | Purpose | Status |
| --- | --- | --- |
| `models.py` | data contract | **built** |
| `corpus/records.py` | record schema, the nine classes | **built** |
| `corpus/verify.py` | verification against pinned source | **built** |
| `evidence/solidity.py` | syntactic backend: declarations and spans | **built** |
| `cli.py` | `verify`, `declarations` | **built** |
| `evidence/` predicates | the shape-level predicate library (§2.3) | not started |
| `evidence/` semantic backend | compiled IR, def-use, call graph (§3) | not started |
| `detectors/` | `evidence()` / `task` / `verdict()` per class (§2) | not started |
| `corpus/harvest.py`, `normalize.py` | the first two pipeline stages (§6.3) | not started |
| `report/` | scoring, match strengths, stratification (§7) | not started |

Consequences worth stating plainly: §2.2's gate and verdict predicates exist as
a rule for writing them, not as code; §3's tier degradation is represented in the
type system but has no backend to degrade between; and §6.4 and §7 are design
only. The only production path into `verify` today is the CLI resolving against a
local checkout, which confirms that a record is coherent against the bytes on
disk but not that those bytes belong to the pinned commit.

```
tests/
├── unit/              data contract, record invariants, declaration indexing
├── offline/           whole pipeline, no model, no network, no toolchain   (planned)
└── incidents/         pinned cases that must alert regardless of verdict   (planned)
```

`tests/incidents/` deserves a note: these are reconstructed real cases wired so
that a detector must alert on them *even when the model returns a benign
verdict*. They guard the property that evidence is independent of the verdict,
which is the one property no amount of prompt tuning can restore once lost.

## 9. Non-goals

- **Severity assignment.** A value judgement, not an observation. Detectors are
  asked only for facts they can point at.
- **Bytecode-level analysis.** Corpus sources are repositories, most never
  deployed; and the classes here need source semantics that bytecode discards.
- **Unverified on-chain contracts.** A real gap for deployed-contract
  monitoring, and out of scope. If taken up later, use a maintained
  selector-recovery tool rather than writing one.
- **Running an execution client.** Simulation, where used, runs through the
  standard contract toolchain against a forked state. A full node solves a
  problem this project does not have.
- **Replacing static analysers.** They are the baseline to be measured against,
  and on `S`-level classes they are expected to win.
