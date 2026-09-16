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

### 1.3 An instrument cannot exceed its own source of truth

The general form of a failure this project keeps meeting:

> When the thing that validates and the thing being validated draw on the same
> source of truth, the validation cannot exceed that source — and the shortfall
> is invisible, because it appears as the subject performing badly rather than as
> the instrument being short.

It is worth stating once because it has three separate instances here, and only
one of them is fixable.

**The verdict layer.** Fixable, and fixed — see §2.1. A `verdict()` that admitted
only what the deterministic predicates already supported would cap a detector's
recall at its predicates' recall, turning "did the model find the defect?" into
"does the model agree with our static analysis?". It would fail hardest on the
`Q` classes, which exist precisely because deterministic tooling cannot reach
them.

**The corpus.** Not fixable, and so stated instead — see §6.6. `verify` rejects
what it cannot confirm, which is correct and is what makes the corpus worth
having. It also means the corpus is not a sample of real defects but a sample of
defects that sit where the declaration index can parse and name them
unambiguously. Assembly-heavy contracts, generated code and heavily overloaded
interfaces are thinner in it than in the world.

**Variant confirmation.** Not fixable, and deferred with the pipeline it belongs
to — see §6.5. Confirming that a mutation preserved a defect by comparing which
predicates fire cannot confirm a defect the predicates never saw, so those cases
fall to human review. Review is the expensive path, so classes needing more of it
yield fewer confirmed variants per unit of effort, and a variant set built
without planning against that cost skews toward the classes the predicates can
see.

**Derived locators.** Not fixable, and the most instructive of the four,
because it appears *inside* the machinery built to implement this rule. A
harvester can recover a line span for a finding that only named a file and a
function, by looking the function up in the declaration index (§6.3). The span is
then verified by asking the declaration index whether the function sits inside
it — which it does, because the span came from there. The check is tautological
for such records and passes at a rate indistinguishable from real confirmation.
So `LocatorProvenance` marks each locator as stated or derived, and the
verification report counts them separately (§6.6): an admitted total mixing the
two would hide the shortfall in the very number built to expose it.

**Exact-location matching.** Fixable, and fixed — see §7. `exact` means the
spans overlap within the same function. For a record whose span was *inferred
from a function named in prose*, the ground-truth span **is** the whole function,
so any prediction inside it overlaps and `exact` is satisfied trivially. Left
alone, every exact-match figure over a mixed corpus would be inflated by however
many prose-derived records it happened to contain, with nothing in the output
able to say by how much — a measurement whose strength is silently set by a
property of the corpus it cannot see. `LocatorProvenance.supports_exact_match`
is the fix: such records report `exact` as unavailable rather than as satisfied.

The pattern generalises past this repository, and the response differs by case:
fix it where the instrument can be decoupled from the subject, and where it
cannot, measure the shortfall and report it. What is never acceptable is leaving
it unstated, because the number it produces looks exactly like a number that
does not have the problem.

Note also how these were found. Most were discovered by asking, of a mechanism
that had just been built, what it shares a source of truth with. That question is
cheap and belongs in a review of anything that measures anything. It also catches
cases that do not look like this section at first: `verify` both wrote the digest
onto a record and checked the digest, so for any record arriving without one the
comparison was against itself — the same shape as a derived locator, arriving in
a different field.

A second question belongs beside it, because it catches a different failure:

> **What test fails if this guarantee is absent?**

If the answer is none, the guarantee is prose no matter how precisely it is
worded — and a precisely worded one is more dangerous than a vague one, because
precision invites sign-off. The digest guarantee above was stated correctly in
this document and implemented nowhere, and nothing in the wording could have
revealed that. What revealed it was writing the test: change the file after the
derivation ran, and assert the rejection.

The two questions are complementary. The first asks whether a mechanism can see
past itself. The second asks whether it exists.

## 2. Detector anatomy

Each detector is a Python class in three layers. The split exists because the
three layers have different failure characteristics and must be tuned against
different objectives.

```
┌─ evidence() ──────────────── deterministic, no model, always runs
│    Structural facts about the code, each with a location.
│    Cannot be influenced by anything the model later says.
│
├─ plan() ─▶ the model ─────── optional, in a sandbox
│    The contract is a variable it explores, not text pasted into a prompt.
│    Produces Findings carrying citations. Returning None runs no model.
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

Independence has a converse, and it is the half that gets forgotten. Evidence
must not be removable by the model — *and the verdict must not be bounded by the
evidence*. The tempting rule is to reject any finding the deterministic
predicates did not already support. It would invert what the benchmark measures:
a detector's recall would be capped at its predicates' recall, so the score
would answer "does the model agree with our static analysis?" rather than "does
the model find defects?" — the opposite of the question §4.1 asks, and invisible
in any aggregate afterwards.

So `verdict()` re-derives its rules against the source **at the location the
finding states**, never against the evidence list. That keeps it strict about the
claim — a finding pointing at a line containing no call is rejected, by name —
while leaving it blind to whether any predicate happened to fire. The predicate
library's own documented blind spots make the difference concrete: a discarded
`IERC20.transfer` return is a real and common defect that no predicate here can
see, and a model that finds it scores for it.

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

The same asymmetry is worth recognising away from detectors, because it keeps
recurring: **extract generously, resolve strictly**. A harvester reading a
function name out of English prose should match freely, because resolution
refuses anything that is not declared exactly once in the pinned file, and the
refusal is counted (§6.3). Reversing it — matching cautiously and resolving
loosely — loses findings silently and admits wrong ones.

The gate is owned by the harness and is not overridable. Its two blocking
conditions are universal rather than per-class — they are exactly the two members
of `SkipReason` — so there is nothing for a detector to contribute. More
importantly, a per-detector skip is indistinguishable, in the recorded result,
from a detector that looked and found nothing. Offering one would hand a
submission a way to convert misses into exclusions with nothing downstream able
to tell the two apart.

### 2.3 Predicates work on shapes, not names

Identifiers are attacker-controlled and author-controlled; shapes are not. A
predicate should not ask whether a parameter is called `amountOutMin`. It should
ask whether the second positional argument of a call whose selector is in the
swap set is a literal zero or a parameter never referenced elsewhere in the
function body.

Corollaries:

- Do not case-fold Solidity identifiers. The language is case-sensitive and
  `owner` and `Owner` are different symbols; folding manufactures false matches.
- Remember that a name match is a fact about the text, not about the thing.
  **Any rule keyed on a name can be made to fire by choosing that name**, so a
  name is evidence that can be manufactured. `send` and `transfer` are address
  members, and also perfectly legal function names on a contract; at the
  syntactic tier `helper.send(x)` and `payableAddress.send(x)` are one shape.
- Prefer 4-byte selectors over name matching for known primitives. The selector
  is the keccak prefix of the canonical signature: exact, free to compute, and
  immune to renaming.
- Use a trie for large synonym sets (router interfaces, oracle interfaces,
  vault entry points) rather than alternating regex.

One more rule belongs here, because it is the same kind of trap — something
that looks like an improvement:

> **A predicate's precision is a property of the corpus, not of the condition.**
> A tighter condition that fires on a common benign pattern is worse than a
> loose one that does not, and only the base rate in real code says which is
> which.

The worked example is access control. "An externally reachable function writes
state and never mentions `msg.sender`" is a coarse condition: a sender reference
used only for logging suppresses it. The obvious repair is to require the
reference to sit inside a `require` or an `if`, which does distinguish a check
from a log — and then fires on every permissionless-by-design function, because
`balances[msg.sender] += msg.value` writes state and reads the sender while
guarding nothing. Deposits vastly outnumber unguarded setters that log their
caller, so the semantically better condition is the empirically worse predicate.
Both directions are pinned by tests, so the trade is visible rather than
inferred.

The same argument decides what an `EvidenceRef` may carry, and one level deeper
than it first appears. Evidence is compared — between a detector's output and
ground truth, and between two versions of one source — so every value in the
compared payload must survive any edit that preserves the property it describes.
That is a test, not a list:

| Value | Stable? | Where it goes |
| --- | --- | --- |
| argument index, literal value, statement ordering | yes | `detail` |
| language builtins (`block.timestamp`, `blockhash`) | yes — unrenameable | `detail` |
| local identifiers: state variables, parameters, helpers | **no** | `diagnostic` |
| external callee identity | only as a 4-byte selector | `detail`, once canonicalised |

Local identifiers fail the test outright: renaming preserves behaviour, so a
`detail` carrying one reports a difference where nothing changed. They are still
worth keeping, because evidence a human cannot read is evidence nobody trusts —
so they go in `diagnostic`, which is excluded from every comparison.

External callee identity is the awkward one, because for the oracle and slippage
classes it *is* the property rather than incidental to it. Its stable form is the
selector: an import can be aliased and a variable holding an interface can be
renamed, while the selector cannot change without changing what is called.
Computing it needs real ABI canonicalisation — `uint` widened to `uint256`,
structs flattened to tuples, array suffixes normalised — which
`Declaration.signature` deliberately does not do. That canonicalisation is
therefore a prerequisite for those classes rather than a later tidy-up.

### 2.4 The interface is a public API

The three layers above are also what people outside this project write against:
a submitted detector is a `Detector` subclass, loaded from a declared entry point
and run under isolation. `docs/api.md` is the external-facing contract and states
the compatibility surface. Two consequences belong here, because they changed the
design rather than merely describing it.

**Nothing a submission returns is taken on trust.** Among cooperating authors an
abstract base class is a convention: nothing checks that `verdict()` returned
what it promised, and nothing needs to. Across an untrusted boundary the same
class is a claim. Every returned value is therefore re-validated, and anything
unusable becomes `invalid` with `schema_violation` — never a crash, and never
`clean`. Recording a submission's bug as `clean` would report the code under test
as sound on the strength of a defect in the code testing it.

The refusals that matter are the charitable ones. A method returning `None` where
a sequence belongs is rejected, `verdict()` included: reading `None` as "no
rejections" means a `verdict()` that falls off an exception path accepts every
finding handed to it. A returned `str` is rejected although strings iterate,
because it would otherwise decompose into characters and fail a layer deeper with
an unrecognisable message.

**Inputs travel in one object.** `AnalysisContext` exists so that the interface
can gain capabilities without changing a signature any submission implements.
Adding a field is a minor version; adding a parameter to `evidence()` would break
every submission ever written against it. A stability commitment is worth only as
much as the mechanism that lets the API keep growing underneath it.

For the same reason the interface owns no task type from the model runtime.
Re-exporting a third-party type inherits stability guarantees this project does
not control and cannot promise on, so `plan()` returns a declarative
`ModelTaskSpec` owned here and the harness translates it on its own side of the
boundary.

Isolation itself is infrastructure and sits outside this package: loading a
submission imports its module, and importing a module runs its top-level code.
The manifest is what makes external isolation possible — it is readable without
executing anything, so what will run can be decided before it runs. Calling the
loader a sandbox would be precisely the error §8 exists to prevent, reporting an
intention as a capability.

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

### 4.3 What nine classes means for the claim

Both source taxonomies describe recurring vulnerability *patterns*, and two
OWASP entries were deliberately not adopted: logic errors and missing input
validation. Both are residual categories rather than patterns — no detector can
be written for "logic error" in a shape that could be evaluated, and a
difficulty grade for it would mean nothing.

Measured against a public audit platform, 71 of 87 accepted high and medium
findings map to none of the nine. The unmapped ones are overwhelmingly
protocol-specific logic: an accounting error that deflates reported holdings, a
token balance that stops tracking one-to-one, a batch identifier collision,
signature replay across chains, standards non-compliance. That is the residual
category, arriving as a measurement.

So the claim this benchmark supports is:

> Can a model find instances of nine known vulnerability patterns, at the right
> location?

And the claim it must never be allowed to drift into is *can a model audit a
smart contract*. Nothing here supports the second, and an 18% mapping rate
against real audit output is the evidence for why.

One consequence worth stating, because it explains the mismatch rather than
merely absorbing it. The class list is incident-derived: OWASP's ranking is built
from what has actually been exploited. So a population made of *pre-deployment
review* should be expected to map onto it poorly, and a population made of
*exploited incidents* should map onto it well — which is a prediction, not a
rationalisation, and it is why `Population` is recorded per record.

The prediction is now measured, and it holds. Seven curated post-mortems of
exploited incidents map to the nine classes five times — flash-loaned governance
twice, oracle manipulation, reentrancy during liquidation, an unprotected
callback — against 19% over 911 findings pooled from four review sources. The
intervals do not overlap even at n=7.

Two do not map, and both are the same thing: a merkle proof accepted when it
should not have been. One bridge initialised its committed root to zero and
pre-approved it, so any all-zero proof verified; another had a flaw in its proof
library. Neither is access control, though the first reads like it — the
functions that accept a proof are permissionless by design, and what failed was
the verification rather than an authorisation. Improper proof verification is not
among the nine and is not being added; it is recorded here because the first of
the two was initially classified as access control from the post-mortem's
phrasing, and only reading the function showed otherwise. Which is the argument
for curating against source rather than against a summary. So the class list is
not a poor taxonomy; it is a taxonomy of exploited patterns being applied to
pre-deployment review output.

Usable yield from the population is nonetheless *one* of those seven, and the
reason is a second filter the class rate does not show. Only two of the seven
have a canonical public repository at all: one protocol shut down, one keeps no
core-contract repository, one org no longer exists, and one victim was a bespoke
trading bot. Of the two that remain, one is among the two that do not map. So
pinnable-and-in-scope is 1 in 7, against roughly 2% for a review platform — far
better per candidate, out of a candidate pool of seven.

`docs/curation.md` records the procedure, including the order, since three of
its steps exist only because doing them later wastes the earlier ones.

That does not make the incident population harvestable, and the obstacle is
structural rather than incidental. A curated incident proof of concept forks a
chain at a block and attacks a deployed address; it carries the *attacker's*
source and interfaces to the victim, never the victim's source. So the artefact
pins chain state, where `SourcePin` pins a repository at a commit, and the two
are not substitutes. Reaching a repository, a pre-fix commit, a path and a
function from an incident is per-incident research rather than extraction —
which places this population with hand-curation rather than with the harvest
pipeline, and runs into §9's exclusion of unverified on-chain contracts for the
cases where no public repository exists at all.

What the population does carry that no review finding does is an executable
demonstration: a test that exploits the defect at a pinned block. That is
stronger ground truth than any prose, and it makes §6.4's pair-differential
available without a detector — the same test run against the vulnerable and
fixed states is itself the measurement.

The prediction does not extend to the difficulty grades. Those come from a
prescriptive review specification rather than from incident data, so an incident
population should be expected to map well by class and to distribute differently
by grade than the grades' own source would suggest. Neither is a defect in
either.

**A tenth catch-all class is refused**, and written down because the proposal
recurs whenever coverage is measured. "Protocol logic" or "business logic error"
would lift the mapping rate immediately and add nothing measurable: no
predicates could be written for it, no difficulty grade would mean anything, no
detector could be aimed at it, and no scorer could tell a correct detection from
a plausible-sounding one. It is a generous enumerator (§6.3) one level up —
improving a number by widening what counts rather than by finding more.

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
  A prior obligation, before any of the accounting: an audit platform and a
  Solidity corpus are different populations. Contests auditing other languages
  are outside what this corpus could ever draw from, so the harvest statement
  says which contests were out of language scope — otherwise the denominator
  quietly includes work no adapter could have used, and every yield figure
  computed from it understates.

  Two obligations, both from §1.3, and a third that turned out to have a better
  answer than disclosure. A harvester parsing only certain report shapes yields a
  corpus skewed toward those platforms, so it tallies what it skipped and why. And it tallies those skips **by class**, not only by platform and
  cause: a skipped finding has no record — that is why it was skipped — so a
  per-platform count gives magnitude while leaving the confound intact, unable to
  separate "we skipped 40% of this platform" from "this platform has a different
  class mix". Class survives location: a report states the vulnerability type
  even when it describes the place in prose. "Skipped 61% of arithmetic
  candidates and 9% of oracle candidates" says the surviving distribution is an
  artefact; per-platform numbers only hint at it.

  Why that matters more than it looks: a finding is only usable if a repository,
  a commit, a path and a span can be recovered from it, so yield is biased toward
  findings whose authors linked precisely. Linking discipline correlates with
  recency, recency with Solidity version, and version with class prevalence —
  0.8.0 made arithmetic checked by default, collapsing overflow findings after
  it, while oracle and flash-loan findings rise over the same period as DeFi
  matures. The bias therefore arrives wearing the appearance of a class
  distribution, which is worse than the platform skew: that one looks like an
  artefact and invites suspicion, this one looks like a finding about the world.

  The third obligation is the enumeration denominator, and it is the one place
  where measurement was the wrong answer. An adapter's enumeration sets the
  denominator of every rate the harvest report quotes, so an enumerator that
  quietly skipped awkward sections would flatter its own yield with nothing able
  to contradict it — the component's own judgement fixing its own score. Where a
  platform publishes its own finding counts, that number is independent of the
  enumerator and the gap becomes a measured quantity instead of an unmeasured
  judgement; the adjustment that has to be stated is that the accepted categories
  are a subset, since low-risk, QA and informational sections are out of scope
  here. Where a platform publishes nothing, an adapter says so, and a reader can
  tell a confirmed denominator from a declared one. The enumerator is a separate
  component rather than the opening of an adapter so that it is runnable on its
  own: countable against declared totals, comparable across platforms, and
  regression-tested, so a later change that narrows it fails a test rather than
  improving a yield.

  The general form, which recurs: where a component's own judgement sets the
  denominator of its own score, take the denominator from somewhere else if you
  can, make the judgement runnable if you cannot, and disclose only when neither
  is available.

  The class-mapping rate is measured, and it decomposes three ways rather than
  two. Hand-assessing 40 randomly sampled unmapped titles: about 65% name a
  defect genuinely outside the nine -- protocol invariants, standards
  non-compliance, signature malleability, economic design. About 10% were a
  keyword table missing a synonym for a property already in the nine, and those
  are now caught. The remaining quarter are in the nine and **not reachable by a
  keyword table**: "pause mechanisms can be bypassed" is access control, "loan
  can get stuck" is denial of service, and matching them would need terms broad
  enough to admit everything else. So the ceiling on keyword classification is
  around 20%, with perhaps another 15% reachable only by reading the title as
  prose.

  That assessment was made by whoever wrote the classifier, which is §1.3 again:
  the instrument judged its own misses, and the bias showed in the direction
  predicted. The first estimate from it was roughly double what disciplined
  synonyms then delivered -- 40% claimed against 20% measured -- because
  "a human would map this" was counted as "the table could map this". The number
  wants an independent pass before anything rests on it.

  Five independent sources have now been measured for class mapping, and they
  agree: 18% over 87 findings from one contest platform, 20% over 400 from a
  second, 32% over 19 from a third, 17% over 424 from a single researcher's
  curated database spanning 87 reviews and 69 protocols, and 11% over 224 from a
  bounty-competition archive. The intervals all overlap around a sixth to a
  fifth. That is a property of the *population* rather than of
  any platform's format or curation, which is what the incident-derivation of the
  class list predicts (§4.3) — and it means no further review-platform adapter
  will move it.

  Two platforms are read, and comparing them isolates which constraint actually
  binds. One publishes consolidated reports where a location is stated in about
  one finding in nine; the other publishes a submission template with a
  structured severity and a section whose purpose is to say where the defect is,
  and a location was readable in every sampled document. So report *format* is
  not the limiting factor. Class mapping is: measured at 18% on 87 findings from
  the first platform and 13% on 8 from the second, which is the same number
  within the noise of those samples. A second platform of the same kind
  multiplies the pool without moving the constraint, which is worth knowing
  before a third is built.

  A fourth route is **measured but not implemented**, recorded here because
  reproducing the measurement costs network access. Findings quote the vulnerable
  code inline far more often than they cite it: across 87 accepted findings, 82%
  carry a fenced code block and 63% carry one that looks like source rather than
  a proof-of-concept harness, against the 11% carrying the structured excerpt the
  adapter already reads. Locating a quoted block in the pinned file by matching
  — comments stripped, whitespace collapsed, elisions dropped — yielded a usable
  span for 2 of 3 candidates tested, with the third correctly refused: its
  fragments matched across a 240-line region, and a match scattered over a whole
  file locates nothing, so a span wider than about three times its excerpt is
  rejected. Three candidates is a direction rather than a rate.

  If built, this route deserves its own locator provenance rather than joining
  the derived family. The span would come from matching the report's own text
  against the repository's bytes — two sources neither of which is the
  declaration index — so their agreement is genuine confirmation of the kind
  §6.6 says a derived locator lacks, and the quote makes it falsifiable by the
  same mechanism that checks a detector's citation.

  One platform makes the branch-reference problem look tractable rather than
  merely large, and the distinction is where the reference lives. A bounty
  competition archive of about a thousand findings cites exactly one Solidity
  file per finding and pins **none** of them: every link names a branch. That is
  worse per finding than a platform pinning half. But a commit identifies the
  *competition's* audited snapshot, not the finding, so establishing it is one
  lookup per competition rather than one per finding — forty lookups for a
  thousand findings. No such archive was found to declare a scope commit,
  though. What one does state, per report, is the **submission date** — which
  supports the same recovery by a different route: resolve the repository as it
  stood when the report was submitted, assuming the reviewed code is the code
  that was there then. Resolving the branch as it stands today rests on no
  assumption anyone can write down, which is why an adapter without a resolver
  refuses branch references rather than following them.

  The assumption is recorded on the pin. `SourcePin.commit_resolved_from` states
  in prose how a commit was obtained when the source did not state it, and
  `is_commit_stated` distinguishes the two. The digest witnesses the bytes either
  way; what differs is whether anybody claimed those were the *right* bytes, and
  a record unable to say which overstates itself. Resolution is injected rather
  than performed in an adapter, so the stage stays runnable with no network —
  the treatment source resolution already gets in `verify`.

  Part of it is recoverable rather than merely measurable. A report naming a file
  and a function but no span can have the span looked up in the declaration
  index, which converts the whole prose-located category from lost to usable —
  and that category is precisely the one whose loss produces the era bias.
  Derivation obeys the same ambiguity discipline as verification: derive only
  when the named function is declared exactly once inside the named type, and
  skip otherwise. Every derived locator is marked as such (§6.6), because
  verification cannot cross-check it.
- **normalize** — resolve locations, deriving a span where the report named only
  a function, and pin commit SHAs and digests. Class mapping is *not* here: it
  belongs to the adapter, because the taxonomy being mapped from is the
  platform's, and because a candidate that fails extraction must already carry
  its class or the skip cannot be counted under one.
- **verify** — check every record against reality: the commit resolves, the
  digest matches, the span lies inside the file, and the named function and
  contract are declared where the record says — the function *within the span*,
  and inside the named contract rather than merely somewhere in the file.
  **Verification failure rejects the record.**

A function name is not a function. Solidity permits overloading, so a name that
resolves to several declarations inside the span is rejected as ambiguous rather
than checked against whichever one happens to be found first. A record that
cannot say which overload it means is not function-granular ground truth, which
is the only granularity this benchmark accepts.

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

### 6.5 Splits

Every record declares which corpus it belongs to, and the field is required from
the first record rather than added once annotation is under way. Retrofitting a
split leaks: whatever criterion divides an existing set is itself a signal about
that set, and applying it after the fact leaves the division visible in the
annotation history even when it is absent from the data.

| Split | Distributed? | Why it is its own value |
| --- | --- | --- |
| `public` | yes | Published with the corpus; nothing scored against it is secret |
| `private_holdout` | no | Ordinary annotation, withheld by decision |
| `synthetic_variant` | never | A derivative work of the contract it came from |

Three values rather than two, because the third obeys distribution rules matching
neither of the others. A held-out record could be published tomorrow by changing
one field. A variant could not: structure-preserving mutation of a contract
produces a derivative of that contract, and a derivative carries the original's
licence however thoroughly its identifiers were changed. Executing one
server-side distributes nothing; publishing the variant set would relicense
somebody else's code. A single `private` value would leave nothing in the schema
able to tell those two situations apart.

A variant carries two further obligations, both enforced at construction. It must
name the record it was mutated from, or neither its licence nor its ground truth
has a source. And it must record how the defect was confirmed to have survived
mutation, because a structure-preserving edit can repair the bug by accident. An
unconfirmed variant is a negative labelled positive, which is the worst record a
corpus can hold: every detector that correctly stays silent on it is scored as
having missed something.

Mutation moves code, so a variant's locator is recomputed against the mutated
source rather than carried forward. The declaration index of §6.3 is what makes
that mechanical rather than manual.

One thing to plan for rather than discover, whenever the pipeline is taken up.
Confirming that a mutation preserved a defect by comparing which predicates fire
cannot confirm a defect the predicates never saw — §1.3 again — so those cases
fall to human review, which is the expensive and lossy path. Classes needing
more review therefore yield fewer confirmed variants per unit of effort, and a
variant set sized by counting available mutations rather than by budgeting
review time will skew toward the classes the predicates can already see. Those
are the `S` and `M` classes, so a hidden test set built that way would
under-represent exactly the `Q` classes the project exists to measure.

A variant also cannot be stored the way every other record is. A pin identifies
bytes in a repository and a variant's bytes exist in no repository, so a variant
needs a **recipe** — source record, ordered operators, seed, tool version — which
regenerates it deterministically from an original that is itself pinned.
Reproducibility survives that indirection, and the licence problem dissolves with
it: a recipe is entirely this project's own work, whereas the mutated bytes are a
derivative of somebody else's contract. Until the recipe exists, `verify` rejects
a variant outright rather than checking it against the source it was mutated
from — which would pass, against bytes that do not contain the mutation, and
write that source's digest onto the record as proof of reproducibility.

### 6.6 What the corpus is a sample of

Verification rejects what it cannot confirm (§6.3), and that is what makes the
corpus worth having. It also has a consequence that no amount of care removes:
the corpus is not a sample of real defects, it is a sample of defects sitting
where the declaration index can parse and name them unambiguously.
Assembly-heavy contracts, generated code and heavily overloaded interfaces are
thinner in it than they are in the world.

This is §1.3's third instance, and the one where the answer is not a fix.
Admitting what cannot be verified would give up the property the corpus exists
to have. So the bias is measured instead: `verify_all` returns a
`VerificationReport` carrying the rejection count per `CheckFailure` and per
class, alongside the admitted counts that give those numbers a denominator.

The tallies are part of the result rather than something a caller may compute,
because what they exist to prevent is their own absence. `sampling_statement()`
produces the sentence a report has to carry beside any number computed from the
corpus, and it is the same sentence everywhere so that omitting it is a visible
choice rather than an oversight.

> Recall 0.62 and *recall 0.62 over a corpus that rejected 11% of candidates as
> unverifiable, concentrated in these classes* are different claims, and only
> the second one is true.

Every record also states which **population** it came from (§4.3), because the
two bodies of work available skew in close to opposite directions and a figure
computed across a mixture describes neither. Pre-deployment review output is
dominated by protocol-specific logic, because that is what reviewers find in code
nobody has attacked. Exploited incidents are dominated by patterns that were
reachable *and* worth the trouble, which over-represents profitable manipulation
and under-represents everything caught before deployment, everything
unprofitable, and everything in code that never held enough value to attack.

Neither is unbiased, and they are not substitutable — which is the point. The
classes one is thin in are the classes the other is thick in, so a class carried
entirely by one population is legible as such rather than averaged. And a
detector scoring differently across populations on the same class is a finding
about the detector rather than noise: it says whether it recognises exploited
patterns or reviewed ones.

Records per class matter more than records in total, and a shortfall there is
not reported by averaging. A hundred records spread unevenly across nine classes
may leave a class with two — and a class with two supports no claim at all while
still appearing in every aggregate. Reports therefore state the record count
beside each per-class figure and name the classes below a stated minimum rather
than folding them in. This is more urgent here than for a deliberately sampled
corpus, because the shortfall arrives by collection rate rather than by choice.

The per-class rate matters more than the overall one, because that is where a
bias shows up: an aggregate can look tolerable while a single class is
decimated, and that class is then quietly under-represented in everything scored
against the corpus afterwards.

The report also splits admitted records by `LocatorProvenance`, for a different
reason: not everything admitted was admitted on equal evidence. There are four
kinds, and what confirms each differs:

| Provenance | Where the span came from | Confirmed by |
| --- | --- | --- |
| `quoted` | matching the report's own excerpt in the pinned file | the repository's bytes containing the report's text, uniquely |
| `stated` | line numbers the report gave | the declaration index, asked whether the named function is declared inside them |
| `anchored` | the declaration containing a line the report gave | nothing independent — see below |
| `derived` | the declaration matching a function the report named in prose | nothing independent |

Whether a location was independently confirmed is **not a property of the
provenance**, and treating it as one was a mistake worth recording. It is a
property of *who answered*, which depends on how many claims the report made.

A `quoted` span is confirmed outright: the repository's bytes contain the
report's text, uniquely, and the bytes are not the report. Otherwise
confirmation needs the report to have made **two** claims about the location,
which the declaration index can then adjudicate — a span and a function name, a
line and a contract, a contract and a function. One claim is never enough,
however strong it looks: a report giving a span and nothing else has its function
name filled in from the index, and `verify` then asks the index whether that
function lies in the span it was read out of. That answer is certain, the check
cannot fail, and it confirms nothing beyond what the digest already guarantees.

So `CorpusRecord.is_cross_checked` is computed from `asserted_labels` — which
labels the *report* supplied — rather than read off the provenance. A finished
record cannot recover that distinction otherwise: once the index has filled a
label in, nothing about the record tells it apart from one the report stated.

This was found by turning §1.3's own question on code written after §1.3 was.
Nothing protects new code from a rule in an old section except somebody pointing
the question at it again.

`quoted` and `stated` fail differently rather than better, and are recorded
rather than ranked. A stated line number goes stale when the report numbered a
different commit than the one pinned; a matched quote cannot. A matched quote can
land in the wrong place when the code is unremarkable; a stated line cannot. So a
quoted match is required to be **unique** in the file — an excerpt occurring
twice locates nothing, and taking the first would be a wrong record that no
contiguity test catches, because a wrong match can be perfectly contiguous.

`anchored` has one real check that the flag above does not cover. Where the
report names a contract *and* points at a line, neither signal came from the
index, so their disagreement is disqualifying. Where a report gives both a span
and an excerpt, the same applies: they must point at the same code or the record
is refused rather than decided by preference.

Only the labels are ever filled in from the index for a stated span, never the
span itself. A report citing a line range without naming a function is common,
and a record with no function cannot be scored at function granularity — so it
would otherwise be lost for want of a name the index can read off the span the
report already gave.

**One repair for this is rejected rather than merely unbuilt**, and it is written
down because it is a good idea that will be proposed again. A derived locator
could apparently be corroborated by asking whether predicates consistent with the
claimed class fire at the derived span: a report saying "reentrancy in
`Vault.withdraw`", a derived span, and the reentrancy predicate firing there
looks like independent confirmation, and it addresses precisely the residual
trust named above.

It is §1.3's first instance in a new costume. Corroboration as an admission
criterion caps derived-locator admission at predicate coverage, so derived
records survive for the classes the predicates can see and die for the classes
they cannot — the `Q` classes — reintroducing the era bias that derivation exists
to remove, by a different route and with a more respectable justification.

Nor does it survive being demoted from a gate to a recorded signal. The
corroboration rate would be confounded by uneven predicate coverage across
classes, so "40% of derived locators had corroborating evidence" would report
which classes they belonged to rather than whether the derivations were sound —
and would be read as a quality measure. There is nothing available to contradict
the prose, and that is the accurate statement.

### 6.7 One defect reported many times

Some platforms publish one document per *submission* rather than one per
*issue*. A competition of any size therefore ships the same defect several
times, and one observed archive had four submissions pointing at one function.

Kept as separate records, duplicates do not merely pad a count. They inflate
recall directly: a detector that finds that defect once matches every copy of
it, and the output says nothing about the corpus having counted it four times.
The inflation is proportional to how popular a defect was with reviewers, which
is to say it is largest exactly where a benchmark is least informative — the
findings everybody saw.

So `normalize` folds records describing one defect and reports the count of
folds. Two records are one defect when they share the pinned commit, the file,
the function and the class. The rule merges two genuinely distinct defects
sitting in one function under one class, and that trade is taken deliberately:
an under-counted corpus understates recall, a duplicated one overstates it, and
only the second is invisible in the output.

Which of the duplicates survives is decided by what the *reports* asserted, not
by how the spans were obtained: confirmation first (§6.6), then the number of
claims the report made, then the narrower span, then the record id so the choice
is deterministic. Deliberately not a ranking of provenances against each other —
`stated` and `quoted` fail in different directions and neither outranks the
other.

A fold is not a loss and is counted apart from losses. Nothing was lost; a
denominator was corrected.

### 6.8 A location can be right and still unscoreable

Scoring is at function granularity (§1.1), so a span covering a state variable
block, a `modifier` or a whole contract has nothing to be scored against, even
when it is exactly where the defect is. Such a draft is a counted loss under its
own cause rather than a record with an empty function field, because a record
without a function weakens every comparison made with it and does so silently.

This is distinguished in the accounting from a *single line* that landed in no
declaration. That one is about a line the report pointed at; this one is about a
span the report gave outright. The two suggest different fixes, and a loss filed
under the wrong cause points investigation away from the fix.

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

Not every record can support every strength, and a tier that cannot
discriminate must say so rather than return a hit. Which strengths are available
depends on where the ground-truth span came from (§6.6):

| Locator provenance | `exact` scored against | `function`, `file` |
| --- | --- | --- |
| `stated` | the span the report gave | yes |
| `anchored` | the anchor line, not the enclosing span | yes |
| `derived` | **unavailable** — the span is the whole function | yes |

An anchored record is scored against its anchor rather than its span, because
the anchor is the finer of the two and is the part the report actually asserted;
the span around it exists so that a prediction naming the right function still
matches at `function` strength.

"Same function" compares declared signatures, not names. `swap(uint256)` and
`swap(uint256,address)` share a name and are two different functions, so
matching on the name alone would score a detector that pointed at the wrong
overload as having found the right one — §1.1's failure again, one scale down.
`Declaration.signature` supplies the comparison; it is the declared form rather
than the ABI-canonical one, which is sufficient here because the compiler
rejects a contract declaring one signature twice.

Reports are stratified by difficulty level, by evidence tier, and by the
locator provenance of the ground truth they scored against (§6.6), and state
counts of `invalid` and `skipped` alongside — never folded in. The third axis is
there so a derived-locator subset can be reported separately or excluded: it is
weaker ground truth, and a score computed over a mixture of the two is a claim
about neither.

### 7.1 Two scores, reported side by side

Location-scored results are reported alongside a classification-only score,
which matches a prediction to ground truth on labels alone — class, subclass,
severity, description similarity — per repository, with no file, function or line
involved.

Running both is not a concession to compatibility. The gap between them is the
measurement. A submission scoring well on labels and poorly on locations is
recognising which kinds of defect a protocol of that shape usually carries, which
is a real skill and not the one being claimed; the same submission scoring well
on both has found something. A single figure averages those two states into a
number that cannot distinguish them — the failure of §1.1, reappearing one level
up.

So the two columns are reported side by side, always, and never averaged into a
composite. Where a ranking needs one number, completion rate *multiplies* rather
than folds in: `invalid` runs stay out of the confusion matrix and cost the
submission separately, so a detector crashing on a third of the corpus ranks
below one that does not, without any error ever being counted as a judgement.

Two details recorded now because they are cheap to write down and expensive to
rediscover:

- Assigning predictions to ground truth **greedily** and assigning them
  **optimally** produce different numbers, and greedy is not an approximation of
  optimal — it is a different rule. Whichever a scorer uses has to be stated
  where it is used. Two scorers silently disagreeing about assignment is a
  discrepancy with no visible cause.
- A detector is not deterministic, so a submission does not have *a* score. A
  scorer reports mean and spread over repeated runs; a single figure asserts a
  precision the measurement does not have, and adding the repetition afterwards
  is a schema change rather than a reporting change.

The label taxonomy is supplied as data (`LabelSpaceSpec`), never built in. A
scorer that hardcodes one label set can score one exercise; one that takes a
taxonomy as input can score any.

### 7.2 Nothing a detector emits is free

> **Output that costs nothing to produce must not be free to produce.**

Stated once because it has decided three separate questions, and each time the
alternative looked locally reasonable.

A run with one verified finding is `vulnerable` even if nine other claims failed
their citation check. That is right at the outcome layer — the run did measure
something — and carried into scoring unchanged it would make spraying claims
free, so the cheapest strategy available would be to emit many and let the
harness sort them. Citation-failed findings are therefore retained in the record,
which is why `VerifiedFinding` keeps them rather than dropping them, and they
count against precision.

A classification claim whose tag falls outside the supplied label space is
retained for the same reason (§7.1), not dropped. Dropping it would refund the
false-positive penalty it earned, making an unusable claim cost nothing.

And a submission's `invalid` runs cost it separately rather than being ignored,
which is why completion rate multiplies a leaderboard score instead of being
folded into the matrix (§7.1). A detector that crashes on a third of the corpus
must not rank alongside one that does not.

The common shape: wherever the harness tidies away output a detector should not
have produced, it also removes the incentive not to produce it.

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
| `evidence/syntax.py` | shape queries: calls, arguments, writes, visibility | **built** |
| `cli.py` | `verify`, `declarations` | **built** |
| `detectors/base.py` | the public detector interface (§2.4) | **built** |
| `detectors/loading.py` | manifest loading, the untrusted boundary (§2.4) | **built** |
| `evidence/predicates.py` | the shape-level predicate library (§2.3) | **partly built** |
| `evidence/` semantic backend | compiled IR, def-use, call graph (§3) | not started |
| `detectors/` per class | the nine `evidence()` / `plan()` / `verdict()` triples (§2) | **partly built** |
| `detectors/runner.py` | composing one detector and one unit into a `DetectorRun` | **built** |
| `corpus/harvest.py` | adapter protocol, extraction, yield accounting (§6.3) | **built** |
| `corpus/adapters/` | shared markdown and label readers; three platforms | **partly built** |
| `corpus/normalize.py` | location resolution, span derivation, digest pinning (§6.3) | **built** |
| `report/scoring.py` | location match strengths and stratification (§7) | **built** |
| `report/` dual track | the classification-only score beside it (§7.1) | not started |
| `corpus/mutate.py` | synthetic variants and their confirmation (§6.5) | not started |

Three of the nine detectors exist — `unchecked_external_call`,
`insecure_randomness` and `access_control`, the classes §4.2 marks as reachable
at the syntactic tier. They also serve as the worked examples a submission author
reads. The remaining six need the semantic backend, so `detectors/` is *partly*
built and will stay that way until it exists.

`detectors/runner.py` is the deterministic half of a run: gate, evidence, plan,
citation re-verification, verdict, and the outcome derivation. The model's
findings are passed in rather than fetched, which is the same injection
`corpus.verify` uses for source resolution and for the same reason — the whole
path stays exercisable with no model, no network and no toolchain. For a
detector whose `plan()` returns `None` it is not half a run but the entire one.

`corpus/harvest.py` is *partly* built in a specific sense: the adapter
protocol, the extraction loop and the whole yield accounting exist and are
covered, and no adapter for a real platform does. What is built is the part that
decides whether the losses are measurable; what is missing is the part that has
to be written once per platform.

`report/scoring.py` scores located findings and refuses three things that would
each produce a figure indistinguishable from one without the problem: it will not
claim a strength it cannot establish, will not compare function *names* as a
fallback when no source is available to compare signatures with, and will not
fold `invalid` or `skipped` runs into a matrix. Assignment is maximum matching
per strength tier rather than greedy, which §7.1 requires be stated where it is
used. The classification-only score of §7.1 is not built, so there is one track
rather than two.

`corpus/normalize.py` is built, and it pins the digest itself rather than leaving
that to `verify`. For a derived span the digest is the only check that survives —
the span check is tautological (§1.3) — and it only survives if the digest
witnesses the bytes the derivation ran against. Left blank for `verify` to fill
in later, verification would compare the file to itself, and the guarantee §6.6
claims for derived locators would be empty.

So the three stages compose into a corpus, and `tests/offline/` runs the whole
way from a report to an admitted record with no network and no toolchain. What is
still absent is any adapter for a real platform, which is why there is no corpus
and nothing here can measure a model yet.

The predicate library is marked *partly* built rather than built, and the gap
is worth naming precisely. Six predicates cover five of the nine classes;
`oracle_integrity`, `flashloan_manipulation`, `denial_of_service` and
`arithmetic_rounding` have none. Two of the five are covered by a predicate that
establishes a **weaker property than the class**: reentrancy needs control flow,
and slippage needs to recognise a callee through aliasing, so
`state_write_after_raw_external_call` establishes only an ordering and
`call_argument_is_zero_literal` reports every literal zero and leaves the
scoping to a verdict. `predicates.coverage_by_class()` reports the count per
class including the zeroes, because "this class has a predicate" and "this class
is covered" are different claims and a table that hid the zeroes would imply the
second.

Recognising a callee across aliasing needs a 4-byte selector rather than a name,
and computing one needs ABI canonicalisation that `Declaration.signature`
deliberately does not do (§6.3). That canonicalisation is therefore a
prerequisite for the oracle and slippage classes, not a later tidy-up.

A third has the same shape, and it is the most expensive of the three because
it costs recall rather than test items. Several predicates key on a call's member
name because a parser has no receiver type to consult, which leaves them unable
to separate `address.transfer`, which reverts, from `IERC20.transfer`, which
returns a discardable bool — so the very common unchecked-token-return defect is
invisible — and unable to reject a local helper named `send`, which makes
evidence appear where nothing is wrong. Both directions need types. Until they
are available the predicate library's precision and its recall are both bounded
by what a name can mean, and `predicates` documents each case with a test
pinning it.

A second dependency has the same shape and is worth stating beside it. An edit
that moves an external call across a function boundary — extracting it into an
internal helper, or inlining a helper that held the state write — leaves a
reentrancy defect perfectly intact while changing whether
`state_write_after_raw_external_call` fires at all. That is a presence change,
not a payload change, so no spelling of the compared payload repairs it: a
syntactic predicate cannot follow a call across a boundary, and following one is
exactly what §3's semantic tier provides. Any comparison that tries to confirm a
defect survived such an edit is therefore blocked on the semantic backend, in the
same way the oracle and slippage classes are blocked on canonicalisation. Stated
here because the alternative is discovering it as a run that rejects sound inputs
for no visible reason.

Consequences worth stating plainly: §2.2's gate is code, but its verdict
predicates remain a rule for writing them rather than a library; §3's tier
degradation is represented in the type system but has no backend to degrade
between, so every result today is `syntactic`; no detector exists yet to exercise
§2.4's interface end to end; and §6.4, the mutation stage of §6.5 and all of §7
are design only. The only production path into `verify` today is the CLI resolving against a
local checkout, which confirms that a record is coherent against the bytes on
disk but not that those bytes belong to the pinned commit.

```
tests/
├── unit/              data contract, record invariants, declaration indexing
├── offline/           whole pipeline, no model, no network, no toolchain
└── incidents/         pinned cases that must alert regardless of verdict   (planned)
```

`tests/incidents/` deserves a note: these are reconstructed real cases wired so
that a detector must alert on them *even when the model returns a benign
verdict*. They guard the property that evidence is independent of the verdict,
which is the one property no amount of prompt tuning can restore once lost.

## 9. Non-goals

- **Severity on a located finding.** `Finding` carries no severity and will not
  gain one: a model asked how bad a defect is states a value judgement as an
  observation, and nothing can check it. Reproducing a severity a named auditor
  recorded is a different claim — it has a ground truth to be wrong about — and
  so it lives on `ClassificationClaim` (§7.1), scored against
  `Provenance.reported_severity` and never mixed into located results.
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
