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

Every rule in this section is an **instruction to go and look**, not a
conclusion to cite. That distinction is the section's own failure mode, and it
has cost real decisions here: §2.3's base-rate rule was followed as far as
stating it and a predicate was nearly shipped on the strength of one catch,
where measuring it showed 17 of 19 firings were on correct code. The rule said
to measure. The measurement gave the answer. A rule cited instead of run reads
as diligence and produces nothing.

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

**This schema's limits present as missing capabilities**, and that has happened
three times now, each discovered only when something tried to use the schema for
a thing it had never been asked to express:

- An exploited contract with no repository read as "the incident population is
  not pinnable" (§6.6). `SourcePin` could not express an address.
- A mutated variant read as "the variant cannot be verified". The bytes existed
  somewhere the pin could not describe.
- Ten records in twelve failing to compile reads as "the toolchain needs
  managing" (§4.2). `SourcePin` pins one file and not a dependency set, so the
  submodule versions are not recorded and no toolchain management recovers them.

The shape is always the same: a capability appears absent because the thing that
would have named its inputs cannot name them, and the missing expressiveness is
invisible from the outside because a schema that cannot say something also
cannot say that it cannot. So the question to ask of any apparent capability gap
is **whether the schema can express the thing the capability would need** —
before the capability is priced, because the answer changes what is being
priced. Two of the three above changed a plan; the third changed it back.

A third rule belongs here rather than in any one subsystem's section, because it
now governs three of them and the next person to record a cause somewhere new
will not think to look under harvest:

> **A cause recorded wrongly points investigation away from the fix.**

It is not about counts being complete. Every instance below had complete,
honest counts and named the wrong reason, which is worse than an aggregate:
an aggregate admits it knows nothing, while a wrong cause asserts something
false and is acted on.

- **A harvest loss.** A branch reference filed as a malformed report; a missing
  line filed as a missing location; a metadata block that could not be read
  filed as the platform declaring the report out of scope; an explorer address
  filed as no location stated (§6.3).
- **A verification failure.** A variant checked against unmutated source
  reported as a location mismatch rather than as a regeneration failure, which
  sent the investigation to the locator.
- **A detector's account of its own limits.** The first register entry written
  here attributed a predicate's silence to one shape when two conditions were
  independently sufficient (§7.3). Same rule, arriving from the instrument's
  side rather than the input's.

The corollary is the dangerous part: **the accounting being complete is what
makes a wrong cause invisible.** Every instance above had honest, complete
counts. Completeness is normally the check that catches errors, so a wrong cause
hiding behind a right count passes the review that would have caught anything
else.

The companion check is cheap and is the one that caught all three: **for each
cause, one input that produced it.** A cause with no example behind it is a
guess about why, and a guess about why is indistinguishable from knowledge when
the number beside it is correct.

**Absence as evidence needs a control; absence as a prompt does not.** The
distinction matters because "pair every absence with a presence" would be
over-applied, and the boundary is the useful part. §7.3's register uses an
absence as *evidence* of a property — this predicate cannot see this shape — and
without a paired sighting the silence is equally consistent with a predicate
that never fires at all, so a control fixture is mandatory. §6.3's zero rule
uses an absence as a *prompt* to investigate, and needs no control: a wholly
broken reader reports everything as not-stated, the samples are opened, and the
conclusion "the reader is broken" is correct. The rule resolves rightly even in
the degenerate case, which is what makes it a procedure rather than a claim.

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

### 3.1 A predicate has three answers, not two

The separation this system is founded on — `invalid` apart from `clean`, an
error never wearing a measurement's clothes — was missing one layer down, inside
the evidence that feeds it. A predicate could fire or stay silent, and silence
carried both "the property is absent here" and "I had no basis to decide". Only
the first is a fact about the code.

So a predicate evaluation is three-valued: **established**, **not fired**, or
**indeterminate with a reason**. It was not a hypothetical. The access-control
predicate looked for state writes and skipped a function that had none, so a
function changing state through `token.mint(to, n)` produced nothing — and
"nothing" was read downstream as "no state change here". An incident record in
the corpus is exactly that shape.

**Indeterminacy belongs to a site, not to a tier.** A tier says what the backend
could do for a compilation *unit*; indeterminacy is a property of one
*evaluation* — this call's effect is unknowable because the callee's
implementation is not in the bytes we hold. Putting a per-site fact in a per-unit
field would be the same misplacement this document keeps catching elsewhere.

Three rules govern how it propagates, and the third is where the defect would
return:

1. **An indeterminate site does not make a run `invalid`.** The model can still
   reason about the code; only the deterministic layer failed to corroborate,
   and a run whose evidence was inconclusive still measured something.
2. **It qualifies the run's negative.** A `clean` outcome with an undecided site
   is not the claim "nothing is here". `DetectorRun.negative_is_established`
   says which, and the score report counts qualified negatives beside `invalid`
   and `skipped`, entering no matrix.
3. **`verdict()` must not treat indeterminate as absent.** This is the natural
   thing to write when a three-valued input meets a two-valued condition, and it
   was already written here: the access-control verdict rejected a finding with
   "the enclosing function writes no contract state, so there is nothing for an
   access check to protect" — false for a function that mints through a call,
   and used to discard a true finding. The claim is still not admitted, because
   §2.2 keeps the verdict side strict and an undecided basis is not a
   confirmation; what changed is that the cause is accurate and counted apart.
   Which is §1.3's cause rule, reaching a verdict predicate.

**The semantic tier does not close indeterminacy, and that is not a gap in the
tier.** Full def-use, control flow and a call graph over the pinned unit still
cannot read code the unit does not contain, and an interface declaration's
implementation is not there. What does close it, for an address-pinned record
(§6.1), is that the callee is a deployed contract at a known address and block,
so its verified source is fetchable — a recursive resolution this design records
and deliberately does not build. The asymmetry is worth knowing: indeterminacy
is closeable for an address pin in a way it is not for a commit pin, where a
third-party interface has no implementation anywhere we hold.

**When to build it is a measured trigger, not a plan.** `ClassScore` counts
*qualified negatives* — clean runs that rested on a site the deterministic layer
could not decide. If that count stays small as the incident population grows,
recursive resolution was never the investment; if it climbs, the count says when
and roughly by how much. A trigger tied to an observation rather than a date
gets settled by data instead of by whoever is arguing at the time. At the last
measurement it was 5 of 54 runs, all in one class and one unit.

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

This table was **audited**, and the audit is in `tests/unit/test_tier_audit.py`
rather than in this paragraph. Its first version was written by reasoning when
the classes were defined — no code existed, nothing was tested, and each "no"
asserted that something could not be done without a compiled backend. Six of
those were never checked. Of the six: two already had working syntactic
predicates in the tree, three collapse wholly or partly, and one turns out not
to be a tier gap at all.

The outcome column is three-valued now, because two of the old "no"s meant
different things. **Never** means the missing fact is another contract's bytes,
so no analysis over this unit reaches it — an indeterminacy (§3.1), and a tier
built for it produces nothing.

| Class | What decides it | Syntactic? | Was |
| --- | --- | --- | --- |
| `unchecked_external_call` | a call result bound or discarded | yes | mostly |
| `insecure_randomness` | a producer-controlled value read | yes | mostly |
| `access_control` | modifiers, visibility, depth-one caller-taint | yes, except aliases | partly |
| `slippage` | a call argument that is a zero literal | yes | no |
| `oracle_integrity` | a destructured timestamp never named in a guard | yes | no |
| `denial_of_service` | declared array type, loop bound, appender visibility | yes | no |
| `arithmetic_rounding` | division before multiplication; declared widths | yes | no |
| `arithmetic_rounding` | a token's `decimals()` | **never** | no |
| `reentrancy` | a state write after a raw call, one function | yes | no |
| `reentrancy` | the same across functions in one unit | **needs a tier** | no |
| `reentrancy` | the same across a contract boundary | **never** | no |
| `flashloan_manipulation` | whether a callee is a market the caller can move | **never** | no |

**What the audit leaves for the semantic tier is one row**: reentrancy across
functions within a unit. Everything else either collapses to the parser or is
not reachable at any tier over one unit. That is a much smaller justification
than "six of nine classes need the compiled backend", which is what the
unaudited column said and what the build order had been following.

**That last row was then checked too, and it collapsed as well.** Running the
newly-collapsed predicates found that the same capability appeared to block
`denial_of_service` in two of its five records, and the claim "these need a call
graph from the semantic tier" was written from reading the records rather than
from a fixture — which is this table's own error, one layer down.

A call graph's job is resolving which function a call names. **Within one file,
with no inheritance and no overload, that is name lookup**, and name lookup is
syntactic. What needs compilation is resolution through an inheritance chain,
through a library, or between overloads. Measured on the two records: every name
in each chain is declared exactly once in its file, the internal appender is
called unqualified from two `external` functions, and the loop bound
`n = collection.length` is a single assignment in one body. Both were built
syntactically, and the first record went from a miss to an exact match.

The soundness condition is checkable and is enforced: a name declared more than
once is an overload or an override, and the predicate refuses rather than
picking — the rule the declaration index already applies to an overloaded name.
An alias assigned twice is refused for the same reason, since which assignment
reached the loop is control-flow dependent.

**And the tier's reach was measured, which had never been done.** Compilability
was parked at the start and stayed parked, and it cannot be measured with a
compiler that is not installed. Import resolution is not circular: a parse and a
set membership test, and it bounds the reach from above, because a record whose
imports do not resolve within the available bytes will not compile however well
the toolchain is managed.

Across the corpus, **two records in twelve** have every direct import resolvable
in their pinned bytes. The rest reference git submodules and package
dependencies — `lib/forge-std/`, `openzeppelin-contracts/`,
`@chainlink/contracts-ccip/` — which live outside the pinned tree at versions
the pin does not state. One of the two that resolve is the address-pinned
record, whose verified-source manifest is self-contained by construction.

Which surfaces a third structural thing: **`SourcePin` pins one file and not a
dependency set**, so compilability is not merely unmeasured, it is unpinnable as
the schema stands. Raising the tier's reach is therefore a pinning problem
before it is a compilation problem, and no amount of toolchain management
touches it.

So the semantic tier stays unbuilt **on measurement rather than on cost**, which
is the more durable answer: nothing in the corpus currently needs it that has
been checked, and it could serve two records if it existed.

The general form, and it is §1.3's rule pointed at this document rather than at
a parser: **a capability column written from reasoning is a claim about whoever
reasoned.** It had been steering the build for weeks, and half a day of fixtures
moved five rows.

The table was wrong three ways, and the third is the structural one:

1. **Wrong values**, in five of six unaudited rows.
2. **Wrong three-valuedness** — "the tier closes it" and "nothing closes it"
   merged under one "no", so a tier built for the second would produce nothing.
3. **Wrong granularity.** One row per class asks "what does this class need" as
   though the class had one answer. `denial_of_service`'s five records contain
   four mechanisms.

The third is why the first two were easy to make. A table with one row per class
cannot express a class whose answer is plural, so whoever fills it in is forced
to pick the most salient mechanism and write it as though it were the only one —
and then the row reads as complete. The rows above are split where the audit
found a split, and the register (§7.4) is where the rest of a class's mechanisms
live, because each entry there carries the record that demonstrates it.

The `access_control` row says "partly" and **caller-taint turned out not to
need the semantic tier at all**, which is worth recording because the
prediction that it did was written into this document and into a register entry
before anybody tested it.

A value an outside caller supplied enters a function under a parameter name. So
an expression mentioning that name is an expression reading something the caller
chose, and the parser knows the parameter names and the identifiers in a
condition already. Depth-one taint is syntactic. What is *not* syntactic is
following an alias -- `address x = from;` and then a guard on `x` -- which needs
def-use and is a genuine tier dependency, and is a much narrower claim than the
one that was made.

Getting there required narrowing the property twice, and the narrowing was
driven by measurement rather than by argument. "A guard mentioning `msg.sender`
and a parameter" fires 19 times over the corpus; 17 of those are **sound**
guards of the form `isApprovedOrOwner(msg.sender, id)`, where the caller passes
an identifier and the contract resolves it against its own state. The
caller-supplied value there is the *subject* of the check. The defect is when it
is the *source of the answer* -- `IVisor(from).owner() == msg.sender` asks a
caller-chosen contract to adjudicate a check on itself -- and that distinction
is the receiver position of a call inside the condition, which fires 4 times.

**Fix the instrument before adjudicating the pool.** Applied to three classes,
it took an adjudication backlog of 137 predictions down to 2, and each narrowing
was a stated property rather than a threshold:

| class | pool before | after | the property |
| --- | --- | --- | --- |
| `arithmetic_rounding` | 28 | 4 | the multiplier differs from the divisor |
| `slippage` | 25 | 4 | the call has a receiver, so it crosses a contract boundary |
| `insecure_randomness` | 88 | 0 | the read reaches a hash, a modulo or a subscript's index |

The third is the one that changes a conclusion recorded here earlier. This
document said that whether a producer-chosen value is *used* as randomness
rather than as a deadline needs data flow, so it was not checked — and that was
right about the general case and wrong about the shallow one, which is the third
time that distinction has been missed. A value reaches a selection three ways
without leaving its expression: a hash, a modulo, or a subscript's index. One
that reaches none of them is read as a quantity. Of 88 firings, none reached
any.

Getting there took two wrong versions, both of which fired correctly and refused
incorrectly — the failure mode a control fixture exists to catch:

- **Lines cannot express containment.** Two nodes on one line contain each other
  by line number, so "the selection contains the read" meant "they share a
  line", and `lastEarn[id] = block.timestamp;` read as a timestamp used as an
  index. `Site` now carries byte offsets.
- **A subscript's extent is not its index.** The grammar gives
  `block.timestamp > locked[id]` a subscript whose *base* is
  `block.timestamp > locked`, so the node contained a read nowhere near the
  index. The index child is what the property is about anyway.

**Fix the instrument before adjudicating the pool**, which the arithmetic class
demonstrated at a cost of one afternoon avoided. Its pool was 28 predictions, and
24 were a single idiom: `(a / b) * b`, rounding down to a multiple of `b`, where
the truncation is the point rather than a discarded quotient. Narrowing the
predicate on that stated property — the multiplier differs from the divisor, or
it does not — left four, one of which already matched a record. Adjudicating 28
by hand would have produced 24 notes saying the same thing and left the predicate
reporting the idiom forever.

Which answers a question left open earlier. A predicate firing 28 times for 2
records was read as either unfixable noise or an artefact of the corpus's
standing to judge; it was neither. It was one recognisable shape accounting for
86% of the firings, removable on a property. The lesson is the ordering: group
the pool by shape and look for an idiom *before* paying to adjudicate it.

Narrowing it also broke a real match and the break is worth recording, because
the first version of the narrowing looked correct. Defining the multiplier as
"the operand with no arithmetic of its own" missed `(a / b) * (c + d)`, so a
corpus record went from an exact match to a miss. The right condition is the
operand with no *division* of its own, and what surfaced the mistake was recall
falling rather than any test — which is the argument for scoring against real
records after every predicate change, not only after new ones.

The property remains **real and insufficient**, and the predicate's name is
careful not to claim otherwise. One corpus source guards with
`require(IAlchemechNFT(_nft).ownerOf(id) == msg.sender)` inside
`if (_nft == alchemechNFT)`: caller-supplied, and pinned by a preceding
comparison, so sound. Settling that belongs to the verdict layer (§2.1), and the
prediction it produces costs precision, which is the correct price (§7.2) rather
than something to suppress.

The original observation arrived from the incident population rather than from
review findings. The
syntactic predicate's proxy for "is the caller checked?" is "is `msg.sender`
referenced?". One record is a function whose authorisation check reads `owner()`
from a **caller-supplied address** and compares the result to `msg.sender`: the
reference is present, the check is worthless, and the predicate is silent. The
blindness is systematic — every defective guard that mentions `msg.sender` is
invisible — and closing it means deciding whether the other side of the
comparison is caller-controlled, which is def-use through an external call.

What this establishes, and what it does not, are worth separating because the
second is tempting.

It establishes a **demonstrated blindness**, and that is certain at one record
because it is a proof rather than a statistic. One counterexample settles "this
predicate cannot see this shape" permanently, and adding records cannot unsettle
it.

It does **not** bear on §6.6's complementarity prediction, though it arrived
from the population that prediction is about. §6.6 predicts complementarity *by
class* — that the classes one population is thin in are the ones the other is
thick in. This is a new defect *shape* inside `access_control`, which both
populations already cover. That exploited defects differ in shape from reviewed
ones within a shared class is a different claim, quite possibly true, and one
§6.6 does not make. Separately, novelty is cheap in a corpus this thin: eleven
records across five classes have seen almost nothing, so any twelfth record has
a high prior of showing something unseen whatever population it came from. The
observation would carry weight only once enough had been seen that novelty were
surprising.

Recorded this way because the failure mode is specific and was nearly walked
into here: an observation feels like confirmation because it arrived from the
population the prediction concerns, while testing something else entirely.

**A class is not a mechanism, and `denial_of_service` is the case that shows
it.** One predicate was built for it, naming one mechanism: a loop bounded by a
collection an outsider can grow. Run against the five records the corpus holds,
it found none of them, and reading each one gave four *different* mechanisms:

| record's mechanism | what it needs |
| --- | --- |
| the appender is one internal call away | a call graph over the unit |
| the bound is a local alias for a length | def-use in a function |
| a loop capped by a literal cannot cover work that grows with time — too *few* iterations | a predicate for the opposite property |
| no iteration at all: a dependency a caller can make revert | a predicate for that mechanism |

The fifth record's mechanism could not be read from its span, so it is left
unaccounted rather than filed under a guess.

This is not a complaint about the class list. It is what §4.2's single row per
class conceals: a capability column answers "what does this class need" as
though the class had one answer, and a five-record sample of one class produced
four. The register (§7.3) holds these as four entries because each has a record
behind it, which is the form in which the finding is checkable rather than
asserted.

It also says what the increment that found them was for. Five records is below
the stated minimum of ten, so no score over them supports a claim — and a reader
seeing "5 records, no valid score" would conclude the work did not pay. What it
bought is four demonstrated facts about the instrument, each certain at the one
record that demonstrates it, in a class where nothing was known before. Records
alone would not have produced them: **harvesting produces records, and only
running detectors produces limits.**

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

A hand-assessment of 141 unmapped titles from 17 reports says how much of that
71-of-87 is the taxonomy and how much was the reader. Roughly 17 of 40 sampled
were **inside** the nine and phrased in words the table did not hold: reports
say "always reverts", "unable to", "inability to", "irrecoverable", "stuck",
"bricked", "prevents" where the table held only the category's own name, which
almost nothing writes. Adding those took mapping from 19% to 34% of accepted
findings on this sample, and every added term was kept only if every title it
newly mapped was right on inspection — "incorrect calculation" mapped two and
both were wrong, because a mistaken formula is not a rounding defect.

The other ~20 of 40 are genuinely outside the nine, and they are one thing
wearing several hats: an accounting identity that no longer holds. Holdings that
stop tracking one-to-one, a plot occupied by two renters, more entities in a
generation than the cap, a fee computed from the wrong side. Judging any of them
needs the protocol's specification, which is exactly what a pattern benchmark
does not have and why they stay out. The remainder are a race between two
transactions, an assumption about ERC-20 behaviour, an incentive, a mismatch
with the documentation.

The audit also caught the table doing to itself what §6.3 caught it doing with
identifiers. **A word that names a mechanism is not a word that names a
defect.** "flash loan" and "flashloan" alone mapped four titles and all four
were wrong — two were flash-loan *fee accounting*, one a rounding defect in a
fee, one a revert — because this class is a property, a price moved inside one
transaction with borrowed capital, and the phrase merely names the instrument
that moved it. The same shape as reading "reentrancy" off a `nonReentrant`
modifier. Removing it let the defect word win: the rounding title maps to
rounding, the reverting one to denial of service, and the two accounting titles
to nothing at all, which is the correct answer three ways.

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

**That obstacle was re-measured, and most of it was the schema rather than the
data.** Two things were being counted as one. Whether an exploited contract's
source is *reachable* is a question about the world; whether this schema can
*express* where it lives is a question about `SourcePin`, which requires a
repository URL and a full commit SHA and validates both. A contract that exists
only as verified source at an address on a chain is unpinnable here by
construction, however available it is.

Measured against a maintained third-party archive of incident
proofs-of-concept — an external denominator (§6.3), since nobody involved
maintains it for this purpose:

- The candidate pool is **849 incidents**, not the seven a hand-assembled list
  reached. Each proof-of-concept forks a chain at a fork point and attacks
  deployed addresses, so the chain, the fork point and the addresses are read
  out of the artefact rather than recalled.
- **30 of 34 sampled** state a chain and a fork point, in two forms: a block
  number, or a transaction hash — which pins a block *and* a position within it,
  so it is the stronger of the two rather than a weaker one.
- **28 of 34** have at least one contract with verified source retrievable at
  that chain, asked of a verification repository that answers with an explicit
  match status. 82%, interval roughly [66%, 92%].

An address pin is not weaker than a commit pin. Deployed bytecode is immutable,
so an address plus a chain plus a fork point is at least as reproducible as a
commit and arguably more so, since an address cannot be force-pushed. The digest
witnesses the bytes exactly as it does now. Proxies are the real complication
and they are answerable: the verification repository resolves them itself,
reporting whether an address is a proxy and naming its implementations, so the
pin can name the implementation rather than the proxy.

§9 excludes *unverified* on-chain contracts and says nothing against verified
ones, so this is inside the stated non-goals rather than an expansion of them.
What it needs is a second kind of pin, not a refusal. This is the same shape as
`VARIANT_NOT_REGENERABLE` — bytes that exist somewhere the pin cannot
describe — and there the refusal was right because nothing could describe them.
Here something can.

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
| pin coordinates: repo URL and commit, **or** chain, address and fork point | contract source |
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

**There is more than one way for bytes to have an address in the world**, and a
pin is one type with two shapes because of it. A file in a repository at a
commit is one. Verified source for a contract deployed at an address, at a point
in a chain's history, is the other — and the incident population (§6.6) is made
almost entirely of the second.

An address pin is not the weaker of the two. Deployed bytecode is immutable, so
an address plus a chain plus a fork point is at least as reproducible as a
commit and rather more so, since an address cannot be force-pushed. The digest
witnesses the bytes in both cases, which is what actually pins the source.

What the fork point pins is the **state**, not the source: which implementation
stood behind a proxy, and what the chain looked like while the defect was live.
Those are separate claims from "these are the bytes", and a record should be
able to be wrong about either. It is required unconditionally rather than only
for proxies, because proxy status cannot be known without asking a verification
repository — and a validator that needed a network call to decide whether a
field is mandatory would be the only impure validator here.

Three consequences worth stating, because each was a decision:

- **One type, not two.** A discriminated union on `kind`, exposing `path`,
  `sha256` and `source_id` to every consumer that needs only those. Two separate
  types would push the branch into every signature that carries a pin; a union
  with a common surface pushes it only into the consumers that genuinely differ,
  which are resolution and anything reporting coordinates. Resolution therefore
  takes the *pin* rather than its parts: a three-argument
  `(repo_url, commit, path)` resolver spelled one kind of pin into every
  resolver ever written against it.
- **`source_id` is opaque.** An identifier that code takes apart to recover its
  components is an identifier doing double duty as a data structure, and the
  coupling stays invisible until a second shape arrives. Components are fields;
  `source_id` is a key. It leads with the pin's kind so that a consumer which
  assumed one shape fails visibly on another rather than mis-parsing it.
- **`path` is not a filesystem path.** It means the same thing in both
  shapes — which file within the pinned unit — in different namespaces. The trap
  is not the namespaces: it is that verified source frequently arrives keyed by
  import-style names such as `@openzeppelin/contracts/token/ERC20/ERC20.sol`,
  which look exactly like repository paths and join to no checkout. Code that
  joins a key to a root because it looked like a path reads the wrong file, or
  none, and says nothing about why. So the pin answers `is_filesystem_path` and
  callers ask it.

One thing the second shape cannot do, recorded rather than worked around: a
post-fix negative (§6.2) requires a commit pin, because "after the fix" is
identified by a commit and an address pin has no commit to compare against. The
deployed analogue — the implementation behind a proxy after an upgrade — is a
different claim and needs its own kind of negative. Refusing is what keeps that
visible.

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

**Post-fix negatives are the cheapest kind to verify and the hardest to
source, and both halves are measured.** They are cheapest because nothing needs
a human judgement: the same file at the fix commit, and `verify` confirms it.
They are hardest to source because a report has to name the fix, which most do
not.

| population | findings measured | naming a fix | usable |
| --- | --- | --- | --- |
| bounty-competition archive | 1002 documents | ~2% link any commit | ~0 |
| contest platform with a mitigation phase | 87 H/M findings, 6 contests | 10% | 7 |

The bounty archive's near-zero is **genuine and structural**, which is the one
case this week where investigating a zero confirmed the absence rather than the
instrument: a competition submission is written before a fix exists, so it
cannot cite one. Most of its 2% cite other projects' source rather than a fix.

The contest platform's 10% is real but **concentrated**: one contest supplied
four of nine and two supplied none, so availability is a per-contest property
and harvesting broadly for fix commits would be the wrong shape. Harvest the
contests that have them.

And the usable figure is lower than the rate for a reason worth stating: the
platform **mirrors** the audited code into its own repository, so a positive
record pins `platform/contest` at the contest commit while the fix lives in the
protocol's upstream repository. Of the nine findings naming a commit, two named
a *dependency's* repository — citations, not fixes, which a rate computed from
links alone would have counted.

**The mirror boundary turned out not to be the problem, and checking it gave a
better construction than the one it replaced.** The mirror is byte-identical to
the upstream at the same paths — measured, not assumed. So both records can pin
the *upstream*: the positive at the fix commit's **parent**, the negative at the
fix commit. Same repository, same path, one commit apart, and §6.2's claim holds
by construction rather than by tolerance. The mirror becomes provenance — where
the report cited the code — rather than a pin.

That yields an **admission condition, checked per fix rather than claimed in
general**: the pair is admissible when the fix commit's parent holds bytes
identical to the audited state. Where it does not, some other change landed
between the audit and the fix, the pair straddles more than one change, and it
is refused. Measured over the seven candidates: three admissible, two refused on
exactly that condition, two with no comparable Solidity in the fix at all.

**And then the kind's own semantics turned out to be the real obstacle.**
`negative_for` asserts that *no instance* of the class exists anywhere in the
pinned file — a completeness claim, which is what licenses a precision figure
(§7.3). A fix commit licenses something weaker: **the reported instance is
gone.** Other instances of the same class may remain in the file, and nothing in
the fix speaks to them.

Bridging the two needs the assumption that the audit found every instance of
that class in that file. That is the corpus-completeness assumption, and
adopting it here would reintroduce one level up the exact error §7.3 exists to
correct — treating "has records for a class" as "is complete for that class".

So **a post-fix negative does not license precision**, and this route does not
reach the leaderboard figure. What it does reach is §6.4's pair-differential,
where the claim it licenses is the claim it makes: the same file one commit
apart, bytes-confirmed, with the defect present in one and absent in the other.

**The repair needs no new kind**, which is the better shape: `post_fix` already
*is* the kind that asserts a fixed instance, and what was wrong was the semantics
attributed to it. So licensing completeness is now a property of the **kind**
rather than of negatives in general —
`NegativeKind.licenses_completeness` — false for `post_fix`, true for the two
kinds a human asserts. The scorer reads that when deciding which units it may
judge, and a post-fix negative licenses nothing there.

Which leaves the two human-asserted kinds as the only ones that license
precision, `confirmed_clean` most cheaply, because a human asserts completeness
directly and records how they confirmed it.

**But a confirmation resting on a structural absence licenses precision
nowhere, and that is §1.3 rather than bad luck.** The tempting way to make
hand-confirmation cheap is to rest it on a premise anyone can re-check: this
file reads no property a block producer chooses, therefore it holds no instance
of the class that misuses one. The premise is sound and the record is honest.

It is also useless for precision, necessarily. Measured over the corpus's nine
units, the two files confirmable on that premise are **exactly** the two where
the predicate fires nothing — which is tautological, because the absence that
licenses the confirmation is the absence the predicate looks for. Precision in
those units is zero over zero.

> When the thing that validates and the thing being validated draw on the same
> source of truth, the validation cannot exceed that source.

The confirmation and the detection are reading the same structural feature, so
the confirmation cannot reach a unit the detection has an opinion about. A
negative record that licenses precision therefore has to be asserted where the
detector *does* fire, on a judgement the detector's own inputs do not settle:
for this class, that every one of the sites it flagged is a legitimate use of a
producer-chosen value rather than a use of it as if unpredictable. That is
genuine review, not a re-checkable premise, and its cost is the number of
flagged sites rather than the number of files.

Which also says what such a negative is worth, and where the cost actually
belongs.

**Judge what was predicted, not what the corpus contains.** This situation —
some true positives known, the rest unenumerable — is *incomplete relevance
judgements*, and information retrieval has treated it for decades. The standard
answer is not to complete the judgements. It is to judge the **pool**: the union
of what submissions actually claimed. Then the cost scales with what was claimed
rather than with the corpus, nothing asserts what a file does not contain, and
the locations nobody pointed at are left unjudged because judging them changes
no score. See TREC's pooled relevance judgements, and `bpref` for a metric
built to ignore unjudged items.

So the corpus gains a location-scoped negative, `NegativeKind.ADJUDICATED`:
*this location was examined and holds no instance of this class*. Its scope is
explicit on the kind (`NegativeScope`) rather than inferred from whether a
locator is present, because an implicit scope is two claims sharing one
appearance. It must carry both a location and a statement of what was found —
the judgement is the record's whole content, and "examined" is not reviewable.

**Precision is then available exactly when the pool is fully judged**, and that
condition is not a nicety. A judged set made only of matches is identically
1.0, because a match is correct by definition; one made only of adjudicated
non-instances is identically 0. Both are degenerate and both look like a
figure. So `precision()` returns nothing until every prediction has been
adjudicated — by matching a known positive, by a file-wide negative covering it,
or by an adjudication of its own location.

What this buys, against the alternative it replaces:

| | count | the claim being made |
| --- | --- | --- |
| file-wide confirmation | one per (file, class) | no instance anywhere in this file — not checkable by reading |
| adjudication | one per flagged location | this read sets a deadline and nothing treats it as unpredictable — checkable by reading five lines |

The same order of work, a far weaker claim, and the weaker claim is the one a
reviewer can actually check. Which is the shape §2.2 already uses in a different
place: the strict side is strict, and it is strict about something narrow enough
to be right about. That is the opposite of where the
cheapness argument pointed. The argument was right about verification cost —
verifying a post-fix negative needs no human judgement at all — and wrong to
treat cheap-to-verify as sufficient-for-purpose, which are different properties.

**And the post-fix pairs are not wasted for precision either: they say which
files are cheapest to hand-confirm.** A file that was audited and then fixed has
already had expert attention on that class, so asserting completeness there is
far better founded, and cheaper, than for an arbitrary file. The pairs are a
prioritisation signal for the hand-confirmation they cannot themselves replace.

The general form, and it is the fourth instance: **reasoning from what a thing
is, rather than from what this one claims.** A negative record, therefore it
licenses what negative records license. Filing one and reading the field found
it; reasoning about the kinds would not have.

**A post-fix negative requires a commit pin, and what that costs is the control
rather than the executable half.** "After the fix" is identified by a commit,
and an address pin (§6.1) has no commit to compare a fix against, so the
incident population currently supports positives and cross-class negatives and
no post-fix ones.

Stated precisely because the loose version — "the pair-differential is
unavailable for this population" — will later be read as "executable ground
truth is unavailable", and that is false. A proof of concept that reproduces the
exploit at a fork point demonstrates the defect is real, at that location,
executably, and that is §6.4's *positive* half needing no negative at all. It is
also the half that was novel, since no prose record can make that claim. What is
missing is the control: fires on vulnerable, silent on fixed.

**No fourth kind is being added, and the reason is that the shape could not be
measured.** The deployed analogue of "after the fix" is at least four
situations, not one: an upgradeable proxy whose implementation was replaced; an
immutable contract redeployed at a new address; a defect fixed in a repository
and never redeployed; and a contract never fixed because the project was
abandoned. Those carry different claims, different controls and different
availability, and carving one enum member now forces all four into one shape —
the approximation refused for variants, for branch references and twice for
pins.

The measurement that would decide it was attempted and **did not determine the
answer**, which is recorded because the attempt is what justifies the delay. Of
34 sampled incidents, the apparent result was 13 immutable and no proxies at
all. Both halves of that are instrument artefacts:

- The victim contract was identified by matching a verified contract's own name
  against the proof-of-concept's project name, and **18 of 34 could not be
  matched** — a bridge named `MainchainGatewayV2` does not resemble its
  project's name, and most victims do not.
- Proxy detection reports a *recognised* proxy standard, not a proxy. In one
  sample it identified a standard proxy correctly, and returned "not a proxy"
  for two contracts whose own names end in `Proxy` — so a bespoke proxy is
  invisible to it.

So "no proxies" is a zero that the §6.3 rule applies to, and the samples said
the instrument. The hypothesis that a proxy upgrade is the dominant shape — in
which case the control is the **same address at a later fork point**, an
ordering on a field that already exists, needing neither a new pin kind nor a
new negative kind — is therefore untested rather than refuted. Settling it needs
proxy status read from the chain (an implementation storage slot, or a
`delegatecall` in the runtime code) rather than from a verification repository,
and a victim identified from the exploit's call targets rather than from a name.

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
  curated database spanning 87 reviews and 69 protocols, and 17% over 331 from a
  bounty-competition archive read in full. The intervals all overlap around a sixth to a
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

  The quote route is **built**, and what it cost was not the matcher. Findings
  quote the vulnerable code far more often than they cite it, and locating an
  excerpt in the pinned file was already implemented; what was missing was that
  a finding citing *several* Solidity files was skipped before its excerpt was
  ever considered. Six of eleven losses over one sample were exactly that: a
  usable excerpt discarded because the **file** was not unique. So the adapter
  now hands over the whole cited set and `normalize` adjudicates — the excerpt
  states which file it came from if it occurs in exactly one of them, and only
  the stage holding the bytes can say. Two files containing it identifies
  neither, which is the same refusal as an excerpt occurring twice in one file.

  Over six held reports the yield went from 6 drafts to 8, and of the records
  admitted, two are located by excerpt rather than by citation.

  **The matcher had a defect that only verification could catch**, and it is the
  kind worth naming. Comments are stripped before matching so that a report
  quoting code without them still locates. Substituting the empty string for a
  block comment removes its newlines and shifts the number of every line after
  it — one file's banner comments shifted a match by 28 lines. The match was
  **unique**, so nothing in the matcher noticed: uniqueness is a property of the
  text, not of the position.

  `verify`'s declaration check found the named function absent from the matched
  span and rejected the record. Which is the whole reason a record is checked
  against the source after being built rather than trusted from the stage that
  built it — and the reason every existing quoted record was re-verified after
  the fix rather than assumed unaffected.

  **It also produced the worst record this corpus has held, which is worth
  recording.** A report cites a dependency to show what the reviewed code was
  derived from or ought to have done. A finding about a Rust port cited the
  Solidity original, the excerpt matched there, and the result was a record
  attributing a defect to an upstream library the report never claimed was
  defective. The reviewed repository is now read from the whole report — within
  one finding a dependency can easily be cited more often than the code under
  review, which is how the record was made — and a citation outside it is
  refused under its own cause, because the fix is to read the report's scope
  rather than to parse a path better.

  The restriction had to hold in three places and held in two, which is the
  transferable part: the stated citation, the sole cited file, and the candidate
  set. A finding whose single Solidity citation was a dependency went through as
  "the one file it cites". **A check that has to be repeated is a check that
  will be forgotten in one of its places**, so the citation set is restricted
  once and every candidate derived from the restricted set.

  A further route is **measured but not implemented**, recorded here because
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

  That archive has now been run end to end, and the run is worth recording for
  what it cost rather than for what it yielded. 1002 report documents produced
  15 drafts and 10 admitted records, against 14 commit lookups -- one per
  (repository, date) pair that a surviving draft actually needed, which is two
  orders of magnitude fewer requests than one per report. The 21 dates in the
  largest competition all resolved to the **same commit**, which is the
  submission-date assumption validating itself: had the repository moved during
  the competition, per-date resolution would have shown it, where one lookup per
  competition would have hidden it.

  The first pass over that archive reported a *quarter of it* as out of scope,
  and the quarter was a defect in the reader. The platform writes one metadata
  block in three renderings -- plain lines, a bulleted list with the keys
  emboldened, and dates as `2nd May`, `Feb 29th` or
  `Tue Aug 13 2024 04:28:52 GMT-0400`. Reading only the first, the adapter got
  an empty report-type field and filed each document under "the platform typed
  this as something else".

  Two lessons, and the second is the transferable one:

  - **A field that cannot be read must not be indistinguishable from a field
    that says no.** An unreadable metadata block now has its own skip cause,
    separate from an out-of-scope report type. The counts had been complete and
    honest the whole time; every document had exactly one outcome and nothing
    was hidden. They were still *wrong about the cause* -- §1.3's third rule,
    whose first three instances were all harvest losses and which has since
    turned up in verification and in a detector's account of its own limits.
  - **A tolerance that is never exercised is not tolerance.** The date parser
    accepted two orderings and a table of full month names, and the one
    competition it had been tested against happened to fall in May -- a month
    whose name is already three letters. Every abbreviated date in the archive
    failed, and the parser looked general. A format variant that no fixture
    exercises is a variant the code does not handle, whatever its regexes
    suggest.

  The second has a sharper form, arrived at by hitting it three more times in a
  single afternoon while measuring the incident archive. A parser reported that
  a proof-of-concept stated no fork point; it stated one in a variable. Fixed,
  it reported seven more as stating none; those stated one as an arithmetic
  expression, or at a transaction hash. **Every single case investigated was a
  form the parser did not handle, and none was genuinely absent.** So:

  > When a reader reports that its input does not state something, that is a
  > claim about the reader until a sample says otherwise.

  Which is worth more than the tolerance rule it generalises, because it says
  what to *do*: a zero is a hypothesis, and the cheapest test of it is to read
  the inputs that produced it. Both the quarter of the archive filed as out of
  scope and the four incident populations written off as unpinnable were zeroes
  nobody had opened.

  **An absence is a claim about the observer wherever it appears**, and the
  reader phrasing is the actionable case rather than the whole of it. Eighty-
  eight findings were dropped as an absence of records for their class (§7.2).
  "One incident in seven is pinnable" was an absence of expressible pins (§6.6).
  A metadata field that could not be read was filed as a platform saying no. The
  same shape every time, and every time the absence was about the instrument.

  So the rule is given the treatment every other check here gets, and stops
  depending on somebody deciding to run it: **the reader retains a few of the
  inputs behind each not-stated verdict, and the statement prints one.** A zero
  arrives with its own evidence, in the sentence where the number is read.
  `SkipCause.is_an_absence` marks which causes qualify — a judgement such as
  "this label maps onto none of the nine" is the reader deciding, not the reader
  failing, and retaining samples for it would bury the causes where a sample
  changes the diagnosis.

  It repaid itself on the first run, and the third application is the one worth
  keeping. A `no_file_path` count of 35 came with its inputs attached: fifteen
  named an explorer `/address/0x…` URL, which is a perfectly good location in
  coordinates an `AddressPin` now holds — so they are counted apart, under a
  cause naming what is actually missing, which is verified source at that
  address rather than a path in the report. Of the remaining twenty, every one
  named a repository at a tag with no file in it. That is a **genuine absence**:
  the sample said otherwise, the diagnosis stood, and the rule stopped. A check
  that only ever confirms its own suspicion is not a check.

  Closing both gaps moved the in-scope population from 224 reports to 331 and
  the class-mapping rate from 11% to 17%, which lands where the other four
  sources already were (§4.3). The gaps had been depressing the *denominator*,
  not the rate.

  Part of it is recoverable rather than merely measurable. A report naming a file
  and a function but no span can have the span looked up in the declaration
  index, which converts the whole prose-located category from lost to usable —
  and that category is precisely the one whose loss produces the era bias.
  Derivation obeys the same ambiguity discipline as verification: derive only
  when the named function is declared exactly once inside the named type, and
  skip otherwise. Every derived locator is marked as such (§6.6), because
  verification cannot cross-check it.

  A second recoverable category: a finding citing the reviewed repository at a
  *branch* rather than a commit. Line numbers against `blob/main` are not a
  location, and nine such losses over one sample were filed as having none. But
  the reports pin their own snapshot: across the sample every report's citations
  of the repository under review named one commit far more often than any other
  — 11, 21, 26, 31, 35 and 44 citations against runners-up of two to five — so
  the commit is **stated by the report**, and the only assumption left is that
  the branch was there when the finding's line numbers were written. Of 22
  drafts over 17 reports, 12 pin their own commit, 6 take the dominant one, and
  4 take the contest's snapshot because a line-numbered excerpt names no commit
  at all.

  Two lessons, both about where a check lives:

  - **Centralising a check centralises its verdict, not its reasons.** The
    repository restriction had to hold at the stated citation, the sole cited
    file and the candidate set; it held in two, and a dependency citation became
    a record pinned to an upstream library. Made single, it silently dropped
    every out-of-scope citation, and three findings needing three different
    fixes — read the report's scope, parse a path, cite anything at all — all
    arrived as `no_location`. So the filter is one function and the *cause* is
    read back off the unfiltered citations, which is the only place the
    difference between them still exists.
  - **A recovery can erase its own evidence.** Rewriting a moving ref to the
    stated commit makes the citation indistinguishable from one the finding
    pinned itself — and `is_pinned` was exactly what both callers asked, so
    every draft came out labelled the wrong way round: findings that pinned
    their own commit were published as resting on an inference, and the
    recovered ones as stated outright. Nothing failed, no count moved, and the
    wrong label was `pin.resolved_from`, which is what a report stratifies on to
    say how much of the corpus rests on an assumption. It surfaced only by
    reading each new record against its source before writing it.

  What the sample yielded, end to end: 174 candidates, 22 drafts, 10 records
  after normalization, 8 after verification, 5 of them new to the corpus. Verify
  rejected two for naming a function not declared in the located span, which is
  the check doing its job on a locator derived from prose. One admitted record
  rests on the recovered commit, and says so.

  A third recoverable category, and the one that taught the most: the
  line-numbered excerpt, which states a file and quotes it. Two thirds of those
  drafts died resolving against no file in the repository, because the heading
  carries a bare `Vault.sol` and the directory is in the report's own citation
  of that name — recoverable, and only when exactly one cited path ends in it,
  since two files of that name is the case where the report has not said which.

  Fixing that exposed two things the numbers were hiding.

  - **A finding quoting several regions has not stated a location.** Of four,
    three quoted a helper or an explanatory call first and the defect site
    later, and one quoted a test file beside the real one. Taking the first
    block was a guess that landed wrong three times in four, so several blocks
    means the route declines; a block quoting the harness is dropped first,
    because a proof of concept exercises the defect rather than containing it.
  - **The excerpt's line numbers are not a location.** One read
    `503: function erc20TransferOutBidAmountToLiqudity(...)`; in the pinned file
    that declaration is at 496 and 503 is inside the *next* function. The file
    resolved, the span parsed, and the function was derived from the span and so
    agreed with itself — the same self-consistency trap as a matcher that
    shifted a quote by 28 lines and found it unique anyway (§6.3), arriving this
    time from the report's side rather than the instrument's. A record would
    have pinned a high-severity defect to an untouched function.

  So the numbers are dropped and the excerpt's *text* is handed over as a quote,
  to be found in the pinned source or refused. That is the falsifiability this
  route was valued for; trusting its numbers threw it away. The same finding now
  lands at 496-499, on the declaration holding the subtraction it is about.

  The losses then moved from harvest to `normalize`, where 23 of 37 drafts were
  dying, and the same rule applied again: a reader reporting that an excerpt is
  not in the file is making a claim about the reader. Opening all 23 gave three
  reader defects and one genuine absence.

  - **A reviewer's marker is not code.** Published excerpts point at the line
    that matters with `@> return x;` or `|>  require(...)`, and those cost whole
    records rather than one line each: the marked line failed to match, which
    broke *contiguity*, so an excerpt whose every other line was present matched
    nothing at all.
  - **A recommendation is not a quote of the defect.** A block of `+` lines
    cannot occur in the pinned file by construction — it is what the report
    wants the file to become. But the same block's context and removed lines are
    the report quoting the code as it stands, so the pre-image is a quote and
    the additions are not. Reconstructed rather than discarded, since some
    findings carry no other excerpt. A diff whose pre-image holds no code is
    dropped, and conflating "not a diff" with "a diff of nothing" in one `or`
    handed the matcher exactly the lines that cannot match.
  - **Spacing is not evidence**, and this one is worth stating for what it did
    *not* do. The matcher collapsed runs of whitespace, so `a  =  b` matched
    `a = b` and `a=b` did not — an inconsistency in a tolerance rather than a
    tolerance withheld. Closing it recovered **no** draft. The excerpt that
    prompted the look quoted genuinely different code: a ternary the report had
    rewritten as an `if`, which is an absence the source confirms.

  Two of those recovered records had to be thrown away again, and both taught
  more than they cost. One was located in `test/mocks/PoolMock.sol` — the
  finding's diff was of a library and its context lines occurred in the mock,
  and the *candidate set* had no test-path restriction while the excerpt route
  did. Third time that check has been needed somewhere it was not, so it now
  lives where citations enter, with the repository restriction.

  The other is §7.3 arriving in curation. Six drafts named a function in prose
  that the quote's span does not contain, and in all six the name was declared
  in **another file**: a library's `validateVariablePoolHasEnoughLiquidity`
  called from the quoted lines, `nuke` where the quote shows `burn`, a hook's
  `onQueueWithdrawal` where the quote shows `closeMarket`. **A call edge is not
  the same function**, and the finding has pointed at two places without saying
  which holds the defect. Preferring the quote would have pinned three of the
  six to code the title was not about; preferring the name throws away the only
  signal the source can confirm. So the draft is refused, under a cause that
  says so — and refused in `normalize`, where both signals are still in hand.
  `verify` had been reporting it as a span with a missing declaration, which
  reads as a defect in the span and sends the reader to the wrong place; with
  the disagreement settled upstream, verification rejects nothing at all on this
  sample, which is what it should look like when every stage's refusals are its
  own.

  That last one exposed a disagreement between two stages about what a record
  is. `normalize` had a rule that a function named in prose *rescues* a span
  lying in no function, and the records it produced — lines 5-5, function
  `setOwner`, declared nowhere near line 5 — are ones `verify` is documented to
  reject and did. A test pinned the rescue rather than the contradiction.

  One more thing the recovery exposed, one level up. The class was being read
  off *identifiers*: `ETHOracle.getLatestPrice` classified a decimals bug as
  oracle integrity, `receiveFlashLoan` a callback bug as flash-loan
  manipulation. §6.3's exemption for keyword matching covers **prose** — nobody
  renames the English word "reentrancy" — and an identifier quoted inside a
  title is exactly the renameable thing the exemption does not reach, so quoted
  spans are dropped before matching. Four classifications over 174 findings, all
  four wrong. Two terms go even unquoted, because they name a *guard that is
  present*: a finding about `nonReentrant` on a `receive()` making every
  withdrawal fail is a denial of service, and the table read the modifier's name
  and called it reentrancy. No keyword can tell a missing guard from a harmful
  one, so the word stops being a signal either way and the title is left
  unmapped and counted — 141 of 174 now, against 136 before, and the five it
  gave up were five wrong labels.
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

Kept as separate records, duplicates do not merely pad a count. Matching is
one-to-one within each strength tier (§7.1), so one finding satisfies exactly
one record and the remaining copies are counted as misses. Measured against the
scorer:

| ground-truth records for one defect | matches | misses | recall | precision |
| --- | --- | --- | --- | --- |
| 1 | 1 | 0 | 100% | 100% |
| 2 | 1 | 1 | 50% | 100% |
| 4 | 1 | 3 | 25% | 100% |

So duplication **understates** recall, by a factor equal to how many reviewers
submitted the defect, and it leaves precision untouched. The understatement is
largest exactly where a benchmark is least informative — the findings everybody
saw — so a detector is penalised most for missing the most-reported defect and
the penalty is applied more than once.

An earlier version of this section had the sign backwards, claiming duplicates
inflate recall because one finding would match every copy. That describes
many-to-one matching, which §7.1 does not do. The correction is recorded rather
than quietly applied because the error was not in the rule -- folding is right
either way -- it was in the *reason*, and a rule kept for a reason that does not
hold is a rule nobody can reason about later.

So `normalize` folds records describing one defect and reports the count of
folds. Two records are one defect when they share the pinned commit, the file,
the function and the class. The rule merges two genuinely distinct defects
sitting in one function under one class, and that trade is taken deliberately:
scoring is at function granularity, so two defects in one function are not
separately scoreable anyway.

Which of the duplicates survives is decided by what the *reports* asserted, not
by how the spans were obtained: confirmation first (§6.6), then the number of
claims the report made, then the narrower span, then the record id so the choice
is deterministic. Deliberately not a ranking of provenances against each other —
`stated` and `quoted` fail in different directions and neither outranks the
other.

A fold is not a loss and is counted apart from losses. Nothing was lost; a
denominator was corrected.

**Where the rule deliberately stops.** Two records can describe one defect at
two levels — a wrapper and the function it calls, same class, overlapping spans,
different function names. Two of the first ten harvested records are such a
pair. Folding them would need a key based on span overlap, and that same key
merges a caller and a callee that genuinely have separate defects.

That question does not belong here at all. What it actually asks is whether one
finding may satisfy more than one ground-truth record, and whether a file-level
match counts toward recall — both of which are *scoring* policy (§7.1). Deciding
it by choosing a dedup key would answer a scoring question inside a
normalisation rule, where nobody reading the score can see it.

So the pair is left as two records and flagged for hand curation
(`docs/curation.md`), recorded as deferred to the scorer rather than as too hard
to automate. When the scorer forces the question, the repair is to **record the
relation** — that one record's function calls the other's, same class,
overlapping spans, which a call-site scan can establish — and let the scorer
apply a stated policy to it. Folding on overlap destroys the fact in order to
encode the policy, and a policy encoded in lost data cannot be changed later.

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

The same rule applies to what a detector *omits*, and that took a separate
mechanism. A declared blindness (§7.3) names a record the detector is silent on,
which makes a claimed blindness checkable by running it. Nothing can force a
detector to declare one it would rather not, so the report states how many
misses no declared blindness accounts for — an undeclared miss then costs
visibility rather than nothing. A class nothing ran against is excluded from
that count, because its records are unmeasured rather than missed and merging
the two would be the conflation this report exists to prevent.

A fourth instance was found by running three detectors against eleven records
rather than by reading the code, and it was the one this rule missed. 90
verified findings went in and 2 came out: the per-class loop visited only the
classes the *ground-truth records* carried, so 88 findings in a class the
corpus does not cover were emitted, checked against source, and dropped. A
detector for an uncovered class could emit any number of claims for nothing --
the exact thing the rule above forbids, arrived at from the corpus side instead
of the detector side.

Counting them as false positives is the opposite overclaim. With no record of
that class, the corpus has no standing to call a claim wrong; what it can say is
how many there were and that it could not adjudicate them. So they are counted
and disclosed, entering no confusion matrix -- the treatment `invalid` and
`skipped` runs already get. The stratification tables were restricted the same
way, and are not any more: those tables describe the submission, and restricting
them to scoreable classes made them describe the corpus's coverage while
appearing to describe the submission.

The general form, which is not about scoring: **a loop keyed on one collection
silently drops everything in the other.** The key was the class, the collections
were records and runs, and the join looked total because every class in the
records was present in the runs.

Sampling is an explicit parameter of a benchmark run, and metrics are reported
at the corpus's real class prevalence. Forcing a balanced sample produces
numbers that describe no population and cannot be compared across classes.

### 7.3 A call edge is not the same function

Two locator cases arose the same week and they ask one question. A record at an
entry point whose defect is in an internal callee, and a pair of records
describing one rounding defect at a caller and at its callee. In both, a defect
spans a call edge while the corpus names one end and a submission names the
other.

One rule answers both:

> **Nothing weaker than the same function counts as the same location, and
> everything weaker is reported as its own named strength.**

So `call_adjacent` joins the strength table between `file` and `function`: same
file, different function, one call edge apart. Reported separately and **never
folded into the function figure**, which is the whole reason it is a tier rather
than a relaxation — `file` is already weaker than `function` and nobody reads a
file match as function-granular. Recall at the `function` floor stays exactly as
strict as §1.1 requires.

Resolution is name lookup within the unit, which is what resolving a call
amounts to when nothing overloads the name (§4.2), and each name must be
declared exactly once or the tier is refused: an overload would make two
unrelated functions look adjacent.

**No corpus record exercises this tier yet, and neither motivating case is
resolved by it.** Stated because the alternative is implying otherwise:

- The entry-point case has no prediction to match. Its defect is a loop bounded
  by a local alias of a *local* array's length, and the denial-of-service
  predicate requires a dynamic array in **storage**, so nothing is claimed
  there at all.
- The caller/callee record pair is not a matching question. Matching is
  one-to-one, so one finding satisfies one record and the second is a miss at
  every tier, this one included. That pair is the duplicate-records question
  (§6.7), which remains deferred to the scorer for the reason recorded there:
  deciding it by a dedup key would bury a scoring policy in a normalisation
  rule.

So what this increment settles is the **rule**, with a tested surface for it,
and what it does not settle is either instance. Both are recorded above rather
than left to be rediscovered as gaps.

### 7.4 What the corpus has standing to judge

A positive record asserts that an instance of its class exists at its location.
It asserts **nothing** about whether other instances exist elsewhere in the same
file. So an unmatched prediction in such a unit is not a false positive — it is
a prediction the corpus has no standing to judge.

This is the same standing argument that keeps an uncovered class's findings out
of the matrix (§7.2), and it had not been applied here for a plain reason:
those classes had no records at all, and these have some. **Having records for a
class is not the corpus being complete for that class in those units**, and the
scorer was treating the first as the second.

A **negative** record does establish completeness: `negative_for` asserts that
no instance of that class exists anywhere in the pinned file. So the line is
computable rather than a matter of judgement:

> Precision is defined over the (unit, class) pairs a negative record covers.
> Everywhere else an unmatched prediction is **unjudged**, and enters no
> precision figure.

Matches in unjudged units are excluded too. Counting a hit against a denominator
that excludes its siblings would inflate the figure in the other direction,
which is the mirror of the error being corrected.

Without this, every precision number is understated by an amount that varies
with how thoroughly each unit happens to be annotated — and understated *most*
for the most productive predicates, which is the worst available direction. The
figures this had already produced were 25%, 4% and 50%, none of which the corpus
could license.

Two states are counted apart so they do not share the single appearance of a
`n/a`: no negative record exists for the class at all, and negatives exist but
nothing ran against the units they cover. The first is a gap in the corpus and
the second is a gap in the run, and they call for different work.

At present the corpus holds no negative records, so **precision is unavailable
everywhere** and every prediction is unjudged. That is a fact about the corpus
rather than about the detectors, and stating it is the only honest form
available.

### 7.5 A score and a declared limit are different kinds of claim

A score is an estimate from a sample and it moves with the sample: add a hundred
records of a class and its recall becomes some other number. A **declared
limit** is a fact about the instrument and it does not move — one counterexample
settles "this cannot be established here" permanently, which is why it is
certain at a single record where no score ever is.

That asymmetry decides how it is reported. A limit gets **its own line**,
not a caveat beside the score, because burying a certain claim inside an
uncertain one loses the certain half and makes both read as provisional. It is
the same separation that keeps `invalid` out of the confusion matrix: different
things must not share a number, and here two different kinds of claim must not
share a sentence.

**Two kinds, and they are not a strong and a weak version of one thing.** A
*blindness* is a shape the instrument should see and does not — a defect, closed
by better analysis. An *indeterminacy* is the instrument correctly reporting
that something is unknowable at this scope (§3.1) — not a lesser blindness but a
different statement, and a true one, closed by more *scope* rather than more
analysis. Merging them would make an honest submission look worse than one that
silently guessed, which is the incentive from the previous subsection one level
in: between two kinds of declaration rather than between declaring and not.

So `kind` is required with no default. Placement as a field rather than as a
separate register is the same call as mandatory `locator_provenance`, required
`split` and required `population`: a value somebody can review and get wrong
visibly, rather than a decision made silently by whoever filed the entry. One
register also keeps the omission check over one population — a check defeated by
forgetting the second lookup is not much of a check — and keeps `isolated`
coherent, since the only record here trips one entry of each kind and a
cross-register relation is the thing that rots first.

The container is named for the set rather than for half of it, which was worth
correcting while there were two entries: a container named wrongly attracts the
wrong contents, exactly as a cause named wrongly points at the wrong fix (§1.3).

So each detector declares a register of what it cannot establish, carried on
every run by the harness rather than asserted at report time. Each entry names
its kind, the shape as a *property* rather than an instance, the corpus record
that demonstrates it, why it is unpatched, **what would close it**, whether that
record **isolates** it, and what closed it once something has.

`closed_when` is stated rather than derived from the kind, because the reader's
question is whether a planned change will absorb the entry, and deriving the
answer would encode a general claim — better analysis closes blindnesses, more
scope closes indeterminacies — of exactly the sort that has already been wrong
here once.

**It was wrong again, on the first entry, and the field is what made that
legible.** The blindness entry predicted "the semantic tier lands and
caller-taint becomes available". It closed at the *syntactic* tier, with no tier
work at all (§4.2). The prediction is left as written and the outcome recorded
beside it in `closed_by`, because the pair is the record of the error — a
`closed_when` quietly corrected to match what happened would read as though the
plan had been right.

And closing it did **not** make the demonstrating record visible, which
`isolated=False` had said in advance: the finding is now established by
evidence, reaches the verdict, and is refused there by the indeterminacy the
second entry describes. That is the register doing the job it was built for, on
its first real use.

**The register's completeness is bounded by the corpus**, which is a consequence
of `demonstrated_by` being required and is worth stating so a reader does not
take the register for a full list of limitations. A limitation known by
construction but demonstrated by no record cannot become an entry — filing one
with an inapplicable record would destroy the property that makes every entry
checkable. Two such limitations exist for this class already: the alias case,
and the pinned-address false positive. They live in the predicate's own
docstring, which is the right place for a limitation nothing yet proves, and
they are written down rather than left to be rediscovered. The last field makes the register a work list
rather than a graveyard: when a tier lands and an entry closes, the entry names
the change that closed it and stops excusing a miss, so a regression resurfaces
as an unexplained one.

**The register cannot be summed**, and that is what `isolated` is really for. A
record can trip several independently sufficient blindnesses: close any one of
them and the record stays invisible. So a count of open entries is not a count
of remaining work, and printing one hands a reader a number whose arithmetic
does not hold — the failure this document keeps catching in other forms. The
entries are therefore named and never totalled, the relation between entries and
the records they name is recorded, and a figure for work remaining, if one is
ever wanted, is computed over **records made visible** rather than over entries
closed. Collapsing entries or summing them would encode a policy in a number,
which is the ruling the caller/callee duplicates got (§6.7) for the same reason.

**Declaring has to read better than not declaring**, and this is the first
mechanism here whose adversary is a stranger rather than a mistake. If a reader
took a register of three entries as weakness, a submission wanting to look good
would declare nothing, its misses would land in the unaccounted count, and the
mechanism would have produced exactly the silence it exists to prevent. So the
sign is built rather than hoped for: declaring moves a miss from unaccounted to
accounted, and adds no figure that grows, because the entries are named and not
counted. The report says which number is the weakness in its own text, since an
incentive design that is correct by accident stops being correct the first time
somebody reformats the output.

The `isolated` field earned its place immediately. The first register entry
written here attributed a detector's silence to one shape. Four minimal cases
then showed **two** independently sufficient conditions — a storage write with
no guard fires; the same write with an unsound guard does not; an external
effect with no guard does not — and the record trips both. The single entry was
true and insufficient, and would have told a reader that fixing the guard
recognition made the record visible. It does not. Which is §6.3's rule about
causes, arriving from the detector's side: a cause recorded wrongly points at
the wrong fix, and that holds for an instrument's account of its own limits as
much as for a harvest loss.

What a reader gets from the pair that neither gives alone: seeing
"`access_control` 33%" beside "known blindness: a guard that is present and
unsound" tells them which way the number moves on a corpus containing more of
that shape. A score alone cannot say that, and it is what a reader most needs to
know.

### 7.6 Ranking, and refusing to rank

A leaderboard is where every rule in this section either holds or stops
mattering, because the single number is what gets quoted. So the arithmetic is
arranged so the number cannot exist unless the things it rests on do.

**Three refusals**, each of which a simpler implementation makes silently:

- **No F1 without both sides.** Precision is unavailable until a class's pool is
  fully judged (§7.3), and a harmonic mean with one side missing is not a weaker
  F1 — it is a different quantity. Substituting zero for an unavailable
  precision would rank a submission nobody has adjudicated *below* one that has
  been, which inverts the incentive the whole adjudication discipline depends
  on.
- **No aggregate over a partial class set.** A mean over whichever classes
  happened to have figures ranks a submission on its corpus's readiness, and two
  submissions measured over different sets are not comparable however close the
  numbers look. So the aggregate exists only when every class in the requested
  set has an F1, and the class set is named beside the table.
- **No built-in weights.** Difficulty weighting is supplied by whoever runs the
  exercise. A weight per level is a coefficient, and a coefficient written into
  the harness makes the ranking a property of this code rather than of the
  exercise it serves.

Completion rate **multiplies** the aggregate (§7.1) rather than folding into the
matrix: a submission that crashes on a third of the corpus must not rank beside
one that does not, and an error must never be counted as a judgement.

**An unrankable submission is not placed last.** It is listed apart with the
reason, because ordering it below a ranked one asserts a comparison nobody
measured — and the usual cause is work the *exercise* owes, unadjudicated
predictions or a class the corpus does not cover, rather than anything the
submission did. The reason is given per class, because an unjudged pool is
adjudication owed and a class with no records is corpus owed, and those are
different work items.

**What this costs the exercise, stated because it is a scheduling fact.**
Precision needs the pool judged, and the pool is what submissions claimed, so a
round cannot be ranked until its pool has been adjudicated. Two things soften
that. Adjudications already made against a reference run cover whatever a
submission predicts in the same places, and the obvious predicates are the ones
everybody implements first, so the residue per submission shrinks as the pool
grows — which is the standard incremental-pooling benefit. And a submission's
own statement says exactly which classes are waiting on how many
adjudications, so the outstanding work is visible before the round rather than
discovered during it.

### 7.7 The boundary a submission surface is built on

A ranking is eventually read on a page, and the page is a different program.
That program must not re-implement any of §7.6, because **a second
implementation of a refusal is a first implementation of a default**: every rule
above is one line of `or 0` away from being lost, and the loss is invisible
precisely where it matters, in the cell a reader believes.

So the engine emits documents rather than prose, and three rules shape them.

- **A figure and its absence are the same shape.** Every measurement is
  `{"value": …, "unavailable": …}`. A `null` value always arrives with a
  sentence saying why, so a consumer that renders the value prints an empty cell
  rather than a zero. Omitting the key instead would make "0" and "not
  licensed" indistinguishable to every caller that defaults.
- **A number a human is told is a list a human can act on.** "59 of its
  predictions are not yet adjudicated" is actionable only if the 59 can be
  opened, so the document carries them with unit, detector and line range. That
  also keeps the count and the sentence from drifting: the queue is built from
  the same judged set the figure is, which caught a first version listing
  predictions that had matched a positive record — work the corpus had already
  done.
- **A document says what it was measured against.** A corpus digest over every
  record's identity and verified bytes, so a stored row can be checked rather
  than trusted. Two rows with different digests were not measured against the
  same ground truth and are not comparable, whatever the numbers say.

#### The model behind a row

An exercise that agrees one baseline model and runs every submission against it
is making a claim about *process*. Nothing in the run record could check it:
`DetectorRun` named no model, `AnalysisContext` carried budgets and no identity,
and `Escalation` named models only when a hand-off happened. A leaderboard could
therefore not say what produced a row — and a reader shown no model assumes the
agreed one, which is the same failure as a missing figure read as zero.

The host is the only thing that knows, because `plan()` says what to ask and the
model is called outside the detector. So a run records `models` — each
`model_id` with its role, calls and tokens — and a run whose findings came from
deterministic code says `produced_without_a_model` **explicitly**. "No model is
named" and "no model ran" are different claims and only one of them supports a
baseline comparison, so findings with neither are refused at construction, with
the message pointing at the host rather than at the submission.

Ranking then enforces the claim instead of assuming it. A row is ranked only
when its runs name one main model and that model is the agreed baseline; a row
under another model, or naming none, or naming two, is listed apart with its own
reason. That reason is kept in a separate field from a missing F1, because the
two are different work for different people: an unlicensed precision is the
exercise's adjudication debt, where a mismatched baseline is a row that was
never comparable. Sub-models do not block a comparison — which helpers a harness
calls is part of what is being compared, and the call and token budgets are what
meter them. And with no baseline stated, submissions are still checked against
each other: if they name different main models, none is ranked, because ranking
whichever ones happen to agree would turn the exercise's silence into a decision
it never made.

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
