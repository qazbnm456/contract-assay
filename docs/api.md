# The detector API

What you implement to submit a detector, what this project promises not to
break, and what it checks before believing anything your code returns.

Everything here concerns `contract_assay.detectors`. If this document and the
code disagree, one of them is a bug — see `docs/design.md` for the same rule
applied to the rest of the system.

## 1. A detector in three layers

A detector answers one question about one Solidity source unit: does an instance
of a particular vulnerability class exist, and *where*.

```python
from collections.abc import Sequence

from contract_assay.detectors import API_VERSION, AnalysisContext, Detector
from contract_assay.models import EvidenceRef, FailedCheck, Finding, VulnerabilityClass


class MissingOwnerCheck(Detector):
    detector_id = "missing-owner-check"
    class_id = VulnerabilityClass.ACCESS_CONTROL
    api_version = API_VERSION

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]: ...

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]: ...
```

Three declarations and two methods is the whole obligation. The layers run in a
fixed order:

| Order | Layer | Model? | Required? |
| --- | --- | --- | --- |
| 1 | `evidence(ctx)` | never | yes |
| 2 | `plan(ctx, evidence)` → the model | optional | no — default runs no model |
| 3 | `verdict(ctx, finding, evidence)` | never | yes |
| 4 | `classify(ctx, findings)` | never | no — only in classification mode |

**A detector that runs no model is a first-class submission.** Leave `plan()`
alone and nothing is called. Static analysis is the baseline this benchmark
measures against, so an interface that could not express a purely deterministic
detector could not express its own control group.

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
- Everything else is compared literally. Identifiers, punctuation, operators and
  the order of lines all have to match.
- The quote must appear **within** the locator's line span — it need not be the
  whole span, but a quote wider than the span is a mismatch.
- A quote that is blank once normalised is a failure, not a pass.

Three failures are distinguished, because they say different things about a
detector: `citation_span_out_of_range`, `citation_quote_elsewhere_in_file` (real
code, wrong place) and `citation_quote_absent_from_source`.

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
claim, and it is checked. Every returned value is re-validated, and anything
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
