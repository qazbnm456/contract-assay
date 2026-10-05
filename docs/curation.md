# Curating a record by hand

How to turn one published incident or finding into one corpus record, and the order to do it in. The order is the point: three of the six steps exist because doing them later wastes the work of the ones before.

Harvesting (§6.3) is the automated path and it is thin: measured at roughly 2% of accepted findings on review platforms. Hand-curation is what the corpus is actually built from for now, at roughly an hour per record.

## The procedure

### 1. Check that a canonical repository exists, before anything else

Search the protocol's org on GitHub. You need the *protocol's own* repository, not a third-party copy or an analysis repo: a copy has no commit that anyone else can verify against, and a record pinned to one asserts a provenance it does not have.

Stop here if there is none. Of seven curated incidents in one public collection, only two had a canonical public repository: protocols shut down, orgs disappear, and some victims were bespoke contracts that were never in a repository at all. This step is first because every later step is wasted without it, and it takes two minutes.

### 2. Find a commit before the fix

List commits up to the day of the incident or the report:

```
/repos/{owner}/{repo}/commits?until=2022-04-17T00:00:00Z
```

Take the most recent one before that date. It needs to precede the *fix*, not merely the disclosure, so check what the fix was if the two are far apart.

### 3. Find the file, at that commit

Fetch the tree at the commit rather than browsing the default branch; files move, and a path from today may not exist there:

```
/repos/{owner}/{repo}/git/trees/{sha}?recursive=1
```

### 4. Read the function. Do not trust the write-up's phrasing

This is the step that earns the hour. A post-mortem describes a mechanism in prose, and prose invites a classification that the code does not support.

A worked example, from getting it wrong: a bridge post-mortem described a "trusted root initialised to zero", which reads as an access-control failure. The code shows `initialize` pre-approving the committed root with no zero check, `acceptableRoot` then returning true for it, and `prove` accepting any all-zero proof. The functions that accept a proof are permissionless by design: what failed was verification, not authorisation. The finding is not access control, and it is not in the nine at all.

Classify from the mechanism in the source. If it does not fit one of the nine, it does not fit; there is no catch-all class and one is not being added (§4.3).

### 5. Build the draft and let the pipeline place it

Do not write the record by hand. Build a `DraftRecord` and run `normalize`, so the span, the enclosing contract, the digest and the locator provenance are all derived the same way they would be for a harvested record:

```python
draft = DraftRecord(
    candidate_id="beanstalk-april-2022",
    repo_url="https://github.com/BeanstalkFarms/Beanstalk",
    commit="e9f49910e287e7a7afaa6db8f536b7194728b0af",
    path="protocol/contracts/farm/facets/GovernanceFacet/GovernanceFacet.sol",
    function="emergencyCommit",  # what the report named
    classes=(VulnerabilityClass.FLASHLOAN_MANIPULATION,),
    provenance=Provenance(
        platform="immunefi-hack-analysis",
        report_url="https://rekt.news/beanstalk-rekt/",
        reported_severity="critical",
    ),
)
report = normalize(
    [draft],
    resolver,
    split=CorpusSplit.PUBLIC,
    population=Population.EXPLOITED_INCIDENT,
)
```

Pass only what the *report* asserted. If it named a function and not a contract, pass the function and leave the contract out: `normalize` records which labels came from the report, and that is what decides whether the record counts as independently confirmed (§6.6). Filling in a contract yourself, because you read it off the source, converts a one-claim record into an apparently two-claim one and quietly overstates it.

### 6. Verify through the CLI, against a real checkout

```
contract-assay verify corpus/records --source-root /path/to/checkout
contract-assay declarations /path/to/checkout/<the file>   # to diagnose a rejection
```

`verify` must exit zero. `declarations` prints every declaration with its signature, which is how a rejected record gets diagnosed without guessing.

Then write the record to `corpus/records/<record_id>.json`.

## What a curated record still cannot claim

Read the statement `verify` prints. A record curated this way is normally `derived`: the report named a function, the span came from the declaration index, so `is_cross_checked` is false and `supports_exact_match` is false: the span is the whole function, and an exact-location match against it would be satisfied trivially.

That is not a defect in the record. It is the record saying what it is, which is the whole reason those fields exist. A corpus of such records supports `function`-strength scoring and not `exact`, and a report over it has to say so.

## Two things to resist

**Do not widen a class to make something fit.** The mapping rate is a measurement (§6.3); improving it by loosening what counts destroys the thing being measured.

**Do not fill in labels the report did not state.** It is the single easiest way to make a weak record look like a strong one, and nothing downstream can detect it afterwards.

**Do not trust a line number the report gives without reading the line.** A published excerpt headed `File: VaultLogic.sol` numbered its first line 503; in the pinned file that declaration is at 496, and 503 is inside the next function. Nothing downstream catches this: the file resolves, the span parses, and a function derived from the span agrees with itself. Where the report quotes source, locate the record by *finding that text* and let the numbers be whatever they turn out to be. Where it gives numbers alone, open the file at them and check that what is there is what the finding describes, and if it is not, the finding has not given you a location.

**Do not adjudicate a prediction made by an instrument you wrote.** Not as an instance, at least: that turns the firing into the ground truth it is scored against, and a detector whose author judges its own hits has a precision of 1 by construction. As a *non*-instance it is allowed and is ordinary curation, because the deciding fact then comes from the source rather than from the instrument. The exercise's asymmetry is what makes the pool work: submissions are judged by whoever runs the exercise, who did not write them.

**A refusal is a result, and it belongs somewhere durable.** Four predictions stand refused, and they are recorded here so the next person does not spend the afternoon reaching the same answer:

| Location | Shape | Why it is refused |
| --- | --- | --- |
| `Stable2.calcLpTokenSupply` L94 | `Ann * sumReserves / A_PRECISION` then `* lpTokenSupply` | Dividing by a scaling constant inside a convergence iteration. Whether the loss survives the iteration is the protocol's tolerance, not the expression's. |
| `Stable2.getBandC` L411 | `lpTokenSupply * lpTokenSupply / (reserves * N) * lpTokenSupply * A_PRECISION` | Same file, same question. |
| `VotingEscrow.amountToRagequit` L350 | `fluxMultiplier * (MAXTIME / EPOCH)` | 365 days over 2 weeks is 26.07, truncated to 26. Truncating to whole epochs before scaling is defensible; so is the other order. The source does not say which was meant. |
| `RewardsDistributor.amountToCompound` L129 | `((amount * price) / 1 ether) * normalizedWeights` | The loss is real and its size depends on the weight's scale, which is set elsewhere. |

In every one of the four the *shape* is present -- that is what the predicate establishes -- and the defect is whether the loss matters. That is a question about the protocol's intent, so the honest answer is a refusal rather than a negative record. The cost is visible: `arithmetic_rounding` has no licensed precision, and it says so.

**An adjudication is worth as much as the thing it settles.** The first one written to unblock a ranking took ten minutes and was decided by a single fact in the analysed unit: a loop bounded by a storage array whose only writer is an initializer guarded against being called twice, so nothing can lengthen the work it does. Say which fact settled it and what the record does *not* cover -- that one says nothing about the rest of the file, and nothing about the same report's own denial of service elsewhere, which is reached through a price check rather than through iteration. An adjudication that cannot name its deciding fact is one to refuse.

**Read every record against its source before writing it.** Two defects in one afternoon were invisible to the pipeline and obvious on sight: the above, and a pin published as resting on an inference when the report had stated the commit in the very citation used. Both produced records that passed every check.

## The one case curation is asked to settle, for now

After a harvest, look for **records of the same class whose spans overlap but whose functions differ**. Typically a wrapper and the function it calls, each written up by a different reviewer, describing one defect at two levels. Two of the first ten harvested records are such a pair.

`normalize` folds duplicates that share a function (§6.7) and deliberately does not fold these, because the key that would (span overlap) also merges a caller and a callee that genuinely have separate defects, and nothing in the records distinguishes those two situations.

For each pair, read both functions and decide:

- **One defect described twice.** Keep the record whose function *contains* the defect rather than the one that reaches it, and delete the other. Note the deletion and the reason in the kept record's `notes`.
- **Two defects.** Keep both, and say in each record's `notes` that the overlap was checked and is not a duplicate. Without that note the next curator repeats the work.

This is deferred to hand curation rather than automated because the question it actually asks is a **scoring** one (whether one finding may satisfy more than one record, and whether a file-level match counts toward recall) and answering it by choosing a dedup key would bury a scoring policy inside a normalisation rule. When the scorer settles that policy, the repair is to record the *relation* between the two records and let the scorer apply the policy to it; this section goes away then.

## Curating from an exploited incident

The same six steps, with two of them replaced. Use this when the victim has no canonical repository, which is most of them, and exists as verified source at an address.

### 1'. Find the fork point and the address, in the artefact

A proof of concept states both: a chain, a block number or a transaction hash, and the addresses it attacks. **Read them out of the artefact.** Do not recall an address from a post-mortem; a 40-hex string is exactly where memory fails silently, and the artefact is the reproducible source.

A transaction hash is the better fork point when the artefact gives one. It pins a block *and* a position within it.

### 3'. Fetch the verified source, and keep it as a map

Ask a verification repository for the address on that chain. It answers with an explicit match status: no match means no record, and that is a fact about what has been verified rather than about the incident.

The answer is a **set of named files**, and the names are import specifiers (`@openzeppelin/contracts/token/ERC20/ERC20.sol`). Store it as a manifest, `<root>/<chain_id>/<address>.json` holding `{"sources": {name: content}}`, which is the shape `contract-assay verify --source-root` reads for an address pin. Writing those names into directories would make them look joinable, which they are not.

Ask the same request whether the address is a proxy. If it is, pin the implementation and set `implementation_of` to the address users call. Bear in mind that the answer names a *recognised* proxy standard: a bespoke proxy comes back as "not a proxy", so a contract whose own name ends in `Proxy` deserves a second look regardless of what the field says.

### 4. Read the function. Do not trust the write-up's phrasing

Unchanged, and it matters more here. A worked example: one incident's write-ups describe an unchecked external call. The interface declares `function delegatedTransferERC20(address, address, uint256) external;`, no return value, so there is nothing for anybody to have failed to check, and `unchecked_external_call` does not apply. What the code actually does is ask the *subject of an authorisation check* for the answer: `from` is caller-supplied and the guard reads `owner()` from it, so an attacker's own contract satisfies the guard by construction. That is `access_control`, and only reading the interface distinguished them.

### What an incident record cannot yet claim

A **post-fix negative**, because "after the fix" is identified by a commit and an address pin has none (§6.2). The positive half of §6.4 survives (the proof of concept demonstrates the defect executably, which no prose record can) but the control does not. Record the positive and do not improvise a negative.


## Adjudicating a prediction

A negative record that licenses a precision figure is asserted at a **location** a detector actually pointed at, and says what was found there and why it is not an instance (§6.2). One per flagged location, not one per file.

The note is the record's whole content. It has to let a reviewer reach the same conclusion by reading the cited lines, so it names the expression or statement examined, says what the code does with the value, and says why that is not the class. "Examined" is not a note.

### Refuse what you cannot settle

**An uncertain adjudication is worse than an unadjudicated prediction**, because it enters a precision figure as a fact while a gap merely leaves the figure unavailable. So the answer "I cannot tell from this code" is a correct outcome and the prediction stays unjudged.

Three arithmetic predictions over one corpus, after the rounding idiom was excluded, went two ways. One was settleable: the division was required for consistency with a value stored three lines above, and reading those three lines settles it. The other two were not: one turned on whether a count of whole epochs is intended or an accumulating undercount, and one on whether a scaling loss is material at the magnitudes involved. Neither is answerable from the source, and filing either would have put a guess into a licensed figure.

That is the cost of this route stated honestly: the pool is not always completable by reading, so some classes will not have a precision figure until somebody who can settle those questions does. The alternative is not a better figure; it is the same figure with a guess inside it.

### Fix the instrument before adjudicating the pool

Check first whether the predictions share a shape. The arithmetic pool was 28 predictions, and 24 were one idiom: `(a / b) * b`, rounding down to a multiple of `b`, where the truncation is the point. Narrowing the predicate on that stated property left four, of which one already matched a record. Adjudicating 28 by hand would have produced 24 notes all saying the same thing, and left the predicate reporting the idiom forever.

So: group the pool by shape, look for an idiom, and narrow the predicate if the idiom is a property rather than a threshold. Then adjudicate what remains.
