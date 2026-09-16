# Curating a record by hand

How to turn one published incident or finding into one corpus record, and the
order to do it in. The order is the point: three of the six steps exist because
doing them later wastes the work of the ones before.

Harvesting (§6.3) is the automated path and it is thin — measured at roughly 2%
of accepted findings on review platforms. Hand-curation is what the corpus is
actually built from for now, at roughly an hour per record.

## The procedure

### 1. Check that a canonical repository exists — before anything else

Search the protocol's org on GitHub. You need the *protocol's own* repository,
not a third-party copy or an analysis repo: a copy has no commit that anyone
else can verify against, and a record pinned to one asserts a provenance it does
not have.

Stop here if there is none. Of seven curated incidents in one public
collection, only two had a canonical public repository — protocols shut down,
orgs disappear, and some victims were bespoke contracts that were never in a
repository at all. This step is first because every later step is wasted without
it, and it takes two minutes.

### 2. Find a commit before the fix

List commits up to the day of the incident or the report:

```
/repos/{owner}/{repo}/commits?until=2022-04-17T00:00:00Z
```

Take the most recent one before that date. It needs to precede the *fix*, not
merely the disclosure, so check what the fix was if the two are far apart.

### 3. Find the file, at that commit

Fetch the tree at the commit rather than browsing the default branch — files
move, and a path from today may not exist there:

```
/repos/{owner}/{repo}/git/trees/{sha}?recursive=1
```

### 4. Read the function. Do not trust the write-up's phrasing

This is the step that earns the hour. A post-mortem describes a mechanism in
prose, and prose invites a classification that the code does not support.

A worked example, from getting it wrong: a bridge post-mortem described a
"trusted root initialised to zero", which reads as an access-control failure. The
code shows `initialize` pre-approving the committed root with no zero check,
`acceptableRoot` then returning true for it, and `prove` accepting any all-zero
proof. The functions that accept a proof are permissionless by design — what
failed was verification, not authorisation. The finding is not access control,
and it is not in the nine at all.

Classify from the mechanism in the source. If it does not fit one of the nine,
it does not fit; there is no catch-all class and one is not being added (§4.3).

### 5. Build the draft and let the pipeline place it

Do not write the record by hand. Build a `DraftRecord` and run `normalize`, so
the span, the enclosing contract, the digest and the locator provenance are all
derived the same way they would be for a harvested record:

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

Pass only what the *report* asserted. If it named a function and not a contract,
pass the function and leave the contract out — `normalize` records which labels
came from the report, and that is what decides whether the record counts as
independently confirmed (§6.6). Filling in a contract yourself, because you read
it off the source, converts a one-claim record into an apparently two-claim one
and quietly overstates it.

### 6. Verify through the CLI, against a real checkout

```
contract-assay verify corpus/records --source-root /path/to/checkout
contract-assay declarations /path/to/checkout/<the file>   # to diagnose a rejection
```

`verify` must exit zero. `declarations` prints every declaration with its
signature, which is how a rejected record gets diagnosed without guessing.

Then write the record to `corpus/records/<record_id>.json`.

## What a curated record still cannot claim

Read the statement `verify` prints. A record curated this way is normally
`derived`: the report named a function, the span came from the declaration
index, so `is_cross_checked` is false and `supports_exact_match` is false —
the span is the whole function, and an exact-location match against it would be
satisfied trivially.

That is not a defect in the record. It is the record saying what it is, which is
the whole reason those fields exist. A corpus of such records supports
`function`-strength scoring and not `exact`, and a report over it has to say so.

## Two things to resist

**Do not widen a class to make something fit.** The mapping rate is a
measurement (§6.3); improving it by loosening what counts destroys the thing
being measured.

**Do not fill in labels the report did not state.** It is the single easiest way
to make a weak record look like a strong one, and nothing downstream can detect
it afterwards.

## The one case curation is asked to settle, for now

After a harvest, look for **records of the same class whose spans overlap but
whose functions differ**. Typically a wrapper and the function it calls, each
written up by a different reviewer, describing one defect at two levels. Two of
the first ten harvested records are such a pair.

`normalize` folds duplicates that share a function (§6.7) and deliberately does
not fold these, because the key that would — span overlap — also merges a caller
and a callee that genuinely have separate defects, and nothing in the records
distinguishes those two situations.

For each pair, read both functions and decide:

- **One defect described twice.** Keep the record whose function *contains* the
  defect rather than the one that reaches it, and delete the other. Note the
  deletion and the reason in the kept record's `notes`.
- **Two defects.** Keep both, and say in each record's `notes` that the overlap
  was checked and is not a duplicate. Without that note the next curator repeats
  the work.

This is deferred to hand curation rather than automated because the question it
actually asks is a **scoring** one — whether one finding may satisfy more than
one record, and whether a file-level match counts toward recall — and answering
it by choosing a dedup key would bury a scoring policy inside a normalisation
rule. When the scorer settles that policy, the repair is to record the *relation*
between the two records and let the scorer apply the policy to it; this section
goes away then.
