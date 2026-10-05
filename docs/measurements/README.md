# Measurements

Figures that a decision rests on, written down with the population they were taken over and the commit that population was pinned at.

This directory exists because of a specific failure. `docs/design.md` recorded several figures from a 34-incident sample and **the sample itself was never written down**: no list, no seed, no selection rule. The figures could therefore never be reproduced or corrected, only re-taken, and one of them was read for two years as sizing a route it does not measure. The design document already carries the rule that came out of it:

> A figure reported in conversation and never written down is a figure that does not exist.

A figure written down without its population is the next version of the same mistake, so each file here records:

- the source it ran over, **named**, not described: a commit SHA of an unnamed repository cannot be checked out;
- the commit, because every source here grows;
- the population rule, so the denominator is reconstructible;
- every outcome, including the ones that were losses, so a shortfall can be read as instrument or as data.

Each file names the tool that reproduces it. The tools cache their network calls, so a re-run is cheap and returns the same numbers or a real difference.

## What is here

| File | Question | Tool |
| --- | --- | --- |
| `incident-yield.json` | How many chain incidents can become corpus records? | `tools/measure_incident_yield.py` |
| `proxy-rate.json` | How many exploited contracts are proxies? | `tools/measure_proxy_rate.py` |

### `incident-yield.json`

`fetch` refuses an `AddressPin`, so no incident record can be built yet, and the figure that decides whether to build the resolver is the yield. Four things have to hold at once and the file records the conjunction, not the marginals: two marginals do not give a joint, which is exactly how the 82% source-availability figure came to be read as a yield.

The headline is **125**: incidents with a resolved fork point, one identified victim, an *exact*-match verified source, and a write-up to map a class from. Not the 291 that clear everything but the match strength: a plain match permits "differences in source code comments, variable names, or other metadata fields such as source paths", so its lines have moved, and a locator here is a line span.


### `proxy-rate.json`

`docs/design.md` §6.2 left open whether the dominant shape of a "fixed" state is a proxy whose implementation was replaced. If it were, one enum member would have been enough for all four situations that carry that claim.

**It is not.** Between 16 and 142 of 471 exploited contracts are proxies (3% to 30%) so a proxy upgrade cannot be the dominant shape, and the hypothesis is refuted rather than untested. The previous attempt reported *no proxies at all* from the same kind of population, which was the instrument: it asked a verification repository, and that reports a recognised proxy standard rather than proxy-ness.

The answer is a range because the two directions are not symmetric. No `DELEGATECALL` conclusively means no proxy; one present is an upper bound, since libraries and facet dispatchers have one too. The lower bound comes from contracts at the distribution's own minimum length, which is derived per run, not from a byte-length cutoff, and the data offers none to pick.
