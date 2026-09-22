"""Reading a chain-incident proof-of-concept for the fields an `AddressPin` needs.

An incident record is pinned by `AddressPin`: a chain, an address, and a fork
point that pins the *state* rather than the source. Nothing in the corpus
produces one yet. `fetch` refuses an `AddressPin` outright -- "a deployed
address's source of truth is a chain explorer, not a repository" -- and this
module is the pure half of closing that gap: it reads a proof-of-concept file
from a maintained incident archive and reports what the artefact **states**.

**Pure and offline, for the reason `sources` gives**: fetching is an outward
act with its own licensing and rate-limit questions, and keeping it out is what
lets the whole harvest stage run in the offline gate. Text in, dataclasses out.

## What the artefact states

Measured over the 874 proof-of-concept files in one archive at one pinned
commit -- the tool that drives this module records both, because a population
that grows makes an unpinned count unreproducible:

- **871 call `vm.createSelectFork`**, so the chain is read out of the artefact
  rather than recalled.
- The fork point is an inline literal in 493 and a **named constant** in a
  further 187. A reader that accepts only literals under-reports fork points by
  a fifth, which is why `_CONSTANT` exists.
- **The arithmetic is evaluated, not dropped.** 56 files write
  `blocknumToForkFrom = 6_467_248 - 1`: the block *before* the exploit, which
  is the state in which the defect was still live. Taking the literal would pin
  the block in which the exploit already landed -- a different chain state, and
  the wrong one, silently.
- The victim is annotated in a header comment, under several spellings. Two
  carry an address: `Vulnerable Contract` and `Vulnerable Contract Code`, the
  second being a link to verified source at an address. `Vuln Contract` and
  `Victim` are the same claim in fewer words.

`Vulnerability` is **excluded** although it looks like the same key. It carries
a root-cause phrase -- `// Vulnerability : Price Manipulation` -- and a reader
that treats it as a contract annotation counts a file as victim-identified on
the strength of a sentence with no address in it.

## The limit this instrument has, stated rather than discovered later

These are addresses the file **mentions**, not addresses the exploit **calls**.
The distinction matters: a mentioned address may be an unused constant, and a
called one may be reached through a factory and never appear as a literal.
Obtaining call targets means running the proof-of-concept under a forking test
runner against an archive node, which is a different instrument with a
different cost, and it is the one to reach for if the annotation's coverage is
not enough.

That is the same shape of error `docs/design.md` §6.2 records against the
previous attempt, which identified the victim by matching a verified contract's
own name against the project's name and failed on 18 of 34. The annotation read
here is the archive's own, which is why it is worth preferring: it is an
external denominator (§6.3) rather than an inference of ours.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

CHAIN_IDS: dict[str, int] = {
    "mainnet": 1,
    "optimism": 10,
    "cronos": 25,
    "bsc": 56,
    "gnosis": 100,
    "polygon": 137,
    "fantom": 250,
    "zksync": 324,
    "sei": 1329,
    "moonriver": 1285,
    "mantle": 5000,
    "base": 8453,
    "arbitrum": 42161,
    "avalanche": 43114,
    "celo": 42220,
    "linea": 59144,
    "blast": 81457,
}
"""Fork alias to EIP-155 chain id.

The aliases are the archive's, declared in its `foundry.toml`. The ids are
**cross-checked against the verification repository's own chain list** rather
than remembered: each id above is listed there under the name its alias
implies, which is the check that catches a plausible-looking wrong id -- and a
wrong chain id does not fail, it silently resolves an address on another chain.

Deliberately incomplete. An alias this map does not hold is a counted loss with
a name, not a guess: two aliases appear in fork calls without being declared in
the archive's own config, and some fork calls pass an RPC **URL** in place of an
alias, from which no chain id can be read at all.
"""


class ForkPointForm(StrEnum):
    """How a fork point was stated, kept because the forms are not equivalent.

    A transaction hash pins a block *and* a position within it, so it is the
    stronger of the two rather than a weaker one. Whether the value was inline
    or behind a constant says nothing about the pin's strength and is recorded
    because it is the axis on which this reader was once wrong.
    """

    BLOCK = "block_number"
    BLOCK_VIA_CONSTANT = "block_number_via_constant"
    TRANSACTION = "transaction_hash"
    TRANSACTION_VIA_CONSTANT = "transaction_hash_via_constant"
    ABSENT = "absent"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class ForkTarget:
    """Where in which chain's history a proof-of-concept runs."""

    alias: str
    chain_id: int | None
    point: str | None
    form: ForkPointForm

    @property
    def pinnable(self) -> bool:
        """Whether this is enough for an `AddressPin`: a chain *and* a point."""
        return self.chain_id is not None and self.point is not None


@dataclass(frozen=True, slots=True)
class IncidentPoC:
    """One proof-of-concept file, as its own text describes it."""

    incident: str
    path: str
    fork: ForkTarget | None
    victims: tuple[str, ...]
    addresses: tuple[str, ...]
    analysis: tuple[str, ...]

    @property
    def victim(self) -> str | None:
        """The victim when the artefact names exactly one, else None.

        Two annotated victims is not half an answer. The record would have to
        choose, and a reader that took the first would be picking by document
        order -- which is the "rank is not a score" error in another costume.
        """
        return self.victims[0] if len(self.victims) == 1 else None


_HEADER = 4000
"""How far into the file the annotation block is looked for.

The annotations sit above the first `interface` declaration. Reading the whole
file instead would pull addresses out of Solidity string literals and comments
inside the exploit body, which are not annotations of anything.
"""

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\b")
_VICTIM = re.compile(
    r"^//[ \t]*(?:Vulnerable[ \t]+Contract(?:[ \t]+Code)?"
    r"|Vuln[ \t]+Contract|Victim(?:[ \t]+Contract)?)"
    r"[^:\n]*:(?P<rest>[^\n]*)$",
    re.M | re.I,
)
_FORK = re.compile(
    r"createSelectFork\([ \t\n]*(?P<quote>[\"'])(?P<alias>[^\"']+)(?P=quote)"
    r"(?:[ \t\n]*,[ \t\n]*(?P<point>[^)]*?))?[ \t\n]*\)",
    re.S,
)
_CONSTANT = re.compile(
    r"\b(?:uint\d*|bytes32)[ \t]+(?:constant[ \t]+|public[ \t]+|internal[ \t]+|private[ \t]+)*"
    r"(?P<name>\w+)[ \t]*=[ \t]*(?P<expression>(?:0x[0-9a-fA-F]+|[0-9_]+)"
    r"(?:[ \t]*-[ \t]*[0-9_]+)*)",
)
"""A constant declaration, capturing the **whole** right-hand expression.

Capturing only the first number is a bug this had and the module docstring
already warned against: 56 files declare `blocknumToForkFrom = 6_467_248 - 1`,
and a reader that stops at the literal pins the block the exploit landed in
rather than the one before it. The subtraction is in the declaration far more
often than in the fork call, so the arithmetic has to be evaluated on both
sides or it is evaluated where it almost never appears.
"""

_TERM = re.compile(r"^(?P<head>0x[0-9a-fA-F]+|[0-9_]+|\w+)(?P<tail>(?:[ \t]*-[ \t]*[0-9_]+)*)$")
_SUBTRAHEND = re.compile(r"-[ \t]*(?P<value>[0-9_]+)")
_URL = re.compile(r"https?://\S+")
_EXPLORER = re.compile(r"/(?:address|tx|token)/0x[0-9a-fA-F]+", re.I)
_TRANSACTION_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_EXP_SUFFIX = re.compile(r"_exp\d*$", re.I)


def incident_key(path: str) -> str:
    """A key that collapses several proofs-of-concept of one incident.

    `2021-07/Chainswap_exp1.sol` and `_exp2.sol` are two artefacts for one
    incident, and counting them separately would report a population larger
    than the number of incidents in it.

    Only the `_exp<n>` suffix is stripped, never trailing digits in the name
    itself: `Cream_exp.sol` and `Cream_2_exp.sol` are two different incidents
    at one protocol, and a rule that stripped digits would merge them and lose
    one.
    """
    parts = path.replace("\\", "/").rstrip("/").split("/")
    stem = parts[-1].removesuffix(".sol")
    directory = parts[-2] if len(parts) > 1 else ""
    base = _EXP_SUFFIX.sub("", stem)
    return f"{directory}/{base}" if directory else base


def _literal(expression: str) -> tuple[str | None, bool]:
    """Evaluate `<literal> (- <literal>)*`, returning the value and whether it is a hash.

    A transaction hash carrying arithmetic is refused rather than truncated:
    subtracting from a hash does not name an earlier transaction, and a reader
    that dropped the subtraction would return a hash the artefact did not state.
    """
    term = _TERM.match(expression.strip())
    if term is None:
        return None, False
    head, tail = term.group("head"), term.group("tail")
    if _TRANSACTION_HASH.match(head):
        return (None, False) if tail.strip() else (head, True)
    digits = head.replace("_", "")
    try:
        value = int(digits, 16) if digits.startswith("0x") else int(digits, 10)
    except ValueError:  # pragma: no cover - the regex admits only these two shapes
        return None, False
    for subtraction in _SUBTRAHEND.finditer(tail):
        value -= int(subtraction.group("value").replace("_", ""))
    return (str(value), False) if value > 0 else (None, False)


def _resolve(text: str, raw: str | None) -> tuple[str | None, ForkPointForm]:
    """The literal a fork call's second argument means, constants resolved."""
    point = (raw or "").strip()
    if not point:
        return None, ForkPointForm.ABSENT
    term = _TERM.match(point)
    if term is None:
        return None, ForkPointForm.UNRESOLVED

    head, tail = term.group("head"), term.group("tail")
    via_constant = False
    if not re.fullmatch(r"0x[0-9a-fA-F]+|[0-9_]+", head):
        declared: dict[str, set[str]] = {}
        for found in _CONSTANT.finditer(text):
            declared.setdefault(found.group("name"), set()).add(found.group("expression").strip())
        expressions = declared.get(head)
        # Declared twice with different values is **refused, not chosen**. 77
        # files declare some name twice, and which one a fork call sees depends
        # on Solidity scoping this reader does not model. Taking the first or
        # the last would be picking by document order -- and a fork point picked
        # by document order is a chain state nobody stated.
        if expressions is None or len(expressions) != 1:
            return None, ForkPointForm.UNRESOLVED
        point, via_constant = f"{next(iter(expressions))}{tail}", True

    value, is_hash = _literal(point)
    if value is None:
        return None, ForkPointForm.UNRESOLVED
    if is_hash:
        form = ForkPointForm.TRANSACTION_VIA_CONSTANT if via_constant else ForkPointForm.TRANSACTION
    else:
        form = ForkPointForm.BLOCK_VIA_CONSTANT if via_constant else ForkPointForm.BLOCK
    return value, form


def fork_target(text: str) -> ForkTarget | None:
    """The first fork a proof-of-concept selects, or None if it selects none.

    The first, because a file that forks twice is testing something across two
    chains and a record pinned to either would describe half of it. That shape
    is rare enough to be a counted loss rather than a modelled case.
    """
    found = _FORK.search(text)
    if found is None:
        return None
    alias = found.group("alias").strip()
    point, form = _resolve(text, found.group("point"))
    return ForkTarget(
        alias=alias,
        chain_id=CHAIN_IDS.get(alias.lower()),
        point=point,
        form=form,
    )


def _victims(header: str) -> tuple[str, ...]:
    """Addresses the archive annotates as the exploited contract, deduplicated.

    Lowercased before deduplication. The same address appears in a checksummed
    and a lowercase form in the same file, and a set of the raw strings counts
    one contract twice -- which inflates the "annotates exactly one victim"
    figure into "annotates two and is therefore ambiguous", the opposite of the
    truth.
    """
    seen: dict[str, None] = {}
    for line in _VICTIM.finditer(header):
        for address in _ADDRESS.findall(line.group("rest")):
            seen.setdefault(address.lower(), None)
    return tuple(seen)


def addresses(text: str) -> tuple[str, ...]:
    """Every address the file mentions, lowercased, in first-mention order.

    An upper bound on the exploit's call targets and not the targets
    themselves; the module docstring says why that distinction is the
    instrument's limit rather than a detail.
    """
    seen: dict[str, None] = {}
    for found in _ADDRESS.finditer(text):
        seen.setdefault(found.group(0).lower(), None)
    return tuple(seen)


def _analysis(header: str) -> tuple[str, ...]:
    """Links in the header that are not explorer links.

    An explorer link is an address or transaction annotation, already read as
    one. What is left is where the incident was written up, which is the only
    route to a defect class: the artefact states what was attacked and never
    which of the nine classes it belongs to.
    """
    seen: dict[str, None] = {}
    for found in _URL.finditer(header):
        url = found.group(0).rstrip(".,);")
        if not _EXPLORER.search(url):
            seen.setdefault(url, None)
    return tuple(seen)


def parse_poc(path: str, text: str) -> IncidentPoC:
    """Everything this reader can take from one proof-of-concept file."""
    header = text[:_HEADER]
    return IncidentPoC(
        incident=incident_key(path),
        path=path,
        fork=fork_target(text),
        victims=_victims(header),
        addresses=addresses(text),
        analysis=_analysis(header),
    )
