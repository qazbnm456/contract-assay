"""Mapping a finding's prose onto the nine classes.

Shared across adapters because it is not platform knowledge. Audit platforms
publish a *severity* -- high, medium, low -- and no vulnerability taxonomy, so
every adapter faces the same problem: the class has to be read out of English.

A separate, runnable component rather than a helper inside one adapter, for the
reason that applies to enumeration too. This judgement decides which findings
enter the corpus at all, so it needs to be testable on its own, comparable
across platforms, and regression-tested -- otherwise a later change that widened
it would show up as improved coverage rather than as a change in what "covered"
means.

Keyword matching on prose is not what §2.3 forbids. That rule concerns
predicates over *code*, where an identifier is the author's to rename and a name
match is therefore evidence that can be manufactured. Nobody renames the English
word "reentrancy" to defeat a harvester.

Which is an argument about *prose*, and the table was reading identifiers too:
a title is written in English with Solidity names quoted inside it, and
`ETHOracle.getLatestPrice` was classifying a decimals bug as oracle integrity,
`receiveFlashLoan` a callback bug as flash-loan manipulation. Those names are
the author's to choose, so the exemption above does not cover them, and quoted
spans are dropped before matching. It cost four classifications over one sample
of 174 findings and every one of them was wrong.

Two terms are dropped even unquoted, because they name a *guard that is
present*: a finding about `nonReentrant` on a `receive()` making withdrawals
fail is a denial of service, and the table read the modifier's name and called
it reentrancy. No keyword can tell a missing guard from a harmful one, so the
word stops being a signal either way; a title whose only claim is the guard's
name is left unmapped and counted.

The table is deliberately narrow. A title matching nothing is skipped and
counted, which turns "how much of this platform do the nine classes cover" into
a number the harvest report states. Widening it until the coverage number
improves is the generous-enumerator failure (§6.3) one level up -- raising a
figure by loosening what counts rather than by finding more.
"""

from __future__ import annotations

import re

from contract_assay.models import VulnerabilityClass

__all__ = ["CLASS_KEYWORDS", "classify_title"]

_QUOTED = re.compile(r"`[^`]*`")
_NAMES_A_GUARD = ("nonreentrant", "reentrancyguard")

CLASS_KEYWORDS: tuple[tuple[str, VulnerabilityClass], ...] = (
    # Synonyms for a property already in the nine, added after hand-assessing 40
    # unmapped titles. Each names the same defect in different words -- "re-enter"
    # and "reentrancy", "truncation" and "rounding" -- which is a recall fix, not
    # a widening of what counts. Terms that would have raised the number by
    # admitting other properties were left out: "bypass" alone matches any
    # circumvented rule, and "locked" alone matches locking as a feature.
    ("reentran", VulnerabilityClass.REENTRANCY),
    ("re-entran", VulnerabilityClass.REENTRANCY),
    ("re-enter", VulnerabilityClass.REENTRANCY),
    ("reenter", VulnerabilityClass.REENTRANCY),
    ("non-cei", VulnerabilityClass.REENTRANCY),
    ("checks-effects", VulnerabilityClass.REENTRANCY),
    # Hand-assessed over 141 unmapped titles from 17 reports. Each addition was
    # kept only if every title it newly mapped was right on inspection, and the
    # rejections are recorded here because the count is the point: "incorrect
    # calculation" mapped two titles and both were wrong -- a mistaken formula
    # is not a rounding defect -- "entropy" two and one was wrong, "blacklist"
    # two and one, "cannot" three and one ("role providers cannot be EOAs as
    # stated in the documentation" is a documentation mismatch), "forced to" and
    # "ignored" one each and both wrong. A keyword that raises coverage by
    # admitting another property is the failure this table is built to avoid.
    ("access control", VulnerabilityClass.ACCESS_CONTROL),
    ("unauthori", VulnerabilityClass.ACCESS_CONTROL),
    ("permission", VulnerabilityClass.ACCESS_CONTROL),
    ("only owner", VulnerabilityClass.ACCESS_CONTROL),
    ("onlyowner", VulnerabilityClass.ACCESS_CONTROL),
    ("unrestricted", VulnerabilityClass.ACCESS_CONTROL),
    ("anyone can", VulnerabilityClass.ACCESS_CONTROL),
    ("slippage", VulnerabilityClass.SLIPPAGE),
    ("min amount out", VulnerabilityClass.SLIPPAGE),
    ("minimum amount out", VulnerabilityClass.SLIPPAGE),
    ("oracle", VulnerabilityClass.ORACLE_INTEGRITY),
    ("stale price", VulnerabilityClass.ORACLE_INTEGRITY),
    ("price feed", VulnerabilityClass.ORACLE_INTEGRITY),
    ("chainlink", VulnerabilityClass.ORACLE_INTEGRITY),
    # "flash loan" and "flashloan" alone were removed after mapping four titles
    # and getting all four wrong: two were flash-loan *fee accounting*, one a
    # rounding defect in a fee, one a revert. The phrase names a mechanism, and
    # this class is a defect property -- a price moved inside one transaction
    # with borrowed capital -- which is the same error as reading "reentrancy"
    # off a `nonReentrant` modifier. Removing it let the defect word win: the
    # rounding title now maps to rounding and the reverting one to denial of
    # service, both correctly, and the two accounting titles map to nothing,
    # also correctly.
    ("flash loan attack", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("flashloan attack", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("price manipulation", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("rounding", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("precision", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("overflow", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("underflow", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("truncat", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("downcast", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("integer division", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("imprecis", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("denial of service", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("dos", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("griefing", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("locked forever", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("locked indefinitely", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("permanently locked", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("lost forever", VulnerabilityClass.DENIAL_OF_SERVICE),
    # How these reports actually phrase a denial of service. The class was
    # matching the *name* of the category and almost nothing writes it: of 141
    # unmapped titles, seventeen described an action that could be made to fail,
    # in these words. They sit after the arithmetic terms deliberately -- "revert
    # due to underflow error" is a rounding defect whose symptom is a revert, and
    # first match wins.
    ("revert", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("always fail", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("will fail", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("unable to", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("not able to", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("won't be able", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("inability to", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("irrecoverable", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("stuck", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("brick", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("prevent", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("randomness", VulnerabilityClass.INSECURE_RANDOMNESS),
    ("unchecked return", VulnerabilityClass.UNCHECKED_EXTERNAL_CALL),
    ("return value", VulnerabilityClass.UNCHECKED_EXTERNAL_CALL),
)


def classify_title(title: str) -> tuple[VulnerabilityClass, ...]:
    """Map a finding title onto the nine classes, or onto none.

    First match wins and only one class is assigned. A title mentioning two
    concepts is usually about one of them, and multi-labelling out of prose would
    put more confidence in a keyword table than it deserves -- §6.1 permits
    multi-labelled records because one *location* can host several classes, which
    is a different claim from one title matching several words.
    """
    lowered = _QUOTED.sub(" ", title).lower()
    for guard in _NAMES_A_GUARD:
        lowered = lowered.replace(guard, " ")
    for keyword, cls in CLASS_KEYWORDS:
        if keyword in lowered:
            return (cls,)
    return ()
