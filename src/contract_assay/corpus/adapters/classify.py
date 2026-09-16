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

The table is deliberately narrow. A title matching nothing is skipped and
counted, which turns "how much of this platform do the nine classes cover" into
a number the harvest report states. Widening it until the coverage number
improves is the generous-enumerator failure (§6.3) one level up -- raising a
figure by loosening what counts rather than by finding more.
"""

from __future__ import annotations

from contract_assay.models import VulnerabilityClass

__all__ = ["CLASS_KEYWORDS", "classify_title"]

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
    ("access control", VulnerabilityClass.ACCESS_CONTROL),
    ("unauthori", VulnerabilityClass.ACCESS_CONTROL),
    ("permission", VulnerabilityClass.ACCESS_CONTROL),
    ("only owner", VulnerabilityClass.ACCESS_CONTROL),
    ("onlyowner", VulnerabilityClass.ACCESS_CONTROL),
    ("slippage", VulnerabilityClass.SLIPPAGE),
    ("min amount out", VulnerabilityClass.SLIPPAGE),
    ("minimum amount out", VulnerabilityClass.SLIPPAGE),
    ("oracle", VulnerabilityClass.ORACLE_INTEGRITY),
    ("stale price", VulnerabilityClass.ORACLE_INTEGRITY),
    ("price feed", VulnerabilityClass.ORACLE_INTEGRITY),
    ("chainlink", VulnerabilityClass.ORACLE_INTEGRITY),
    ("flash loan", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("flashloan", VulnerabilityClass.FLASHLOAN_MANIPULATION),
    ("rounding", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("precision", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("overflow", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("underflow", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("truncat", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("downcast", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("integer division", VulnerabilityClass.ARITHMETIC_ROUNDING),
    ("denial of service", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("dos", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("griefing", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("locked forever", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("locked indefinitely", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("permanently locked", VulnerabilityClass.DENIAL_OF_SERVICE),
    ("lost forever", VulnerabilityClass.DENIAL_OF_SERVICE),
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
    lowered = title.lower()
    for keyword, cls in CLASS_KEYWORDS:
        if keyword in lowered:
            return (cls,)
    return ()
