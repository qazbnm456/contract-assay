"""A stand-in for YOUR harness. Replace `analyze` and nothing else in this file.

The benchmark never imports this module; `byo_caller.py` does. It exists so the
example runs end to end before you have connected anything, and so that the
shape of what the adapter needs from you is written down in one place:

- **claims in your own taxonomy.** `category` is whatever your harness calls a
  finding. The benchmark's classes are fixed (`VulnerabilityClass`), and
  `byo_caller.CATEGORY_TO_CLASS` is where yours are mapped onto them.
- **a quote that is whole lines of the span the claim names.** Slice the source
  by line at the lines you report and the two cannot disagree. A paraphrase, or
  half a line, fails the benchmark's citation check and the run is `invalid`.
- **what the analysis cost.** `calls` and `tokens` are reported, never assumed:
  `contract-assay run` states the budgets and does not enforce them, so this is
  the only place a figure for what you spent can come from.

The rule below is a toy that stands in for a detector and claims nothing real.
It is here to give the adapter something to adapt.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Claim:
    category: str
    start_line: int
    end_line: int
    quote: str
    reasoning: str


@dataclass(frozen=True, slots=True)
class Analysis:
    claims: tuple[Claim, ...]
    model_id: str
    calls: int
    tokens: int


def analyze(source: str) -> Analysis:
    """Run your harness over one source file. Raise on failure; do not guess."""
    claims = tuple(
        Claim(
            category="authorization",
            start_line=number,
            end_line=number,
            quote=line,
            reasoning="tx.origin is the original sender, not the caller, so a contract "
            "that authorises on it can be driven by whoever the owner is tricked into calling",
        )
        for number, line in enumerate(source.splitlines(), start=1)
        if "tx.origin" in line
    )
    # Report what your harness really spent. A stand-in that makes no model call
    # says so with zeros, and `model_id` still names what produced the claims.
    return Analysis(claims=claims, model_id="byo-stand-in", calls=0, tokens=0)
