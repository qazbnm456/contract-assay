"""The benchmark's own source analysis, public because a submission should use it.

This package is what `Detector.evidence()` runs by default, and it is exported
so a submission can call it directly rather than reimplement it.

The reason is about what a comparison measures. A benchmark for vulnerability
detection is meant to compare judgement about vulnerabilities; if every entrant
has to write its own parser queries first, then two figures differ partly
because one entrant wrote better tree-sitter code, and that second variable is
in every comparison the benchmark publishes. Shipping the analysis holds it
constant. Overriding it is still allowed -- a detector that can establish
something this layer cannot should say so -- but nobody has to start there.

Two things to reach for:

- `Syntax.of(source)` -- a parsed unit queried by shape: `functions`, `calls`,
  `writes`, `guards`, `loops`, `arithmetic`, `member_reads`, `state_variables`,
  `callers_of`. Every site carries `start_line`, `end_line`, `host` (contract
  and function) and `text`, the **exact** source it spans. `site.locator(path)`
  hands back a `Locator` in the shape a `Finding` wants.
- `predicates.run_all(syntax, path, classes=[...])` -- the registered
  predicates, filtered to the classes you care about, returned as
  `EvidenceRef`s already located. `coverage_by_class()` says which predicates
  exist, which is a different claim from which classes are covered.

The function `predicates.predicates()` -- the full registry -- is deliberately
**not** re-exported here. A package-level name equal to one of its own submodule
names shadows the submodule, so `from contract_assay.evidence import predicates`
would hand back a function and every `predicates.run_all(...)` in the wild would
break. Reach it at `contract_assay.evidence.predicates.predicates()`.

What `site.text` is for: a `Finding`'s quote is checked against the source at
its locator, unconditionally, and a quote typed from memory fails that check
about half the time. Quoting `site.text` or the lines a site spans is how a
true finding survives to be scored.
"""

from contract_assay.evidence.predicates import (
    PredicateSpec,
    coverage_by_class,
    run_all,
)
from contract_assay.evidence.solidity import Declaration, DeclarationKind, index_source
from contract_assay.evidence.syntax import (
    Argument,
    ArithmeticSite,
    CallSite,
    Destructuring,
    FunctionSite,
    GuardSite,
    Host,
    LoopSite,
    Site,
    Syntax,
    WriteSite,
)

__all__ = [
    "Argument",
    "ArithmeticSite",
    "CallSite",
    "Declaration",
    "DeclarationKind",
    "Destructuring",
    "FunctionSite",
    "GuardSite",
    "Host",
    "LoopSite",
    "PredicateSpec",
    "Site",
    "Syntax",
    "WriteSite",
    "coverage_by_class",
    "index_source",
    "run_all",
]
