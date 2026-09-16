"""Per-platform report adapters.

One module per platform, because a report format is platform-specific knowledge
and nothing about it generalises. What does generalise -- the two-phase protocol,
the accounting, the skip causes -- lives in `corpus.harvest`.

No real report text is vendored anywhere in this repository, including in tests.
Report prose is somebody else's writing, and embedding it here would attach its
terms to an MIT release for exactly the reason the corpus stores pointers instead
of source (§6.1). Adapter fixtures are therefore written by hand to mimic a
format's structure, and an adapter is validated against real reports outside the
tree.
"""

from contract_assay.corpus.adapters.code4rena import (
    Code4renaAdapter,
    Code4renaEnumerator,
    EnumeratedFinding,
)

__all__ = ["Code4renaAdapter", "Code4renaEnumerator", "EnumeratedFinding"]
