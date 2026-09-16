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

from contract_assay.corpus.adapters.classify import CLASS_KEYWORDS, classify_title
from contract_assay.corpus.adapters.code4rena import (
    Code4renaAdapter,
    Code4renaEnumerator,
    EnumeratedFinding,
)
from contract_assay.corpus.adapters.immunefi import (
    CommitResolver,
    ImmunefiAdapter,
    ImmunefiEnumerator,
    ImmunefiReport,
)
from contract_assay.corpus.adapters.markdown import (
    SourceCitation,
    contest_snapshot,
    permalinks,
    quoted_source,
    section,
)
from contract_assay.corpus.adapters.sherlock import (
    SherlockAdapter,
    SherlockEnumerator,
    SherlockIssue,
)

__all__ = [
    "CLASS_KEYWORDS",
    "Code4renaAdapter",
    "Code4renaEnumerator",
    "CommitResolver",
    "EnumeratedFinding",
    "ImmunefiAdapter",
    "ImmunefiEnumerator",
    "ImmunefiReport",
    "SherlockAdapter",
    "SherlockEnumerator",
    "SherlockIssue",
    "SourceCitation",
    "classify_title",
    "contest_snapshot",
    "permalinks",
    "quoted_source",
    "section",
]
