## What this changes

<!-- One sentence. If it changes a published figure, say which and to what. -->

## What it establishes

<!-- For a record: the pinned bytes, the locator, and where the locator came
     from. For an adapter: which population, and what it refuses. For a result:
     the pointer and the document it was built from. For code: the measurement
     that shows it works, not the argument that it should. -->

## Checks

- [ ] `ruff check . && ruff format --check . && mypy && pytest -q -m offline`
- [ ] New or changed behaviour has a test that fails when the behaviour is
      reverted (a count is not a behaviour — assert the reason)
- [ ] Any figure stated in code, docs or the commit message was measured, and
      the command that measured it is in the message
- [ ] For a record: `contract-assay verify corpus/records --source-root ./checkout`
