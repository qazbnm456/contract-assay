# Security

## Reporting

Email **boik.su@cycraft.com**. Once this repository is public, GitHub's
**private vulnerability reporting** (Security → Report a vulnerability) is also
open and is the preferred channel.

This is a single-maintainer project. Expect an acknowledgement within 7 days.
There is no other service level. Please do not open a public issue for anything
in the first section below.

## What counts as a vulnerability here

This project's whole claim is that a finding it scores is a finding somebody can
check. The most serious defect class is therefore not memory safety or a network
service — it is **a way to make an unverifiable claim score**. Concretely, we
want to hear about:

1. **A citation that scores without being true.** Any input for which
   `contract-assay score` credits a prediction whose quote is not the source text
   at the lines it names, or whose source was never verified against its pinned
   digest. Two real examples, both since fixed: a locator one line wider than the
   quote used to fail whole-line containment, and the scorer once read each unit
   twice and gated only one of the reads, so a plant arriving after the gate
   scored 0.9402.
2. **An escape from `--source-root`.** `contract-assay fetch` and the local
   resolver write and read files under a root derived from corpus pins. A pin, a
   symlink or a path component that lands a write or a read outside that root is
   in scope, in either direction.
3. **A corpus record that can make the tool crash or hang the whole build.** The
   pipeline is supposed to refuse one malformed record and count it, never abort
   the corpus.

## What does not count

- **A detector that scores badly**, or a prediction you think should have
  matched. Open an issue with the run and the record.
- **A record whose adjudication you disagree with.** That is a corpus issue, and
  the record templates exist for it.
- **Arbitrary code execution from a submission you chose to run.**
  `contract-assay run` imports the detector module you point it at. That is what
  the command is for, and it is not sandboxed. Running a submission you did not
  write means running that author's code with your credentials and your
  filesystem — do it in a container you are willing to lose. If you need
  confinement, the benchmark does not provide it; put it outside.

## Supported versions

Pre-1.0. Only `main` is supported. Fixes land there and in the next release; no
backports.
