"""Reading runtime bytecode for the one property a proxy cannot hide.

`AddressPin` settles that a proxy's pin names the implementation, and says the
proxy *rate* has to be measured "from the chain: an implementation storage slot,
or a `delegatecall` in the runtime bytecode". This is the second of those, and
it is the one that can actually be taken: reading a storage slot at a fork point
needs archive state, which public endpoints refuse, while runtime code is
immutable and answers at any block.

## What the result means, in both directions

The two directions are not symmetric, and the asymmetry is the whole value:

- **No `DELEGATECALL` means not a proxy.** Conclusive. Forwarding a call to
  another contract's code while keeping your own storage is what a proxy does,
  and there is no other instruction that does it.
- **A `DELEGATECALL` does not mean a proxy.** It is an upper bound. A contract
  that links a library, dispatches to facets, or batches calls has one too.

So this bounds the rate from above and rules proxies out from below, which is
strictly more than the instrument §6.2 found wanting: a verification repository
reports a *recognised* proxy standard, so it under-reports, and it returned "not
a proxy" for two of three contracts whose own names end in `Proxy`. A bespoke
proxy is invisible to that and visible here.

No threshold turns the upper bound into a count. A short contract with a
`DELEGATECALL` is almost always a proxy and a long one usually is not, but
"almost always" is not a measurement and a byte-length cutoff would be a
threshold picked rather than measured -- the mistake a language filter already
made elsewhere in this corpus. `code_size` is reported instead, so a reader can
see the shape without this module asserting one.

## Why the walk cannot be a substring search

`0xf4` occurs constantly inside `PUSH` immediates -- in addresses, in selectors,
in constants -- and none of those bytes is an instruction. A scan that looked
for the byte would report a `DELEGATECALL` in most contracts on the chain, which
is a proxy rate of nearly 100% and reads as a discovery rather than as a bug.
The immediate bytes have to be skipped, which needs nothing more than the length
`PUSH` encodes in its own opcode.
"""

from __future__ import annotations

DELEGATECALL = 0xF4
CALLCODE = 0xF2
"""The deprecated predecessor. Counted separately rather than folded in.

`CALLCODE` keeps the caller's address but *not* its storage, so a contract using
it is not the shape a proxy pin has to worry about. It is reported because a
2016-era contract may still use it, and silently counting it as a proxy would
put contracts in the proxy bucket for the wrong reason.
"""

_PUSH0 = 0x5F
_PUSH1 = 0x60
_PUSH32 = 0x7F


def instructions(runtime: bytes) -> list[int]:
    """The opcodes of `runtime`, with every `PUSH` immediate skipped.

    Truncated code is not an error here. A `PUSH32` two bytes from the end is
    what a compiler's trailing metadata looks like when it is cut, and the walk
    stops rather than reading past the buffer -- an opcode list is not a claim
    that the code is well-formed.
    """
    found: list[int] = []
    position = 0
    end = len(runtime)
    while position < end:
        opcode = runtime[position]
        found.append(opcode)
        if _PUSH1 <= opcode <= _PUSH32:
            position += 1 + (opcode - _PUSH0)
        else:
            position += 1
    return found


def has_delegatecall(runtime: bytes) -> bool:
    """Whether the code can forward a call while keeping its own storage."""
    return DELEGATECALL in instructions(runtime)


def has_callcode(runtime: bytes) -> bool:
    return CALLCODE in instructions(runtime)


def parse_code(hex_code: str) -> bytes:
    """Runtime code as an RPC returns it: `0x`-prefixed hex, or `0x` for none.

    An account with no code answers `0x`, which is not a failure and not a
    contract either. It is returned as empty bytes so the caller counts it as
    its own outcome: a contract that has since self-destructed answers this way,
    and counting it as "no delegatecall, therefore not a proxy" would draw a
    conclusion about code nobody can read any more.
    """
    body = hex_code.removeprefix("0x").removeprefix("0X")
    if not body:
        return b""
    if len(body) % 2:
        raise ValueError(f"runtime code has an odd hex length: {len(body)} digits")
    return bytes.fromhex(body)
