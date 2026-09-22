"""The opcode walk, and the substring search it exists to not be."""

from __future__ import annotations

import pytest

from contract_assay.corpus.bytecode import (
    CALLCODE,
    DELEGATECALL,
    has_callcode,
    has_delegatecall,
    instructions,
    parse_code,
)

pytestmark = pytest.mark.offline

STOP = b"\x00"
PUSH1 = b"\x60"
PUSH20 = b"\x73"
PUSH32 = b"\x7f"


class TestTheWalkSkipsPushImmediates:
    def test_a_delegatecall_byte_inside_a_push_is_not_an_instruction(self) -> None:
        """The defect this module exists to avoid.

        `0xf4` appears constantly inside addresses and constants. A substring
        search reports a proxy in most contracts on the chain, which looks like
        a finding rather than a bug.
        """
        code = PUSH1 + bytes([DELEGATECALL]) + STOP
        assert DELEGATECALL in code
        assert not has_delegatecall(code)
        assert instructions(code) == [0x60, 0x00]

    def test_a_delegatecall_byte_inside_a_twenty_byte_push_is_skipped(self) -> None:
        code = PUSH20 + bytes([DELEGATECALL]) * 20 + STOP
        assert not has_delegatecall(code)

    def test_a_real_delegatecall_is_found(self) -> None:
        code = PUSH1 + b"\x00" + bytes([DELEGATECALL])
        assert has_delegatecall(code)

    def test_a_delegatecall_immediately_after_a_push_ends_is_found(self) -> None:
        """Off by one in the skip length shows up here and nowhere else."""
        assert has_delegatecall(PUSH1 + b"\xaa" + bytes([DELEGATECALL]))

    def test_push32_consumes_thirty_two_bytes(self) -> None:
        code = PUSH32 + bytes(32) + STOP
        assert instructions(code) == [0x7F, 0x00]

    def test_push0_consumes_none(self) -> None:
        """`PUSH0` is in the push range by opcode but takes no immediate.

        A skip computed as `opcode - 0x5f` gives zero for it only if the range
        check starts at `PUSH1`, which is why the constant is not `_PUSH0`.
        """
        assert instructions(b"\x5f" + bytes([DELEGATECALL])) == [0x5F, DELEGATECALL]
        assert has_delegatecall(b"\x5f" + bytes([DELEGATECALL]))

    def test_truncated_push_data_stops_the_walk_rather_than_reading_past_it(self) -> None:
        assert instructions(PUSH32 + b"\x01\x02") == [0x7F]

    def test_empty_code_has_no_instructions(self) -> None:
        assert instructions(b"") == []
        assert not has_delegatecall(b"")


class TestCallcodeIsCountedApart:
    def test_callcode_is_not_reported_as_a_delegatecall(self) -> None:
        """It keeps the caller's address but not its storage, so it is not the
        shape a proxy pin has to worry about."""
        code = bytes([CALLCODE])
        assert has_callcode(code)
        assert not has_delegatecall(code)

    def test_a_callcode_byte_inside_a_push_is_also_skipped(self) -> None:
        assert not has_callcode(PUSH1 + bytes([CALLCODE]))


class TestParsingWhatAnRpcReturns:
    def test_the_prefix_is_optional_and_case_is_ignored(self) -> None:
        assert parse_code("0x60f4") == b"\x60\xf4"
        assert parse_code("0X60F4") == b"\x60\xf4"
        assert parse_code("60f4") == b"\x60\xf4"

    def test_an_account_with_no_code_is_empty_not_an_error(self) -> None:
        """Self-destructed contracts answer this way, and treating it as
        "no delegatecall, therefore not a proxy" concludes about unreadable code."""
        assert parse_code("0x") == b""

    def test_an_odd_hex_length_is_refused(self) -> None:
        with pytest.raises(ValueError, match="odd hex length"):
            parse_code("0xabc")
