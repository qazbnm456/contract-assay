"""What a proof-of-concept file states, and what this reader refuses to guess.

Every fixture here is written for the test. None is copied from an archive: the
formats being parsed are annotation *shapes*, and a shape is reproducible in
four lines, while pasting a real file would vendor somebody's incident write-up
into this repository to assert something about a regex.

The cases that matter are the refusals. A parser that returns a plausible fork
point for an expression it did not understand produces a record pinned to a
chain state nobody stated, and nothing downstream can tell that from a correct
one -- the digest will witness whatever bytes were at the wrong block.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.incidents import (
    CHAIN_IDS,
    ForkPointForm,
    addresses,
    fork_target,
    incident_key,
    parse_poc,
)

pytestmark = pytest.mark.offline

VICTIM = "0x" + "11" * 20
OTHER = "0x" + "22" * 20
TX = "0x" + "ab" * 32


def poc(body: str) -> str:
    return f"// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.10;\n{body}\n"


class TestIncidentKey:
    def test_the_exp_suffix_collapses_several_artefacts_of_one_incident(self) -> None:
        assert incident_key("src/test/2021-07/Chainswap_exp1.sol") == "2021-07/Chainswap"
        assert incident_key("src/test/2021-07/Chainswap_exp2.sol") == "2021-07/Chainswap"
        assert incident_key("src/test/2021-07/Chainswap_exp.sol") == "2021-07/Chainswap"

    def test_a_digit_in_the_name_itself_is_kept(self) -> None:
        """Two incidents at one protocol must not merge into one.

        `Cream_exp.sol` and `Cream_2_exp.sol` are separate incidents. A rule
        that stripped trailing digits from the name would report one where the
        archive holds two, and the lost one would never be counted as lost.
        """
        assert incident_key("src/test/2021-08/Cream_exp.sol") == "2021-08/Cream"
        assert incident_key("src/test/2021-10/Cream_2_exp.sol") == "2021-10/Cream_2"

    def test_the_dated_directory_is_part_of_the_key(self) -> None:
        assert incident_key("src/test/2024-03/Woofi_exp.sol") == "2024-03/Woofi"

    def test_a_bare_filename_still_yields_a_key(self) -> None:
        assert incident_key("Woofi_exp.sol") == "Woofi"


class TestTheForkPoint:
    def test_an_inline_block_number_is_read_with_its_underscores_removed(self) -> None:
        fork = fork_target(poc('vm.createSelectFork("mainnet", 18_000_000);'))
        assert fork is not None
        assert (fork.chain_id, fork.point, fork.form) == (1, "18000000", ForkPointForm.BLOCK)
        assert fork.pinnable

    def test_a_named_constant_is_resolved(self) -> None:
        fork = fork_target(
            poc('uint256 forkBlock = 18_000_000;\nvm.createSelectFork("bsc", forkBlock);')
        )
        assert fork is not None
        assert fork.chain_id == 56
        assert fork.point == "18000000"
        assert fork.form is ForkPointForm.BLOCK_VIA_CONSTANT

    def test_arithmetic_in_the_declaration_is_evaluated(self) -> None:
        """The regression. `= 6_467_248 - 1` forks the block *before* the exploit.

        This reader once captured only the first literal of the declaration and
        returned the un-decremented block. No count moved when it was fixed --
        the fork point was resolvable either way -- so 56 files were pinned one
        block late and every total looked right. That is why the assertion is on
        the value and not on whether a value was produced.
        """
        fork = fork_target(
            poc(
                "uint256 blocknumToForkFrom = 6_467_248 - 1;\n"
                'vm.createSelectFork("mainnet", blocknumToForkFrom);'
            )
        )
        assert fork is not None
        assert fork.point == "6467247"

    def test_arithmetic_in_the_fork_call_is_evaluated(self) -> None:
        fork = fork_target(
            poc('uint256 ATTACK_BLOCK = 500;\nvm.createSelectFork("mainnet", ATTACK_BLOCK - 1);')
        )
        assert fork is not None
        assert fork.point == "499"

    def test_arithmetic_on_both_sides_composes(self) -> None:
        fork = fork_target(poc('uint256 b = 1_000 - 4;\nvm.createSelectFork("mainnet", b - 6);'))
        assert fork is not None
        assert fork.point == "990"

    def test_a_transaction_hash_is_kept_as_a_hash(self) -> None:
        fork = fork_target(poc(f'vm.createSelectFork("mainnet", {TX});'))
        assert fork is not None
        assert (fork.point, fork.form) == (TX, ForkPointForm.TRANSACTION)

    def test_a_transaction_hash_behind_a_constant_is_still_a_hash(self) -> None:
        fork = fork_target(
            poc(f'bytes32 internal constant TX_HASH = {TX};\nvm.createSelectFork("bsc", TX_HASH);')
        )
        assert fork is not None
        assert (fork.point, fork.form) == (TX, ForkPointForm.TRANSACTION_VIA_CONSTANT)

    def test_arithmetic_on_a_transaction_hash_is_refused(self) -> None:
        """Subtracting from a hash does not name an earlier transaction."""
        fork = fork_target(poc(f'vm.createSelectFork("mainnet", {TX} - 1);'))
        assert fork is not None
        assert (fork.point, fork.form) == (None, ForkPointForm.UNRESOLVED)
        assert not fork.pinnable

    def test_a_name_that_is_declared_nowhere_is_refused(self) -> None:
        fork = fork_target(poc('vm.createSelectFork("mainnet", blocknumToForkFrom);'))
        assert fork is not None
        assert (fork.point, fork.form) == (None, ForkPointForm.UNRESOLVED)

    def test_a_name_declared_twice_with_different_values_is_refused(self) -> None:
        """Refused rather than chosen. Which one applies depends on scoping.

        Picking the first or the last would be picking by document order, and a
        fork point picked by document order is a chain state nobody stated.
        """
        fork = fork_target(
            poc(
                "uint256 forkBlock = 100;\nuint256 forkBlock = 200;\n"
                'vm.createSelectFork("mainnet", forkBlock);'
            )
        )
        assert fork is not None
        assert fork.form is ForkPointForm.UNRESOLVED

    def test_a_name_declared_twice_with_the_same_value_is_accepted(self) -> None:
        """The ambiguity is the disagreement, not the repetition."""
        fork = fork_target(
            poc(
                "uint256 forkBlock = 100;\nuint256 forkBlock = 100;\n"
                'vm.createSelectFork("mainnet", forkBlock);'
            )
        )
        assert fork is not None
        assert fork.point == "100"

    def test_a_fork_with_no_second_argument_is_absent_not_unresolved(self) -> None:
        """A distinct cause: the artefact stated a chain and no point."""
        fork = fork_target(poc('vm.createSelectFork("mainnet");'))
        assert fork is not None
        assert (fork.chain_id, fork.point, fork.form) == (1, None, ForkPointForm.ABSENT)
        assert not fork.pinnable

    def test_a_file_with_no_fork_call_has_no_fork_target(self) -> None:
        assert fork_target(poc("uint256 x = 1;")) is None

    def test_arithmetic_that_reaches_zero_is_refused(self) -> None:
        fork = fork_target(poc('vm.createSelectFork("mainnet", 1 - 1);'))
        assert fork is not None
        assert fork.form is ForkPointForm.UNRESOLVED

    def test_the_first_fork_is_the_one_read(self) -> None:
        """A file that forks twice tests something across two chains."""
        fork = fork_target(
            poc('vm.createSelectFork("mainnet", 10);\nvm.createSelectFork("bsc", 20);')
        )
        assert fork is not None
        assert (fork.chain_id, fork.point) == (1, "10")


class TestTheChain:
    def test_an_alias_the_map_does_not_hold_yields_no_chain_id(self) -> None:
        """Counted as a loss with a name, never guessed."""
        fork = fork_target(poc('vm.createSelectFork("citrea", 10);'))
        assert fork is not None
        assert (fork.alias, fork.chain_id) == ("citrea", None)
        assert not fork.pinnable

    def test_an_rpc_url_in_place_of_an_alias_yields_no_chain_id(self) -> None:
        """Some fork calls pass a URL. No chain id can be read from one."""
        fork = fork_target(poc('vm.createSelectFork("https://hyperliquid.drpc.org", 10);'))
        assert fork is not None
        assert fork.chain_id is None

    def test_the_alias_is_matched_without_regard_to_case(self) -> None:
        fork = fork_target(poc('vm.createSelectFork("Mainnet", 10);'))
        assert fork is not None
        assert fork.chain_id == 1

    def test_every_mapped_alias_has_a_positive_chain_id(self) -> None:
        assert CHAIN_IDS and all(chain > 0 for chain in CHAIN_IDS.values())

    def test_no_two_aliases_name_the_same_chain(self) -> None:
        """A duplicate id means one alias is mapped to the wrong chain."""
        assert len(set(CHAIN_IDS.values())) == len(CHAIN_IDS)


class TestTheVictim:
    def test_the_annotation_is_read_from_the_header(self) -> None:
        parsed = parse_poc("src/test/2024-03/X_exp.sol", poc(f"// Vulnerable Contract : {VICTIM}"))
        assert parsed.victims == (VICTIM,)
        assert parsed.victim == VICTIM

    def test_a_link_to_the_contract_code_is_the_same_claim(self) -> None:
        body = f"// Vulnerable Contract Code : https://etherscan.io/address/{VICTIM}#code"
        assert parse_poc("X_exp.sol", poc(body)).victim == VICTIM

    def test_the_shorter_spellings_are_read_too(self) -> None:
        assert parse_poc("X_exp.sol", poc(f"// Vuln Contract : {VICTIM}")).victim == VICTIM
        assert parse_poc("X_exp.sol", poc(f"// Victim : {VICTIM}")).victim == VICTIM

    def test_one_address_in_two_cases_is_one_victim(self) -> None:
        """Checksummed and lowercase forms of one address appear in one file.

        Deduplicating the raw strings counts one contract twice, which turns
        "annotates exactly one victim" into "annotates two and is ambiguous" --
        the opposite of the truth, and a loss that looks like a data problem.
        """
        mixed = "0x" + "aB" * 20
        body = f"// Vulnerable Contract : {mixed}\n// Vulnerable Contract Code : {mixed.lower()}"
        parsed = parse_poc("X_exp.sol", poc(body))
        assert parsed.victims == (mixed.lower(),)
        assert parsed.victim == mixed.lower()

    def test_a_vulnerability_line_is_not_a_contract_annotation(self) -> None:
        """`// Vulnerability : Price Manipulation` carries a phrase, not an address.

        Admitting the key would count a file as victim-identified on the
        strength of a sentence, and the address the record needs would then be
        taken from somewhere else in the file.
        """
        body = f"// Vulnerability : Price Manipulation\n// Attacker : {OTHER}"
        parsed = parse_poc("X_exp.sol", poc(body))
        assert parsed.victims == ()
        assert parsed.victim is None

    def test_two_annotated_victims_leave_no_single_victim(self) -> None:
        """Two is not half an answer; taking the first would choose by order."""
        body = f"// Vulnerable Contract : {VICTIM}\n// Vulnerable Contract : {OTHER}"
        parsed = parse_poc("X_exp.sol", poc(body))
        assert set(parsed.victims) == {VICTIM, OTHER}
        assert parsed.victim is None

    def test_an_address_elsewhere_in_the_file_is_not_a_victim(self) -> None:
        body = f"// Attacker : {OTHER}\ncontract E {{ address a = {VICTIM}; }}"
        parsed = parse_poc("X_exp.sol", poc(body))
        assert parsed.victims == ()
        assert VICTIM in parsed.addresses


class TestTheAddressesMentioned:
    def test_they_are_lowercased_deduplicated_and_in_first_mention_order(self) -> None:
        text = poc(f"a = {OTHER}; b = {VICTIM}; c = {OTHER.upper().replace('0X', '0x')};")
        assert addresses(text) == (OTHER, VICTIM)

    def test_a_longer_hex_string_is_not_an_address(self) -> None:
        """A 32-byte hash contains no 20-byte address, and reading one out of it
        would put a transaction hash's prefix into a pin's address field."""
        assert addresses(poc(f"bytes32 h = {TX};")) == ()


class TestTheAnalysisLinks:
    def test_an_explorer_link_is_not_an_analysis_link(self) -> None:
        body = (
            f"// Attacker : https://arbiscan.io/address/{OTHER}\n"
            "// @Analysis\n// https://example.org/write-up"
        )
        assert parse_poc("X_exp.sol", poc(body)).analysis == ("https://example.org/write-up",)

    def test_trailing_punctuation_is_not_part_of_the_url(self) -> None:
        body = "// Post-mortem : https://example.org/a-b-c."
        assert parse_poc("X_exp.sol", poc(body)).analysis == ("https://example.org/a-b-c",)

    def test_a_file_with_no_write_up_reports_none(self) -> None:
        assert parse_poc("X_exp.sol", poc(f"// Attacker : {OTHER}")).analysis == ()
