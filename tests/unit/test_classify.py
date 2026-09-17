"""The class a finding's title claims, and the words that do not claim one.

Every title here is written by hand in the shape the published ones take. The
rejected terms carry the weight: each one raised coverage and was wrong on
inspection, so a later change that re-adds them to improve a number has a test
telling it what that number would cost.
"""

from __future__ import annotations

import pytest

from contract_assay.corpus.adapters.classify import classify_title
from contract_assay.models import VulnerabilityClass

pytestmark = pytest.mark.offline


class TestHowTheseReportsPhraseADenialOfService:
    """The table held the category's own name, and almost nothing writes it.

    Of 141 unmapped titles over 17 reports, seventeen described an action that
    could be made to fail, in none of the words the table held. These are the
    phrasings that were kept, each because every title it newly mapped was a
    denial of service on inspection.
    """

    @pytest.mark.parametrize(
        "title",
        [
            "wrapNativeTokenInWallet always reverts on Arbitrum",
            "ETH withdrawals from EigenLayer always fail",
            "Minting will fail because of the wrong modifier",
            "Miscalculation could lead to a user unable to unstake all NFTs",
            "Borrower is not able to compensate his lenders",
            "Most users won't be able to claim their share of fees",
            "Broken assumptions lead to the inability to seize staked tokens",
            "All supplied collateral deposited by a strategy will be irrecoverable",
            "Excess payment can get stuck in the forging contract",
            "Borrow and lend operations are bricked after a migration",
            "An adversary can prevent the launch of any pool",
        ],
    )
    def test_an_action_that_can_be_made_to_fail(self, title: str) -> None:
        assert classify_title(title) == (VulnerabilityClass.DENIAL_OF_SERVICE,)

    def test_a_symptom_does_not_outrank_the_defect_that_causes_it(self) -> None:
        # Ordering, not coincidence: the arithmetic terms sit before the denial
        # of service ones because a revert is how this defect *shows*, and the
        # rounding is what it *is*.
        assert classify_title("Revert due to underflow error, locking the NFT") == (
            VulnerabilityClass.ARITHMETIC_ROUNDING,
        )


class TestAMechanismIsNotADefect:
    """`flash loan` named the instrument, not the property, and was always wrong.

    Four titles, four wrong classes: two were flash-loan fee accounting, one a
    rounding defect in a fee, one a revert. The class is a price moved inside
    one transaction with borrowed capital; the phrase is the thing that moved
    it. Removing the bare form let the defect word win in each case.
    """

    def test_a_fee_accounting_bug_in_a_flash_loan_is_not_manipulation(self) -> None:
        assert classify_title("StrategyLeverage.harvest doesn't account flashloan fee") == ()

    def test_a_rounding_defect_in_a_flash_fee_is_rounding(self) -> None:
        assert classify_title(
            "Rounding-down of flashFee can result in calls to flash loan to revert"
        ) == (VulnerabilityClass.ARITHMETIC_ROUNDING,)

    def test_a_flash_loan_callback_that_reverts_is_a_denial_of_service(self) -> None:
        assert classify_title(
            "Invalid handling of flash loan fees, forcing it to always revert"
        ) == (VulnerabilityClass.DENIAL_OF_SERVICE,)

    def test_the_named_attack_still_maps(self) -> None:
        assert classify_title("Price manipulation via a flash loan attack on the pool") == (
            VulnerabilityClass.FLASHLOAN_MANIPULATION,
        )

    def test_a_guard_that_is_present_is_not_the_defect_it_guards_against(self) -> None:
        # `nonReentrant` on a `receive()` that makes every withdrawal fail is a
        # denial of service. No keyword can tell a missing guard from a harmful
        # one, so the modifier's name is not a signal either way.
        assert VulnerabilityClass.REENTRANCY not in classify_title(
            "Withdrawals always fail due to the delegator's nonReentrant receive()"
        )


class TestTermsThatRaisedCoverageAndWereWrong:
    """Each of these mapped titles that inspection rejected. They stay out."""

    @pytest.mark.parametrize(
        "title",
        [
            # A mistaken formula is not a rounding defect. Two titles, both wrong.
            "Incorrect calculation of queued withdrawals can deflate reported holdings",
            "Updating the rate parameters before applying interest gives an incorrect"
            " calculation of the rate",
            # Returning the wrong figure is an accounting error, not a rounding one.
            "executeBuyCreditMarket returns the wrong amount of cash",
            # "cannot" describes as often as it denies: this is a documentation
            # mismatch, and the fix is to the documentation.
            "Role providers cannot be EOAs as stated in the documentation",
            # Being made to take an extra step is not being prevented.
            "Users are forced to borrow again in order to unlock their NFTs",
            # A setting that can be circumvented is not an unchecked call.
            "Credit can be sold forcibly as the forSale setting can be ignored",
        ],
    )
    def test_the_title_maps_to_nothing(self, title: str) -> None:
        assert classify_title(title) == ()

    def test_an_identifier_holding_the_word_entropy_is_not_randomness(self) -> None:
        # One of the two titles it mapped was a mistaken comparison against a
        # constant, which is not a randomness defect. The other genuinely was,
        # and is given up: refusing beats one right answer and one wrong one.
        assert classify_title("Incorrect check against the golden entropy value") == ()


class TestTheExemptionCoversProseNotNames:
    """§6.3's argument is that nobody renames the English word "reentrancy"."""

    def test_a_class_is_not_read_off_a_quoted_identifier(self) -> None:
        assert classify_title("`ETHOracle.getLatestPrice` needs to convert to 18 decimals") == ()

    def test_the_same_claim_in_prose_still_maps(self) -> None:
        assert classify_title("The oracle price is never checked for staleness") == (
            VulnerabilityClass.ORACLE_INTEGRITY,
        )
