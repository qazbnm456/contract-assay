"""Corpus record invariants and verification behaviour.

The record type refuses to represent ground truth that cannot be scored, and the
verifier refuses to admit a record it cannot confirm. Both are strict on purpose:
a corpus is the thing every later number is computed against, so an error here is
invisible everywhere downstream.
"""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from contract_assay.corpus.records import (
    CorpusRecord,
    CorpusSplit,
    LocatorProvenance,
    NegativeKind,
    Provenance,
    SourcePin,
    VulnerabilityClass,
)
from contract_assay.corpus.verify import (
    CheckFailure,
    SourceResolver,
    verify_all,
    verify_record,
)
from contract_assay.models import DifficultyLevel, Locator

pytestmark = pytest.mark.offline

VULN_SHA = "a" * 40
FIX_SHA = "b" * 40

SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function swapAndWithdraw(uint256 amountIn, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, 0, path, address(this), block.timestamp);
    }
}
"""
SOURCE_SHA = hashlib.sha256(SOURCE.encode()).hexdigest()

# swapAndWithdraw spans lines 11-13.
SWAP_START, SWAP_END = 11, 13


def resolver(source: str | None = SOURCE) -> SourceResolver:
    def _resolve(repo_url: str, commit: str, path: str) -> str | None:
        return source

    return _resolve


def a_pin(**over: object) -> SourcePin:
    base: dict[str, object] = {
        "repo_url": "https://github.com/example/vault",
        "commit": VULN_SHA,
        "path": "src/Vault.sol",
        "sha256": SOURCE_SHA,
    }
    return SourcePin(**{**base, **over})  # type: ignore[arg-type]


def a_locator(**over: object) -> Locator:
    base: dict[str, object] = {
        "file": "src/Vault.sol",
        "contract": "Vault",
        "function": "swapAndWithdraw",
        "start_line": SWAP_START,
        "end_line": SWAP_END,
    }
    return Locator(**{**base, **over})  # type: ignore[arg-type]


def a_provenance(**over: object) -> Provenance:
    base: dict[str, object] = {
        "platform": "example-platform",
        "report_url": "https://example.invalid/report/1",
        "reported_severity": "high",
    }
    return Provenance(**{**base, **over})  # type: ignore[arg-type]


def a_positive(**over: object) -> CorpusRecord:
    base: dict[str, object] = {
        "record_id": "vault-slippage-1",
        "split": CorpusSplit.PUBLIC,
        "pin": a_pin(),
        "locator": a_locator(),
        "locator_provenance": LocatorProvenance.STATED,
        "classes": [VulnerabilityClass.SLIPPAGE],
        "provenance": a_provenance(),
    }
    return CorpusRecord(**{**base, **over})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Pins must be reproducible
# ---------------------------------------------------------------------------


class TestSourcePin:
    @pytest.mark.parametrize("bad", ["main", "a1b2c3d", "A" * 40, "z" * 40, ""])
    def test_rejects_anything_that_is_not_a_full_lowercase_sha(self, bad: str) -> None:
        # Branch names and short SHAs move. A corpus pinned to a moving target
        # silently changes what it measures.
        with pytest.raises(ValidationError, match="40-character"):
            a_pin(commit=bad)

    def test_source_id_is_stable_and_readable(self) -> None:
        assert a_pin().source_id == f"vault@{'a' * 12}:src/Vault.sol"


# ---------------------------------------------------------------------------
# Records must be scoreable
# ---------------------------------------------------------------------------


class TestPositiveRecords:
    def test_a_positive_must_say_where(self) -> None:
        # An unlocated positive cannot be scored at function granularity, which
        # is the only granularity this benchmark recognises.
        with pytest.raises(ValidationError, match="must say where"):
            a_positive(locator=None)

    def test_locator_must_agree_with_the_pin(self) -> None:
        with pytest.raises(ValidationError, match=r"does not match pin\.path"):
            a_positive(locator=a_locator(file="src/Other.sol"))

    def test_cannot_be_positive_and_negative_for_the_same_class(self) -> None:
        with pytest.raises(ValidationError, match="both positive and negative"):
            a_positive(negative_for=[VulnerabilityClass.SLIPPAGE])

    def test_multi_labelling_is_allowed(self) -> None:
        # One location can host instances of several classes. A corpus that
        # forces a single label teaches that classes are mutually exclusive.
        record = a_positive(
            classes=[VulnerabilityClass.SLIPPAGE, VulnerabilityClass.ORACLE_INTEGRITY]
        )
        assert record.covers(VulnerabilityClass.SLIPPAGE)
        assert record.covers(VulnerabilityClass.ORACLE_INTEGRITY)
        assert not record.covers(VulnerabilityClass.REENTRANCY)

    def test_level_is_the_hardest_class_present(self) -> None:
        assert a_positive(classes=[VulnerabilityClass.SLIPPAGE]).level is DifficultyLevel.Q
        assert (
            a_positive(classes=[VulnerabilityClass.UNCHECKED_EXTERNAL_CALL]).level
            is DifficultyLevel.S
        )
        mixed = a_positive(
            classes=[
                VulnerabilityClass.UNCHECKED_EXTERNAL_CALL,
                VulnerabilityClass.FLASHLOAN_MANIPULATION,
            ]
        )
        assert mixed.level is DifficultyLevel.Q


class TestNegativeRecords:
    def _negative(self, **over: object) -> CorpusRecord:
        base: dict[str, object] = {
            "record_id": "vault-slippage-fixed",
            "split": CorpusSplit.PUBLIC,
            "pin": a_pin(commit=FIX_SHA),
            "locator": None,
            "classes": [],
            "negative_for": [VulnerabilityClass.SLIPPAGE],
            "negative_kind": NegativeKind.POST_FIX,
            "provenance": a_provenance(fix_commit=FIX_SHA),
        }
        return CorpusRecord(**{**base, **over})  # type: ignore[arg-type]

    def test_a_negative_must_state_what_it_is_negative_for(self) -> None:
        with pytest.raises(ValidationError, match="must state what it is a negative for"):
            self._negative(negative_for=[])

    def test_a_negative_must_state_its_kind(self) -> None:
        with pytest.raises(ValidationError, match="must state its kind"):
            self._negative(negative_kind=None)

    def test_a_post_fix_negative_must_be_pinned_to_the_fix_commit(self) -> None:
        # Pinning a post-fix negative at the vulnerable commit would score the
        # defect as absent while measuring the code that contains it.
        with pytest.raises(ValidationError, match="must be pinned to the fix commit"):
            self._negative(pin=a_pin(commit=VULN_SHA))

    def test_a_post_fix_negative_must_know_its_fix_commit(self) -> None:
        with pytest.raises(ValidationError, match="must record the fix commit"):
            self._negative(provenance=a_provenance())

    def test_cross_class_negatives_need_no_fix_commit(self) -> None:
        # The reason all nine classes are built together: a repository vulnerable
        # to one class and clean for another is the hardest available negative.
        record = self._negative(
            record_id="vault-not-reentrant",
            pin=a_pin(),
            negative_for=[VulnerabilityClass.REENTRANCY],
            vulnerable_to=[VulnerabilityClass.SLIPPAGE],
            negative_kind=NegativeKind.CROSS_CLASS,
            provenance=a_provenance(),
        )
        assert not record.is_positive
        assert record.covers(VulnerabilityClass.REENTRANCY)

    def test_a_valid_post_fix_negative_is_accepted(self) -> None:
        assert self._negative().negative_kind is NegativeKind.POST_FIX


# ---------------------------------------------------------------------------
# Verification rejects, it does not warn
# ---------------------------------------------------------------------------


class TestVerification:
    def test_a_sound_record_is_admitted(self) -> None:
        result = verify_record(a_positive(), resolver())
        assert result.ok, str(result)
        assert result.computed_sha256 == SOURCE_SHA

    def test_unresolvable_source_is_rejected(self) -> None:
        result = verify_record(a_positive(), resolver(None))
        assert not result.ok
        assert result.failures == (CheckFailure.SOURCE_UNRESOLVABLE,)

    def test_digest_mismatch_is_rejected(self) -> None:
        # The pinned commit resolved, but the bytes are not the bytes that were
        # annotated. Every line number in the record is now suspect.
        result = verify_record(a_positive(pin=a_pin(sha256="0" * 64)), resolver())
        assert not result.ok
        assert CheckFailure.DIGEST_MISMATCH in result.failures

    def test_span_past_end_of_file_is_rejected(self) -> None:
        result = verify_record(
            a_positive(locator=a_locator(start_line=900, end_line=999)), resolver()
        )
        assert not result.ok
        assert CheckFailure.SPAN_OUT_OF_RANGE in result.failures

    def test_function_absent_from_span_is_rejected(self) -> None:
        # The most common annotation error: correct file, wrong lines. Left
        # unchecked it produces ground truth that scores every detector wrongly.
        result = verify_record(a_positive(locator=a_locator(start_line=7, end_line=9)), resolver())
        assert not result.ok
        assert CheckFailure.FUNCTION_NOT_IN_SPAN in result.failures

    def test_contract_absent_from_file_is_rejected(self) -> None:
        result = verify_record(a_positive(locator=a_locator(contract="Treasury")), resolver())
        assert not result.ok
        assert CheckFailure.CONTRACT_NOT_FOUND in result.failures

    def test_empty_source_is_rejected(self) -> None:
        result = verify_record(a_positive(), resolver("   \n  "))
        assert not result.ok
        assert result.failures == (CheckFailure.EMPTY_SOURCE,)

    def test_a_negative_record_needs_no_locator_to_verify(self) -> None:
        record = CorpusRecord(
            record_id="vault-not-reentrant",
            split=CorpusSplit.PUBLIC,
            pin=a_pin(),
            classes=[],
            negative_for=[VulnerabilityClass.REENTRANCY],
            vulnerable_to=[VulnerabilityClass.SLIPPAGE],
            negative_kind=NegativeKind.CROSS_CLASS,
            provenance=a_provenance(),
        )
        assert verify_record(record, resolver()).ok

    def test_failures_accumulate_rather_than_short_circuit(self) -> None:
        # A record with several problems should report all of them, so a single
        # pass tells an annotator everything that needs fixing.
        result = verify_record(
            a_positive(
                pin=a_pin(sha256="0" * 64),
                locator=a_locator(contract="Treasury", start_line=7, end_line=9),
            ),
            resolver(),
        )
        assert not result.ok
        assert set(result.failures) == {
            CheckFailure.DIGEST_MISMATCH,
            CheckFailure.FUNCTION_NOT_IN_SPAN,
            CheckFailure.CONTRACT_NOT_FOUND,
        }

    def test_verify_all_partitions_without_mutating(self) -> None:
        good = a_positive()
        bad = a_positive(record_id="vault-bad", locator=a_locator(start_line=900, end_line=999))
        report = verify_all([good, bad], resolver())
        admitted, rejected = list(report.admitted), list(report.rejected)

        assert [r.record_id for r in admitted] == ["vault-slippage-1"]
        assert [r.record_id for r in rejected] == ["vault-bad"]
        assert "rejected" in str(rejected[0])


class TestClassTaxonomy:
    def test_every_class_has_a_difficulty_level(self) -> None:
        for cls in VulnerabilityClass:
            assert cls.level in (DifficultyLevel.S, DifficultyLevel.M, DifficultyLevel.Q)

    def test_the_taxonomy_has_exactly_nine_classes(self) -> None:
        assert len(VulnerabilityClass) == 9

    def test_the_frontier_classes_are_graded_q(self) -> None:
        # These are the classes static analysis cannot reach in principle, and
        # the ones the whole approach has to justify itself on.
        assert VulnerabilityClass.SLIPPAGE.level is DifficultyLevel.Q
        assert VulnerabilityClass.FLASHLOAN_MANIPULATION.level is DifficultyLevel.Q


class TestDigestWriteBack:
    """A pin without a digest promises reproducibility it cannot deliver."""

    def test_an_admitted_record_gains_the_digest_it_was_verified_against(self) -> None:
        unpinned = a_positive(pin=a_pin(sha256=None))
        report = verify_all([unpinned], resolver())
        admitted, rejected = list(report.admitted), list(report.rejected)

        assert not rejected
        assert admitted[0].pin.sha256 == SOURCE_SHA

    def test_the_input_record_is_not_mutated(self) -> None:
        unpinned = a_positive(pin=a_pin(sha256=None))
        verify_all([unpinned], resolver())
        assert unpinned.pin.sha256 is None

    def test_a_digest_already_pinned_is_left_alone(self) -> None:
        admitted = list(verify_all([a_positive()], resolver()).admitted)
        assert admitted[0].pin.sha256 == SOURCE_SHA

    def test_without_write_back_the_same_record_would_admit_different_bytes(self) -> None:
        # The point of the write-back, stated as the failure it prevents.
        unpinned = a_positive(pin=a_pin(sha256=None))
        admitted = list(verify_all([unpinned], resolver()).admitted)

        other = SOURCE.replace("amountIn, 0,", "amountIn, minOut,")
        rejected = list(verify_all(admitted, resolver(other)).rejected)
        assert rejected and CheckFailure.DIGEST_MISMATCH in rejected[0].failures


class TestGroundTruthMustBeScoreable:
    def test_a_positive_must_name_a_function(self) -> None:
        # Function granularity is what everything is scored against; a positive
        # without it weakens every comparison made with it, silently.
        with pytest.raises(ValidationError, match="must name the function"):
            a_positive(locator=a_locator(function=None))

    def test_a_negative_locator_must_also_agree_with_the_pin(self) -> None:
        # Otherwise the span and declaration checks run against the pinned file's
        # bytes while the locator names a different file entirely.
        with pytest.raises(ValidationError, match=r"does not match pin\.path"):
            CorpusRecord(
                record_id="vault-neg-mismatch",
                split=CorpusSplit.PUBLIC,
                pin=a_pin(),
                locator=a_locator(file="src/Elsewhere.sol"),
                classes=[],
                negative_for=[VulnerabilityClass.REENTRANCY],
                vulnerable_to=[VulnerabilityClass.SLIPPAGE],
                negative_kind=NegativeKind.CROSS_CLASS,
                provenance=a_provenance(),
            )


class TestNegativeKindsCarryTheirEvidence:
    def _neg(self, **over: object) -> CorpusRecord:
        base: dict[str, object] = {
            "record_id": "vault-neg",
            "split": CorpusSplit.PUBLIC,
            "pin": a_pin(),
            "classes": [],
            "negative_for": [VulnerabilityClass.REENTRANCY],
            "provenance": a_provenance(),
        }
        return CorpusRecord(**{**base, **over})  # type: ignore[arg-type]

    def test_a_cross_class_negative_must_name_what_it_is_vulnerable_to(self) -> None:
        # Without it the record is an ordinary clean sample, and the hard negative
        # it was collected to provide does not exist.
        with pytest.raises(ValidationError, match="must name what it IS vulnerable to"):
            self._neg(negative_kind=NegativeKind.CROSS_CLASS)

    def test_a_confirmed_clean_negative_must_say_how_it_was_confirmed(self) -> None:
        with pytest.raises(ValidationError, match="must record how it was confirmed"):
            self._neg(negative_kind=NegativeKind.CONFIRMED_CLEAN)

    def test_a_confirmed_clean_negative_with_a_note_is_accepted(self) -> None:
        record = self._neg(
            negative_kind=NegativeKind.CONFIRMED_CLEAN,
            notes="Reviewed against the reentrancy checklist; all state writes precede calls.",
        )
        assert record.negative_kind is NegativeKind.CONFIRMED_CLEAN

    def test_a_record_cannot_be_vulnerable_to_and_clean_for_one_class(self) -> None:
        with pytest.raises(ValidationError, match="both vulnerable to and clean for"):
            self._neg(
                negative_kind=NegativeKind.CROSS_CLASS,
                vulnerable_to=[VulnerabilityClass.REENTRANCY],
            )


class TestLevelIsTotal:
    def test_level_does_not_raise_on_a_record_with_no_classes(self) -> None:
        # model_copy bypasses validation, so this state is reachable even though
        # the validator forbids it. A property on a frozen model must not explode.
        stripped = a_positive().model_copy(update={"classes": [], "negative_for": []})
        assert stripped.level is DifficultyLevel.S

    def test_level_of_a_negative_comes_from_what_it_is_negative_for(self) -> None:
        record = CorpusRecord(
            record_id="vault-neg-level",
            split=CorpusSplit.PUBLIC,
            pin=a_pin(),
            classes=[],
            negative_for=[VulnerabilityClass.FLASHLOAN_MANIPULATION],
            vulnerable_to=[VulnerabilityClass.ACCESS_CONTROL],
            negative_kind=NegativeKind.CROSS_CLASS,
            provenance=a_provenance(),
        )
        assert record.level is DifficultyLevel.Q


class TestVerificationUsesAParser:
    """A mention of a declaration is not a declaration.

    These go through the public API rather than the index directly, because the
    failure they guard against is a record being *admitted* -- the index being
    correct does not help if the verifier does not consult it.
    """

    COMMENT_ONLY = """\
contract Vault {
    // The old function swapAndWithdraw() lived here; contract Treasury owns it now.
    /* function swapAndWithdraw() external {} */
    uint256 public total;
}
"""

    def test_a_record_pointing_at_a_comment_is_rejected(self) -> None:
        result = verify_record(
            a_positive(pin=a_pin(sha256=None), locator=a_locator(start_line=2, end_line=3)),
            resolver(self.COMMENT_ONLY),
        )
        assert not result.ok
        assert CheckFailure.FUNCTION_NOT_IN_SPAN in result.failures

    def test_a_contract_named_only_in_a_comment_is_rejected(self) -> None:
        result = verify_record(
            a_positive(
                pin=a_pin(sha256=None),
                locator=a_locator(contract="Treasury", start_line=2, end_line=3),
            ),
            resolver(self.COMMENT_ONLY),
        )
        assert not result.ok
        assert CheckFailure.CONTRACT_NOT_FOUND in result.failures

    def test_a_constructor_is_accepted(self) -> None:
        # A pattern matcher misses these, which removes most access-control
        # annotations from the corpus while the totals still look healthy.
        source = "contract Wallet {\n    constructor(address o) {\n        owner = o;\n    }\n}\n"
        result = verify_record(
            a_positive(
                pin=a_pin(sha256=None),
                locator=a_locator(
                    contract="Wallet", function="constructor", start_line=2, end_line=4
                ),
            ),
            resolver(source),
        )
        assert result.ok, str(result)

    def test_a_function_in_the_wrong_contract_is_rejected(self) -> None:
        source = (
            "contract Token {\n    function withdraw() external {}\n}\n"
            "contract Vault {\n    function deposit() external {}\n}\n"
        )
        result = verify_record(
            a_positive(
                pin=a_pin(sha256=None),
                locator=a_locator(contract="Vault", function="withdraw", start_line=1, end_line=3),
            ),
            resolver(source),
        )
        assert not result.ok
        assert CheckFailure.FUNCTION_NOT_IN_CONTRACT in result.failures
        assert "Token" in result.detail

    def test_an_unparseable_file_is_rejected_rather_than_waved_through(self) -> None:
        # "I could not read this" is not evidence that the record is sound.
        result = verify_record(a_positive(pin=a_pin(sha256=None)), resolver("}{ not solidity ]["))
        assert not result.ok
        assert CheckFailure.UNPARSEABLE_SOURCE in result.failures


class TestCorpusSplit:
    """Which corpus a record belongs to, and what that permits."""

    def test_the_split_must_be_stated(self) -> None:
        # No default, because the dangerous direction is asymmetric: a forgotten
        # split that defaulted to public would publish a record meant to be
        # withheld, and that mistake cannot be taken back.
        with pytest.raises(ValidationError, match="split"):
            CorpusRecord(
                record_id="vault-no-split",
                pin=a_pin(),
                locator=a_locator(),
                classes=[VulnerabilityClass.SLIPPAGE],
                provenance=a_provenance(),
            )

    def test_only_the_public_split_may_be_distributed(self) -> None:
        assert CorpusSplit.PUBLIC.is_distributable
        assert not CorpusSplit.PRIVATE_HOLDOUT.is_distributable
        assert not CorpusSplit.SYNTHETIC_VARIANT.is_distributable

    def test_a_holdout_record_needs_nothing_extra(self) -> None:
        # It is ordinary annotation that is merely withheld, so it could be
        # published tomorrow by changing one field.
        record = a_positive(record_id="vault-held", split=CorpusSplit.PRIVATE_HOLDOUT)
        assert not record.split.is_distributable
        assert record.derived_from is None

    def _variant(self, **over: object) -> CorpusRecord:
        base: dict[str, object] = {
            "record_id": "vault-slippage-1-v2",
            "split": CorpusSplit.SYNTHETIC_VARIANT,
            "derived_from": "vault-slippage-1",
            "notes": "Renamed params and reordered members; re-ran the PoC and it still drains.",
        }
        return a_positive(**{**base, **over})

    def test_a_well_formed_variant_is_accepted(self) -> None:
        assert self._variant().derived_from == "vault-slippage-1"

    def test_a_variant_must_name_what_it_came_from(self) -> None:
        with pytest.raises(ValidationError, match="must name the record it was mutated from"):
            self._variant(derived_from=None)

    def test_a_variant_cannot_be_derived_from_itself(self) -> None:
        with pytest.raises(ValidationError, match="cannot be derived from itself"):
            self._variant(derived_from="vault-slippage-1-v2")

    def test_a_variant_must_record_that_the_defect_survived(self) -> None:
        # A structure-preserving edit can repair the bug by accident, and an
        # unconfirmed variant is a negative labelled positive.
        with pytest.raises(ValidationError, match="survived mutation"):
            self._variant(notes="   ")

    def test_only_a_variant_may_be_derived_from_another_record(self) -> None:
        with pytest.raises(ValidationError, match="only a synthetic variant is derived"):
            a_positive(split=CorpusSplit.PUBLIC, derived_from="vault-slippage-1")


class TestOverloadedFunctionsAreAmbiguous:
    """A record naming an overloaded function has not identified a function."""

    SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Router {
    function swap(uint256 amountIn) external returns (uint256) {
        return amountIn;
    }

    function swap(uint256 amountIn, address recipient) external returns (uint256) {
        return amountIn;
    }
}
"""

    def _record(self, start: int, end: int, **over: object) -> CorpusRecord:
        base: dict[str, object] = {
            "record_id": "router-slippage-1",
            "split": CorpusSplit.PUBLIC,
            "pin": a_pin(path="src/Router.sol", sha256=None),
            "locator": Locator(
                file="src/Router.sol",
                contract="Router",
                function="swap",
                start_line=start,
                end_line=end,
            ),
            "locator_provenance": LocatorProvenance.STATED,
            "classes": [VulnerabilityClass.SLIPPAGE],
            "provenance": a_provenance(),
        }
        return CorpusRecord(**{**base, **over})  # type: ignore[arg-type]

    def test_a_span_covering_two_overloads_is_rejected(self) -> None:
        # Admitting it would verify the record against whichever overload was
        # found first, which is not the one the annotator necessarily meant.
        result = verify_record(self._record(5, 11), resolver(self.SOURCE))
        assert not result.ok
        assert CheckFailure.FUNCTION_AMBIGUOUS_IN_SPAN in result.failures
        assert "swap(uint256)" in result.detail
        assert "swap(uint256,address)" in result.detail

    @pytest.mark.parametrize(("start", "end"), [(5, 7), (9, 11)])
    def test_a_span_covering_one_overload_is_admitted(self, start: int, end: int) -> None:
        assert verify_record(self._record(start, end), resolver(self.SOURCE)).ok

    TWO_CONTRACTS = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Router {
    function swap(uint256 amountIn) external {}
}

contract Other {
    function swap(uint256 amountIn) external {}
}
"""

    def test_naming_the_contract_disambiguates_a_shared_function_name(self) -> None:
        # Lines 5-9 span a `swap` in each contract. Naming one of them narrows
        # the candidates to a single declaration, so the record is not ambiguous.
        result = verify_record(self._record(5, 9), resolver(self.TWO_CONTRACTS))
        assert result.ok, result.detail

    def test_without_a_contract_the_same_span_is_ambiguous(self) -> None:
        # Same file, same span, same function name -- the only thing removed is
        # the contract that was doing the disambiguating.
        record = self._record(
            5,
            9,
            locator=Locator(file="src/Router.sol", function="swap", start_line=5, end_line=9),
        )
        result = verify_record(record, resolver(self.TWO_CONTRACTS))
        assert not result.ok
        assert CheckFailure.FUNCTION_AMBIGUOUS_IN_SPAN in result.failures


class TestVariantsCannotBeVerifiedAgainstAPin:
    """A variant's bytes exist in no repository, so no commit can pin them."""

    def _variant(self, **over: object) -> CorpusRecord:
        base: dict[str, object] = {
            "record_id": "vault-slippage-1-v2",
            "split": CorpusSplit.SYNTHETIC_VARIANT,
            "derived_from": "vault-slippage-1",
            "notes": "Renamed params; re-ran the PoC and the defect survives.",
        }
        return a_positive(**{**base, **over})

    def test_a_variant_is_rejected_rather_than_checked_against_its_source(self) -> None:
        # Nothing stops the pin describing the unmutated original, and every
        # check would then pass against source that does not contain the
        # mutation.
        result = verify_record(self._variant(), resolver())
        assert not result.ok
        assert result.failures == (CheckFailure.VARIANT_NOT_REGENERABLE,)

    def test_no_digest_is_computed_for_a_variant(self) -> None:
        # The write-back is what makes a pin's promise real, so a digest of the
        # wrong bytes is worse than none: it certifies the original as the
        # variant.
        assert verify_record(self._variant(), resolver()).computed_sha256 is None

    def test_a_variant_is_never_admitted_by_verify_all(self) -> None:
        report = verify_all([self._variant(), a_positive()], resolver())
        admitted, rejected = list(report.admitted), list(report.rejected)
        assert [r.record_id for r in admitted] == ["vault-slippage-1"]
        assert [r.record_id for r in rejected] == ["vault-slippage-1-v2"]

    @pytest.mark.parametrize("split", [CorpusSplit.PUBLIC, CorpusSplit.PRIVATE_HOLDOUT])
    def test_the_other_splits_still_verify(self, split: CorpusSplit) -> None:
        assert verify_record(a_positive(split=split), resolver()).ok


class TestTheReportSaysWhatTheCorpusIsASampleOf:
    """Rejection is correct, and it biases the corpus. Both have to be visible.

    Verification turns away what it cannot confirm, which is what makes the
    corpus worth having. It also means the corpus is a sample of defects sitting
    where the declaration index can parse and name them, not a sample of real
    defects. That cannot be fixed without giving up the property; it can only be
    measured and stated.
    """

    UNPARSEABLE = "}{ not solidity ]["

    def test_failures_are_tallied_by_check(self) -> None:
        # No digest pinned, so the parse failure is the only cause and the tally
        # can be compared exactly.
        record = a_positive(pin=a_pin(sha256=None))
        report = verify_all([record], resolver(self.UNPARSEABLE))
        assert report.by_failure == {CheckFailure.UNPARSEABLE_SOURCE: 1}

    def test_a_record_failing_several_checks_counts_under_each(self) -> None:
        # Otherwise the tally would describe records rather than causes, and the
        # causes are what says which shapes are being excluded.
        record = a_positive(
            pin=a_pin(sha256="0" * 64),
            locator=a_locator(contract="Treasury", start_line=7, end_line=9),
        )
        report = verify_all([record], resolver())
        assert set(report.by_failure) == {
            CheckFailure.DIGEST_MISMATCH,
            CheckFailure.FUNCTION_NOT_IN_SPAN,
            CheckFailure.CONTRACT_NOT_FOUND,
        }

    def test_both_polarities_are_tallied_by_the_class_they_concern(self) -> None:
        negative = CorpusRecord(
            record_id="vault-not-reentrant",
            split=CorpusSplit.PUBLIC,
            pin=a_pin(),
            classes=[],
            negative_for=[VulnerabilityClass.REENTRANCY],
            vulnerable_to=[VulnerabilityClass.SLIPPAGE],
            negative_kind=NegativeKind.CROSS_CLASS,
            provenance=a_provenance(),
        )
        report = verify_all([a_positive(), negative], resolver())
        assert report.admitted_by_class == {
            VulnerabilityClass.SLIPPAGE: 1,
            VulnerabilityClass.REENTRANCY: 1,
        }

    def test_rejections_are_tallied_by_class(self) -> None:
        report = verify_all([a_positive()], resolver(self.UNPARSEABLE))
        assert report.rejected_by_class == {VulnerabilityClass.SLIPPAGE: 1}
        assert report.admitted_by_class == {}

    def test_the_overall_rate_is_reported(self) -> None:
        good = a_positive()
        bad = a_positive(record_id="vault-bad", locator=a_locator(start_line=99, end_line=99))
        report = verify_all([good, bad], resolver())
        assert report.candidates == 2
        assert report.rejection_rate == 0.5

    def test_a_per_class_rate_is_available_because_that_is_where_bias_shows(self) -> None:
        # An overall rate can look tolerable while one class is decimated, and
        # that class is then quietly under-represented in every later number.
        report = verify_all([a_positive()], resolver(self.UNPARSEABLE))
        assert report.rejection_rate_for(VulnerabilityClass.SLIPPAGE) == 1.0
        assert report.rejection_rate_for(VulnerabilityClass.REENTRANCY) == 0.0

    def test_an_empty_run_reports_zero_rather_than_dividing_by_zero(self) -> None:
        report = verify_all([], resolver())
        assert report.candidates == 0
        assert report.rejection_rate == 0.0
        assert report.rejection_rate_for(VulnerabilityClass.SLIPPAGE) == 0.0

    def test_the_statement_names_the_causes_and_the_concentration(self) -> None:
        report = verify_all([a_positive()], resolver(self.UNPARSEABLE))
        statement = report.sampling_statement()
        assert "0 records admitted" in statement
        assert "1 of 1 candidate " in statement
        assert "unparseable_source 1" in statement
        assert "slippage (1)" in statement
        assert "describes the admitted records only" in statement

    def test_a_clean_run_still_makes_a_statement(self) -> None:
        # A sentence that only appears on failure is a sentence nobody reads, and
        # what the corpus is a sample of is a property of the corpus rather than
        # a warning about one invocation.
        report = verify_all([a_positive()], resolver())
        assert report.sampling_statement() == ("1 record admitted; no candidates were rejected.")


class TestLocatorProvenanceIsRecorded:
    """A derived span is weaker ground truth, and the difference must be visible.

    `verify` cross-checks a stated span by confirming the named function is
    declared inside it, which catches a transcription error. Asking the
    declaration index whether a function sits in a span the index itself produced
    is a tautology: it passes at a rate indistinguishable from real confirmation.
    An admitted count that mixed the two would hide exactly the kind of shortfall
    §1.3 exists to expose, inside the report built to expose it.
    """

    def test_a_record_with_a_locator_must_say_where_the_span_came_from(self) -> None:
        with pytest.raises(ValidationError, match="must say whether the span was stated"):
            a_positive(locator_provenance=None)

    def test_provenance_without_a_locator_describes_nothing(self) -> None:
        with pytest.raises(ValidationError, match="describes nothing"):
            CorpusRecord(
                record_id="vault-neg-prov",
                split=CorpusSplit.PUBLIC,
                pin=a_pin(),
                classes=[],
                negative_for=[VulnerabilityClass.REENTRANCY],
                vulnerable_to=[VulnerabilityClass.SLIPPAGE],
                negative_kind=NegativeKind.CROSS_CLASS,
                locator_provenance=LocatorProvenance.STATED,
                provenance=a_provenance(),
            )

    def test_a_missing_locator_reports_that_rather_than_the_provenance_field(self) -> None:
        # Ordering matters: the primary problem with an unlocated positive is
        # that it cannot be scored, not that a companion field describes nothing.
        with pytest.raises(ValidationError, match="must say where the defect is"):
            a_positive(locator=None, locator_provenance=None)

    def test_only_a_stated_span_is_cross_checked(self) -> None:
        assert LocatorProvenance.STATED.is_cross_checked
        assert not LocatorProvenance.DERIVED.is_cross_checked

    def test_admitted_records_are_split_by_provenance(self) -> None:
        stated = a_positive(record_id="vault-stated")
        derived = a_positive(
            record_id="vault-derived", locator_provenance=LocatorProvenance.DERIVED
        )
        report = verify_all([stated, derived], resolver())
        assert report.admitted_by_locator_provenance == {
            LocatorProvenance.STATED: 1,
            LocatorProvenance.DERIVED: 1,
        }
        assert report.derived_locator_count == 1

    def test_the_statement_says_how_many_spans_were_not_cross_checked(self) -> None:
        derived = a_positive(locator_provenance=LocatorProvenance.DERIVED)
        statement = verify_all([derived], resolver()).sampling_statement()
        assert "1 of those carries a derived locator" in statement
        assert "cannot cross-check" in statement

    def test_a_corpus_of_stated_records_says_nothing_about_derivation(self) -> None:
        # No noise when the distinction does not apply.
        statement = verify_all([a_positive()], resolver()).sampling_statement()
        assert "derived" not in statement
