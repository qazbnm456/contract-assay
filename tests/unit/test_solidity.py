"""Declaration indexing, and the cases a text match gets wrong.

This is the highest-risk code in the project: it decides what enters ground
truth. It can be wrong in two directions, and both are damaging in ways that are
invisible downstream.

*Certifying what is not there* admits a record pointing at a comment, so a
detector is scored against a location containing no code. *Missing what is
there* rejects real annotations, and it does so unevenly -- a matcher that
cannot see a constructor removes a whole family of access-control cases from the
corpus while the totals still look healthy.

Every case below was verified to defeat a regex-based matcher.
"""

from __future__ import annotations

import pytest

from contract_assay.evidence.solidity import DeclarationKind, index_source

pytestmark = pytest.mark.offline


class TestMentionsAreNotDeclarations:
    """A file may talk about a symbol at length and declare nothing."""

    SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    // The old function withdraw() used to live here; it was deleted in the
    // rewrite because contract Treasury now owns the balance.
    /* function drain() external { selfdestruct(payable(msg.sender)); } */
    uint256 public total;

    function report() external view returns (string memory) {
        require(total > 0, "function withdraw() reverted");
        return "contract Treasury is deprecated";
    }
}
"""

    @pytest.fixture
    def index(self):  # type: ignore[no-untyped-def]
        return index_source(self.SOURCE)

    @pytest.mark.parametrize(
        ("name", "where"),
        [
            ("withdraw", "a line comment"),
            ("drain", "a commented-out block"),
        ],
    )
    def test_a_function_named_only_in_a_comment_is_not_declared(self, index, name, where) -> None:  # type: ignore[no-untyped-def]
        assert index.callables(name) == [], f"{name} was matched inside {where}"

    def test_a_function_named_only_in_a_string_literal_is_not_declared(self, index) -> None:  # type: ignore[no-untyped-def]
        # "function withdraw() reverted" is a revert message, not a declaration.
        assert index.callables("withdraw") == []

    @pytest.mark.parametrize("where", ["a comment", "a string literal"])
    def test_a_contract_named_only_in_prose_is_not_declared(self, index, where) -> None:  # type: ignore[no-untyped-def]
        assert not index.declares_type("Treasury")

    def test_the_real_declarations_are_still_found(self, index) -> None:  # type: ignore[no-untyped-def]
        # The point is discrimination, not silence.
        assert index.declares_type("Vault")
        assert index.callables("report")


class TestDeclarationsWithoutTheObviousKeywords:
    """Shapes a `function <name>` pattern cannot see."""

    SOURCE = """\
pragma solidity ^0.8.20;

contract Wallet {
    address owner;

    constructor(address _owner) {
        owner = _owner;
    }

    receive() payable external {}

    fallback() external payable {}

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function withdraw(
        uint256 amount,
        address payable recipient
    )
        external
        onlyOwner
    {
        recipient.transfer(amount);
    }
}
"""

    @pytest.fixture
    def index(self):  # type: ignore[no-untyped-def]
        return index_source(self.SOURCE)

    def test_a_constructor_is_a_declaration(self, index) -> None:  # type: ignore[no-untyped-def]
        # Constructors carry neither `function` nor a visibility keyword since
        # 0.7. Missing them removes most access-control annotations from the
        # corpus -- exactly the cases the class exists to measure.
        found = index.callables("constructor")
        assert found, "constructor not indexed"
        assert found[0].kind is DeclarationKind.CONSTRUCTOR

    @pytest.mark.parametrize("name", ["receive", "fallback"])
    def test_receive_and_fallback_are_declarations(self, index, name) -> None:  # type: ignore[no-untyped-def]
        # Solidity does not fix modifier order: `payable external` and
        # `external payable` are both legal and both appear in the wild.
        assert index.callables(name), f"{name} not indexed"

    def test_a_modifier_is_a_declaration(self, index) -> None:  # type: ignore[no-untyped-def]
        assert index.callables("onlyOwner")

    def test_a_signature_spanning_many_lines_is_found_across_its_whole_span(self, index) -> None:  # type: ignore[no-untyped-def]
        decl = index.callables("withdraw")[0]
        assert decl.start_line < decl.end_line
        # The span must cover the body, or a locator pointing at the vulnerable
        # line inside it would not match the declaration.
        assert index.callables("withdraw", within=(decl.end_line, decl.end_line))


class TestScoping:
    """Which type a function belongs to is part of the location."""

    SOURCE = """\
pragma solidity ^0.8.20;

contract Token {
    function withdraw() external {}
}

contract Vault {
    function deposit() external {}
}

library Math {
    function mulDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }
}

interface IOracle {
    function latestAnswer() external view returns (int256);
}
"""

    @pytest.fixture
    def index(self):  # type: ignore[no-untyped-def]
        return index_source(self.SOURCE)

    def test_a_function_knows_its_enclosing_type(self, index) -> None:  # type: ignore[no-untyped-def]
        assert index.callables("withdraw")[0].parent == "Token"
        assert index.callables("deposit")[0].parent == "Vault"

    def test_filtering_by_type_distinguishes_same_named_functions(self, index) -> None:  # type: ignore[no-untyped-def]
        # A record naming Vault.withdraw is wrong even though `withdraw` exists:
        # it is Token's. Checking the name alone would admit it.
        assert index.callables("withdraw", inside_type="Token")
        assert index.callables("withdraw", inside_type="Vault") == []

    @pytest.mark.parametrize(
        ("name", "kind"),
        [
            ("Token", DeclarationKind.CONTRACT),
            ("Math", DeclarationKind.LIBRARY),
            ("IOracle", DeclarationKind.INTERFACE),
        ],
    )
    def test_contracts_libraries_and_interfaces_are_all_types(self, index, name, kind) -> None:  # type: ignore[no-untyped-def]
        assert index.types(name)[0].kind is kind

    def test_span_filtering_excludes_declarations_elsewhere_in_the_file(self, index) -> None:  # type: ignore[no-untyped-def]
        deposit = index.callables("deposit")[0]
        assert index.callables("deposit", within=(deposit.start_line, deposit.end_line))
        assert index.callables("deposit", within=(1, 2)) == []


class TestRobustness:
    def test_an_unreadable_file_reports_that_rather_than_absence(self) -> None:
        # "I could not read this" and "this is not here" are different answers,
        # and a verifier must not treat the first as the second.
        index = index_source("}{ not solidity at all ][")
        assert not index.parsed
        assert index.callables("anything") == []

    @pytest.mark.parametrize("blank", ["", "   ", "\n\n\t\n"])
    def test_a_blank_file_is_unparsed(self, blank: str) -> None:
        assert not index_source(blank).parsed

    def test_declarations_are_recovered_around_a_syntax_error(self) -> None:
        # Corpus sources are pinned at historical commits and may not match any
        # single grammar revision. Recovering what is readable beats refusing.
        index = index_source("""\
contract Good { function ok() external {} }
contract Broken { function bad(((( }
contract AlsoGood { function fine() external {} }
""")
        assert index.parsed
        assert index.callables("ok")
        assert index.callables("fine")

    def test_deep_nesting_does_not_exhaust_the_stack(self) -> None:
        source = (
            "contract A {"
            + "".join(
                f" function f{i}() external {{ if (true) {{ if (true) {{}} }} }}"
                for i in range(200)
            )
            + "}"
        )
        index = index_source(source)
        assert len(index.callables("f199")) == 1

    def test_line_numbers_are_one_indexed_and_inclusive(self) -> None:
        index = index_source("pragma solidity ^0.8.0;\n\ncontract A {\n    uint256 x;\n}\n")
        decl = index.types("A")[0]
        assert (decl.start_line, decl.end_line) == (3, 5)
