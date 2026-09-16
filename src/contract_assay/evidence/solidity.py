"""Syntactic backend: what a Solidity file declares, and where.

This is the floor. It requires no compiler, no dependency resolution and no
network, so it is available for every source unit regardless of whether the
project builds. Everything that needs types, data flow or a call graph belongs
to the semantic backend; everything that needs only "is this symbol declared
here, and where" belongs here.

Why a parser and not a pattern match
------------------------------------
Text matching cannot tell a declaration from a mention of one. These all contain
the characters of a declaration and none of them declares anything::

    // The old function withdraw() used to live here
    /* function drain() external { selfdestruct(x); } */
    require(ok, "function withdraw() reverted");

A verifier built on text matching certifies locations that contain no code,
which is the opposite of its purpose. It also *rejects* real declarations that
do not fit the pattern -- a modern `constructor(address owner)` carries no
visibility keyword and no `function` keyword, so exactly the access-control
cases most worth annotating are the ones it turns away.

The parser is error-tolerant. A file with a syntax error still yields the
declarations it could read, which matters because corpus sources are pinned at
historical commits and may predate or postdate any given grammar revision.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node, Parser

__all__ = [
    "Declaration",
    "DeclarationIndex",
    "DeclarationKind",
    "SolidityUnavailable",
    "index_source",
]


class SolidityUnavailable(RuntimeError):
    """The syntactic backend could not be loaded."""


class DeclarationKind(StrEnum):
    CONTRACT = "contract"
    LIBRARY = "library"
    INTERFACE = "interface"
    FUNCTION = "function"
    CONSTRUCTOR = "constructor"
    MODIFIER = "modifier"
    RECEIVE_OR_FALLBACK = "receive_or_fallback"

    @property
    def is_type(self) -> bool:
        return self in (
            DeclarationKind.CONTRACT,
            DeclarationKind.LIBRARY,
            DeclarationKind.INTERFACE,
        )


# Nodes whose presence we care about, and the kind each maps to. The grammar
# emits a single node type for `receive` and `fallback`; both are unnamed in the
# source, so a synthetic name is supplied below.
_NODE_KINDS: dict[str, DeclarationKind] = {
    "contract_declaration": DeclarationKind.CONTRACT,
    "library_declaration": DeclarationKind.LIBRARY,
    "interface_declaration": DeclarationKind.INTERFACE,
    "function_definition": DeclarationKind.FUNCTION,
    "constructor_definition": DeclarationKind.CONSTRUCTOR,
    "modifier_definition": DeclarationKind.MODIFIER,
    "fallback_receive_definition": DeclarationKind.RECEIVE_OR_FALLBACK,
}

# Declarations the grammar leaves unnamed, because the keyword *is* the name.
_IMPLICIT_NAMES: dict[DeclarationKind, tuple[str, ...]] = {
    DeclarationKind.CONSTRUCTOR: ("constructor",),
    DeclarationKind.RECEIVE_OR_FALLBACK: ("receive", "fallback"),
}


@dataclass(frozen=True, slots=True)
class Declaration:
    """One declaration, its 1-indexed inclusive line span, and its enclosing type."""

    kind: DeclarationKind
    names: tuple[str, ...]
    start_line: int
    end_line: int
    parent: str | None

    def is_named(self, name: str) -> bool:
        return name in self.names

    def spans(self, start_line: int, end_line: int) -> bool:
        """True if this declaration's span intersects the given one."""
        return self.start_line <= end_line and start_line <= self.end_line


@lru_cache(maxsize=1)
def _parser() -> Parser:
    try:
        import tree_sitter_solidity
        from tree_sitter import Language
        from tree_sitter import Parser as TSParser
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise SolidityUnavailable(
            "the syntactic backend requires tree-sitter and tree-sitter-solidity"
        ) from exc

    with warnings.catch_warnings():
        # tree-sitter-solidity still hands back an int rather than a capsule.
        # Harmless, and not ours to fix; suppressed so it does not surface on
        # every parse.
        warnings.simplefilter("ignore", DeprecationWarning)
        language = Language(tree_sitter_solidity.language())

    return TSParser(language)


@dataclass(frozen=True, slots=True)
class DeclarationIndex:
    """Every declaration in one source file.

    `parsed` is False when the file yielded nothing a parser could recognise.
    Callers that verify ground truth must treat that as a refusal to confirm,
    not as an absence of the symbol: "I could not read this" and "this is not
    here" are different answers, and only the second is evidence.
    """

    declarations: tuple[Declaration, ...]
    parsed: bool

    def types(self, name: str) -> list[Declaration]:
        return [d for d in self.declarations if d.kind.is_type and d.is_named(name)]

    def declares_type(self, name: str) -> bool:
        return bool(self.types(name))

    def callables(
        self,
        name: str,
        *,
        within: tuple[int, int] | None = None,
        inside_type: str | None = None,
    ) -> list[Declaration]:
        """Function-like declarations matching `name`, optionally constrained.

        `within` restricts to declarations whose span intersects a line range;
        `inside_type` restricts to those lexically inside a named contract,
        library or interface.
        """
        found = [d for d in self.declarations if not d.kind.is_type and d.is_named(name)]
        if within is not None:
            found = [d for d in found if d.spans(*within)]
        if inside_type is not None:
            found = [d for d in found if d.parent == inside_type]
        return found


def _name_of(node: Node, source: bytes, kind: DeclarationKind) -> tuple[str, ...]:
    if implicit := _IMPLICIT_NAMES.get(kind):
        return implicit
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return ()
    return (source[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace"),)


def index_source(source: str) -> DeclarationIndex:
    """Parse `source` and index every declaration it contains.

    Never raises on malformed input: a file the grammar cannot fully read still
    yields whatever declarations it recovered, with `parsed` reflecting whether
    anything was recognised at all.
    """
    if not source.strip():
        return DeclarationIndex(declarations=(), parsed=False)

    data = source.encode("utf-8")
    tree = _parser().parse(data)

    found: list[Declaration] = []
    # Explicit stack rather than recursion: contract sources are occasionally
    # deep enough to matter, and a parse must not be able to exhaust the stack.
    stack: list[tuple[Node, str | None]] = [(tree.root_node, None)]
    while stack:
        node, parent = stack.pop()
        enclosing = parent

        if (kind := _NODE_KINDS.get(node.type)) is not None:
            names = _name_of(node, data, kind)
            if names:
                found.append(
                    Declaration(
                        kind=kind,
                        names=names,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        parent=parent,
                    )
                )
            if kind.is_type and names:
                enclosing = names[0]

        stack.extend((child, enclosing) for child in reversed(node.children))

    found.sort(key=lambda d: (d.start_line, d.end_line))
    return DeclarationIndex(declarations=tuple(found), parsed=bool(found))
