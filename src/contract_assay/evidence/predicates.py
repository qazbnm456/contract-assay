"""The predicate library: deterministic facts about Solidity, each with a place.

A predicate observes. It does not judge, and the distinction is not stylistic.
`evidence()` runs before any model and its output is recorded whatever the model
concludes, which is what makes a verdict asserted against the evidence visible
as exactly that. A predicate that quietly declined to report an awkward case
would remove that check, so a predicate reports what it sees and leaves what it
means to `verdict()`.

Consequences worth stating, because they read as flaws until the division of
labour is clear:

*   Some predicates here are **noisy on purpose**. `call_argument_is_zero_literal`
    fires on every literal zero passed to anything. Narrowing it to the calls
    that matter means recognising a callee across aliasing and renaming, which
    needs a selector rather than a name -- see the note on that predicate. Until
    then the scoping belongs in `verdict()`, where a rule that rejects is
    recorded and countable, rather than here, where a rule that declines to look
    would be invisible.

*   Some predicates establish a **weaker property than the class they serve**.
    Reentrancy needs control flow and state-write ordering, which a parser does
    not have. `state_write_after_raw_external_call` therefore names the shape it
    can actually establish rather than claiming the class, and the status table
    records the class as partly covered. A predicate named for a class it cannot
    establish is how a project comes to believe it has coverage it does not.

What a member name cannot establish
-----------------------------------
Several predicates here key on a call's member name -- `call`, `send`,
`transfer`. Those are address members at the language level, but nothing stops a
contract declaring a function with the same name, and at this tier
`helper.send(x)` and `payableAddress.send(x)` are the same shape. Telling them
apart needs the receiver's type, which is what the semantic tier is for. Three
consequences, all pinned by tests rather than described here only:

*   **Evidence can be manufactured by choosing a name.** A local helper called
    `send` makes `low_level_call_result_discarded` fire where nothing is wrong.
    The general form is worth holding on to: any rule keyed on a name can be
    made to fire by picking that name, so a name match is a fact about the text
    and not about the call.

*   **`transfer` is two different members.** `address.transfer` reverts on
    failure, so discarding its result is not a defect and it is absent from
    `FLAG_RETURNING_MEMBERS`. `IERC20.transfer` returns a bool that is very
    commonly discarded, which is a real and common defect -- and that exclusion
    makes it invisible. The exclusion is right for one meaning and wrong for the
    other, and no syntactic rule separates them.

*   **A defect split across functions is invisible.** An external call extracted
    into an internal helper, or a state write moved behind one, leaves the
    reentrancy intact while `state_write_after_raw_external_call` finds nothing
    in either function. Extracting a balance update into a helper is ordinary
    Solidity, so this is a recall gap against the natural corpus rather than an
    artefact of anything.

The third is the most costly of the three. A false fact is loud once someone
looks at it, whereas a shape the predicate cannot see costs every record of that
shape, silently, and looks exactly like the predicate working.

Naming
------
A predicate is named for the **property** it establishes, never for the form it
found it in. The form goes in `detail`.

`detail` is compared, so every value in it must survive any edit that preserves
the property: positions, counts, literal values, and language tokens that no
author can rename. Local identifiers go in `diagnostic`, which is never
compared. See section 2.3 of docs/design.md for the rule and why it is a test
rather than a list.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from contract_assay.evidence.solidity import Declaration, DeclarationKind
from contract_assay.evidence.syntax import (
    CHAIN_STATE_MEMBERS,
    LOW_LEVEL_CALL_MEMBERS,
    Syntax,
)
from contract_assay.models import Determination, EvidenceRef, EvidenceTier, VulnerabilityClass

__all__ = [
    "FLAG_RETURNING_MEMBERS",
    "RAW_EXTERNAL_CALL_MEMBERS",
    "PredicateSpec",
    "coverage_by_class",
    "predicates",
    "run_all",
]


FLAG_RETURNING_MEMBERS = LOW_LEVEL_CALL_MEMBERS | {"send"}
"""Call members that report failure as a return value the caller must inspect.

`transfer` is deliberately absent: it reverts on failure, so discarding its
result is not the same defect and reporting it as one would be a false fact.
"""

RAW_EXTERNAL_CALL_MEMBERS = FLAG_RETURNING_MEMBERS | {"transfer"}
"""Call members that are unambiguously an external call at the language level.

An ordinary `token.transferFrom(...)` is also an external call, but a parser
cannot tell it from a call to an internal helper of the same name -- that needs
types. Restricting to language members keeps the facts here true, at the cost of
covering less.
"""

_SYNTACTIC = EvidenceTier.SYNTACTIC

Predicate = Callable[[Syntax, str], list[EvidenceRef]]


@dataclass(frozen=True, slots=True)
class PredicateSpec:
    """One registered predicate, and what it claims to establish."""

    predicate_id: str
    classes: tuple[VulnerabilityClass, ...]
    tier: EvidenceTier
    summary: str
    run: Predicate


_REGISTRY: dict[str, PredicateSpec] = {}


def _register(
    predicate_id: str, *classes: VulnerabilityClass, summary: str, tier: EvidenceTier = _SYNTACTIC
) -> Callable[[Predicate], Predicate]:
    def decorate(function: Predicate) -> Predicate:
        if predicate_id in _REGISTRY:
            raise ValueError(f"predicate id {predicate_id!r} is already registered")
        _REGISTRY[predicate_id] = PredicateSpec(
            predicate_id=predicate_id,
            classes=classes,
            tier=tier,
            summary=summary,
            run=function,
        )
        return function

    return decorate


def predicates() -> tuple[PredicateSpec, ...]:
    """Every registered predicate, in registration order."""
    return tuple(_REGISTRY.values())


def coverage_by_class() -> dict[VulnerabilityClass, tuple[str, ...]]:
    """Which predicates exist per class.

    Reported so that "this class has a predicate" and "this class is covered"
    stay distinguishable. They are different claims, and only the first is ever
    established by a registry.
    """
    found: dict[VulnerabilityClass, list[str]] = {cls: [] for cls in VulnerabilityClass}
    for spec in _REGISTRY.values():
        for cls in spec.classes:
            found[cls].append(spec.predicate_id)
    return {cls: tuple(ids) for cls, ids in found.items()}


def run_all(
    syntax: Syntax, path: str, *, classes: Iterable[VulnerabilityClass] | None = None
) -> list[EvidenceRef]:
    """Run every predicate, or only those serving `classes`.

    Ordered by locator and predicate id so that two runs over the same source
    produce the same sequence. An unstable order would make a recorded trace
    differ from its own replay for no reason anybody could diagnose.
    """
    wanted = None if classes is None else frozenset(classes)
    found: list[EvidenceRef] = []
    for spec in _REGISTRY.values():
        if wanted is not None and not wanted.intersection(spec.classes):
            continue
        found.extend(spec.run(syntax, path))
    found.sort(
        key=lambda ref: (
            ref.locator.file,
            ref.locator.start_line,
            ref.locator.end_line,
            ref.predicate,
        )
    )
    return found


# ---------------------------------------------------------------------------
# Unchecked external calls
# ---------------------------------------------------------------------------


@_register(
    "low_level_call_result_discarded",
    VulnerabilityClass.UNCHECKED_EXTERNAL_CALL,
    summary="A call reporting failure by return value is a whole statement, so the flag is lost.",
)
def _low_level_call_result_discarded(syntax: Syntax, path: str) -> list[EvidenceRef]:
    return [
        EvidenceRef(
            predicate="low_level_call_result_discarded",
            tier=_SYNTACTIC,
            locator=call.site.locator(path),
            detail={"call_member": call.callee, "result_bound": False},
            diagnostic={"receiver": call.receiver},
        )
        for call in syntax.calls
        if call.callee in FLAG_RETURNING_MEMBERS and call.is_bare_statement
    ]


@_register(
    "low_level_call_result_bound_but_unread",
    VulnerabilityClass.UNCHECKED_EXTERNAL_CALL,
    summary="The failure flag is bound to a name that never appears again in the function.",
)
def _low_level_call_result_bound_but_unread(syntax: Syntax, path: str) -> list[EvidenceRef]:
    found: list[EvidenceRef] = []
    for call in syntax.calls:
        if call.callee not in FLAG_RETURNING_MEMBERS or not call.bound_names:
            continue
        host = syntax.callable_at(call.site.start_line)
        if host is None:
            continue
        # A count of one is the binding occurrence itself, so the name is never
        # mentioned again. A higher count is not proof of a *check* -- it could
        # be a reassignment -- so only the unambiguous direction is reported.
        unread = [
            position
            for position, name in enumerate(call.bound_names)
            if syntax.identifier_uses(host, name) == 1
        ]
        if not unread:
            continue
        found.append(
            EvidenceRef(
                predicate="low_level_call_result_bound_but_unread",
                tier=_SYNTACTIC,
                locator=call.site.locator(path),
                detail={
                    "call_member": call.callee,
                    "bound_count": len(call.bound_names),
                    "unread_count": len(unread),
                    "first_unread_position": unread[0],
                },
                diagnostic={
                    "unread_names": ",".join(call.bound_names[p] for p in unread),
                    "receiver": call.receiver,
                },
            )
        )
    return found


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------


@_register(
    "producer_controlled_value_read",
    VulnerabilityClass.INSECURE_RANDOMNESS,
    summary="A value is read from chain state that whoever produces the block controls.",
)
def _producer_controlled_value_read(syntax: Syntax, path: str) -> list[EvidenceRef]:
    """Named for the read, not for what the read is used for.

    An earlier name for this was `randomness_from_chain_state`, which was wrong
    in a way worth recording: the predicate fires on `block.timestamp` passed as
    a swap deadline, where the read is real but nothing about randomness has been
    established. A name that asserts the use makes every other use of the same
    property look like a false positive, and invites a second predicate for each
    one -- at which point no name counts the property.

    So this establishes the read. Which class it bears on is the registry's
    business, and a deadline-oriented consumer can subscribe to the same fact
    without it being renamed.
    """
    found: list[EvidenceRef] = []
    for site, receiver, prop in syntax.member_reads:
        if prop in CHAIN_STATE_MEMBERS.get(receiver, frozenset()):
            found.append(
                EvidenceRef(
                    predicate="producer_controlled_value_read",
                    tier=_SYNTACTIC,
                    locator=site.locator(path),
                    # A language builtin: unrenameable, so it is stable as itself.
                    detail={"source": f"{receiver}.{prop}"},
                )
            )
    found.extend(
        EvidenceRef(
            predicate="producer_controlled_value_read",
            tier=_SYNTACTIC,
            locator=call.site.locator(path),
            detail={"source": "blockhash"},
        )
        for call in syntax.calls
        if call.callee == "blockhash" and call.receiver is None
    )
    return found


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


@_register(
    "state_change_reachable_without_modifier_or_sender_reference",
    VulnerabilityClass.ACCESS_CONTROL,
    summary="An externally reachable function writes state, carries no modifier, and never "
    "mentions msg.sender.",
)
def _state_change_reachable_without_modifier_or_sender_reference(
    syntax: Syntax, path: str
) -> list[EvidenceRef]:
    """Named for the two absences it observes, not for "unguarded".

    A `msg.sender` reference is not the same thing as a guard, so a name
    claiming one would overclaim. What this establishes is narrower and exactly
    stateable: externally reachable, writes state, no modifier, no mention of
    `msg.sender` anywhere in the body.

    The sender condition is deliberately coarse, and tightening it would make
    the predicate worse rather than better. Requiring the reference to sit in a
    `require` or an `if` would distinguish a check from a log -- and would then
    fire on every permissionless-by-design function, because
    `balances[msg.sender] += msg.value` writes state and reads the sender
    without guarding anything. Those are non-findings, and there would be far
    more of them than of the case tightening would catch.

    Two things it therefore misses, both worth knowing before trusting a zero:

    *   A sender reference used only for logging -- `emit Changed(msg.sender)`
        beside an unguarded write -- suppresses the fact.
    *   A guard implemented as an internal helper, `_checkOwner()`, is invisible:
        distinguishing that call from any other internal call needs types.

    A third thing it used to miss *silently*, which is the worse kind. A
    function that changes state through an external call -- `token.mint(to, n)`
    -- writes no storage itself, so the search for writes came back empty and
    the predicate said nothing. "Nothing" then meant both "no state changes
    here" and "the state change happens somewhere I cannot see", and only the
    first is a fact about this code. Such a site is now reported as
    **indeterminate** with its reason, which is the `invalid`/`clean`
    separation this project is built on, applied one layer down
    (`models.Determination`).
    """
    found: list[EvidenceRef] = []
    for function in syntax.functions:
        declaration = function.declaration
        if declaration.kind in (DeclarationKind.CONSTRUCTOR, DeclarationKind.MODIFIER):
            # A constructor runs once at deployment and a modifier is not itself
            # reachable, so neither is an instance of this property.
            continue
        if not function.is_externally_reachable or function.is_read_only:
            continue
        if function.modifiers:
            continue
        writes = [
            w for w in syntax.writes if w.writes_state and _inside(declaration, w.site.start_line)
        ]
        if not writes:
            outbound = [
                call
                for call in syntax.calls
                if call.receiver is not None and _inside(declaration, call.site.start_line)
            ]
            if outbound:
                found.append(
                    EvidenceRef(
                        predicate="state_change_reachable_without_modifier_or_sender_reference",
                        tier=_SYNTACTIC,
                        locator=function.site.locator(path),
                        determination=Determination.INDETERMINATE,
                        indeterminate_because=(
                            "the function writes no storage itself and makes "
                            f"{len(outbound)} external "
                            f"{'call' if len(outbound) == 1 else 'calls'}, so whether it "
                            "changes state depends on what the callees do -- which is not "
                            "in the analysed unit"
                        ),
                        detail={"outbound_calls": len(outbound), "writes_storage": False},
                        diagnostic={"callees": ", ".join(sorted({c.callee for c in outbound})[:5])},
                    )
                )
            continue
        senders = [
            1
            for site, receiver, prop in syntax.member_reads
            if receiver == "msg" and prop == "sender" and _inside(declaration, site.start_line)
        ]
        if senders:
            continue
        found.append(
            EvidenceRef(
                predicate="state_change_reachable_without_modifier_or_sender_reference",
                tier=_SYNTACTIC,
                locator=function.site.locator(path),
                detail={
                    # `unspecified` rather than `private`: before 0.5 an omitted
                    # visibility defaulted to public, and reading the absence as
                    # restrictive would exempt the most exposed functions in the
                    # oldest code.
                    "visibility": function.visibility or "unspecified",
                    "modifier_count": 0,
                    "state_write_count": len(writes),
                    "sender_read_count": 0,
                },
                diagnostic={"written_roots": ",".join(sorted({w.target_root for w in writes}))},
            )
        )
    return found


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


@_register(
    "state_write_after_raw_external_call",
    VulnerabilityClass.REENTRANCY,
    summary="State is written after a language-level external call in the same function.",
)
def _state_write_after_raw_external_call(syntax: Syntax, path: str) -> list[EvidenceRef]:
    """Named for the shape it establishes, not for the class it serves.

    Reentrancy needs control flow and state-write ordering, and a parser has
    neither. This establishes the ordering only, over the calls the language
    itself marks as external -- so the class is *partly* covered, which is what
    the status table says.

    The payload carries the ordering relation and nothing else. It once carried
    a count of the writes following the call, which had to go: rewriting
    `total = c ? a : 0` as an `if`/`else` turns one state write into two,
    leaving the property untouched while the count moves. A compared value that
    moves when the property does not is a false difference, and the count was
    never part of the property.

    What this predicate cannot survive at all is an edit that moves the call
    across a function boundary. Extracting it into an internal helper leaves the
    defect intact as cross-function reentrancy, and this predicate then finds no
    external call in the function and stays silent; inlining a helper that held
    the state write does the reverse, and it starts firing where it did not
    before. Both are presence changes rather than payload changes, so no
    spelling of the payload fixes them -- following a call across a boundary is
    what the semantic tier is for. See section 8.
    """
    found: list[EvidenceRef] = []
    for call in syntax.calls:
        if call.callee not in RAW_EXTERNAL_CALL_MEMBERS:
            continue
        host = syntax.callable_at(call.site.start_line)
        if host is None:
            continue
        after = [
            w
            for w in syntax.writes
            if w.writes_state
            and _inside(host, w.site.start_line)
            and w.site.start_line > call.site.end_line
        ]
        if not after:
            continue
        found.append(
            EvidenceRef(
                predicate="state_write_after_raw_external_call",
                tier=_SYNTACTIC,
                locator=call.site.locator(path),
                detail={
                    "call_member": call.callee,
                    # The ordering relation alone. Not a count, which an
                    # if/else rewrite of a ternary changes while preserving the
                    # property; and not a line delta, which any inserted blank
                    # line changes.
                    "ordering": "write_follows_call",
                },
                diagnostic={"written_roots": ",".join(sorted({w.target_root for w in after}))},
            )
        )
    return found


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


@_register(
    "call_argument_is_zero_literal",
    VulnerabilityClass.SLIPPAGE,
    summary="A positional argument of a call is the literal zero, in any spelling.",
)
def _call_argument_is_zero_literal(syntax: Syntax, path: str) -> list[EvidenceRef]:
    """Deliberately unscoped, and the reason is worth stating.

    Section 2.3's example is the *second* argument of a call whose selector is in
    the swap set. Recognising that callee means recognising it through an aliased
    import and a renamed variable, which a name cannot survive and a selector
    can -- and computing a selector needs ABI canonicalisation that this tier
    does not have. So this reports every literal zero passed to anything, and a
    detector scopes it in `verdict()`, where a rule that rejects is recorded and
    countable. Scoping it here would hide the rule inside a predicate that simply
    declined to look.
    """
    return [
        EvidenceRef(
            predicate="call_argument_is_zero_literal",
            tier=_SYNTACTIC,
            locator=call.site.locator(path),
            detail={
                "position": argument.position,
                "argument_count": len(call.arguments),
                "literal": 0,
            },
            diagnostic={"callee": call.callee, "receiver": call.receiver},
        )
        for call in syntax.calls
        for argument in call.arguments
        if argument.is_zero_literal
    ]


@_register(
    "authorisation_reads_its_answer_from_caller_supplied_address",
    VulnerabilityClass.ACCESS_CONTROL,
    summary="A guard checking msg.sender reads the value it compares against from an "
    "address the caller supplied, so the check is satisfiable by construction.",
)
def _authorisation_reads_its_answer_from_caller_supplied_address(
    syntax: Syntax, path: str
) -> list[EvidenceRef]:
    """A guard that is present and asks the caller for its own answer.

    Named for the property, not for "broken access control": what is
    established is that a gating condition checks `msg.sender` against a value
    it reads *from an address the caller supplied*. The caller can pass an
    address it controls, so the adjudicator of the check is chosen by the party
    being checked.

    The narrowness is the whole of it, and a broader version was measured and
    rejected. Firing on any guard that mentions `msg.sender` and a parameter
    fired nineteen times over the corpus where this fires twice, and seventeen
    of the nineteen were **sound** guards -- `isApprovedOrOwner(msg.sender, id)`
    takes a caller-supplied id and resolves it against the contract's own
    state, which is the ordinary and correct way to write that check. The
    caller-supplied value there is the *subject* of the check; here it is the
    *source of the answer*, and only the second is a defect. Treating them alike
    would have made the predicate fire mostly on correct code.

    This exists because the neighbouring predicate treats *any* mention of
    `msg.sender` as a check, so a guard that is present and unsound suppresses
    it. That was a declared limit of the access-control detector with a corpus
    record behind it, and the limit's stated closure was **wrong**: it said the
    semantic tier and caller-taint. Depth-one taint needs neither. A value an
    outside caller supplied enters under a parameter name, so an expression
    mentioning that name is an expression reading something the caller chose,
    and the parser already knows both.

    The property is real and it is **not sufficient**, which the name is careful
    not to claim. One corpus source guards with
    `require(IAlchemechNFT(_nft).ownerOf(id) == msg.sender)` inside
    `if (_nft == alchemechNFT)`: the address is caller-supplied and a preceding
    comparison has pinned it to a state variable, so the check is sound. Deciding
    that is the verdict layer's, not evidence's (§2.1) -- evidence reports a
    shape, and a predicate that tried to settle soundness would be back to
    guessing. The cost is a prediction against a location the corpus holds no
    record for, which costs precision, and that is the correct price rather than
    a problem to suppress (§7.2).

    What it deliberately does not do, since the shallowness is the whole point:

    *   It does not follow an alias. `address x = from;` and then a guard on `x`
        names no parameter, and this predicate is silent. That is the part that
        does need def-use. It is recorded here rather than in the declared-limit
        register because that register requires a corpus record behind every
        entry (§7.3), and no record demonstrates this shape -- which is a bound
        on the register, not a reason to leave the limitation unwritten.
    *   It does not check whether a preceding condition pinned the
        caller-supplied address, as above.
    *   It does not judge soundness. A guard may compare the sender against a
        caller-supplied value and still be correct -- `require(to == msg.sender)`
        restricts an action to the caller's own account. So this is evidence
        about a shape, and the verdict layer is where a claim about it is
        checked (§2.1).
    """
    found: list[EvidenceRef] = []
    for function in syntax.functions:
        declaration = function.declaration
        if declaration.kind in (DeclarationKind.CONSTRUCTOR, DeclarationKind.MODIFIER):
            continue
        if not function.is_externally_reachable or function.is_read_only:
            continue
        if not function.parameter_names:
            continue
        for guard in syntax.guards:
            if not _inside(declaration, guard.site.start_line):
                continue
            if "sender" not in guard.identifiers:
                continue
            supplied = sorted(frozenset(guard.call_receivers) & frozenset(function.parameter_names))
            if not supplied:
                continue
            found.append(
                EvidenceRef(
                    predicate="authorisation_reads_its_answer_from_caller_supplied_address",
                    tier=_SYNTACTIC,
                    locator=function.site.locator(path),
                    detail={
                        "guard_line": guard.site.start_line,
                        "caller_supplied_receiver_count": len(supplied),
                    },
                    diagnostic={"receivers": ",".join(supplied)},
                )
            )
    return found


@_register(
    "loop_bounded_by_externally_growable_storage_array",
    VulnerabilityClass.DENIAL_OF_SERVICE,
    summary="A loop is bounded by the length of a dynamic storage array that an "
    "externally reachable function appends to.",
)
def _loop_bounded_by_externally_growable_storage_array(
    syntax: Syntax, path: str
) -> list[EvidenceRef]:
    """Three facts, each of them a declaration or a shape.

    The array's declared type says whether it is dynamic -- `address[]` grows,
    `address[3]` does not, and a mapping has no length to loop over. The loop's
    continuation condition says which name bounds it. And the function calling
    `push` on it has a visibility, which says whether an outsider can make the
    loop longer.

    §4.2 recorded this class as needing storage and dynamic-array *types* from a
    compiled backend. The declaration states both in the source text, which is
    what the audit in `tests/unit/test_tier_audit.py` established.

    Not established: that the loop is expensive enough to exceed a block's gas,
    which depends on what the body does per element and on a gas schedule that
    changes between forks. So this reports an unbounded iteration an outsider
    can extend, and the verdict layer is where a claim about it is checked.
    """
    growable: dict[str, str] = {}
    for call in syntax.calls:
        if call.callee != "push" or call.receiver is None:
            continue
        declared = syntax.state_variable_types.get(call.receiver)
        if declared is None or not declared.endswith("[]"):
            continue
        host = syntax.host_at(call.site.start_line)
        if host.function is None:
            continue
        appender = next(
            (f for f in syntax.functions if f.declaration.names[0] == host.function), None
        )
        if appender is None:
            continue
        if appender.is_externally_reachable:
            growable[call.receiver] = host.function
            continue
        # One hop through an internal appender, which the first version of this
        # predicate could not see and which was filed as needing a call graph
        # from the semantic tier. Measured: within one file, resolving a call is
        # name lookup, and it is sound exactly when the name is declared once --
        # more than one is an overload or an override, where a syntactic answer
        # must refuse rather than pick.
        if syntax.declarations_of(host.function) != 1:
            continue
        reachable = [
            caller
            for caller in syntax.callers_of(host.function)
            if syntax.declarations_of(caller) == 1
            and next(
                (
                    f.is_externally_reachable
                    for f in syntax.functions
                    if f.declaration.names[0] == caller
                ),
                False,
            )
        ]
        if reachable:
            growable[call.receiver] = f"{host.function} via {reachable[0]}"

    found: list[EvidenceRef] = []
    for loop in syntax.loops:
        host = syntax.host_at(loop.site.start_line)
        enclosing = next(
            (f for f in syntax.functions if f.declaration.names[0] == host.function), None
        )
        aliases = syntax.length_aliases.get(enclosing.site.start_line, {}) if enclosing else {}
        # A bound may name the collection directly, or a local assigned its
        # length once in the same body. The second was filed as needing def-use
        # from a tier; it is one assignment inside one body.
        named = set(loop.bound_identifiers) | {
            aliases[name] for name in loop.bound_identifiers if name in aliases
        }
        via_alias = bool(
            {aliases[name] for name in loop.bound_identifiers if name in aliases} & set(growable)
        )
        bounded_by = sorted(named & frozenset(growable))
        if not bounded_by:
            continue
        if "length" not in loop.bound_identifiers and not via_alias:
            continue
        found.append(
            EvidenceRef(
                predicate="loop_bounded_by_externally_growable_storage_array",
                tier=_SYNTACTIC,
                locator=loop.site.locator(path),
                detail={
                    "bounded_array_count": len(bounded_by),
                    "array_is_dynamic": True,
                    "bound_through_a_local": via_alias,
                },
                diagnostic={
                    "arrays": ",".join(bounded_by),
                    "appenders": ",".join(growable[name] for name in bounded_by),
                },
            )
        )
    return found


@_register(
    "multi_return_timestamp_never_reaches_a_guard",
    VulnerabilityClass.ORACLE_INTEGRITY,
    summary="A time-typed value unpacked from a multi-return is never mentioned in any "
    "condition in the function that unpacked it.",
)
def _multi_return_timestamp_never_reaches_a_guard(syntax: Syntax, path: str) -> list[EvidenceRef]:
    """A freshness value the code asked for and then never consulted.

    Named for the property and not for an oracle, which is what makes it
    reachable without an ABI: the class had been parked on knowing *which*
    interface returns a price. It does not need to know. A call that returns a
    timestamp alongside a value, whose caller binds the timestamp and then never
    mentions it in a condition, asked for a freshness claim and discarded it --
    whoever the callee is.

    A binding is treated as time-typed on its declared type and its name
    together, and both are in the tuple's own declaration.

    What it cannot see, and the shape is worth knowing before trusting a zero:
    an older single-return feed carries no timestamp at all, so there is nothing
    to bind and this is silent. That is a *different* situation from a discarded
    timestamp -- arguably a worse one -- and it is not this property.
    """
    found: list[EvidenceRef] = []
    for function in syntax.functions:
        declaration = function.declaration
        unpacked = [d for d in syntax.destructurings if _inside(declaration, d.site.start_line)]
        if not unpacked:
            continue
        mentioned = {
            identifier
            for guard in syntax.guards
            if _inside(declaration, guard.site.start_line)
            for identifier in guard.identifiers
        }
        for destructuring in unpacked:
            stale = sorted(
                name
                for declared, name in destructuring.bindings
                if _looks_like_a_time(declared, name) and name not in mentioned
            )
            if not stale:
                continue
            found.append(
                EvidenceRef(
                    predicate="multi_return_timestamp_never_reaches_a_guard",
                    tier=_SYNTACTIC,
                    locator=destructuring.site.locator(path),
                    detail={
                        "unguarded_time_binding_count": len(stale),
                        "guards_in_function": len(mentioned) > 0,
                    },
                    diagnostic={"bindings": ",".join(stale), "from": destructuring.source_text},
                )
            )
    return found


@_register(
    "division_evaluated_before_multiplication",
    VulnerabilityClass.ARITHMETIC_ROUNDING,
    summary="One expression divides and then multiplies, discarding precision that "
    "multiplying first would have kept.",
)
def _division_evaluated_before_multiplication(syntax: Syntax, path: str) -> list[EvidenceRef]:
    """Integer division truncates, so the order of the two decides the result.

    `a / b * c` and `a * c / b` differ by up to `c - 1` in integer arithmetic,
    and the first is the shape that loses. It is the shape of a single
    expression: an outer multiplication whose operand already divided. §4.2
    recorded this class as needing types and evaluation order from a compiled
    backend; evaluation order is the parse tree, which is the part the audit
    separated out.

    Not established: that the loss matters. Dividing first is correct when the
    quotient is exact or the scale is deliberate, which is why this is evidence
    about a shape rather than a verdict (§2.1).
    """
    found: list[EvidenceRef] = []
    for expression in syntax.arithmetic:
        if expression.operator != "*" or "/" not in expression.operand_operators:
            continue
        found.append(
            EvidenceRef(
                predicate="division_evaluated_before_multiplication",
                tier=_SYNTACTIC,
                locator=expression.site.locator(path),
                detail={"outer_operator": "*", "divides_in_operand": True},
                diagnostic={"expression": expression.site.text[:120]},
            )
        )
    return found


def _looks_like_a_time(declared: str, name: str) -> bool:
    """Whether a binding is a timestamp, from its declared type and its name.

    Both, because either alone is wrong in a common case: every `uint256` is not
    a time, and a name is a user identifier that may say anything. Requiring an
    unsigned integer type *and* a name that speaks of time is narrow enough to
    be worth reporting and shallow enough to be honest about -- a binding named
    for time and typed as one is the shape, not a proof.
    """
    if not declared.startswith(("uint", "int")):
        return False
    lowered = name.lower()
    return any(
        term in lowered for term in ("time", "timestamp", "updated", "roundid", "age", "stale")
    )


def _inside(declaration: Declaration, line: int) -> bool:
    return declaration.start_line <= line <= declaration.end_line
