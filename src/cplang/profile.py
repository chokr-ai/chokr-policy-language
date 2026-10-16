"""Host profiles: how a program that embeds the language adds its own vocabulary and checks.

A host passes one `Profile` to the loader and the evaluator:

* `reason_codes` and `reason_text`: extra standard reason codes and their messages;
* `signal_families`: the allowed first parts of a bare signal code (`None` allows any);
* `signal_effect`: what a signal does by itself, before any rule runs (for example "this code always denies");
* `hard_signal_codes`: the codes whose effect is a hard deny, so the prover can reason about them;
* `roots`: extra input names expressions can read, with an optional type;
* `rule_keys`: extra keys under a rule's `when:`, each with a validator and an evaluation check.

The neutral profile (`Profile()`) adds nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cplang.model import Edit, JsonValue, Obligation, Outcome, Signal

if TYPE_CHECKING:
    from cplang.runtime import InputView


@dataclass(frozen=True)
class SignalEffect:
    """What one signal does before the rules run. `hard` effects cannot be overridden by an `allow`; `monitor_aware`
    effects are downgraded to `watch` when the policy runs in monitor mode; a lower `step` wins ties."""

    outcome: Outcome
    reason: str
    obligations: tuple[Obligation, ...] = ()
    edits: tuple[Edit, ...] | None = None
    hard: bool = False
    monitor_aware: bool = False
    step: int = 1


@dataclass(frozen=True)
class Failure:
    """The result of a failed host rule-key check."""

    outcome: Outcome
    reason: str
    obligations: tuple[Obligation, ...] = ()
    step: int = 3


@dataclass(frozen=True)
class RuleKey:
    """An extra key under `when:`. `parse` checks the value when the policy is loaded (raise `ValueError` with a
    message) and returns what is stored; `check` runs for each matching rule and returns a `Failure` or `None`."""

    parse: Callable[[Any], object]
    check: Callable[[str, Any, InputView], Failure | None]


@dataclass(frozen=True)
class Profile:
    """Host extensions passed to the loader and the evaluator; see the module documentation."""

    reason_codes: frozenset[str] = frozenset()
    reason_text: Mapping[str, str] = field(default_factory=dict)
    obligation_types: frozenset[str] = frozenset()
    signal_families: frozenset[str] | None = None
    signal_effect: Callable[[Signal], SignalEffect | None] | None = None
    hard_signal_codes: frozenset[str] = frozenset()  # codes whose effect is a hard deny (for the prover)
    roots: Mapping[str, Callable[[InputView], JsonValue] | None] = field(default_factory=dict)
    rule_keys: Mapping[str, RuleKey] = field(default_factory=dict)


NEUTRAL = Profile()
