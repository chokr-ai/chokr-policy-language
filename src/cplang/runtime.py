"""Evaluation runtime: limits, the input view the language reads, and the per-decision context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cplang.model import Action, Signal
from cplang.profile import NEUTRAL, Profile
from cplang.types import check_value
from cplang.values import (
    ABSENT,
    EnumVal,
    EvalError,
    Quantity,
    SetVal,
    V,
    from_json,
    parse_timestamp,
)

if TYPE_CHECKING:
    from cplang.declarations import DeclarationSet


@dataclass(frozen=True)
class CplLimits:
    """Size and effort limits applied while loading and evaluating policies."""

    max_expression_nodes: int = 256
    max_eval_steps: int = 10_000
    max_call_depth: int = 8
    max_type_depth: int = 8
    max_table_rows: int = 100_000
    max_regex_pattern_len: int = 1024
    max_value_chars: int = 1_048_576
    max_rules: int = 4096
    max_threshold_entries: int = 64
    max_explain_chars: int = 512
    max_document_bytes: int = 1_048_576
    max_document_depth: int = 100
    max_table_bytes: int = 67_108_864


def signal_order(s: Signal) -> tuple[str, str, str]:
    """Canonical signal order, so the verdict never depends on the order a host supplied them in."""
    return (s.code, s.source, s.id)


def walk(value: Any, part: Any) -> Any:
    """One step into a value. A missing key, index or wrong container yields `absent`."""
    if value is ABSENT:
        return ABSENT
    if isinstance(part, str):
        if isinstance(value, dict):
            return value.get(part, ABSENT)
        if isinstance(value, Quantity):
            return {"value": value.value, "unit": value.unit}.get(part, ABSENT)
        if isinstance(value, EnumVal) and part == "name":
            return value.name
        return ABSENT
    if type(part) is int:
        if isinstance(value, list | SetVal) and -len(value) <= part < len(value):
            return value[part]
        return ABSENT
    raise EvalError("index must be a string or integer")


class InputView:
    """The names an expression can read from one action plus its signals. Built once per decision."""

    def __init__(
        self, action: Action, signals: list[Signal], decls: DeclarationSet, profile: Profile = NEUTRAL
    ) -> None:
        self.action = action
        self.signals = sorted(signals, key=signal_order)
        self.decls = decls
        self.profile = profile
        self.wire: dict[str, Any] = from_json(action.to_wire())
        self.now = parse_timestamp(action.timestamp)
        self._attrs: dict[str, V] = {}
        self._state: dict[str, Any] | None = None
        self._host: dict[str, V] = {}

    @property
    def state(self) -> dict[str, Any]:
        if self._state is None:
            state = dict(self.wire.get("context") or {})
            if "depth" in self.wire:
                state["run"] = {**state.get("run", {}), "depth": self.wire["depth"]}
            if "call_chain" in self.wire:
                state["chain"] = self.wire["call_chain"]
            self._state = state
        return self._state

    def validate_inputs(self) -> None:
        """Check every declared input the action carries against its declared type."""
        for name in self.decls.inputs:
            self._declared_input(name)

    def _declared_input(self, name: str) -> V:
        """A declared input, checked against and converted to its declared type once per decision."""
        if name not in self._host:
            raw = self.wire.get(name, ABSENT)
            try:
                value = ABSENT if raw is ABSENT else check_value(self.decls.inputs[name], raw)
            except EvalError as exc:
                raise EvalError(f"input {name!r}: {exc}") from exc
            self._host[name] = V(value, True)
        return self._host[name]

    def attribute(self, name: str) -> V:
        """Typed attribute value and its trusted flag; absent when the action does not carry it."""
        if name not in self._attrs:
            raw = (self.wire.get("attributes") or {}).get(name, ABSENT)
            source = (self.wire.get("attribute_sources") or {}).get(name, "asserted")
            if raw is ABSENT:
                self._attrs[name] = V(ABSENT, True)
            else:
                self._attrs[name] = V(self.decls.typed_attribute(name, raw), source != "derived")
        return self._attrs[name]

    def root(self, name: str) -> V:
        """Top-level name to its value and trusted flag."""
        if name in self.decls.inputs:
            return self._declared_input(name)
        if name in self.profile.roots:
            if name not in self._host:
                provider = self.profile.roots[name]
                value = provider(self) if provider is not None else self.wire.get(name, ABSENT)
                self._host[name] = V(from_json(value) if value is not ABSENT else ABSENT, True)
            return self._host[name]
        if name == "state":
            return V(self.state, True)
        if name == "time":
            return V({"now": self.now}, True)
        if name == "arguments":
            return V(self.wire.get("arguments", ABSENT), False)
        if name == "attributes":
            return V({n: self.attribute(n).v for n in (self.wire.get("attributes") or {})}, True)
        return V(self.wire.get(name, ABSENT), True)


@dataclass
class Ctx:
    """Per-decision mutable state: step counter, local names and cached computed values."""

    view: InputView
    limits: CplLimits
    steps: int = 0
    depth: int = 0
    locals: dict[str, V] = field(default_factory=dict)
    vars: dict[str, V] = field(default_factory=dict)
    computed: dict[str, V] = field(default_factory=dict)
    trace: list[dict[str, Any]] | None = None
    signal_hits: list[Signal] = field(default_factory=list)  # Signals that satisfied the rule's `signal` conditions

    def step(self, n: int = 1) -> None:
        """Count `n` evaluation steps and fail when the budget is spent."""
        self.steps += n
        if self.steps > self.limits.max_eval_steps:
            raise EvalError("step budget exceeded")

    def text_steps(self, *operands: Any) -> None:
        """Charge one step per 4096 characters of each string operand and enforce the string size limit."""
        for x in operands:
            if isinstance(x, str):
                if len(x) > self.limits.max_value_chars:
                    raise EvalError("string operand is too long")
                self.step(len(x) // 4096)
