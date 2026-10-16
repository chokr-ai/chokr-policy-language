"""Policy documents: validation, compilation into evaluable rules, and the policy fingerprint."""

from __future__ import annotations

import dataclasses
import functools
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, TypedDict

from cplang.canonical import digest_object
from cplang.compile import Compiled, Compiler, Scope, compile_expression, compile_node
from cplang.conditions import ADMISSION_KEYS, ConditionBuilder, path_node, private_reference
from cplang.declarations import CondDef, DeclarationSet, PackResolver, load_declarations, sha256_file
from cplang.errors import AuthoringError
from cplang.expr import Node, defer_response, reads_response
from cplang.functions import FunctionRegistry
from cplang.model import JsonValue, Mode, Obligation, Outcome, Strategy
from cplang.profile import NEUTRAL, Profile
from cplang.registry import CUSTOM_NAMESPACED, CUSTOM_REASON, REASON_CODES, is_outcome
from cplang.runtime import CplLimits
from cplang.source import Source, read_source
from cplang.types import Type, parse_type_expr
from cplang.values import ABSENT, V, render, to_wire


def _reads_result(node: Any) -> bool:
    """Whether a rule's canonical form reads signals or the tool response (`arguments.response`)."""
    if isinstance(node, dict):
        if node.get("k") == "op" and node.get("op") == "signal":
            return True
        if node.get("k") == "path" and node.get("op") == "arguments":
            args = node.get("args") or []
            if args and args[0] == "response":
                return True
        return any(_reads_result(v) for v in node.values())
    if isinstance(node, list):
        return any(_reads_result(v) for v in node)
    return False


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TOP = {
    "cpl",
    "id",
    "version",
    "fragment",
    "imports",
    "vocabulary",
    "params",
    "mode",
    "default",
    "strategy",
    "risk_tiers",
    "default_risk_tier",
    "rules",
    "conditions",
    "description",
    "ext",
}
_RULE = {
    "id",
    "description",
    "priority",
    "enabled",
    "mode",
    "match",
    "let",
    "when",
    "outcome",
    "modify",
    "reason",
    "explain",
    "hint",
    "obligations",
    "ext",
}


class PolicyWarning(TypedDict):
    """A problem that does not stop a policy from loading, with its location."""

    code: str
    file: str | None
    line: int | None
    column: int | None
    path: str
    message: str


STRATEGIES = ("first_match", "deny_overrides", "priority")
_STANDARD_OBLIGATIONS = frozenset({"human_approval", "redact", "notify"})
_PLACEHOLDER = re.compile(r"\{\{|\}\}|\{([^{}]+)\}")
_SIGNAL_FIELDS = ("code", "source", "severity", "confidence", "id", "evidence", "facts")


class Template:
    """A compiled `explain` text with placeholders."""

    def __init__(self, source: str, parts: list[str | tuple[str, Any]]) -> None:
        self.source, self.parts = source, parts

    def render(self, ctx: Any, *, agent: bool) -> str:
        """Fill in the placeholders for one decision."""
        out: list[str] = []
        for part in self.parts:
            if isinstance(part, str):
                out.append(part)
                continue
            kind, payload = part
            if kind == "signal":
                out.append(self._signal(ctx, payload, agent))
            else:
                v: V = payload.fn(ctx)
                out.append("[withheld]" if agent and not v.trusted and v.v is not ABSENT else render(v.v))
        return "".join(out)[: ctx.limits.max_explain_chars]

    @staticmethod
    def _signal(ctx: Any, path: tuple[str, ...], agent: bool) -> str:
        if not ctx.signal_hits:
            return "n/a"
        value: Any = ctx.signal_hits[0].to_wire()
        for part in path:
            value = value.get(part, ABSENT) if isinstance(value, dict) else ABSENT
        if value is ABSENT:
            return "n/a"
        if agent and path and path[0] == "evidence":
            return "[withheld]"
        return render(value)


def _named_types(t: Type) -> Iterator[str]:
    """The declared type names a type expression writes, e.g. `Money` in `list<Money>` (not what Money uses)."""
    if t.name:
        yield t.name
        return
    for arg in t.args:
        yield from _named_types(arg)


def _check_public(node: Node, scope: Scope, src: Source, where: tuple[str | int, ...]) -> None:
    """Policy text may not name a declaration that is private to its file."""
    name = private_reference(node, scope.decls)
    if name is not None:
        raise src.error("DECLARATION_UNKNOWN_NAME", f"{name} is private to its declaration file", *where)


def compile_template(text: str, scope: Scope, src: Source, where: tuple[str | int, ...]) -> Template:
    """Parse an `explain` template."""
    parts: list[str | tuple[str, Any]] = []
    pos = 0
    for m in _PLACEHOLDER.finditer(text):
        parts.append(text[pos : m.start()])
        pos = m.end()
        if m.group() == "{{":
            parts.append("{")
        elif m.group() == "}}":
            parts.append("}")
        else:
            expr = m.group(1).strip()
            if expr.startswith("signal."):
                names = tuple(expr.split(".")[1:])
                if not names or names[0] not in _SIGNAL_FIELDS:
                    raise src.error("SCHEMA_INVALID", f"unknown signal field in {{{expr}}}", *where)
                parts.append(("signal", names))
                continue
            try:
                node = path_node(expr)
                parts.append(("path", Compiler(scope).compile(node)))
            except AuthoringError as exc:
                raise src.error("SCHEMA_INVALID", f"unknown path in {{{expr}}}: {exc.message}", *where) from exc
            _check_public(node, scope, src, where)
    parts.append(text[pos:])
    return Template(text, parts)


@dataclass
class Threshold:
    """A compiled `thresholds` entry."""

    index: int
    cond: Compiled
    outcome: Outcome
    reason: str | None
    path: Compiled | None
    value: Compiled | None
    expr: str | None
    canon: dict[str, Any]
    path_text: str | None = None
    cond_before: Compiled | None = None  # the condition as it reads before the call, when it reads the response


@dataclass
class Admission:
    """The compiled requirement keys of a rule: deny, thresholds, parameter checks, rate limit and approval."""

    deny: Compiled | None = None
    deny_before: Compiled | None = None  # `deny` as it reads before the call, when it reads the response
    host: dict[str, Any] = field(default_factory=dict)  # values of the host's rule keys, after `parse`
    immutable: dict[str, Any] | None = None
    bounded: dict[str, dict[str, Any]] | None = None
    max_calls: dict[str, int] | None = None
    thresholds: list[Threshold] = field(default_factory=list)
    approval: dict[str, Any] | None = None
    canon: dict[str, Any] = field(default_factory=dict)


@dataclass
class CRule:
    """A compiled rule."""

    id: str
    description: str | None
    priority: int
    enabled: bool
    mode: Mode  # effective: rule > file > rules.mode > enforce
    match: Compiled | None
    lets: list[tuple[str, Compiled]]
    gate: Compiled | None
    admission: Admission
    outcome: Outcome
    modify: dict[str, Any] | None
    reason: str | None
    explain: Template | None
    hint: dict[str, JsonValue] | None
    obligations: list[Obligation]
    canon: dict[str, Any]
    result_aware: bool = False  # also considered when evaluating after the action


@dataclass
class CompiledPolicy:
    """A loaded policy set: its rules, declarations, limits and fingerprint."""

    id: str
    version: int | str
    cpl_version: str
    mode: Mode
    default: Outcome
    strategy: Strategy
    risk_tiers: list[tuple[str, Compiled]]
    default_risk_tier: str | None
    rules: list[CRule]
    decls: DeclarationSet
    files: dict[str, str]
    plugin_refs: set[str]
    warnings: list[PolicyWarning]
    fingerprint: str
    limits: CplLimits
    plugins: FunctionRegistry | None = None
    risk_canon: list[dict[str, Any]] = field(default_factory=list)
    profile: Profile = NEUTRAL


def _num_ok(x: Any) -> bool:
    return type(x) is not bool and isinstance(x, int | Decimal)


class _PolicyCompiler:
    def __init__(
        self,
        decls: DeclarationSet,
        limits: CplLimits,
        plugins: FunctionRegistry | None,
        strict: bool,
        rules_mode: Mode | None,
        defaults: tuple[int, int],
        profile: Profile = NEUTRAL,
    ) -> None:
        self.decls, self.limits, self.plugins, self.strict = decls, limits, plugins, strict
        self.profile = profile
        self.reason_codes = REASON_CODES | profile.reason_codes
        self.rules_mode, self.defaults = rules_mode, defaults
        self.warnings: list[PolicyWarning] = []
        self.plugin_refs: set[str] = set()

    def scope(self, vars_: dict[str, Any] | None = None, src: Source | None = None) -> Scope:
        return Scope(self.decls, {}, dict(vars_ or {}), self.plugins, self.limits, src.file if src else None)

    def reason(self, src: Source, code: Any, where: tuple[str | int, ...]) -> str:
        if not isinstance(code, str):
            raise src.error("SCHEMA_INVALID", "reason is a string", *where)
        if code in self.reason_codes:
            return code
        if CUSTOM_REASON.fullmatch(code):
            if code not in self.decls.open_values["reason_codes"]:
                if self.strict:
                    raise src.error("VOCABULARY_UNKNOWN_VALUE", f"reason {code} is not declared", *where)
                file, line, col = src.where(*where)
                self.warnings.append(
                    {
                        "code": "VOCABULARY_UNKNOWN_VALUE",
                        "file": file,
                        "line": line,
                        "column": col,
                        "path": ".".join(map(str, where)),
                        "message": f"reason {code} is not declared",
                    }
                )
            return code
        raise src.error(
            "VOCABULARY_UNKNOWN_VALUE", f"{code!r} is neither a standard nor a namespaced reason code", *where
        )

    def compile_cond(self, node: Node, scope: Scope, src: Source, where: tuple[str | int, ...]) -> Compiled:
        try:
            compiled = compile_node(node, scope)
        except AuthoringError as exc:
            raise exc.located(*src.where(*where)) from exc
        self._note_plugins(node)
        return compiled

    def _note_plugins(self, node: Node) -> None:
        if node.k == "call" and "/" in (node.op or ""):
            self.plugin_refs.add(node.op or "")
        for a in node.args:
            if isinstance(a, Node):
                self._note_plugins(a)

    def builder(self, src: Source, *, in_match: bool = False) -> ConditionBuilder:
        return ConditionBuilder(
            src,
            self.decls,
            in_match=in_match,
            check_signal_code=lambda code, where: self.vocab("signal_codes", src, code, where),
            host_keys=self.profile.rule_keys,
            host_roots=self.profile.roots,
            public_only=True,
        )

    def vocab(self, section: str, src: Source, value: str, where: tuple[str | int, ...]) -> None:
        """Cross-check: a bare value must be standard; a namespaced one should be declared."""
        if "/" not in value:
            head = value.split(".", 1)[0]
            families = self.profile.signal_families
            ok = families is None or head in families
            if not ok:
                kind = section[:-1].replace("_", " ")
                raise src.error("VOCABULARY_UNKNOWN_VALUE", f"{value!r} is not a standard {kind}", *where)
            return
        if not CUSTOM_NAMESPACED.fullmatch(value):
            raise src.error("VOCABULARY_UNKNOWN_VALUE", f"{value!r} is not a valid namespaced value", *where)
        if value not in self.decls.open_values[section]:
            if self.strict:
                raise src.error("VOCABULARY_UNKNOWN_VALUE", f"{value} is not declared", *where)
            file, line, col = src.where(*where)
            self.warnings.append(
                {
                    "code": "VOCABULARY_UNKNOWN_VALUE",
                    "file": file,
                    "line": line,
                    "column": col,
                    "path": ".".join(map(str, where)),
                    "message": f"{value} is not declared",
                }
            )

    def expr(self, text: Any, scope: Scope, src: Source, where: tuple[str | int, ...]) -> Compiled:
        if not isinstance(text, str):
            raise src.error("SCHEMA_INVALID", "an expression is a string", *where)
        try:
            compiled = compile_expression(text, scope)
        except AuthoringError as exc:
            raise exc.located(*src.where(*where)) from exc
        if compiled.node is not None:
            _check_public(compiled.node, scope, src, where)
            self._note_plugins(compiled.node)
        return compiled

    def rule(self, raw: Any, src: Source, base: tuple[str | int, ...], file_mode: Mode | None, prefix: str) -> CRule:
        if not isinstance(raw, dict):
            raise src.error("SCHEMA_INVALID", "a rule is a mapping", *base)
        for key in raw:
            if key not in _RULE:
                raise src.error("SCHEMA_INVALID", f"unknown rule key {key!r}", *base, key)
        rid = raw.get("id")
        if not isinstance(rid, str) or not _ID.fullmatch(rid):
            raise src.error(
                "SCHEMA_INVALID",
                "a rule needs a stable `id` (letters, digits, . _ -)",
                *base,
                "id" if "id" in raw else "",
            )
        outcome = raw.get("outcome")
        if not is_outcome(outcome):
            raise src.error("SCHEMA_INVALID", f"unknown outcome {outcome!r}", *base, "outcome")
        priority = raw.get("priority", 0)
        if type(priority) is not int:
            raise src.error("SCHEMA_INVALID", "priority is an integer", *base, "priority")
        enabled = raw.get("enabled", True)
        if type(enabled) is not bool:
            raise src.error("SCHEMA_INVALID", "enabled is true or false", *base, "enabled")
        mode = raw.get("mode")
        if mode not in (None, "enforce", "monitor"):
            raise src.error("SCHEMA_INVALID", "mode is enforce or monitor", *base, "mode")
        b = self.builder(src, in_match=True)
        match = None
        if raw.get("match") is not None:
            match = self.compile_cond(
                b.block(raw["match"], (*base, "match")), self.scope(src=src), src, (*base, "match")
            )
        if isinstance(raw.get("match"), dict):
            for key, value in raw["match"].items():
                if isinstance(value, list) and not value:
                    file, line, col = src.where(*base, "match", key)
                    self.warnings.append(
                        {
                            "code": "RULE_NEVER_MATCHES",
                            "file": file,
                            "line": line,
                            "column": col,
                            "path": ".".join(map(str, (*base, "match", key))),
                            "message": f"match.{key} is an empty list, so this rule can never match",
                        }
                    )
        lets, vars_ = self._lets(raw.get("let"), src, base)
        when = {} if raw.get("when") is None else raw["when"]
        if not isinstance(when, dict):
            raise src.error("SCHEMA_INVALID", "when is a mapping", *base, "when")
        gb = self.builder(src)
        gate_node = gb.block(when, (*base, "when"), allow_admission=True)
        gate = self.compile_cond(gate_node, self.scope(vars_, src), src, (*base, "when"))
        gate_canon = gate_node.canon()
        admission = self._admission(when, vars_, src, (*base, "when"))
        approval_needed = outcome == "ask" or any(t.outcome == "ask" for t in admission.thresholds)
        if approval_needed and admission.approval is None:
            raise src.error("SCHEMA_INVALID", "an `ask` outcome needs an `approval` block in `when`", *base)
        reason = self.reason(src, raw["reason"], (*base, "reason")) if "reason" in raw else None
        scope = self.scope(vars_, src)
        explain = (
            compile_template(raw["explain"], scope, src, (*base, "explain"))
            if isinstance(raw.get("explain"), str)
            else None
        )
        if "explain" in raw and explain is None:
            raise src.error("SCHEMA_INVALID", "explain is a string", *base, "explain")
        modify = self._modify(raw.get("modify"), outcome, src, (*base, "modify"))
        obligations = self._obligations(raw.get("obligations"), src, (*base, "obligations"))
        hint = raw.get("hint")
        if hint is not None and not isinstance(hint, dict):
            raise src.error("SCHEMA_INVALID", "hint is a mapping", *base, "hint")
        full_id = f"{prefix}{rid}"
        canon = {
            "id": full_id,
            "enabled": enabled,
            "priority": priority,
            "mode": mode,
            "match": match.node.canon() if match and match.node else None,
            "let": [[n, c.node.canon() if c.node else None] for n, c in lets],
            "when": gate_canon,
            "admission": admission.canon,
            "outcome": outcome,
            "modify": to_wire(modify) if modify else None,
            "reason": reason,
            "explain": raw.get("explain"),
            "hint": to_wire(hint) if hint else None,
            "obligations": to_wire(obligations),
        }
        result_aware = _reads_result(canon)
        return CRule(
            full_id,
            raw.get("description"),
            priority,
            enabled,
            mode or file_mode or self.rules_mode or "enforce",
            match,
            lets,
            gate,
            admission,
            outcome,
            modify,
            reason,
            explain,
            hint,
            obligations,
            canon,
            result_aware,
        )

    def _lets(
        self, raw: Any, src: Source, base: tuple[str | int, ...]
    ) -> tuple[list[tuple[str, Compiled]], dict[str, Any]]:
        if raw is None:
            return [], {}
        if not isinstance(raw, dict):
            raise src.error("SCHEMA_INVALID", "let is a mapping of names to expressions", *base, "let")
        lets: list[tuple[str, Compiled]] = []
        vars_: dict[str, Any] = {}
        for name, text in raw.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
                raise src.error("SCHEMA_INVALID", f"{name!r} is not a valid variable name", *base, "let", name)
            c = self.expr(text, self.scope(vars_, src), src, (*base, "let", name))
            lets.append((name, c))
            vars_[name] = c.t
        return lets, vars_

    def _modify(self, raw: Any, outcome: Outcome, src: Source, where: tuple[str | int, ...]) -> dict[str, Any] | None:
        if raw is None:
            if outcome == "modify":
                raise src.error("SCHEMA_INVALID", "a `modify` outcome needs a `modify` block", *where[:-1])
            return None
        if outcome != "modify":
            raise src.error("SCHEMA_INVALID", "`modify` is only valid with outcome modify", *where)
        if not isinstance(raw, dict) or len(raw) != 1 or next(iter(raw)) not in ("apply_suggested", "edits", "replace"):
            raise src.error(
                "SCHEMA_INVALID", "modify is {apply_suggested: true}, {edits: [...]} or {replace: {...}}", *where
            )
        key = next(iter(raw))
        if key == "apply_suggested" and raw[key] is not True:
            raise src.error("SCHEMA_INVALID", "apply_suggested is true", *where)
        if key == "replace" and not isinstance(raw[key], dict):
            raise src.error("SCHEMA_INVALID", "replace is a mapping", *where)
        if key == "edits":
            if not isinstance(raw[key], list) or not raw[key]:
                raise src.error("SCHEMA_INVALID", "edits is a non-empty list", *where)
            for i, e in enumerate(raw[key]):
                if (
                    not isinstance(e, dict)
                    or e.get("op") not in ("redact", "replace", "drop_field", "set")
                    or (not str(e.get("json_pointer", "x")).startswith("/") and e.get("json_pointer") != "")
                ):
                    raise src.error("SCHEMA_INVALID", "an edit is {op, json_pointer, value?, placeholder?}", *where, i)
        return dict(raw)

    def _obligations(self, raw: Any, src: Source, where: tuple[str | int, ...]) -> list[Obligation]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise src.error("SCHEMA_INVALID", "obligations is a list", *where)
        out: list[Obligation] = []
        for i, o in enumerate(raw):
            if not isinstance(o, dict) or not isinstance(o.get("type"), str) or set(o) - {"type", "params"}:
                raise src.error("SCHEMA_INVALID", "an obligation is {type, params?}", *where, i)
            t = o["type"]
            known = t in _STANDARD_OBLIGATIONS or t in self.profile.obligation_types
            if not known and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,62}/[a-z][a-z0-9_]*", t):
                raise src.error("SCHEMA_INVALID", f"unknown obligation type {t!r}", *where, i, "type")
            out.append({"type": t, "params": dict(o.get("params") or {})})
        return out

    def _admission(
        self, when: dict[str, Any], vars_: dict[str, Any], src: Source, base: tuple[str | int, ...]
    ) -> Admission:
        a = Admission()
        canon: dict[str, Any] = {}
        scope = self.scope(vars_, src)
        for key in (*ADMISSION_KEYS, *self.profile.rule_keys):
            if key not in when:
                continue
            v, w = when[key], (*base, key)
            if key in self.profile.rule_keys:
                try:
                    a.host[key] = self.profile.rule_keys[key].parse(v)
                except ValueError as exc:
                    raise src.error("SCHEMA_INVALID", f"{key}: {exc}", *w) from exc
                canon[key] = to_wire(v)
                continue
            if key == "deny":
                node = self.builder(src).block(v, w)
                a.deny = self.compile_cond(node, scope, src, w)
                a.deny_before = self._before_call(a.deny, scope, src, w)
                canon[key] = node.canon()
                continue
            if key == "immutable_params":
                if not isinstance(v, dict) or not v:
                    raise src.error("SCHEMA_INVALID", "immutable_params is {name: value}", *w)
                a.immutable = dict(v)
            elif key == "bounded_params":
                if not isinstance(v, dict) or not v:
                    raise src.error("SCHEMA_INVALID", "bounded_params is {name: {min, max}}", *w)
                for name, bound in v.items():
                    if (
                        not isinstance(bound, dict)
                        or not bound
                        or set(bound) - {"min", "max"}
                        or not all(_num_ok(x) for x in bound.values())
                    ):
                        raise src.error("SCHEMA_INVALID", "a bound is {min?, max?} with at least one number", *w, name)
                a.bounded = {k: dict(b) for k, b in v.items()}
            elif key == "max_calls_per_window":
                if (
                    not isinstance(v, dict)
                    or set(v) - {"limit", "window_seconds"}
                    or not all(type(x) is int and x >= 1 for x in v.values())
                ):
                    raise src.error(
                        "SCHEMA_INVALID", "max_calls_per_window is {limit, window_seconds} (integers >= 1)", *w
                    )
                a.max_calls = {
                    "limit": v.get("limit", self.defaults[0]),
                    "window_seconds": v.get("window_seconds", self.defaults[1]),
                }
                canon[key] = dict(a.max_calls)  # the resolved limit, so a different default changes the fingerprint
                continue
            elif key == "thresholds":
                a.thresholds = self._thresholds(v, vars_, src, w)
                canon[key] = [t.canon for t in a.thresholds]
                continue
            elif key == "approval":
                a.approval = self._approval(v, src, w)
            canon[key] = to_wire(v)
        a.canon = canon
        return a

    def _approval(self, v: Any, src: Source, w: tuple[str | int, ...]) -> dict[str, Any]:
        keys = {"timeout_seconds", "on_timeout", "fatigue_threshold", "fatigue_window_seconds"}
        if (
            not isinstance(v, dict)
            or set(v) - keys
            or type(v.get("timeout_seconds")) is not int
            or v["timeout_seconds"] < 1
        ):
            raise src.error("SCHEMA_INVALID", "approval is {timeout_seconds >= 1, on_timeout?, fatigue_*?}", *w)
        on_timeout = v.get("on_timeout", "deny")
        if on_timeout not in ("deny", "escalate"):
            raise src.error(
                "SCHEMA_INVALID", "on_timeout is deny or escalate (allow is refused: fail closed)", *w, "on_timeout"
            )
        ft, fw = v.get("fatigue_threshold"), v.get("fatigue_window_seconds")
        if (ft is not None and (type(ft) is not int or ft < 1)) or (fw is not None and (type(fw) is not int or fw < 1)):
            raise src.error("SCHEMA_INVALID", "fatigue values are integers >= 1", *w)
        if ft is not None and fw is None:
            raise src.error("SCHEMA_INVALID", "fatigue_threshold needs fatigue_window_seconds", *w)
        return {**{k: v[k] for k in v}, "on_timeout": on_timeout}

    def _thresholds(self, v: Any, vars_: dict[str, Any], src: Source, w: tuple[str | int, ...]) -> list[Threshold]:
        if not isinstance(v, list) or not v or len(v) > self.limits.max_threshold_entries:
            raise src.error(
                "SCHEMA_INVALID", f"thresholds is a list of 1..{self.limits.max_threshold_entries} entries", *w
            )
        scope = self.scope(vars_, src)
        out = []
        for i, t in enumerate(v):
            tw = (*w, i)
            if not isinstance(t, dict) or t.get("outcome") not in ("deny", "ask", "watch"):
                raise src.error("SCHEMA_INVALID", "a threshold needs outcome deny|ask|watch", *tw)
            reason = self.reason(src, t["reason"], (*tw, "reason")) if "reason" in t else None
            rest = {k: x for k, x in t.items() if k not in ("outcome", "reason")}
            b = self.builder(src)
            if "expr" in rest:
                if set(rest) != {"expr"}:
                    raise src.error("SCHEMA_INVALID", "an expr threshold has only expr, outcome, reason", *tw)
                cond = self.expr(rest["expr"], scope, src, (*tw, "expr"))
                out.append(
                    Threshold(
                        i,
                        cond,
                        t["outcome"],
                        reason,
                        None,
                        None,
                        rest["expr"],
                        {"expr": cond.node.canon() if cond.node else None, "outcome": t["outcome"], "reason": reason},
                    )
                )
                continue
            path_text = rest.pop("path", None)
            if path_text is None:
                raise src.error("SCHEMA_INVALID", "a threshold needs `path` or `expr`", *tw)
            target = b.path(path_text, (*tw, "path"))
            ops = dict(rest)
            if not ops:
                raise src.error("SCHEMA_INVALID", "a threshold needs an operator", *tw)
            node = b.operators(target, ops, tw)
            cond = self.compile_cond(node, scope, src, tw)
            first_op = next(k for k in ops if k not in ("negate", "sep", "case_insensitive", "normalize"))
            value_node = b.value(ops[first_op], (*tw, first_op)) if first_op not in ("exists",) else None
            out.append(
                Threshold(
                    i,
                    cond,
                    t["outcome"],
                    reason,
                    self.compile_cond(target, scope, src, tw),
                    self.compile_cond(value_node, scope, src, tw) if value_node is not None else None,
                    None,
                    {"node": node.canon(), "outcome": t["outcome"], "reason": reason},
                    str(path_text),
                )
            )
        for threshold in out:
            threshold.cond_before = self._before_call(threshold.cond, scope, src, w)
        return out

    def _before_call(self, cond: Compiled, scope: Scope, src: Source, where: tuple[str | int, ...]) -> Compiled | None:
        if cond.node is None or not reads_response(cond.node):
            return None
        return self.compile_cond(defer_response(cond.node), scope, src, where)


def _as_authoring_error[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Whatever a malformed document trips over is reported as an authoring error, never as a raw exception."""

    @functools.wraps(fn)
    def run(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return fn(*args, **kwargs)
        except AuthoringError:
            raise
        except (ArithmeticError, LookupError, TypeError, ValueError, AttributeError, RecursionError) as exc:
            raise AuthoringError(
                "SCHEMA_INVALID", f"the policy has an unsupported structure ({type(exc).__name__})"
            ) from exc

    return run


@_as_authoring_error
def load_policy(
    paths: Sequence[Path],
    *,
    decl_paths: Sequence[Path] = (),
    roots: Sequence[Path] | None = None,
    config_params: Sequence[Mapping[str, object]] = (),
    limits: CplLimits | None = None,
    plugins: FunctionRegistry | None = None,
    profile: Profile = NEUTRAL,
    strict: bool = False,
    strict_inputs: bool = False,
    rules_mode: Mode | None = None,
    rules_strategy: Strategy | None = None,
    pack_resolver: PackResolver | None = None,
    max_import_depth: int = 16,
    lock: Mapping[str, Any] | None = None,
    require_lock: bool = False,
    inline_decls: Sequence[tuple[Mapping[str, Any], str | None]] = (),
    default_rate: tuple[int, int] = (100, 60),
) -> CompiledPolicy:
    """Load one policy set: exactly one root document plus any `fragment: true` files, sorted by path."""
    limits = limits or CplLimits()
    files = sorted((Path(p) for p in paths), key=lambda p: str(p))
    if not files:
        raise AuthoringError("SCHEMA_INVALID", "no policy files were given")
    sources = [(p, read_source(p, limits)) for p in files]
    root_idx = []
    for i, (_, s) in enumerate(sources):
        _check_top(s)
        if not s.data.get("fragment"):
            root_idx.append(i)
    if len(root_idx) != 1:
        raise AuthoringError("SCHEMA_INVALID", f"exactly one non-fragment policy is required, found {len(root_idx)}")
    root_path, root = sources[root_idx[0]]
    ordered = [sources[root_idx[0]], *[s for i, s in enumerate(sources) if i != root_idx[0]]]
    # imports: declaration files go to the declaration loader, policy fragments (at any depth) join the policy set
    import_specs: list[tuple[Path, Source, list[tuple[int, dict[str, Any]]]]] = []
    seen = {path.resolve() for path, _ in ordered}
    queue = [(path, s, 0) for path, s in ordered]
    for path, s, depth in queue:  # the queue grows while it is walked
        decl_specs = []
        for idx, spec in _imports_of(s):
            target = _peek(path, spec, s, idx, roots or [path.parent], pack_resolver, limits)
            if not _is_fragment(target, limits):
                decl_specs.append((idx, spec))
                continue
            if depth + 1 > max_import_depth:
                raise s.error("IMPORT_FORBIDDEN", "import depth exceeds declarations.max_import_depth", "imports", idx)
            if target.resolve() in seen:  # a fragment is added once, however many files import it
                continue
            seen.add(target.resolve())
            frag = read_source(target, limits)
            _check_top(frag)
            frag.data["__alias__"] = spec.get("as")
            ordered.append((target, frag))
            queue.append((target, frag, depth + 1))
        import_specs.append((path, s, decl_specs))
    bindings = [dict(root.data.get("params") or {}), *config_params]
    decls = load_declarations(
        decl_paths,
        roots=roots or [root_path.parent],
        bindings=bindings,
        limits=limits,
        max_import_depth=max_import_depth,
        pack_resolver=pack_resolver,
        lock=lock,
        require_lock=require_lock,
        plugins=plugins,
        inline=inline_decls,
        import_specs=import_specs,
    )
    decls.profile = profile
    decls.strict_inputs = strict_inputs
    for path, s in ordered:
        for cname, cspec in (s.data.get("conditions") or {}).items():
            params = {p: parse_type_expr(str(t), decls.types) for p, t in (cspec.get("params") or {}).items()}
            for pname, ptype in params.items():
                private = next((n for n in _named_types(ptype) if ("types", n) in decls.private), None)
                if private is not None:
                    raise s.error(
                        "DECLARATION_UNKNOWN_NAME",
                        f"type {private} is private to its declaration file",
                        "conditions",
                        cname,
                        "params",
                        pname,
                    )
            if cname in decls.conditions:
                raise s.error(
                    "DECLARATION_CONFLICT",
                    f"named condition {cname!r} is already defined in {decls.conditions[cname].file}",
                    "conditions",
                    cname,
                )
            decls.conditions[cname] = CondDef(params, cspec.get("when"), str(path), s, in_policy=True)
    return _compile_set(ordered, decls, limits, plugins, strict, rules_mode, rules_strategy, default_rate, profile)


def _check_top(s: Source) -> None:
    doc = s.data
    if not isinstance(doc, dict):
        raise s.error("SCHEMA_INVALID", "a policy is a mapping")
    for key in doc:
        if key not in _TOP:
            raise s.error("SCHEMA_INVALID", f"unknown top-level key {key!r}", key)
    if doc.get("cpl") != "1.0":
        raise s.error("SCHEMA_INVALID", 'a policy needs cpl: "1.0"', "cpl")
    if not doc.get("fragment") and ("id" not in doc or not isinstance(doc["id"], str) or not doc["id"].strip()):
        raise s.error("SCHEMA_INVALID", "a policy needs a non-empty `id`", "id")
    version = doc.get("version", 1)
    if type(version) is bool or not (isinstance(version, int | str) and version != ""):
        raise s.error("SCHEMA_INVALID", "version is an integer or a non-empty string", "version")
    for section in ("params", "conditions"):
        if doc.get(section) is not None and not isinstance(doc[section], dict):
            raise s.error("SCHEMA_INVALID", f"{section} is a mapping", section)
    for cname, cspec in (doc.get("conditions") or {}).items():
        if not isinstance(cspec, dict) or not isinstance(cspec.get("params") or {}, dict):
            raise s.error("SCHEMA_INVALID", "a named condition is {params?, when}", "conditions", cname)
    if doc.get("fragment") is not None and type(doc["fragment"]) is not bool:
        raise s.error("SCHEMA_INVALID", "fragment is true or false", "fragment")
    if doc.get("fragment") and {"default", "strategy", "mode"} & set(doc):
        raise s.error("SCHEMA_INVALID", "a fragment has no default, strategy or mode", "fragment")
    if doc.get("strategy", "deny_overrides") not in STRATEGIES:
        raise s.error("SCHEMA_INVALID", f"strategy is one of {', '.join(STRATEGIES)}", "strategy")
    if doc.get("mode", "enforce") not in ("enforce", "monitor"):
        raise s.error("SCHEMA_INVALID", "mode is enforce or monitor", "mode")
    if doc.get("default", "deny") not in ("allow", "deny"):
        raise s.error("SCHEMA_INVALID", "default is allow or deny", "default")
    if doc.get("rules") is not None and not isinstance(doc["rules"], list):
        raise s.error("SCHEMA_INVALID", "rules is a list", "rules")
    if "vocabulary" in doc and "imports" in doc:
        raise s.error("SCHEMA_INVALID", "use `imports`; `vocabulary` is shorthand for one import", "vocabulary")


def _imports_of(s: Source) -> list[tuple[int, dict[str, Any]]]:
    doc = s.data
    if "vocabulary" in doc:
        return [(0, {"from": doc["vocabulary"]})]
    specs = doc.get("imports") or []
    if not isinstance(specs, list):
        raise s.error("SCHEMA_INVALID", "imports is a list", "imports")
    return list(enumerate(specs))


def _peek(
    importer: Path,
    spec: Any,
    s: Source,
    idx: int,
    roots: Sequence[Path],
    resolver: PackResolver | None,
    limits: CplLimits,
) -> Path:
    from cplang.declarations import _Loader

    loader = _Loader(roots, limits, 16, resolver, None, False, None)
    return loader._resolve_import(importer, spec, s, idx)


def _is_fragment(path: Path, limits: CplLimits) -> bool:
    try:
        data = read_source(path, limits).data
    except AuthoringError:
        return False
    return isinstance(data, dict) and data.get("fragment") is True


def _compile_set(
    ordered: list[tuple[Path, Source]],
    decls: DeclarationSet,
    limits: CplLimits,
    plugins: FunctionRegistry | None,
    strict: bool,
    rules_mode: Mode | None,
    rules_strategy: Strategy | None,
    default_rate: tuple[int, int],
    profile: Profile,
) -> CompiledPolicy:
    _, root = ordered[0]
    pc = _PolicyCompiler(decls, limits, plugins, strict, rules_mode, default_rate, profile)
    rules: list[CRule] = []
    seen: dict[str, str] = {}
    for path, s in ordered:
        file_mode = s.data.get("mode") or root.data.get("mode")  # a fragment follows the root document's mode
        prefix = f"{s.data['__alias__']}." if s.data.get("__alias__") else ""
        for i, raw in enumerate(s.data.get("rules") or []):
            rule = pc.rule(raw, s, ("rules", i), file_mode, prefix)
            if rule.id in seen:
                raise s.error(
                    "DECLARATION_CONFLICT", f"rule id {rule.id!r} is already used in {seen[rule.id]}", "rules", i, "id"
                )
            seen[rule.id] = str(path)
            rules.append(rule)
    if len(rules) > limits.max_rules:
        raise AuthoringError("SCHEMA_INVALID", f"a policy set has at most {limits.max_rules} rules")
    tiers: list[tuple[str, Compiled]] = []
    risk_canon: list[dict[str, Any]] = []
    for i, tier in enumerate(root.data.get("risk_tiers") or []):
        if not isinstance(tier, dict) or not isinstance(tier.get("id"), str) or set(tier) - {"id", "when"}:
            raise root.error("SCHEMA_INVALID", "a risk tier is {id, when}", "risk_tiers", i)
        if any(t == tier["id"] for t, _ in tiers):
            raise root.error("SCHEMA_INVALID", f"risk tier id {tier['id']!r} is used twice", "risk_tiers", i, "id")
        node = pc.builder(root).block(tier.get("when"), ("risk_tiers", i, "when"))
        tiers.append((tier["id"], pc.compile_cond(node, pc.scope(src=root), root, ("risk_tiers", i, "when"))))
        risk_canon.append({"id": tier["id"], "when": node.canon()})
    strategy = rules_strategy or root.data.get("strategy") or "deny_overrides"
    if root.data.get("strategy"):
        strategy = root.data["strategy"]
    policy = CompiledPolicy(
        id=root.data["id"],
        version=root.data.get("version", 1),
        cpl_version="1.0",
        mode=root.data.get("mode") or rules_mode or "enforce",
        default=root.data.get("default", "deny"),
        strategy=strategy,
        risk_tiers=tiers,
        default_risk_tier=root.data.get("default_risk_tier"),
        rules=rules,
        decls=decls,
        files={str(p): _digest_file(p) for p, _ in ordered},
        plugin_refs=pc.plugin_refs,
        warnings=pc.warnings,
        fingerprint="",
        limits=limits,
        plugins=plugins,
        risk_canon=risk_canon,
        profile=profile,
    )
    policy.fingerprint = compute_fingerprint(policy)
    return policy


def _digest_file(path: Path) -> str:
    return sha256_file(path.read_bytes())


def compute_fingerprint(policy: CompiledPolicy) -> str:
    """`sha256:` digest of the canonical JSON (RFC 8785) of the compiled policy. Comments, key order and descriptions do
    not change it."""
    plugins = policy.plugins.versions(policy.plugin_refs) if policy.plugins is not None else []
    f = {
        "fp_version": 1,
        "policy": {
            "id": policy.id,
            "version": policy.version,
            "cpl": policy.cpl_version,
            "mode": policy.mode,
            "default": policy.default,
            "strategy": policy.strategy,
            "risk_tiers": policy.risk_canon,
            "default_risk_tier": policy.default_risk_tier,
        },
        "rules": [r.canon for r in policy.rules],
        **policy.decls.fingerprint_parts(),
        "vocabulary_version": policy.decls.version,
        "plugins": plugins,
        "limits": dataclasses.asdict(policy.limits),  # a limit can turn a decision into a refusal
    }
    return digest_object(_jsonable(f))


def _jsonable(x: Any) -> Any:
    if isinstance(x, Decimal):
        return render(x)
    if isinstance(x, dict):
        return {k: _jsonable(v) for k, v in x.items()}
    if isinstance(x, list | tuple):
        return [_jsonable(v) for v in x]
    return x
