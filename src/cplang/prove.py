"""Policy prover: boundary check, change diff and no-bypass proofs over a modeled fragment of the language.

Constructs outside the fragment are reported as `unsupported` with a stable reason. Every counterexample is
replayed through the evaluator; a disagreement is reported as `error` (`model_mismatch`).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal

from cplang.declarations import DeclarationSet
from cplang.evaluator import pointer_overlap
from cplang.expr import Node, reads_response
from cplang.inputs import STRING_PATHS
from cplang.jsontypes import JsonValue
from cplang.model import Action, Signal
from cplang.policy import CompiledPolicy, CRule
from cplang.registry import PERMITTED, RANK
from cplang.values import EnumVal, Quantity, SetVal

try:  # the `prove` extra
    import z3
except ImportError:  # pragma: no cover
    z3 = None

type ProofStatus = Literal["within_boundary", "exceeds_boundary", "error", "unsupported", "inconclusive"]
"""The result of a proof: the candidate is inside the boundary, outside it, or the proof could not be completed."""

type ProofMode = Literal["boundary", "diff", "no_bypass"]
"""The question a proof answers; see `prove`."""

EXIT: dict[ProofStatus, int] = {
    "within_boundary": 0,
    "exceeds_boundary": 1,
    "error": 2,
    "unsupported": 3,
    "inconclusive": 3,
}
PERMITTED_MAX_RANK = RANK["modify"]


class Unsupported(Exception):
    """Raised for constructs the prover does not model."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason, self.detail = reason, detail


@dataclass
class ProofResult:
    """The result of a proof, with a counterexample when the boundary is exceeded."""

    result: ProofStatus
    reason_code: str | None = None
    coverage: list[str] = field(default_factory=list)
    counterexample: dict[str, JsonValue] | None = None
    solver_ms: int = 0
    detail: str | None = None

    @property
    def exit_code(self) -> int:
        """The command-line exit code for this result."""
        return EXIT[self.result]

    def to_dict(self) -> dict[str, JsonValue]:
        """The result as JSON data."""
        out: dict[str, Any] = {
            "result": self.result,
            "reason_code": self.reason_code,
            "coverage": {"domains": self.coverage},
            "solver_ms": self.solver_ms,
        }
        if self.counterexample is not None:
            out["counterexample"] = self.counterexample
        if self.detail:
            out["detail"] = self.detail
        return out


class Vars:
    """Symbolic action shared by every policy in one proof: path -> (sort, value var, presence var)."""

    def __init__(self) -> None:
        self.paths: dict[str, tuple[str, Any, Any]] = {}
        self.signals: dict[str, Any] = {}
        self.exists: dict[str, Any] = {}
        self._presence: dict[str, Any] = {}
        self._count = 0

    def _fresh(self, prefix: str, name: str) -> str:
        """A solver name no other variable can share, even when two paths differ only in `.` versus `_`."""
        self._count += 1
        return f"{prefix}{self._count}_{name.replace('.', '_')}"

    def _present(self, name: str) -> Any:
        if name not in self._presence:
            self._presence[name] = z3.Bool(self._fresh("p", name))
        return self._presence[name]

    def path(self, name: str, sort: str) -> tuple[Any, Any]:
        """The solver value and presence variables for a path of the given sort."""
        if name in self.paths:
            known, value, present = self.paths[name]
            if known != sort:
                raise Unsupported("type_conflict", f"{name} is used as {known} and as {sort}")
            return value, present
        ctor = {"string": z3.String, "real": z3.Real, "bool": z3.Bool}[sort]
        value = ctor(self._fresh("v", name))
        present = self._present(name)
        self.paths[name] = (sort, value, present)
        return value, present

    def presence(self, name: str) -> Any:
        """Presence of a path whose value type is not needed (a bare `exists`)."""
        if name in self.paths:
            return self.paths[name][2]
        return self.exists.setdefault(name, self._present(name))

    def signal(self, code: str) -> Any:
        """The solver variable for the presence of a signal code."""
        if code not in self.signals:
            self.signals[code] = z3.Bool(self._fresh("sig", code))
        return self.signals[code]


Tri = tuple[Any, Any]  # (definitely true, definitely false)


class Encoder:
    """Translates a compiled policy into solver formulas."""

    def __init__(self, vars_: Vars, policy: CompiledPolicy) -> None:
        self.v = vars_
        self.policy = policy
        self.decls: DeclarationSet = policy.decls
        self.lets: dict[str, Node] = {}

    def const_value(self, node: Node) -> Any:
        """The Python value of a constant node."""
        if node.k == "lit":
            return node.val
        if node.k == "path" and node.op in ("param", "const") and node.args and isinstance(node.args[0], str):
            found = self.decls.param(node.args[0]) if node.op == "param" else self.decls.const(node.args[0])
            if found is not None and len(node.args) == 1:
                return found[1]
        if node.k == "op" and node.op == "list":
            return [self.const_value(a) for a in node.args]
        raise Unsupported("not_constant", "a non-constant value cannot be modeled")

    def path_name(self, node: Node) -> str:
        """The dotted name of a path node."""
        if node.k != "path" or not all(isinstance(p, str) for p in node.args):
            raise Unsupported("unsupported_policy_shape", "a dynamic path cannot be modeled")
        name = ".".join([node.op or "", *node.args])
        if node.op == "attributes" and len(node.args) == 1:
            att = self.decls.attribute_type(str(node.args[0]))
            if att is not None and att.kind == "quantity":
                raise Unsupported("unsupported_policy_shape", "quantity attributes carry units")
        return name

    def sort_of(self, name: str, hint: str | None) -> str:
        """The solver sort used for a path."""
        if name in STRING_PATHS:
            return "string"
        if name.startswith("attributes."):
            att = self.decls.attribute_type(name.split(".")[1])
            if att is not None:
                kind = (
                    att.kind
                    if len(name.split(".")) == 2
                    else ("integer" if att.c.get("base") == "integer" else "number")
                )
                if kind in ("integer", "number"):
                    return "real"
                if kind in ("string", "enum"):
                    return "string"
                if kind == "boolean":
                    return "bool"
        declared = self.decls.input_type(name.split("."))
        if declared is not None:
            kind = declared.args[0].kind if declared.kind == "optional" else declared.kind
            if kind in ("integer", "number"):
                return "real"
            if kind in ("string", "enum"):
                return "string"
            if kind == "boolean":
                return "bool"
        if hint is None:
            raise Unsupported("unsupported_policy_shape", f"the type of {name} cannot be inferred")
        return hint

    def operand(self, node: Node, hint: str | None) -> tuple[Any, Any, str]:
        """(value, present, sort) of a term."""
        if node.k == "lit" or (node.k == "path" and node.op in ("param", "const")):
            value = self.const_value(node)
            return self.literal(value)
        if node.k == "path" and node.op == "var":
            name = str(node.args[0]) if node.args else ""
            if name not in self.lets:
                raise Unsupported("unsupported_policy_shape", f"var.{name} is not modeled")
            return self.operand(self.lets[name], hint)
        if node.k == "path" and node.op and node.op in self.decls.types and self.decls.types[node.op].kind == "enum":
            return z3.StringVal(str(node.args[0])), z3.BoolVal(True), "string"
        if node.k == "path":
            name = self.path_name(node)
            sort = self.sort_of(name, hint)
            value, present = self.v.path(name, sort)
            return value, present, sort
        if node.k == "op" and node.op in ("add", "sub", "mul"):
            (a, pa, sa), (b, pb, sb) = (self.operand(x, "real") for x in node.args)
            if sa != "real" or sb != "real":
                raise Unsupported("unsupported_policy_shape", "arithmetic on non-numbers")
            val = {"add": a + b, "sub": a - b, "mul": a * b}[node.op]
            return val, z3.And(pa, pb), "real"
        raise Unsupported("unsupported_policy_shape", f"{node.k} {node.op or ''} is not modeled")

    @staticmethod
    def literal(value: Any) -> tuple[Any, Any, str]:
        """A literal as a solver value, its presence and its sort."""
        if type(value) is bool:
            return z3.BoolVal(value), z3.BoolVal(True), "bool"
        if isinstance(value, int | Decimal):
            return z3.RealVal(str(value)), z3.BoolVal(True), "real"
        if isinstance(value, str):
            return z3.StringVal(value), z3.BoolVal(True), "string"
        if isinstance(value, EnumVal):
            return z3.StringVal(value.name), z3.BoolVal(True), "string"
        if isinstance(value, Quantity | list | SetVal | dict):
            raise Unsupported("unsupported_policy_shape", "structured constants are not modeled")
        raise Unsupported("unsupported_policy_shape", "unknown constant type")

    def tri(self, node: Node) -> Tri:
        """The pair (definitely true, definitely false) formulas for a condition."""
        k, op = node.k, node.op
        if k == "lit" and type(node.val) is bool:
            return z3.BoolVal(node.val), z3.BoolVal(not node.val)
        if k == "op" and op in ("and", "or"):
            parts = [self.tri(a) for a in node.args]
            if op == "and":
                return z3.And(*(t for t, _ in parts)), z3.Or(*(f for _, f in parts))
            return z3.Or(*(t for t, _ in parts)), z3.And(*(f for _, f in parts))
        if k == "op" and op == "not":
            t, f = self.tri(node.args[0])
            return f, t
        if k == "op" and op == "with_locals":
            raise Unsupported("unsupported_policy_shape", "named conditions with parameters are not modeled")
        if k == "op" and op == "signal":
            return self.signal(node)
        if k == "op" and op == "exists":
            target = node.args[0]
            if target.k == "path" and target.op not in ("param", "const", "var"):
                present = self.v.presence(self.path_name(target))
            else:
                _, present, _ = self.operand(target, None)
            expect = bool(node.opts.get("expect", True))
            return (present, z3.Not(present)) if expect else (z3.Not(present), present)
        if k == "op" and op in (
            "eq",
            "ne",
            "lt",
            "lte",
            "gt",
            "gte",
            "in",
            "nin",
            "between",
            "glob",
            "contains",
            "starts_with",
            "len_gt",
            "len_lt",
        ):
            return self.compare(node)
        if k == "path" and node.op in ("param", "const"):
            value = self.const_value(node)
            if type(value) is bool:
                return z3.BoolVal(value), z3.BoolVal(not value)
        raise Unsupported("unsupported_policy_shape", f"{k} {op or ''} is not modeled")

    def signal(self, node: Node) -> Tri:
        """The formulas for a `signal` condition."""
        o = node.opts
        if set(o) - {"code"}:
            raise Unsupported("unsupported_policy_shape", "only `signal: {code}` is modeled")
        return self.v.signal(str(o["code"])), z3.Not(self.v.signal(str(o["code"])))

    def compare(self, node: Node) -> Tri:
        """The formulas for a comparison condition."""
        op = node.op or ""
        a_node = node.args[0]
        hint = None
        for other in node.args[1:]:
            if other.k == "lit":
                hint = {"string": "string", "integer": "real", "number": "real", "boolean": "bool"}.get(other.typ or "")
            elif other.k == "op" and other.op == "list" and other.args and other.args[0].k == "lit":
                hint = {"string": "string", "integer": "real", "number": "real", "boolean": "bool"}.get(
                    other.args[0].typ or ""
                )
        a, pa, sa = self.operand(a_node, hint)
        if op in ("in", "nin"):
            items = self.const_value(node.args[1])
            if not isinstance(items, list | tuple):
                raise Unsupported("unsupported_policy_shape", "`in` over a non-list")
            clauses = [a == self.literal(i)[0] for i in items]
            cond = z3.Or(*clauses) if clauses else z3.BoolVal(False)
            return (
                (z3.And(pa, cond), z3.And(pa, z3.Not(cond)))
                if op == "in"
                else (z3.And(pa, z3.Not(cond)), z3.And(pa, cond))
            )
        if op == "between":
            (lo, plo, _), (hi, phi, _) = (self.operand(x, "real") for x in node.args[1:])
            cond = z3.And(a >= lo, a <= hi)
            present = z3.And(pa, plo, phi)
            return z3.And(present, cond), z3.And(present, z3.Not(cond))
        if op in ("glob", "contains", "starts_with"):
            pattern = self.const_value(node.args[1])
            if sa != "string" or not isinstance(pattern, str):
                raise Unsupported("unsupported_policy_shape", f"{op} needs a string and a constant pattern")
            if op == "glob":
                if node.opts.get("normalize") or node.opts.get("case_insensitive"):
                    raise Unsupported("unsupported_policy_shape", "normalized or case-insensitive globs")
                cond = z3.InRe(a, _glob_regex(pattern, node.opts.get("sep")))
            elif op == "contains":
                cond = z3.Contains(a, z3.StringVal(pattern))
            else:
                cond = z3.PrefixOf(z3.StringVal(pattern), a)
            return z3.And(pa, cond), z3.And(pa, z3.Not(cond))
        if op in ("len_gt", "len_lt"):
            n = self.const_value(node.args[1])
            if sa != "string" or type(n) is not int:
                raise Unsupported("unsupported_policy_shape", "len over a non-string")
            cond = z3.Length(a) > n if op == "len_gt" else z3.Length(a) < n
            return z3.And(pa, cond), z3.And(pa, z3.Not(cond))
        b, pb, sb = self.operand(node.args[1], sa)
        if sa != sb:
            raise Unsupported("type_conflict", "operands of different sorts")
        present = z3.And(pa, pb)
        cond = {"eq": a == b, "ne": a != b}.get(op)
        if cond is None:
            if sa != "real":
                raise Unsupported("unsupported_policy_shape", "ordering over non-numbers")
            cond = {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[op]
        return z3.And(present, cond), z3.And(present, z3.Not(cond))

    def rule_matches(self, rule: CRule) -> Any:
        """The formula for when a rule matches."""
        self.lets = {}
        for name, compiled in rule.lets:
            if compiled.node is None:
                raise Unsupported("unsupported_policy_shape", "a `let` without an AST")
            self.lets[name] = compiled.node
        parts = [self.tri(rule.match.node)[0]] if rule.match and rule.match.node else []
        if rule.gate is not None and rule.gate.node is not None:
            parts.append(self.tri(rule.gate.node)[0])
        return z3.And(*parts) if parts else z3.BoolVal(True)

    def rule_rank(self, rule: CRule) -> Any:
        """The formula for the rank of a rule's outcome."""
        a = rule.admission
        guards = [a.deny, *(t.cond for t in a.thresholds)]
        if any(g is not None and reads_response(g.node) for g in guards):
            raise Unsupported(
                "unsupported_policy_shape", f"rule {rule.id}: guards on the tool response are not modeled"
            )
        if a.host or a.immutable or a.bounded or a.max_calls:
            raise Unsupported(
                "unsupported_policy_shape",
                f"rule {rule.id}: host rule keys, parameter limits and rate limits are not modeled",
            )
        base = z3.IntVal(RANK[rule.outcome])
        rank = {"deny": RANK["deny"], "ask": RANK["ask"], "watch": RANK["watch"]}
        result = base
        if a.thresholds:
            triggered = [  # a guard trips unless it is definitely false (see evaluator._trips)
                (z3.Not(self.tri(t.cond.node)[1]) if t.cond.node else z3.BoolVal(False), rank[t.outcome])
                for t in a.thresholds
            ]
            strongest = z3.IntVal(0)
            any_triggered = z3.BoolVal(False)
            for cond, r in triggered:
                strongest = z3.If(z3.And(cond, z3.IntVal(r) > strongest), z3.IntVal(r), strongest)
                any_triggered = z3.Or(any_triggered, cond)
            result = z3.If(any_triggered, strongest, base)
        if a.deny is not None and a.deny.node is not None:
            result = z3.If(z3.Not(self.tri(a.deny.node)[1]), z3.IntVal(RANK["deny"]), result)
        if rule.mode == "monitor":
            result = z3.If(result >= RANK["ask"], z3.IntVal(1), z3.If(result == RANK["modify"], z3.IntVal(1), result))
        return result

    def policy_rank(self) -> Any:
        """The formula for the rank of the policy's outcome."""
        p = self.policy
        order = sorted(p.rules, key=lambda r: -r.priority) if p.strategy == "priority" else list(p.rules)
        active = [r for r in order if r.enabled]
        _reject_conflicting_modifies(active)
        matched = [self.rule_matches(r) for r in active]
        ranks = [self.rule_rank(r) for r in active]
        default = z3.IntVal(RANK["deny"] if p.default == "deny" else 0)
        if p.mode == "monitor" and p.default == "deny":
            default = z3.IntVal(1)
        if p.strategy == "deny_overrides":
            total = default
            any_match = z3.BoolVal(False)
            best = z3.IntVal(0)
            for m, r in zip(matched, ranks, strict=True):
                best = z3.If(z3.And(m, r > best), r, best)
                any_match = z3.Or(any_match, m)
            total = z3.If(any_match, best, default)
        else:
            total = default
            for m, r in reversed(list(zip(matched, ranks, strict=True))):
                total = z3.If(m, r, total)
        hard = [self.v.signal(code) for code in sorted(p.profile.hard_signal_codes)]
        hard_rank = z3.IntVal(1 if p.mode == "monitor" else RANK["deny"])
        return z3.If(z3.Or(*hard), z3.If(hard_rank > total, hard_rank, total), total) if hard else total


def _edit_pointers(rule: CRule) -> set[str]:
    """The JSON pointers a modify rule may touch; a wholesale replacement or suggested edits may touch any."""
    modify = rule.modify or {}
    if "edits" not in modify:
        return {""}
    return {str(e.get("json_pointer", "")) for e in modify["edits"]}


def _reject_conflicting_modifies(rules: list[CRule]) -> None:
    """Two modify rules whose edits overlap make the evaluator deny, which the model does not capture."""
    mods = [r for r in rules if r.outcome == "modify"]
    for i, a in enumerate(mods):
        for b in mods[i + 1 :]:
            if any(pointer_overlap(x, y) for x in _edit_pointers(a) for y in _edit_pointers(b)):
                raise Unsupported(
                    "unsupported_policy_shape", f"rules {a.id} and {b.id} may edit the same part of the action"
                )


def _glob_regex(pattern: str, sep: str | None) -> Any:
    """A glob as a z3 regular expression (same syntax as the evaluator: `*`, `?`, classes, `**` with a separator)."""
    any_char = z3.AllChar(z3.ReSort(z3.StringSort()))
    plain = any_char if sep is None else z3.Intersect(any_char, z3.Complement(z3.Re(z3.StringVal(sep))))
    parts: list[Any] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            parts.append(z3.Re(z3.StringVal(pattern[i + 1])))
            i += 2
        elif c == "*":
            j = i
            while j < len(pattern) and pattern[j] == "*":
                j += 1
            parts.append(z3.Star(any_char if (j - i >= 2 and sep) else plain))
            i = j
        elif c == "?":
            parts.append(plain)
            i += 1
        elif c == "[":
            end = pattern.find("]", i + 2)
            if end < 0:
                parts.append(z3.Re(z3.StringVal(c)))
                i += 1
                continue
            body = pattern[i + 1 : end]
            negate = body[:1] in ("!", "^")
            body = body[1:] if negate else body
            members = []
            k = 0
            while k < len(body):
                if k + 2 < len(body) and body[k + 1] == "-":
                    members.append(z3.Range(body[k], body[k + 2]))
                    k += 3
                else:
                    members.append(z3.Re(z3.StringVal(body[k])))
                    k += 1
            union = z3.Union(*members) if len(members) > 1 else members[0]
            parts.append(z3.Intersect(plain, z3.Complement(union)) if negate else z3.Intersect(plain, union))
            i = end + 1
        else:
            parts.append(z3.Re(z3.StringVal(c)))
            i += 1
    return z3.Concat(*parts) if len(parts) > 1 else (parts[0] if parts else z3.Re(z3.StringVal("")))


def _new_solver(timeout_ms: int) -> Any:
    z3.set_param("smt.random_seed", 0)
    z3.set_param("sat.random_seed", 0)
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.set("random_seed", 0)
    return solver


def _check(
    solver: Any, vars_: Vars, policies: list[CompiledPolicy], mode: ProofMode, timeout_ms: int, started: float
) -> ProofResult:
    ms = int((time.perf_counter() - started) * 1000)
    outcome = solver.check()
    ms = int((time.perf_counter() - started) * 1000)
    coverage = sorted(vars_.paths) + [f"signal:{c}" for c in sorted(vars_.signals)]
    if outcome == z3.unsat:
        note = "assumes every input is well-typed and evaluates without error; a failed evaluation is a refusal"
        return ProofResult("within_boundary", None, coverage, None, ms, note)
    if outcome == z3.unknown:
        return ProofResult("inconclusive", "solver_timeout", coverage, None, ms)
    return _counterexample(solver.model(), vars_, policies, mode, coverage, ms)


def _counterexample(
    model: Any, vars_: Vars, policies: list[CompiledPolicy], mode: ProofMode, coverage: list[str], ms: int
) -> ProofResult:
    action_data: dict[str, Any] = {}
    for name, (sort, value, present) in vars_.paths.items():
        if not z3.is_true(model.eval(present, model_completion=True)):
            continue
        evaluated = model.eval(value, model_completion=True)
        if sort == "string":
            data: Any = _SMT_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), evaluated.as_string())
        elif sort == "bool":
            data = z3.is_true(evaluated)
        else:
            fraction = evaluated.as_fraction()
            data = int(fraction) if fraction.denominator == 1 else float(fraction)
        _assign(action_data, name.split("."), data)
    for name, present in vars_.exists.items():
        if name not in vars_.paths and z3.is_true(model.eval(present, model_completion=True)):
            _assign(action_data, name.split("."), True)
    codes = [c for c, var in vars_.signals.items() if z3.is_true(model.eval(var, model_completion=True))]
    env, signals = _materialize(action_data, codes)
    from cplang.evaluator import RuleEvaluator

    verdicts = [RuleEvaluator(p, live=False).evaluate(env, signals) for p in policies]
    if mode == "no_bypass":
        faithful = verdicts[0].outcome in PERMITTED
    else:
        faithful = verdicts[0].outcome in PERMITTED and verdicts[1].outcome not in PERMITTED
    detail: dict[str, JsonValue] = {
        "action": action_data,
        "signals": list[JsonValue](codes),
        "outcome_candidate": verdicts[0].outcome,
        "outcome_boundary": verdicts[1].outcome if len(verdicts) > 1 else None,
    }
    if not faithful:
        return ProofResult(
            "error",
            "model_mismatch",
            coverage,
            detail,
            ms,
            "the evaluator disagrees with the model; the proof is not trusted",
        )
    return ProofResult(
        "exceeds_boundary", "boundary_exceeded" if mode != "no_bypass" else "hard_deny_bypassed", coverage, detail, ms
    )


_SMT_ESCAPE = re.compile(r"\\u\{([0-9a-fA-F]+)\}")  # how z3 prints characters it cannot show


def _assign(root: dict[str, Any], parts: list[str], value: Any) -> None:
    node = root
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _materialize(raw: dict[str, Any], codes: list[str]) -> tuple[Action, list[Signal]]:
    data: dict[str, Any] = {"id": "proof", "timestamp": "2026-01-01T12:00:00Z", **raw}
    state = dict(data.pop("state", {}))
    run = state.pop("run", {})
    if state:
        data["context"] = state
    if "depth" in run:
        data["depth"] = run["depth"]
    signals = [Signal(code=c, source="prover", severity="high", id=f"sig-{i:03d}") for i, c in enumerate(codes)]
    return Action(data), signals


def _guard(timeout_ms: int) -> None:
    if z3 is None:
        raise Unsupported("prover_not_installed", "install chokr-policy-language[prove] to use the prover")


def prove(
    candidate: CompiledPolicy,
    boundary: CompiledPolicy,
    *,
    mode: ProofMode = "boundary",
    timeout_ms: int = 10_000,
    max_rules: int = 1024,
) -> ProofResult:
    """`boundary`: candidate permits only what `boundary` permits. `diff`: boundary is the old policy and `candidate`
    the new one: lists what the change newly permits. `no_bypass`: no action carrying a hard-deny signal is
    permitted by `candidate`."""
    started = time.perf_counter()
    try:
        _guard(timeout_ms)
        for p in (candidate, boundary):
            if len(p.rules) > max_rules:
                return ProofResult(
                    "inconclusive",
                    "resource_limit",
                    [],
                    None,
                    0,
                    f"{len(p.rules)} rules exceed prove.max_rules={max_rules}",
                )
        vars_ = Vars()
        solver = _new_solver(timeout_ms)
        cand = Encoder(vars_, candidate).policy_rank()
        if mode == "no_bypass":
            codes = sorted(candidate.profile.hard_signal_codes)
            if not codes:
                raise Unsupported("unsupported_policy_shape", "the profile declares no hard-deny signal codes")
            hard = z3.Or(*[vars_.signal(c) for c in codes])
            solver.add(hard, cand <= PERMITTED_MAX_RANK)
            return _check(solver, vars_, [candidate, candidate], mode, timeout_ms, started)
        bound = Encoder(vars_, boundary).policy_rank()
        solver.add(cand <= PERMITTED_MAX_RANK, bound > PERMITTED_MAX_RANK)
        return _check(solver, vars_, [candidate, boundary], mode, timeout_ms, started)
    except Unsupported as exc:
        return ProofResult(
            "inconclusive" if exc.reason == "resource_limit" else "unsupported",
            exc.reason,
            [],
            None,
            int((time.perf_counter() - started) * 1000),
            exc.detail,
        )
