"""Expression compiler: checks the types of a parsed expression against a scope and turns it into a function that
computes its value for one action."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Protocol

from cplang.errors import AuthoringError
from cplang.expr import Node, parse_expression
from cplang.functions import FunctionRegistry
from cplang.inputs import CONDITION_ROOTS, PATH_TYPES, ROOTS
from cplang.matching import compile_regex
from cplang.ops import Ops
from cplang.runtime import CplLimits, Ctx, walk
from cplang.types import (
    BUILTIN,
    T_ANY,
    T_BOOLEAN,
    T_DURATION,
    T_INTEGER,
    T_NUMBER,
    T_STRING,
    T_TIMESTAMP,
    Type,
    comparable,
)
from cplang.values import (
    ABSENT,
    EPOCH,
    EnumVal,
    EvalError,
    SetVal,
    V,
    dec,
)

if TYPE_CHECKING:
    from cplang.profile import Profile

Fn = Callable[[Ctx], V]
_ENV_TYPES: dict[tuple[str, ...], Type] = {path: BUILTIN[kind] for path, kind in PATH_TYPES.items()}


class DeclLike(Protocol):
    """What the compiler needs from a DeclarationSet."""

    types: dict[str, Type]

    def attribute_type(self, name: str) -> Type | None: ...
    def const(self, name: str) -> tuple[Type, Any] | None: ...
    def param(self, name: str) -> tuple[Type, Any] | None: ...
    def table(self, name: str) -> Any: ...
    def function(self, name: str) -> Any: ...
    def computed(self, name: str) -> Any: ...
    def enum_order(self, etype: str) -> tuple[str, ...] | None: ...
    def conversions(self, qtype: str | None) -> dict[str, Any]: ...

    profile: Profile
    inputs: dict[str, Type]
    shortcuts: dict[str, dict[str, Any]]
    strict_inputs: bool
    private: set[tuple[str, str]]  # (section, name) a policy may not name


@dataclass
class Compiled:
    """A compiled expression: the function that evaluates it, its static type and its node count."""

    fn: Fn
    t: Type | None
    nodes: int
    node: Node | None = None


@dataclass
class Scope:
    """Everything an expression can refer to: declarations, local names, rule variables and limits."""

    decls: DeclLike
    locals: dict[str, Type | None] = field(
        default_factory=dict
    )  # bare names: function parameters and the loop variables of all/any/filter/map
    vars: dict[str, Type | None] = field(default_factory=dict)  # rule-local `let` (var.<name>)
    plugins: FunctionRegistry | None = None
    limits: CplLimits = field(default_factory=CplLimits)
    file: str | None = None
    allow_computed: bool = True
    env_ok: bool = True  # False for constants, tables, parameters

    @property
    def ops(self) -> Ops:
        return Ops(self.decls.enum_order, self.decls.conversions)

    def child(self, local: dict[str, Type | None]) -> Scope:
        return Scope(
            self.decls,
            {**self.locals, **local},
            self.vars,
            self.plugins,
            self.limits,
            self.file,
            self.allow_computed,
            self.env_ok,
        )


def _tc(msg: str, node: Node | None = None) -> AuthoringError:
    err = AuthoringError("TYPE_ERROR", msg)
    if node is not None:
        err.at_expression(node.pos + 1)
    return err


def _unk(msg: str, node: Node | None = None) -> AuthoringError:
    err = AuthoringError("DECLARATION_UNKNOWN_NAME", msg)
    if node is not None:
        err.at_expression(node.pos + 1)
    return err


def unwrap(t: Type | None) -> Type | None:
    """The type inside `optional<T>`, or the type itself."""
    return t.args[0] if t is not None and t.kind == "optional" else t


def _definitely_not(t: Type | None, *kinds: str) -> bool:
    t = unwrap(t)
    return t is not None and t.kind != "any" and t.kind not in kinds


def _bool(v: Any) -> bool:
    if type(v) is not bool:
        raise EvalError("expected boolean")
    return v


def _static_compat(a: Type | None, b: Type | None) -> bool:
    """Whether `eq`/`in` between the two static types can ever be well typed (no coercion)."""
    a, b = unwrap(a), unwrap(b)
    if a is None or b is None or a.kind == "any" or b.kind == "any":
        return True
    if a.kind in ("integer", "number") and b.kind in ("integer", "number"):
        return True
    if a.kind != b.kind:
        return False
    if a.kind == "enum":
        return a.name == b.name
    if a.kind == "quantity":
        return a.name == b.name or a.c.get("dimension") == b.c.get("dimension")
    return True


class Compiler:
    """Compiles parsed expression nodes against a scope."""

    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self.ops = scope.ops

    def compile(self, node: Node) -> Compiled:
        method = getattr(self, f"_{node.k}")
        compiled: Compiled = method(node)
        compiled.nodes = node.count()
        compiled.node = node
        return compiled

    def _lit(self, n: Node) -> Compiled:
        value = n.val
        t = {"integer": T_INTEGER, "number": T_NUMBER, "string": T_STRING, "boolean": T_BOOLEAN}.get(n.typ or "")
        out = V(value, True)

        def run(ctx: Ctx) -> V:
            ctx.step()
            return out

        return Compiled(run, t, 1)

    def _path(self, n: Node) -> Compiled:
        root, parts = n.op or "", n.args
        d = self.scope.decls
        names = [p for p in parts if isinstance(p, str)]
        dyn = [self.compile(p) if isinstance(p, Node) else None for p in parts]
        if root in self.scope.locals:
            base, t = self._local(root), self.scope.locals[root]
        elif root == "var":
            if not parts or not isinstance(parts[0], str) or parts[0] not in self.scope.vars:
                raise _unk(f"unknown variable var.{names[0] if names else ''}", n)
            name = parts[0]
            base, t, parts, dyn = self._var(name), self.scope.vars[name], parts[1:], dyn[1:]
        elif root in ("param", "const"):
            lookup = d.param if root == "param" else d.const
            picked = self._pick(lookup, parts)
            if picked is None:
                raise _unk(f"unknown {root}.{names[0] if names else ''}", n)
            _, (t, value), used = picked
            base, parts, dyn = self._const_value(value), parts[used:], dyn[used:]
        elif root == "table":
            return self._table(n, dyn)
        elif root == "computed":
            picked = self._pick(d.computed, parts) if self.scope.allow_computed else None
            if picked is None:
                raise _unk(f"unknown computed.{names[0] if names else ''}", n)
            cname, comp, used = picked
            base, t, parts, dyn = self._computed(cname, comp), comp.type, parts[used:], dyn[used:]
        elif root == "attributes":
            if not self.scope.env_ok:
                raise _tc("the action is not available in a declaration", n)
            if not parts or not isinstance(parts[0], str):
                return self._env_root(n, dyn)
            at = d.attribute_type(parts[0])
            if at is None:
                raise _unk(f"unknown attribute attributes.{parts[0]}", n)
            base, t, parts, dyn = self._attr(parts[0]), at, parts[1:], dyn[1:]
        elif root in d.types and d.types[root].kind == "enum" and parts and isinstance(parts[0], str):
            et = d.types[root]
            if parts[0] not in et.c["values"] or len(parts) != 1:
                raise _unk(f"unknown enum value {root}.{parts[0]}", n)
            value = EnumVal(root, parts[0])
            return Compiled(self._const_value(value), et, 1)
        elif root in d.inputs or root in ROOTS or root in d.profile.roots or not d.strict_inputs:
            return self._env_root(n, dyn)
        else:
            raise _unk(f"unknown name {root!r}", n)
        return self._descend(base, t, parts, dyn, n)

    @staticmethod
    def _pick(lookup: Callable[[str], Any], parts: tuple[Any, ...]) -> tuple[str, Any, int] | None:
        """Find a declared name in `parts`, allowing the `alias.name` form of an aliased import."""
        if parts and isinstance(parts[0], str):
            found = lookup(parts[0])
            if found is not None:
                return parts[0], found, 1
            if len(parts) > 1 and isinstance(parts[1], str):
                dotted = f"{parts[0]}.{parts[1]}"
                found = lookup(dotted)
                if found is not None:
                    return dotted, found, 2
        return None

    def _local(self, name: str) -> Fn:
        def run(ctx: Ctx) -> V:
            ctx.step()
            return ctx.locals[name]

        return run

    def _var(self, name: str) -> Fn:
        def run(ctx: Ctx) -> V:
            ctx.step()
            return ctx.vars.get(name, V(ABSENT, True))

        return run

    @staticmethod
    def _const_value(value: Any) -> Fn:
        out = V(value, True)

        def run(ctx: Ctx) -> V:
            ctx.step()
            return out

        return run

    @staticmethod
    def _attr(name: str) -> Fn:
        def run(ctx: Ctx) -> V:
            ctx.step()
            return ctx.view.attribute(name)

        return run

    @staticmethod
    def _computed(name: str, comp: Any) -> Fn:
        def run(ctx: Ctx) -> V:
            ctx.step()
            if name not in ctx.computed:
                ctx.computed[name] = V(ABSENT, True)  # cycles are rejected while loading; this is a safety net
                ctx.computed[name] = comp.evaluate(ctx)
            return ctx.computed[name]

        return run

    def _descend(
        self, base: Fn, t: Type | None, parts: tuple[Any, ...], dyn: list[Compiled | None], n: Node
    ) -> Compiled:
        if not parts:
            return Compiled(base, t, 1)
        for part in parts:
            t = self._member_type(t, part, n)

        def run(ctx: Ctx) -> V:
            cur = base(ctx)
            value, trusted = cur.v, cur.trusted
            for part, compiled in zip(parts, dyn, strict=True):
                if compiled is not None:
                    key = compiled.fn(ctx)
                    trusted = trusted and key.trusted
                    if key.v is ABSENT:
                        return V(ABSENT, trusted)
                    part = key.v
                value = walk(value, part)
                if value is ABSENT:
                    return V(ABSENT, trusted)
            return V(value, trusted)

        return Compiled(run, t, 1)

    def _member_type(self, t: Type | None, part: Any, n: Node) -> Type | None:
        t = unwrap(t)
        if t is None or t.kind == "any":
            return None
        if not isinstance(part, str):
            return t.args[0] if t.kind in ("list", "set", "map") and t.args else None
        if t.kind == "quantity":
            if part == "value":
                return T_INTEGER if t.c.get("base") == "integer" else T_NUMBER
            if part == "unit":
                return T_STRING
            raise _tc(f"quantity has no member {part!r}", n)
        if t.kind == "object":
            f = t.fields.get(part)
            if f is None:
                raise _tc(f"{t} has no field {part!r}", n)
            return f.type if f.required else Type("optional", args=(f.type,))
        if t.kind == "map":
            return t.args[0]
        if t.kind == "enum" and part == "name":
            return T_STRING
        raise _tc(f"{t} has no member {part!r}", n)

    def _env_root(self, n: Node, dyn: list[Compiled | None]) -> Compiled:
        if not self.scope.env_ok:
            raise _tc("the action is not available in a declaration", n)
        root, parts = n.op or "", n.args
        declared = self.scope.decls.inputs.get(root)
        if declared is not None:
            t: Type | None = declared
            for part in parts:
                t = self._member_type(t, part, n)
        else:
            t = _ENV_TYPES.get((root, *parts)) if all(isinstance(p, str) for p in parts) else None

        def run(ctx: Ctx) -> V:
            ctx.step()
            cur = ctx.view.root(root)
            value, trusted = cur.v, cur.trusted
            for part, compiled in zip(parts, dyn, strict=True):
                if compiled is not None:
                    k = compiled.fn(ctx)
                    trusted = trusted and k.trusted
                    if k.v is ABSENT:
                        return V(ABSENT, trusted)
                    part = k.v
                value = walk(value, part)
                if value is ABSENT:
                    return V(ABSENT, trusted)
            return V(value, trusted)

        return Compiled(run, t, 1)

    def _table(self, n: Node, dyn: list[Compiled | None]) -> Compiled:
        parts = n.args
        picked = self._pick(self.scope.decls.table, parts)
        if picked is None:
            raise _unk(f"unknown table.{parts[0] if parts and isinstance(parts[0], str) else ''}", n)
        tname, table, used = picked
        key_c = dyn[used] if len(parts) > used and dyn[used] is not None else None
        skip = used + (1 if key_c is not None else 0)
        rest, rest_dyn = parts[skip:], dyn[skip:]
        if key_c is not None and not _static_compat(key_c.t, table.key_type):
            raise _tc(f"table {tname} is keyed by {table.key_type}", n)
        t: Type | None = Type("optional", args=(table.value_type,)) if key_c is not None else None
        for part in rest:
            t = self._member_type(t, part, n)

        def run(ctx: Ctx) -> V:
            ctx.step(2)  # node + one table lookup
            if key_c is None:
                return V(table.as_value(), True)
            k = key_c.fn(ctx)
            if k.v is ABSENT:
                return V(ABSENT, k.trusted)
            value = table.lookup(k.v)
            for part, compiled in zip(rest, rest_dyn, strict=True):
                if compiled is not None:
                    kk = compiled.fn(ctx)
                    if kk.v is ABSENT:
                        return V(ABSENT, k.trusted)
                    part = kk.v
                value = walk(value, part)
            return V(value, k.trusted)

        return Compiled(run, t, 1)

    def _op(self, n: Node) -> Compiled:
        op = n.op or ""
        handler = getattr(self, f"_op_{op}", None)
        if handler is not None:
            result: Compiled = handler(n)
            return result
        args = [self.compile(a) for a in n.args]
        return self._generic(n, op, args)

    def _generic(self, n: Node, op: str, args: list[Compiled]) -> Compiled:
        ops = self.ops
        t: Type | None = T_BOOLEAN
        if op in ("eq", "ne"):
            self._need(len(args) == 2, n)
            if not _static_compat(args[0].t, args[1].t):
                raise _tc(f"cannot compare {args[0].t} with {args[1].t}", n)
            f: Callable[..., Any] = lambda ctx, a, b: ops.compare(op, a, b)  # noqa: E731
        elif op in ("lt", "lte", "gt", "gte"):
            self._need(len(args) == 2, n)
            if args[0].t is not None and args[1].t is not None and not comparable(args[0].t, args[1].t):
                raise _tc(f"{args[0].t} and {args[1].t} cannot be ordered", n)
            f = lambda ctx, a, b: ops.compare(op, a, b)  # noqa: E731
        elif op in ("in", "nin"):
            self._need(len(args) == 2, n)
            f = lambda ctx, a, b: self._text(ctx, a, b) or (ops.member_of(a, b) != (op == "nin"))  # noqa: E731
        elif op == "between":
            self._need(len(args) == 3, n)
            f = lambda ctx, a, lo, hi: ops.between(a, lo, hi)  # noqa: E731
        elif op == "contains":
            self._need(len(args) == 2, n)
            f = lambda ctx, a, b: self._text(ctx, a, b) or ops.contains(a, b)  # noqa: E731
        elif op == "starts_with":
            self._need(len(args) == 2, n)
            f = lambda ctx, a, b: self._text(ctx, a, b) or ops.starts_with(a, b)  # noqa: E731
        elif op in ("len_gt", "len_lt"):
            self._need(len(args) == 2, n)
            f = lambda ctx, a, b: ops.len_cmp(op, a, b)  # noqa: E731
        elif op == "regex":
            self._need(len(args) == 2, n)
            self._static_pattern(n, args[1])
            f = lambda ctx, a, b: self._text(ctx, a, b) or ops.regex(a, b, ctx.limits.max_regex_pattern_len)  # noqa: E731
        elif op == "glob":
            self._need(len(args) == 2, n)
            opts = dict(n.opts)
            f = lambda ctx, a, b: self._text(ctx, a, b) or ops.glob(a, b, opts)  # noqa: E731
        elif op in ("add", "sub", "mul", "div", "mod"):
            self._need(len(args) == 2, n)
            t = self._arith_type(op, args[0].t, args[1].t, n)
            f = lambda ctx, a, b: (self._text(ctx, a, b), ops.arith(op, a, b))[1]  # noqa: E731
        elif op == "neg":
            self._need(len(args) == 1, n)
            t = unwrap(args[0].t)
            f = lambda ctx, a: ops.negate(a)  # noqa: E731
        else:
            raise _tc(f"unknown operator {op!r}", n)

        def run(ctx: Ctx) -> V:
            ctx.step()
            vals = [a.fn(ctx) for a in args]
            trusted = all(v.trusted for v in vals)
            if any(v.v is ABSENT for v in vals):
                return V(ABSENT, trusted)
            return V(f(ctx, *(v.v for v in vals)), trusted)

        return Compiled(run, t, 1)

    @staticmethod
    def _need(ok: bool, n: Node) -> None:
        if not ok:
            raise _tc(f"wrong number of operands for {n.op}", n)

    @staticmethod
    def _text(ctx: Ctx, *operands: Any) -> bool:
        ctx.text_steps(*operands)
        return False

    @staticmethod
    def _static_pattern(n: Node, pattern: Compiled) -> None:
        node = pattern.node
        ok = node is not None and (node.k == "lit" or (node.k == "path" and node.op in ("const", "param")))
        if not ok:
            raise _tc("a regex pattern must be a literal, const or param", n)
        if node is not None and node.k == "lit":
            try:
                compile_regex(str(node.val))
            except ValueError as exc:
                raise _tc(str(exc), n) from exc

    def _arith_type(self, op: str, a: Type | None, b: Type | None, n: Node) -> Type | None:
        ua, ub = unwrap(a), unwrap(b)
        if ua is None or ub is None or ua.kind == "any" or ub.kind == "any":
            return None
        if ua.kind in ("integer", "number") and ub.kind in ("integer", "number"):
            return T_INTEGER if (ua.kind == ub.kind == "integer" and op != "div") else T_NUMBER
        if ua.kind == ub.kind == "quantity" and op in ("add", "sub"):
            return ua
        if ua.kind == ub.kind == "string" and op == "add":
            return T_STRING
        if ua.kind == "timestamp" and ub.kind == "duration" and op in ("add", "sub"):
            return T_TIMESTAMP
        if ua.kind == ub.kind == "timestamp" and op == "sub":
            return T_DURATION
        if ua.kind == ub.kind == "duration" and op in ("add", "sub"):
            return T_DURATION
        raise _tc(f"{op} is not defined for {ua} and {ub}", n)

    def _op_and(self, n: Node) -> Compiled:
        return self._logic(n, True)

    def _op_or(self, n: Node) -> Compiled:
        return self._logic(n, False)

    def _logic(self, n: Node, is_and: bool) -> Compiled:
        args = [self.compile(a) for a in n.args]
        for a in args:
            if _definitely_not(a.t, "boolean"):
                raise _tc(f"{n.op} needs boolean operands", n)
        decisive = not is_and  # `and` short-circuits on False, `or` on True

        def run(ctx: Ctx) -> V:
            ctx.step()
            absent, trusted = False, True
            for a in args:
                v = a.fn(ctx)
                trusted = trusted and v.trusted
                if v.v is ABSENT:
                    absent = True
                    continue
                if _bool(v.v) == decisive:
                    return V(decisive, trusted)
            return V(ABSENT if absent else (not decisive), trusted)

        return Compiled(run, T_BOOLEAN, 1)

    def _op_not(self, n: Node) -> Compiled:
        (a,) = (self.compile(x) for x in n.args)
        if _definitely_not(a.t, "boolean"):
            raise _tc("! needs a boolean operand", n)

        def run(ctx: Ctx) -> V:
            ctx.step()
            v = a.fn(ctx)
            return V(ABSENT if v.v is ABSENT else not _bool(v.v), v.trusted)

        return Compiled(run, T_BOOLEAN, 1)

    def _op_exists(self, n: Node) -> Compiled:
        (a,) = (self.compile(x) for x in n.args)
        flag = bool(n.opts.get("expect", True))

        def run(ctx: Ctx) -> V:
            ctx.step()
            v = a.fn(ctx)
            return V((v.v is not ABSENT) == flag, v.trusted)

        return Compiled(run, T_BOOLEAN, 1)

    def _op_tern(self, n: Node) -> Compiled:
        c, y, z = (self.compile(x) for x in n.args)
        if _definitely_not(c.t, "boolean"):
            raise _tc("the condition of ?: must be boolean", n)
        t = y.t if y.t is z.t else None

        def run(ctx: Ctx) -> V:
            ctx.step()
            cond = c.fn(ctx)
            if cond.v is ABSENT:
                return V(ABSENT, cond.trusted)
            chosen = (y if _bool(cond.v) else z).fn(ctx)
            return V(chosen.v, chosen.trusted and cond.trusted)

        return Compiled(run, t, 1)

    def _op_at(self, n: Node) -> Compiled:
        """`expr.name` / `expr[index]` on a value that is not a plain path (e.g. a parenthesised expression)."""
        base, key = (self.compile(a) for a in n.args)
        t = self._member_type(base.t, key.node.val if key.node is not None and key.node.k == "lit" else 0, n)

        def run(ctx: Ctx) -> V:
            ctx.step()
            b, k = base.fn(ctx), key.fn(ctx)
            trusted = b.trusted and k.trusted
            if b.v is ABSENT or k.v is ABSENT:
                return V(ABSENT, trusted)
            return V(walk(b.v, k.v), trusted)

        return Compiled(run, t, 1)

    def _op_list(self, n: Node) -> Compiled:
        items = [self.compile(a) for a in n.args]
        et = items[0].t if items and all(i.t is items[0].t for i in items) else None
        t = Type("list", args=(et or T_ANY,))

        def run(ctx: Ctx) -> V:
            ctx.step()
            vals = [i.fn(ctx) for i in items]
            if any(v.v is ABSENT for v in vals):
                raise EvalError("absent list element")
            return V([v.v for v in vals], all(v.trusted for v in vals))

        return Compiled(run, t, 1)

    def _op_map(self, n: Node) -> Compiled:
        pairs = [(e.args[0].val, self.compile(e.args[1])) for e in n.args]

        def run(ctx: Ctx) -> V:
            ctx.step()
            out: dict[str, Any] = {}
            trusted = True
            for k, c in sorted(pairs, key=lambda p: p[0]):
                v = c.fn(ctx)
                if v.v is ABSENT:
                    raise EvalError("absent map value")
                out[k] = v.v
                trusted = trusted and v.trusted
            return V(out, trusted)

        return Compiled(run, Type("map", args=(T_ANY,)), 1)

    def _call(self, n: Node) -> Compiled:
        name = n.op or ""
        if name.startswith("fn."):
            return self._declared_call(n, name[3:])
        if "/" in name:
            return self._plugin_call(n, name)
        from cplang.builtins import compile_builtin

        return compile_builtin(self, n, name)

    def _declared_call(self, n: Node, name: str) -> Compiled:
        fdef = self.scope.decls.function(name)
        if fdef is None:
            raise _unk(f"unknown function fn.{name}", n)
        args = [self.compile(a) for a in n.args]
        if len(args) != len(fdef.params):
            raise _tc(f"fn.{name} takes {len(fdef.params)} argument(s)", n)
        for (pname, ptype), a in zip(fdef.params.items(), args, strict=True):
            if a.t is not None and not _static_compat(a.t, ptype):
                raise _tc(f"argument {pname} of fn.{name} expects {ptype}", n)
        names = list(fdef.params)

        def run(ctx: Ctx) -> V:
            ctx.step()
            vals = [a.fn(ctx) for a in args]
            if ctx.depth + 1 > ctx.limits.max_call_depth:
                raise EvalError("call depth exceeded")
            saved = ctx.locals
            ctx.locals = dict(zip(names, vals, strict=True))
            ctx.depth += 1
            try:
                out: V = fdef.body.fn(ctx)
                return out
            finally:
                ctx.depth -= 1
                ctx.locals = saved

        return Compiled(run, fdef.returns, 1)

    def _plugin_call(self, n: Node, name: str) -> Compiled:
        registry = self.scope.plugins
        if registry is None or not registry.has(name):
            # `ns/fn(` with no spaces is always a host call; a path divided by a call needs spaces around `/`
            head = name.split("/", 1)[0].split(".", 1)[0]
            hint = f" (to divide, write `{name.replace('/', ' / ', 1)}(...)`)" if head in CONDITION_ROOTS else ""
            raise AuthoringError("EVALUATION_ERROR", f"function {name} is not registered{hint}")
        fn = registry.resolve(name)
        args = [self.compile(a) for a in n.args]
        as_op = bool(n.opts.get("as_op"))

        def run(ctx: Ctx) -> V:
            ctx.step(2)
            vals = [a.fn(ctx) for a in args]
            trusted = all(v.trusted for v in vals)
            try:
                from cplang.values import from_json, to_wire

                payload = (
                    {"operand": to_wire(vals[0].v), "value": to_wire(vals[1].v)}
                    if as_op
                    else {"args": [to_wire(v.v) for v in vals]}
                )
                result = fn(ctx.view.action, payload)
            except Exception as exc:  # report the exception type, never its message
                raise EvalError(type(exc).__name__) from exc
            if as_op:
                return V(bool(result), trusted)
            return V(from_json(result) if result is not None else ABSENT, trusted)

        return Compiled(run, None, 1)

    def _macro(self, n: Node) -> Compiled:
        coll = self.compile(n.args[0])
        var = n.val
        ct = unwrap(coll.t)
        et = ct.args[0] if ct is not None and ct.kind in ("list", "set", "map") and ct.args else None
        body = Compiler(self.scope.child({var: et})).compile(n.args[1])
        name = n.op or ""
        if name in ("all", "any", "filter") and _definitely_not(body.t, "boolean"):
            raise _tc(f"{name} needs a boolean predicate", n)
        t: Type | None = (
            Type("list", args=(body.t or T_ANY,))
            if name == "map"
            else (T_BOOLEAN if name in ("all", "any") else coll.t)
        )

        def run(ctx: Ctx) -> V:
            ctx.step()
            c = coll.fn(ctx)
            if c.v is ABSENT:
                return V(ABSENT, c.trusted)
            if isinstance(c.v, dict):
                items = [c.v[k] for k in sorted(c.v)]
            elif isinstance(c.v, list | SetVal):
                items = list(c.v)
            else:
                raise EvalError("macro needs a collection")
            saved = ctx.locals.get(var)
            results: list[Any] = []
            kept: list[Any] = []
            trusted = c.trusted
            absent = False
            try:
                for item in items:
                    ctx.step()
                    ctx.locals[var] = V(item, c.trusted)
                    r = body.fn(ctx)
                    trusted = trusted and r.trusted
                    if name == "map":
                        if r.v is ABSENT:
                            raise EvalError("absent map result")
                        results.append(r.v)
                    elif r.v is ABSENT:
                        absent = True
                    elif _bool(r.v):
                        kept.append(item)
                        if name == "any":
                            return V(True, trusted)
                    elif name == "all":
                        return V(False, trusted)
            finally:
                if saved is None:
                    ctx.locals.pop(var, None)
                else:
                    ctx.locals[var] = saved
            if name == "map":
                return V(results, trusted)
            if name == "filter":
                return V(kept, trusted)
            return V(ABSENT if absent else (name == "all"), trusted)

        return Compiled(run, t, 1)

    def _use(self, n: Node) -> Compiled:
        raise _tc("unexpanded condition reference", n)

    def _op_signal(self, n: Node) -> Compiled:
        o = n.opts
        sev = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        need = o.get("count_gte", 1)
        floor_conf = dec(o["confidence_gte"]) if "confidence_gte" in o else None
        wanted = {k: (v if isinstance(v, list) else [v]) for k, v in o.get("facts", {}).items()}

        def facts_hit(s: Any) -> bool:
            have = s.facts or {}
            return all(
                k in have and any(type(have[k]) is type(w) and have[k] == w for w in ws) for k, ws in wanted.items()
            )

        def hit(s: Any) -> bool:
            return (
                (("code" not in o) or s.code == o["code"])
                and (("code_prefix" not in o) or s.code.startswith(o["code_prefix"]))
                and (("source" not in o) or s.source == o["source"])
                and (("severity_gte" not in o) or sev[s.severity] >= sev[o["severity_gte"]])
                and (floor_conf is None or Decimal(repr(s.confidence)) >= floor_conf)
                and facts_hit(s)
            )

        def run(ctx: Ctx) -> V:
            ctx.step()
            hits = [s for s in ctx.view.signals if hit(s)]
            if len(hits) >= need:
                known = {id(s) for s in ctx.signal_hits}  # signals may share an id (the default is empty)
                ctx.signal_hits.extend(s for s in hits if id(s) not in known)
                return V(True, True)
            return V(False, True)

        return Compiled(run, T_BOOLEAN, 1)

    def _op_time_window(self, n: Node) -> Compiled:
        o = n.opts
        names = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
        frm, to = (int(o[k][:2]) * 3600 + int(o[k][3:]) * 60 for k in ("from", "to"))
        tz = o["tz"]
        offset = 0 if tz == "UTC" else (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 3600 + int(tz[4:6]) * 60)
        days = set(o["days"])

        def run(ctx: Ctx) -> V:
            ctx.step()
            local = EPOCH + timedelta(microseconds=ctx.view.now.us + offset * 1_000_000)
            tod = local.hour * 3600 + local.minute * 60 + local.second
            today = names[local.weekday()]
            if frm <= to:
                inside = today in days and frm <= tod < to
            else:  # wraps midnight: `days` is the start day
                yesterday = names[(local.weekday() - 1) % 7]
                inside = (today in days and tod >= frm) or (yesterday in days and tod < to)
            return V(inside, True)

        return Compiled(run, T_BOOLEAN, 1)

    def _op_with_locals(self, n: Node) -> Compiled:
        names: list[str] = n.opts["names"]
        ptypes: dict[str, Type] = n.opts["types"]
        values = [self.compile(a) for a in n.args[1:]]
        for name, v in zip(names, values, strict=True):
            if v.t is not None and not _static_compat(v.t, ptypes[name]):
                raise _tc(f"parameter {name} expects {ptypes[name]}", n)
        body = Compiler(self.scope.child({name: ptypes[name] for name in names})).compile(n.args[0])

        def run(ctx: Ctx) -> V:
            ctx.step()
            evaluated = [v.fn(ctx) for v in values]
            saved = {k: ctx.locals.get(k) for k in names}
            for k, ev in zip(names, evaluated, strict=True):
                ctx.locals[k] = ev
            try:
                return body.fn(ctx)
            finally:
                for k, old in saved.items():
                    if old is None:
                        ctx.locals.pop(k, None)
                    else:
                        ctx.locals[k] = old

        return Compiled(run, T_BOOLEAN, 1)


def compile_node(node: Node, scope: Scope) -> Compiled:
    """Compile an already parsed expression, enforcing the expression size limit."""
    compiled = Compiler(scope).compile(node)
    if compiled.nodes > scope.limits.max_expression_nodes:
        raise AuthoringError(
            "EXPRESSION_LIMIT", f"expression has {compiled.nodes} nodes (limit {scope.limits.max_expression_nodes})"
        )
    return compiled


def compile_expression(src: str, scope: Scope) -> Compiled:
    """Parse, type-check and compile `src`. Raises EXPRESSION_SYNTAX / EXPRESSION_LIMIT / TYPE_ERROR / names."""
    node = parse_expression(src)
    if node.count() > scope.limits.max_expression_nodes:
        raise AuthoringError(
            "EXPRESSION_LIMIT", f"expression has {node.count()} nodes (limit {scope.limits.max_expression_nodes})"
        )
    return compile_node(node, scope)


__all__ = [
    "Compiled",
    "Compiler",
    "DeclLike",
    "Fn",
    "Scope",
    "compile_expression",
    "compile_node",
    "unwrap",
]
