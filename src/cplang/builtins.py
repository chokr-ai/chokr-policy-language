"""Built-in functions of the language's standard library: string, number, collection and time helpers."""

from __future__ import annotations

from collections.abc import Callable
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_EVEN, Decimal
from typing import TYPE_CHECKING, Any

from cplang.errors import AuthoringError
from cplang.expr import Node
from cplang.runtime import Ctx
from cplang.types import (
    T_BOOLEAN,
    T_DURATION,
    T_INTEGER,
    T_NUMBER,
    T_STRING,
    T_TIMESTAMP,
    Type,
)
from cplang.values import (
    ABSENT,
    EvalError,
    SetVal,
    Timestamp,
    V,
    arith,
    dec,
    is_int,
    is_num,
    parse_duration,
    parse_timestamp,
    quantize,
    to_integer,
)

if TYPE_CHECKING:
    from cplang.compile import Compiled, Compiler

_UNITS = {"seconds": 1_000_000, "minutes": 60_000_000, "hours": 3_600_000_000, "days": 86_400_000_000}


def _num(x: Any) -> Any:
    if not is_num(x):
        raise EvalError("expected number")
    return x


def _str(x: Any) -> str:
    if not isinstance(x, str):
        raise EvalError("expected string")
    return x


def _coll(x: Any) -> list[Any]:
    if isinstance(x, list | SetVal):
        return list(x)
    if isinstance(x, dict):
        return [x[k] for k in sorted(x)]
    raise EvalError("expected collection")


def _round(n: Any, digits: Any) -> Any:
    if not is_int(digits):
        raise EvalError("expected integer digits")
    return dec(quantize(_num(n), Decimal(1).scaleb(-digits), ROUND_HALF_EVEN))


def _extreme(pick: Callable[[list[Any]], Any]) -> Callable[..., Any]:
    def run(ctx: Ctx, ops: Any, *args: Any) -> Any:
        items = _coll(args[0]) if len(args) == 1 else list(args)
        if not items:
            raise EvalError("min/max of nothing")
        best = items[0]
        for x in items[1:]:
            if pick([ops.cmp(x, best)]):
                best = x
        return best

    return run


def _sum(ctx: Ctx, ops: Any, items: Any) -> Any:
    total: Any = 0
    for x in _coll(items):
        total = arith("+", total, _num(x))
    return total


def _split(ctx: Ctx, ops: Any, s: Any, sep: Any) -> list[str]:
    ctx.text_steps(s)
    if _str(sep) == "":
        raise EvalError("empty separator")
    return _str(s).split(sep)


def _join(ctx: Ctx, ops: Any, items: Any, sep: Any) -> str:
    parts = _coll(items)
    if not all(isinstance(p, str) for p in parts):
        raise EvalError("join needs strings")
    separator = _str(sep)
    total = sum(len(p) for p in parts) + len(separator) * max(len(parts) - 1, 0)
    if total > ctx.limits.max_value_chars:
        raise EvalError("string result is too long")
    ctx.step(total // 4096)
    return separator.join(parts)


def _date_diff(ctx: Ctx, ops: Any, a: Any, b: Any, unit: Any) -> int:
    if not (isinstance(a, Timestamp) and isinstance(b, Timestamp)) or unit not in _UNITS:
        raise EvalError("date_diff needs two timestamps and a unit")
    diff = a.us - b.us
    q = abs(diff) // _UNITS[unit]
    return -q if diff < 0 else q


def _matches(ctx: Ctx, ops: Any, s: Any, pattern: Any) -> bool:
    ctx.text_steps(s)
    return bool(ops.regex(s, pattern, ctx.limits.max_regex_pattern_len))


def _abs(ctx: Ctx, ops: Any, x: Any) -> Any:
    return arith("*", _num(x), -1) if _num(x) < 0 else x


def _integral(rounding: str) -> Callable[..., int]:
    return lambda ctx, ops, x: to_integer(_num(x), rounding)


# name -> (min args, max args, impl(ctx, ops, *values), static result type)
_TABLE: dict[str, tuple[int, int, Callable[..., Any], Type | None]] = {
    "size": (1, 1, lambda ctx, ops, x: ops.size(x), T_INTEGER),
    "count": (1, 1, lambda ctx, ops, x: ops.size(x), T_INTEGER),
    "abs": (1, 1, _abs, None),
    "min": (1, 8, _extreme(lambda c: c[0] < 0), None),
    "max": (1, 8, _extreme(lambda c: c[0] > 0), None),
    "round": (2, 2, lambda ctx, ops, n, d: _round(n, d), T_NUMBER),
    "floor": (1, 1, _integral(ROUND_FLOOR), T_INTEGER),
    "ceil": (1, 1, _integral(ROUND_CEILING), T_INTEGER),
    "lower": (1, 1, lambda ctx, ops, s: (ctx.text_steps(s), _str(s).lower())[1], T_STRING),
    "upper": (1, 1, lambda ctx, ops, s: (ctx.text_steps(s), _str(s).upper())[1], T_STRING),
    "trim": (1, 1, lambda ctx, ops, s: (ctx.text_steps(s), _str(s).strip())[1], T_STRING),
    "starts_with": (2, 2, lambda ctx, ops, a, b: (ctx.text_steps(a), ops.starts_with(a, b))[1], T_BOOLEAN),
    "ends_with": (2, 2, lambda ctx, ops, a, b: (ctx.text_steps(a), _str(a).endswith(_str(b)))[1], T_BOOLEAN),
    "contains": (2, 2, lambda ctx, ops, a, b: (ctx.text_steps(a), ops.contains(a, b))[1], T_BOOLEAN),
    "matches": (2, 2, _matches, T_BOOLEAN),
    "split": (2, 2, _split, Type("list", args=(T_STRING,))),
    "join": (2, 2, _join, T_STRING),
    "keys": (1, 1, lambda ctx, ops, m: sorted(m) if isinstance(m, dict) else _bad(), Type("list", args=(T_STRING,))),
    "values": (1, 1, lambda ctx, ops, m: _coll(m) if isinstance(m, dict) else _bad(), None),
    "sum": (1, 1, _sum, T_NUMBER),
    "duration": (1, 1, lambda ctx, ops, s: parse_duration(_str(s)), T_DURATION),
    "timestamp": (1, 1, lambda ctx, ops, s: parse_timestamp(_str(s)), T_TIMESTAMP),
    "date_diff": (3, 3, _date_diff, T_INTEGER),
}


def _bad() -> Any:
    raise EvalError("expected map")


def compile_builtin(compiler: Compiler, n: Node, name: str) -> Compiled:
    """Compile a call to the built-in function `name`, checking its argument count and types."""
    from cplang.compile import Compiled, _tc, unwrap

    args = [compiler.compile(a) for a in n.args]
    ops = compiler.ops
    if name == "has":
        if len(args) != 1:
            raise _tc("has takes one argument", n)

        def has(ctx: Ctx) -> V:
            ctx.step()
            v = args[0].fn(ctx)
            return V(v.v is not ABSENT, v.trusted)

        return Compiled(has, T_BOOLEAN, 1)
    if name == "default":
        if len(args) != 2:
            raise _tc("default takes two arguments", n)

        def default(ctx: Ctx) -> V:
            ctx.step()
            v = args[0].fn(ctx)
            return v if v.v is not ABSENT else args[1].fn(ctx)

        return Compiled(default, unwrap(args[0].t) or args[1].t, 1)
    if name == "coalesce":
        if not args:
            raise _tc("coalesce needs arguments", n)

        def coalesce(ctx: Ctx) -> V:
            ctx.step()
            last = V(ABSENT, True)
            for a in args:
                last = a.fn(ctx)
                if last.v is not ABSENT:
                    return last
            return last

        return Compiled(coalesce, unwrap(args[0].t), 1)
    entry = _TABLE.get(name)
    if entry is None:
        raise AuthoringError("DECLARATION_UNKNOWN_NAME", f"unknown function {name!r}", column=n.pos + 1, line=1)
    low, high, impl, rtype = entry
    if not low <= len(args) <= high:
        raise _tc(f"{name} takes {low}..{high} argument(s)", n)
    if name == "matches":
        compiler._static_pattern(n, args[1])
    if name in ("duration", "timestamp") and args[0].node is not None and args[0].node.k == "lit":
        try:
            (parse_duration if name == "duration" else parse_timestamp)(str(args[0].node.val))
        except EvalError as exc:
            raise _tc(f"invalid {name} literal", n) from exc
    rt = rtype
    if name in ("abs", "min", "max") and args and args[0].t is not None and unwrap(args[0].t) is not None:
        first = unwrap(args[0].t)
        rt = first if first and first.kind in ("integer", "number", "quantity") else None

    def run(ctx: Ctx) -> V:
        ctx.step()
        vals = [a.fn(ctx) for a in args]
        trusted = all(v.trusted for v in vals)
        if any(v.v is ABSENT for v in vals):
            return V(ABSENT, trusted)
        return V(impl(ctx, ops, *(v.v for v in vals)), trusted)

    return Compiled(run, rt, 1)
