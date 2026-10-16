"""Operator semantics for present values. A missing (`absent`) operand is handled by the evaluator: a comparison
involving a missing value is neither true nor false."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Any

from cplang.matching import glob_match, regex_search
from cplang.values import (
    Duration,
    EnumVal,
    EvalError,
    Quantity,
    SetVal,
    Timestamp,
    arith,
    checked_timestamp,
    is_int,
    is_num,
    neg,
)

Tri = Any  # True | False | ABSENT


def family(x: Any) -> str:
    if type(x) is bool:
        return "boolean"
    if is_num(x):
        return "number"
    if isinstance(x, str):
        return "string"
    if isinstance(x, EnumVal):
        return "enum:" + x.etype
    if isinstance(x, Quantity):
        return "quantity"
    if isinstance(x, Timestamp):
        return "timestamp"
    if isinstance(x, Duration):
        return "duration"
    if isinstance(x, SetVal):
        return "set"
    if isinstance(x, list):
        return "list"
    if isinstance(x, dict):
        return "map"
    return "other"


class Ops:
    """Operators bound to the declarations that give them meaning (enum order, quantity conversions)."""

    def __init__(
        self,
        enum_order: Callable[[str], tuple[str, ...] | None] | None = None,
        conversions: Callable[[str | None], dict[str, Any]] | None = None,
    ) -> None:
        self._enum_order = enum_order or (lambda _name: None)
        self._conversions = conversions or (lambda _name: {})

    def _unify(self, a: Quantity, b: Quantity) -> tuple[Quantity, Quantity]:
        if a.unit == b.unit:
            return a, b
        conv = self._conversions(a.qtype)
        if a.qtype != b.qtype and b.qtype is not None and a.qtype is not None:
            raise EvalError("quantities of different types")
        if a.unit in conv and conv[a.unit]["to"] == b.unit:
            return Quantity(arith("*", a.value, conv[a.unit]["factor"]), b.unit, a.qtype), b
        if b.unit in conv and conv[b.unit]["to"] == a.unit:
            return a, Quantity(arith("*", b.value, conv[b.unit]["factor"]), a.unit, b.qtype)
        raise EvalError("unit mismatch")

    def eq(self, a: Any, b: Any) -> bool:
        fa, fb = family(a), family(b)
        if fa != fb:
            raise EvalError("type mismatch")
        if fa == "quantity":
            qa, qb = self._unify(a, b)
            return Decimal(qa.value) == Decimal(qb.value)
        if fa in ("list", "set"):
            return len(a) == len(b) and all(self.eq(x, y) for x, y in zip(a, b, strict=True))
        if fa == "map":
            return a.keys() == b.keys() and all(self.eq(a[k], b[k]) for k in a)
        return bool(a == b)

    def cmp(self, a: Any, b: Any) -> int:
        fa, fb = family(a), family(b)
        if fa != fb:
            raise EvalError("type mismatch")
        if fa == "number":
            return (Decimal(a) > Decimal(b)) - (Decimal(a) < Decimal(b))
        if fa in ("timestamp", "duration"):
            return int((a.us > b.us) - (a.us < b.us))
        if fa == "quantity":
            qa, qb = self._unify(a, b)
            return (Decimal(qa.value) > Decimal(qb.value)) - (Decimal(qa.value) < Decimal(qb.value))
        if fa.startswith("enum:"):
            order = self._enum_order(a.etype)
            if order is None:
                raise EvalError("enum is not ordered")
            ia, ib = order.index(a.name), order.index(b.name)
            return (ia > ib) - (ia < ib)
        if fa == "string":
            return int((a > b) - (a < b))
        raise EvalError("type is not ordered")

    def compare(self, op: str, a: Any, b: Any) -> bool:
        if op == "eq":
            return self.eq(a, b)
        if op == "ne":
            return not self.eq(a, b)
        c = self.cmp(a, b)
        return {"lt": c < 0, "lte": c <= 0, "gt": c > 0, "gte": c >= 0}[op]

    def between(self, x: Any, lo: Any, hi: Any) -> bool:
        return self.cmp(x, lo) >= 0 and self.cmp(x, hi) <= 0

    def _member(self, item: Any, collection: Any) -> bool:
        fi = family(item)
        found = False
        for other in collection:
            if family(other) != fi:  # like `==`, a type mismatch is an error, so a deny list cannot be bypassed
                raise EvalError("type mismatch")
            found = found or self.eq(item, other)
        return found

    def contains(self, left: Any, right: Any) -> bool:
        """contains(left, right): list/set element, string substring, map key."""
        if isinstance(left, str):
            if not isinstance(right, str):
                raise EvalError("type mismatch")
            return right in left
        if isinstance(left, dict):
            if not isinstance(right, str):
                raise EvalError("type mismatch")
            return right in left
        if isinstance(left, list | SetVal):
            return self._member(right, left)
        raise EvalError("type mismatch")

    def member_of(self, item: Any, collection: Any) -> bool:
        """`item in collection`: list/set membership, substring of a string, key of a map."""
        if isinstance(collection, str):
            if not isinstance(item, str):
                raise EvalError("type mismatch")
            return item in collection
        if isinstance(collection, dict):
            if not isinstance(item, str):
                raise EvalError("type mismatch")
            return item in collection
        if isinstance(collection, list | SetVal):
            return self._member(item, collection)
        raise EvalError("type mismatch")

    @staticmethod
    def starts_with(left: Any, right: Any) -> bool:
        if not (isinstance(left, str) and isinstance(right, str)):
            raise EvalError("type mismatch")
        return left.startswith(right)

    @staticmethod
    def size(x: Any) -> int:
        if isinstance(x, str | list | dict | SetVal):
            return len(x)
        raise EvalError("type mismatch")

    def len_cmp(self, op: str, x: Any, n: Any) -> bool:
        if not is_int(n):
            raise EvalError("type mismatch")
        size = self.size(x)
        return bool(size > n if op == "len_gt" else size < n)

    @staticmethod
    def regex(text: Any, pattern: Any, max_len: int) -> bool:
        if not (isinstance(text, str) and isinstance(pattern, str)):
            raise EvalError("type mismatch")
        return regex_search(pattern, text, max_len)

    @staticmethod
    def glob(text: Any, pattern: Any, opts: dict[str, Any]) -> bool:
        if not (isinstance(text, str) and isinstance(pattern, str)):
            raise EvalError("type mismatch")
        return glob_match(
            pattern,
            text,
            sep=opts.get("sep"),
            case_insensitive=bool(opts.get("case_insensitive")),
            normalize=opts.get("normalize"),
        )

    def arith(self, op: str, a: Any, b: Any) -> Any:
        fa, fb = family(a), family(b)
        if fa == "number" and fb == "number":
            return arith({"add": "+", "sub": "-", "mul": "*", "div": "/", "mod": "%"}[op], a, b)
        if fa == "quantity" and fb == "quantity" and op in ("add", "sub"):
            qa, qb = self._unify(a, b)
            return Quantity(arith("+" if op == "add" else "-", qa.value, qb.value), qa.unit, qa.qtype)
        if fa == "string" and fb == "string" and op == "add":
            return a + b
        if fa == "timestamp" and fb == "duration" and op in ("add", "sub"):
            return checked_timestamp(a.us + b.us if op == "add" else a.us - b.us)
        if fa == "timestamp" and fb == "timestamp" and op == "sub":
            return Duration(a.us - b.us)
        if fa == "duration" and fb == "duration" and op in ("add", "sub"):
            return Duration(a.us + b.us if op == "add" else a.us - b.us)
        raise EvalError("type mismatch")

    @staticmethod
    def negate(a: Any) -> Any:
        if is_num(a):
            return neg(a)
        if isinstance(a, Duration):
            return Duration(-a.us)
        raise EvalError("type mismatch")
