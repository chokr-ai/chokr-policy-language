"""Runtime values: exact decimals, explicit conversions and `absent` for missing data."""

from __future__ import annotations

import decimal
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, NamedTuple

INT_MIN, INT_MAX = -(2**63), 2**63 - 1
_CTX = decimal.Context(
    prec=34,
    rounding=decimal.ROUND_HALF_EVEN,
    Emin=-6143,
    Emax=6144,
    traps=[decimal.Overflow, decimal.InvalidOperation, decimal.DivisionByZero, decimal.Underflow],
)


class EvalError(Exception):
    """Run-time failure inside the evaluator, reported as EVALUATION_ERROR. The message names the cause only."""


class _Absent:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        raise EvalError("absent used as a boolean")


ABSENT: Any = _Absent()


class V(NamedTuple):
    """A value with a trusted flag. Values derived from an action's `arguments` are untrusted, and an expression result
    is trusted only when every input is."""

    v: Any
    trusted: bool = True


ABSENT_V = V(ABSENT, True)


@dataclass(frozen=True)
class Quantity:
    """A number with a unit."""

    value: int | Decimal
    unit: str
    qtype: str | None = None  # declared quantity type; conversions are looked up there


@dataclass(frozen=True)
class EnumVal:
    """A member of an enum type."""

    etype: str
    name: str


@dataclass(frozen=True)
class Duration:
    """A length of time in microseconds."""

    us: int


@dataclass(frozen=True)
class Timestamp:
    """An instant in microseconds since the Unix epoch, UTC."""

    us: int  # microseconds since the Unix epoch, UTC


class SetVal(tuple[Any, ...]):
    """A set: unique items in ascending order."""

    __slots__ = ()

    def __new__(cls, items: Any = ()) -> SetVal:
        unique: dict[Any, Any] = {}
        for item in items:
            unique.setdefault(sort_key(item), item)
        return super().__new__(cls, (unique[k] for k in sorted(unique)))


def is_int(x: Any) -> bool:
    """True for integers (booleans excluded)."""
    return type(x) is int


def is_num(x: Any) -> bool:
    """True for integers and decimals (booleans excluded)."""
    return type(x) is int or type(x) is Decimal


def sort_key(x: Any) -> tuple[Any, ...]:
    if type(x) is bool:
        return (0, x)
    if is_num(x):
        return (1, Decimal(x))
    if isinstance(x, str):
        return (2, x)
    if isinstance(x, EnumVal):
        return (3, x.etype, x.name)
    if isinstance(x, Timestamp | Duration):
        return (4, x.us)
    if isinstance(x, Quantity):
        return (5, x.unit, Decimal(x.value))
    return (9, repr(x))


def dec(x: int | Decimal | str) -> Decimal:
    """Convert a number to an exact Decimal."""
    try:
        return _CTX.create_decimal(x)
    except decimal.DecimalException as exc:
        raise EvalError("decimal out of range") from exc


def quantize(x: int | Decimal, exponent: Decimal, rounding: str) -> Decimal:
    """`x` rounded to `exponent` under the language's own decimal context, never the host thread's."""
    ctx = _CTX.copy()
    ctx.rounding = rounding
    try:
        return ctx.quantize(Decimal(x), exponent)
    except decimal.DecimalException as exc:
        raise EvalError("decimal out of range") from exc


def to_integer(x: int | Decimal, rounding: str) -> int:
    """`x` rounded to an integer under the language's own decimal context."""
    ctx = _CTX.copy()
    ctx.rounding = rounding
    try:
        return _int_checked(int(ctx.to_integral_value(Decimal(x))))
    except decimal.DecimalException as exc:
        raise EvalError("decimal out of range") from exc


def _int_checked(n: int) -> int:
    if not INT_MIN <= n <= INT_MAX:
        raise EvalError("integer overflow")
    return n


def arith(op: str, a: int | Decimal, b: int | Decimal) -> int | Decimal:
    try:
        if op == "/":
            if b == 0:
                raise EvalError("division by zero")
            return _CTX.divide(Decimal(a), Decimal(b))
        if op == "%":
            if b == 0:
                raise EvalError("division by zero")
            if is_int(a) and is_int(b):
                rem = abs(int(a)) % abs(int(b))  # the remainder takes the sign of the dividend
                return -rem if a < 0 else rem
            return _CTX.remainder(Decimal(a), Decimal(b))
        if is_int(a) and is_int(b):
            i, j = int(a), int(b)
            return _int_checked({"+": i + j, "-": i - j, "*": i * j}[op])
        x, y = Decimal(a), Decimal(b)
        return {"+": _CTX.add, "-": _CTX.subtract, "*": _CTX.multiply}[op](x, y)
    except decimal.DecimalException as exc:
        raise EvalError("decimal arithmetic failed") from exc


def neg(a: int | Decimal) -> int | Decimal:
    """Negate a number."""
    if is_int(a):
        return _int_checked(-int(a))
    return _CTX.minus(Decimal(a))


def render_number(x: int | Decimal) -> str:
    """A decimal's text without an exponent."""
    if is_int(x):
        return str(x)
    d = Decimal(x)
    if d == 0:
        return "0"
    text = format(d.normalize(), "f")
    return text


_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$", re.ASCII
)
_DUR = re.compile(r"^(-)?P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.(\d{1,6}))?S)?)?$", re.ASCII)
TS_MIN_US, TS_MAX_US = -62_135_596_800_000_000, 253_402_300_799_999_999  # 0001-01-01 .. 9999-12-31 UTC
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def parse_timestamp(text: str) -> Timestamp:
    """Parse an RFC 3339 timestamp."""
    m = _TS.fullmatch(text)
    if not m:
        raise EvalError("invalid timestamp")
    frac = m.group(7) or ""
    if len(frac) > 6 and frac[6:].strip("0"):
        raise EvalError("timestamp finer than microseconds")
    try:
        year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
        moment = datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError as exc:
        raise EvalError("invalid timestamp") from exc
    offset = 0
    if m.group(8):
        hours, minutes = int(m.group(9)), int(m.group(10))
        if hours > 23 or minutes > 59:
            raise EvalError("invalid timestamp")
        offset = (hours * 3600 + minutes * 60) * 1_000_000 * (1 if m.group(8) == "+" else -1)
    return checked_timestamp(((moment - EPOCH) // timedelta(microseconds=1)) + int((frac + "000000")[:6]) - offset)


def checked_timestamp(us: int) -> Timestamp:
    """A timestamp, or an error when it falls outside years 0001 to 9999."""
    if not TS_MIN_US <= us <= TS_MAX_US:
        raise EvalError("timestamp out of range")
    return Timestamp(us)


def format_timestamp(t: Timestamp) -> str:
    """Format a timestamp as RFC 3339 text."""
    moment = EPOCH + timedelta(microseconds=t.us)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}Z"


def parse_duration(text: str) -> Duration:
    """Parse an ISO 8601 duration such as `PT30M`."""
    m = _DUR.fullmatch(text)
    if not m or text in ("P", "-P") or text.endswith("T"):
        raise EvalError("invalid duration")
    days, hours, minutes, seconds = (int(m.group(i) or 0) for i in (2, 3, 4, 5))
    micro = int(((m.group(6) or "") + "000000")[:6])
    total = ((days * 24 + hours) * 60 + minutes) * 60 + seconds
    value = total * 1_000_000 + micro
    return Duration(-value if m.group(1) else value)


def from_json(x: Any) -> Any:
    """JSON data to a language value: floats become exact decimals (via their shortest repr), containers are copied."""
    if type(x) is float:
        if x != x or x in (float("inf"), float("-inf")):
            raise EvalError("non-finite number")
        return Decimal(repr(x))
    if type(x) is int and not INT_MIN <= x <= INT_MAX:
        raise EvalError("integer outside signed 64-bit")
    if isinstance(x, dict):
        return {k: from_json(v) for k, v in x.items()}
    if isinstance(x, list | tuple):
        return [from_json(v) for v in x]
    return x


def type_label(x: Any) -> str:
    """The name of a value's type."""
    if x is ABSENT:
        return "absent"
    if type(x) is bool:
        return "boolean"
    if type(x) is int:
        return "integer"
    if type(x) is Decimal:
        return "number"
    if isinstance(x, str):
        return "string"
    if isinstance(x, SetVal):
        return "set"
    if isinstance(x, list):
        return "list"
    if isinstance(x, dict):
        return "map"
    if isinstance(x, EnumVal):
        return "enum"
    if isinstance(x, Quantity):
        return "quantity"
    if isinstance(x, Timestamp):
        return "timestamp"
    if isinstance(x, Duration):
        return "duration"
    return "any"


def render(x: Any) -> str:
    """Operator-view text of a value: decimals without exponent, booleans as true/false."""
    if x is ABSENT:
        return "n/a"
    if type(x) is bool:
        return "true" if x else "false"
    if is_num(x):
        return render_number(x)
    if isinstance(x, Quantity):
        return f"{render_number(x.value)} {x.unit}"
    if isinstance(x, EnumVal):
        return x.name
    if isinstance(x, Timestamp):
        return format_timestamp(x)
    if isinstance(x, Duration):
        return f"{x.us}us"
    if isinstance(x, list | SetVal):
        return "[" + ", ".join(render(i) for i in x) + "]"
    if isinstance(x, dict):
        return "{" + ", ".join(f"{k}: {render(v)}" for k, v in sorted(x.items())) + "}"
    return str(x)


def to_wire(x: Any) -> Any:
    """A language value to canonical JSON data (decimals as strings, so digests never depend on float formatting)."""
    if type(x) is Decimal:
        return render_number(x)
    if isinstance(x, Quantity):
        return {"value": to_wire(x.value), "unit": x.unit}
    if isinstance(x, EnumVal):
        return x.name
    if isinstance(x, Timestamp):
        return format_timestamp(x)
    if isinstance(x, Duration):
        return x.us
    if isinstance(x, list | SetVal):
        return [to_wire(i) for i in x]
    if isinstance(x, dict):
        return {k: to_wire(v) for k, v in x.items()}
    return x


__all__ = [
    "ABSENT",
    "ABSENT_V",
    "INT_MAX",
    "INT_MIN",
    "Duration",
    "EnumVal",
    "EvalError",
    "Quantity",
    "SetVal",
    "Timestamp",
    "V",
    "arith",
    "dec",
    "format_timestamp",
    "from_json",
    "is_int",
    "is_num",
    "neg",
    "parse_duration",
    "parse_timestamp",
    "render",
    "render_number",
    "sort_key",
    "to_wire",
    "type_label",
]
