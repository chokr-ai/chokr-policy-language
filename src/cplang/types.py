"""Type system of the policy language: declared types, type expressions and validation of JSON data against a type."""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

from cplang.errors import AuthoringError
from cplang.inputs import CONDITION_ROOTS, ROOTS
from cplang.matching import regex_search
from cplang.values import (
    ABSENT,
    INT_MAX,
    INT_MIN,
    EnumVal,
    EvalError,
    Quantity,
    SetVal,
    from_json,
    is_int,
    is_num,
    parse_duration,
    parse_timestamp,
)

SCALARS = ("string", "integer", "number", "boolean", "timestamp", "duration", "any")
KINDS = (*SCALARS, "enum", "quantity", "list", "set", "map", "object", "union", "optional")
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# Names a declared type cannot take: the language's own types and the names policies already use for data.
RESERVED_TYPE_NAMES = frozenset({*KINDS, *ROOTS, *CONDITION_ROOTS, "true", "false", "null"})
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$", re.ASCII)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$", re.ASCII)


@dataclass(frozen=True)
class FieldDef:
    """A field of an object type."""

    type: Type
    required: bool = True
    default: Any = ABSENT


@dataclass(frozen=True, eq=False)
class Type:
    """A language type: its kind, constraints and component types."""

    kind: str
    name: str | None = None
    c: dict[str, Any] = field(default_factory=dict)  # constraints
    args: tuple[Type, ...] = ()  # element / member types
    fields: dict[str, FieldDef] = field(default_factory=dict)  # object fields

    def __str__(self) -> str:
        if self.name:
            return self.name
        if self.kind in ("list", "set", "optional"):
            return f"{self.kind}<{self.args[0]}>"
        if self.kind == "map":
            return f"map<string,{self.args[0]}>"
        if self.kind == "union":
            return "union<" + "|".join(str(a) for a in self.args) + ">"
        return self.kind

    def depth(self) -> int:
        inner = [a.depth() for a in self.args] + [f.type.depth() for f in self.fields.values()]
        return 1 + max(inner, default=0)


T_STRING, T_INTEGER, T_NUMBER, T_BOOLEAN = Type("string"), Type("integer"), Type("number"), Type("boolean")
T_TIMESTAMP, T_DURATION, T_ANY = Type("timestamp"), Type("duration"), Type("any")
BUILTIN = {t.kind: t for t in (T_STRING, T_INTEGER, T_NUMBER, T_BOOLEAN, T_TIMESTAMP, T_DURATION, T_ANY)}


def _err(code: str, message: str) -> AuthoringError:
    return AuthoringError(code, message)


def parse_type_expr(text: str, named: dict[str, Type], max_depth: int = 8) -> Type:
    """`string`, `list<string>`, `map<string,number>`, `set<Region>`, `optional<number>`, or a declared name."""
    pos = 0

    def ident() -> str:
        nonlocal pos
        while pos < len(text) and text[pos] == " ":
            pos += 1
        m = re.compile(r"[A-Za-z][A-Za-z0-9_]*").match(text, pos)
        if not m:
            raise _err("TYPE_ERROR", f"invalid type expression {text!r}")
        pos = m.end()
        return m.group()

    def expect(ch: str) -> None:
        nonlocal pos
        while pos < len(text) and text[pos] == " ":
            pos += 1
        if pos >= len(text) or text[pos] != ch:
            raise _err("TYPE_ERROR", f"invalid type expression {text!r}")
        pos += 1

    def parse(depth: int) -> Type:
        if depth > max_depth:
            raise _err("TYPE_ERROR", "type nesting exceeds cpl.max_type_depth")
        name = ident()
        if name in ("list", "set", "optional") and pos < len(text) and text[pos] == "<":
            expect("<")
            inner = parse(depth + 1)
            expect(">")
            return Type(name, args=(inner,))
        if name == "map" and pos < len(text) and text[pos] == "<":
            expect("<")
            if ident() != "string":
                raise _err("TYPE_ERROR", "map keys must be string")
            expect(",")
            inner = parse(depth + 1)
            expect(">")
            return Type("map", args=(inner,))
        if name in BUILTIN:
            return BUILTIN[name]
        if name in named:
            return named[name]
        raise _err("TYPE_ERROR", f"unknown type {name!r}")

    result = parse(1)
    if text[pos:].strip():
        raise _err("TYPE_ERROR", f"invalid type expression {text!r}")
    return result


def define_type(name: str, spec: dict[str, Any], named: dict[str, Type], max_depth: int = 8) -> Type:
    """Build a named type from a `types:` entry."""
    if not _NAME.fullmatch(name):
        raise _err("DECLARATION_INVALID", f"invalid type name {name!r}")
    if name in RESERVED_TYPE_NAMES:
        raise _err("DECLARATION_INVALID", f"{name!r} is reserved by the language and cannot name a type")
    kind = spec.get("kind")
    if kind not in KINDS or kind in ("any", "optional"):
        raise _err("TYPE_ERROR", f"type {name} has an unknown kind")
    c = {k: v for k, v in spec.items() if k not in ("kind", "description", "deprecated", "private", "ext")}
    if kind == "enum":
        values = [v["name"] if isinstance(v, dict) else v for v in spec.get("values", [])]
        if (
            not values
            or not all(isinstance(v, str) and _NAME.fullmatch(v) for v in values)
            or len(set(values)) != len(values)
        ):
            raise _err("TYPE_ERROR", f"enum {name} needs unique identifier values")
        c = {"values": tuple(values), "ordered": bool(spec.get("ordered", False))}
        result = Type("enum", name, c)
    elif kind in ("list", "set", "map"):
        element = parse_type_expr(str(spec.get("of", "any")), named, max_depth)
        result = Type(kind, name, c, (element,))
    elif kind == "union":
        members = tuple(parse_type_expr(str(m), named, max_depth) for m in spec.get("of", []))
        if len(members) < 2:
            raise _err("TYPE_ERROR", f"union {name} needs at least two members")
        result = Type("union", name, c, members)
    elif kind == "object":
        fields = {}
        for fname, fspec in spec.get("fields", {}).items():
            ftype = parse_type_expr(str(fspec["type"]), named, max_depth)
            fields[fname] = FieldDef(ftype, bool(fspec.get("required", True)), fspec.get("default", ABSENT))
        c["closed"] = bool(spec.get("closed", True))
        result = Type("object", name, c, fields=fields)
    elif kind == "quantity":
        base = spec.get("base", "number")
        if base not in ("integer", "number") or not spec.get("units"):
            raise _err("TYPE_ERROR", f"quantity {name} needs base integer|number and units")
        c["units"] = tuple(spec["units"])
        c["conversions"] = dict(spec.get("conversions", {}))
        for unit, conv in c["conversions"].items():
            if (
                unit not in c["units"]
                or conv.get("to") not in c["units"]
                or not isinstance(conv.get("factor"), int | Decimal)
                or conv["factor"] <= 0
            ):
                raise _err("TYPE_ERROR", f"quantity {name} has an invalid conversion for {unit}")
        result = Type("quantity", name, c)
    else:
        result = Type(kind, name, c)
    if result.depth() > max_depth:
        raise _err("TYPE_ERROR", f"type {name} exceeds cpl.max_type_depth")
    return result


def is_subtype(a: Type, b: Type) -> bool:
    """True when a value of type `a` can be used where type `b` is expected."""
    if b.kind == "any" or a is b:
        return True
    if a.kind == "integer" and b.kind == "number" and not b.name:
        return True
    if b.kind == "optional":
        return is_subtype(a.args[0] if a.kind == "optional" else a, b.args[0])
    if b.kind == "union":
        return any(is_subtype(a, m) for m in b.args)
    if a.kind != b.kind:
        return False
    if a.name or b.name:
        return a.name == b.name and a.kind == b.kind
    if a.kind in ("list", "set", "map"):
        return is_subtype(a.args[0], b.args[0])
    return True


def comparable(a: Type, b: Type) -> bool:
    """Whether `<`-style ordering is allowed between the two types."""
    a, b = (t.args[0] if t.kind == "optional" else t for t in (a, b))
    if a.kind == "any" or b.kind == "any":
        return True
    if a.kind in ("integer", "number") and b.kind in ("integer", "number"):
        return True
    if a.kind != b.kind:
        return False
    if a.kind == "enum":
        return a.name == b.name and bool(a.c.get("ordered"))
    if a.kind == "quantity":
        return a.c.get("dimension") == b.c.get("dimension")
    return a.kind in ("timestamp", "duration", "string")


def check_value(t: Type, raw: Any) -> Any:
    """Validate JSON data against `t`, returning the language value. Raises EvalError naming only the reason."""
    k = t.kind
    if k == "any":
        return from_json(raw)
    if k == "optional":
        return ABSENT if raw is ABSENT else check_value(t.args[0], raw)
    if raw is ABSENT:
        raise EvalError("value is absent")
    if k == "string":
        return _string(t, raw)
    if k == "integer":
        if not is_int(raw):
            raise EvalError("expected integer")
        return _bounded(t, raw)
    if k == "number":
        return _number(t, raw)
    if k == "boolean":
        if type(raw) is not bool:
            raise EvalError("expected boolean")
        return raw
    if k == "timestamp":
        if not isinstance(raw, str):
            raise EvalError("expected timestamp")
        return _bounded_ordered(t, parse_timestamp(raw))
    if k == "duration":
        if not isinstance(raw, str):
            raise EvalError("expected duration")
        return _bounded_ordered(t, parse_duration(raw))
    if k == "enum":
        if not isinstance(raw, str) or raw not in t.c["values"]:
            raise EvalError("not a member of the enum")
        return EnumVal(t.name or "enum", raw)
    if k == "quantity":
        return _quantity(t, raw)
    if k in ("list", "set"):
        return _collection(t, raw)
    if k == "map":
        return _map(t, raw)
    if k == "object":
        return _object(t, raw)
    if k == "union":
        for member in t.args:
            try:
                return check_value(member, raw)
            except EvalError:
                continue
        raise EvalError("matches no union member")
    raise EvalError("unknown type")


def _string(t: Type, raw: Any) -> str:
    if not isinstance(raw, str):
        raise EvalError("expected string")
    c = t.c
    if ("min_len" in c and len(raw) < c["min_len"]) or ("max_len" in c and len(raw) > c["max_len"]):
        raise EvalError("string length out of range")
    if "pattern" in c and not regex_search(c["pattern"], raw):
        raise EvalError("string does not match its pattern")
    fmt = c.get("format")
    if fmt and not _format_ok(fmt, raw):
        raise EvalError(f"string is not a valid {fmt}")
    return raw


def _email_ok(text: str) -> bool:
    """`local@domain.tld` with no whitespace: a single linear scan, so hostile input costs no more than its length."""
    local, at, domain = text.partition("@")
    if not at or not local or "@" in domain or any(c.isspace() for c in text):
        return False
    head, dot, tail = domain.rpartition(".")
    return bool(dot and head and tail)


def _format_ok(fmt: str, text: str) -> bool:
    try:
        if fmt == "uri":
            parts = urlsplit(text)
            return bool(parts.scheme and (parts.netloc or parts.path))
        if fmt == "email":
            return _email_ok(text)
        if fmt == "uuid":
            return str(uuid.UUID(text)) == text.lower()
        if fmt == "ip":
            ipaddress.ip_address(text)
            return True
        if fmt == "cidr":
            ipaddress.ip_network(text, strict=True)
            return True
        if fmt == "date":
            if not _DATE.fullmatch(text):
                return False
            parse_timestamp(text + "T00:00:00Z")
            return True
        if fmt == "datetime":
            parse_timestamp(text)
            return True
        if fmt == "semver":
            return bool(_SEMVER.fullmatch(text))
    except ValueError, EvalError:
        return False
    return False


def _bounded(t: Type, x: int | Decimal) -> int | Decimal:
    if not INT_MIN <= x <= INT_MAX and is_int(x):
        raise EvalError("integer outside signed 64-bit")
    if ("min" in t.c and x < t.c["min"]) or ("max" in t.c and x > t.c["max"]):
        raise EvalError("number out of range")
    return x


def _bounded_ordered(t: Type, x: Any) -> Any:
    if "min" in t.c or "max" in t.c:
        lo = t.c.get("min")
        hi = t.c.get("max")
        parse = parse_timestamp if t.kind == "timestamp" else parse_duration
        if (lo is not None and x.us < parse(lo).us) or (hi is not None and x.us > parse(hi).us):
            raise EvalError("value out of range")
    return x


def _number(t: Type, raw: Any) -> int | Decimal:
    if type(raw) is float:
        raw = from_json(raw)
    if not is_num(raw):
        raise EvalError("expected number")
    if "scale" in t.c and type(raw) is Decimal and -raw.as_tuple().exponent > t.c["scale"]:  # type: ignore[operator]
        raise EvalError("too many decimal places")
    return _bounded(t, raw)


def _quantity(t: Type, raw: Any) -> Quantity:
    if not isinstance(raw, dict) or set(raw) - {"value", "unit"} or "value" not in raw:
        raise EvalError("expected {value, unit}")
    unit = raw.get("unit")
    if unit is None and len(t.c["units"]) == 1:
        unit = t.c["units"][0]
    if unit not in t.c["units"]:
        raise EvalError("unknown unit")
    base = T_INTEGER if t.c.get("base") == "integer" else T_NUMBER
    value = check_value(Type(base.kind, None, {k: v for k, v in t.c.items() if k == "scale"}), raw["value"])
    if "min" in t.c or "max" in t.c:  # bounds are in the first listed unit, so compare in that unit
        in_base = _in_unit(value, str(unit), t.c["units"][0], t.c["conversions"])
        if ("min" in t.c and in_base < t.c["min"]) or ("max" in t.c and in_base > t.c["max"]):
            raise EvalError("number out of range")
    return Quantity(value, str(unit), t.name)


def _in_unit(value: Any, unit: str, target: str, conversions: dict[str, Any]) -> Any:
    """`value` expressed in `target`, following declared conversions."""
    for _ in range(len(conversions) + 1):
        if unit == target:
            return value
        conv = conversions.get(unit)
        if conv is None:
            break
        value, unit = Decimal(value) * Decimal(conv["factor"]), conv["to"]
    raise EvalError("unit mismatch")


def _collection(t: Type, raw: Any) -> Any:
    if not isinstance(raw, list):
        raise EvalError(f"expected {t.kind}")
    c = t.c
    if ("min_items" in c and len(raw) < c["min_items"]) or ("max_items" in c and len(raw) > c["max_items"]):
        raise EvalError("collection size out of range")
    items = [check_value(t.args[0], i) for i in raw]
    if t.kind == "set":
        result = SetVal(items)
        if len(result) != len(items):
            raise EvalError("duplicate set member")
        return result
    return items


def _map(t: Type, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise EvalError("expected map")
    c = t.c
    if "max_entries" in c and len(raw) > c["max_entries"]:
        raise EvalError("map has too many entries")
    out = {}
    for key in sorted(raw):
        if "key_pattern" in c and not regex_search(c["key_pattern"], key):
            raise EvalError("map key does not match its pattern")
        out[key] = check_value(t.args[0], raw[key])
    return out


def _object(t: Type, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise EvalError("expected object")
    if t.c.get("closed", True) and set(raw) - set(t.fields):
        raise EvalError("unknown object field")
    out: dict[str, Any] = {}
    for name, f in t.fields.items():
        if name in raw:
            try:
                out[name] = check_value(f.type, raw[name])
            except EvalError as exc:
                raise EvalError(f"field {name!r}: {exc}") from exc
        elif f.default is not ABSENT:
            out[name] = check_value(f.type, f.default)
        elif f.required:
            raise EvalError(f"missing field {name!r}")
    return out
