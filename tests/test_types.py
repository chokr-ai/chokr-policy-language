"""The type system: type expressions, named types, subtyping and wire-value validation."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from tests.conftest import BARE_HEAD, Project, make_env

from cplang.errors import AuthoringError
from cplang.types import (
    BUILTIN,
    T_ANY,
    T_INTEGER,
    T_NUMBER,
    T_STRING,
    Type,
    check_value,
    comparable,
    define_type,
    is_subtype,
    parse_type_expr,
)
from cplang.values import ABSENT, EvalError, Quantity, SetVal


def named(**specs: dict[str, Any]) -> dict[str, Type]:
    out: dict[str, Type] = {}
    for name, spec in specs.items():
        out[name] = define_type(name, spec, out)
    return out


class TestTypeExpressions:
    @pytest.mark.parametrize(
        ("text", "canonical"),
        [
            ("string", "string"),
            ("list<string>", "list<string>"),
            ("map<string, number>", "map<string,number>"),
            ("optional<list<integer>>", "optional<list<integer>>"),
            ("set<string>", "set<string>"),
        ],
    )
    def test_parse(self, text: str, canonical: str) -> None:
        assert str(parse_type_expr(text, {})) == canonical

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "list<",
            "list<string",
            "map<integer,string>",
            "map<string string>",
            "nope",
            "string extra",
            "list<string>>",
            "1x",
        ],
    )
    def test_invalid(self, text: str) -> None:
        with pytest.raises(AuthoringError) as e:
            parse_type_expr(text, {})
        assert e.value.code == "TYPE_ERROR"

    def test_depth_limit(self) -> None:
        with pytest.raises(AuthoringError):
            parse_type_expr("list<list<list<string>>>", {}, max_depth=2)

    def test_named_types_resolve(self) -> None:
        env = named(Region={"kind": "enum", "values": ["eu", "us"]})
        assert str(parse_type_expr("list<Region>", env)) == "list<Region>"

    def test_string_forms(self) -> None:
        env = named(U={"kind": "union", "of": ["string", "integer"]})
        assert str(env["U"]) == "U" and str(Type("union", args=(T_STRING, T_INTEGER))) == "union<string|integer>"
        assert Type("list", args=(T_STRING,)).depth() == 2


class TestDefineType:
    def test_bad_names_and_kinds(self) -> None:
        with pytest.raises(AuthoringError) as e:
            define_type("1bad", {"kind": "string"}, {})
        assert e.value.code == "DECLARATION_INVALID"
        for kind in ("any", "optional", "nope", None):
            with pytest.raises(AuthoringError):
                define_type("T", {"kind": kind}, {})

    @pytest.mark.parametrize("values", [[], ["a", "a"], ["1x"], [1]])
    def test_enum_needs_unique_identifiers(self, values: list[Any]) -> None:
        with pytest.raises(AuthoringError):
            define_type("E", {"kind": "enum", "values": values}, {})

    def test_enum_with_described_values(self) -> None:
        t = define_type("E", {"kind": "enum", "values": [{"name": "a"}, "b"], "ordered": True}, {})
        assert t.c["values"] == ("a", "b") and t.c["ordered"]

    def test_union_needs_two_members(self) -> None:
        with pytest.raises(AuthoringError):
            define_type("U", {"kind": "union", "of": ["string"]}, {})

    def test_quantity_validation(self) -> None:
        for spec in (
            {"kind": "quantity", "base": "string", "units": ["a"]},
            {"kind": "quantity", "units": []},
            {"kind": "quantity", "units": ["a"], "conversions": {"b": {"to": "a", "factor": 1}}},
            {"kind": "quantity", "units": ["a", "b"], "conversions": {"a": {"to": "c", "factor": 1}}},
            {"kind": "quantity", "units": ["a", "b"], "conversions": {"a": {"to": "b", "factor": 0}}},
            {"kind": "quantity", "units": ["a", "b"], "conversions": {"a": {"to": "b", "factor": "x"}}},
        ):
            with pytest.raises(AuthoringError):
                define_type("Q", spec, {})

    def test_depth_limit_for_named_types(self) -> None:
        with pytest.raises(AuthoringError):
            define_type("L", {"kind": "list", "of": "list<list<string>>"}, {}, max_depth=2)


class TestSubtyping:
    def test_relations(self) -> None:
        opt = Type("optional", args=(T_STRING,))
        env = named(
            A={"kind": "enum", "values": ["x"]},
            B={"kind": "enum", "values": ["x"]},
            U={"kind": "union", "of": ["string", "integer"]},
        )
        assert is_subtype(T_INTEGER, T_NUMBER) and not is_subtype(T_NUMBER, T_INTEGER)
        assert is_subtype(T_STRING, T_ANY) and is_subtype(T_STRING, opt) and is_subtype(opt, opt)
        assert is_subtype(T_STRING, env["U"]) and not is_subtype(T_NUMBER, env["U"])
        assert not is_subtype(T_STRING, T_INTEGER)
        assert is_subtype(env["A"], env["A"]) and not is_subtype(env["A"], env["B"])
        assert is_subtype(parse_type_expr("list<integer>", {}), parse_type_expr("list<number>", {}))
        assert not is_subtype(parse_type_expr("list<string>", {}), parse_type_expr("list<number>", {}))
        assert is_subtype(BUILTIN["boolean"], Type("boolean"))

    def test_comparable(self) -> None:
        enum = named(
            Level={"kind": "enum", "values": ["lo", "hi"], "ordered": True},
            Plain={"kind": "enum", "values": ["lo", "hi"]},
        )
        assert comparable(T_INTEGER, T_NUMBER) and comparable(T_ANY, T_STRING)
        assert comparable(Type("optional", args=(T_INTEGER,)), T_INTEGER)
        assert not comparable(T_STRING, T_INTEGER)
        assert comparable(enum["Level"], enum["Level"]) and not comparable(enum["Plain"], enum["Plain"])
        assert comparable(BUILTIN["timestamp"], BUILTIN["timestamp"]) and not comparable(
            BUILTIN["boolean"], BUILTIN["boolean"]
        )
        q = {"kind": "quantity", "units": ["m"]}
        env = named(A=q, B={**q, "dimension": "x"})
        assert comparable(env["A"], env["A"]) and not comparable(env["A"], env["B"])


def ok(t: Type, raw: Any) -> Any:
    return check_value(t, raw)


def bad(t: Type, raw: Any) -> None:
    with pytest.raises(EvalError):
        check_value(t, raw)


class TestValues:
    def test_scalars(self) -> None:
        assert ok(T_ANY, {"a": [1]}) is not None
        assert ok(BUILTIN["boolean"], True) is True
        bad(BUILTIN["boolean"], 1)
        bad(T_INTEGER, "1")
        bad(T_INTEGER, 2**70)
        bad(T_STRING, 1)
        bad(T_NUMBER, "x")
        bad(T_STRING, ABSENT)
        assert ok(Type("optional", args=(T_STRING,)), ABSENT) is ABSENT
        assert ok(Type("optional", args=(T_STRING,)), "a") == "a"
        assert ok(T_NUMBER, 1.5) == Decimal("1.5")

    def test_bounds_and_scale(self) -> None:
        ranged = define_type("R", {"kind": "integer", "min": 1, "max": 3}, {})
        assert ok(ranged, 2) == 2
        bad(ranged, 0)
        bad(ranged, 4)
        scaled = define_type("S", {"kind": "number", "scale": 1}, {})
        assert ok(scaled, Decimal("1.5")) == Decimal("1.5")
        bad(scaled, Decimal("1.55"))

    def test_string_constraints_and_formats(self) -> None:
        t = define_type("T", {"kind": "string", "min_len": 2, "max_len": 4, "pattern": "^a"}, {})
        assert ok(t, "abc") == "abc"
        for raw in ("a", "abcde", "bcd"):
            bad(t, raw)
        formats = {
            "uri": ("https://x.test/p", "nope"),
            "email": ("a@b.co", "a@b"),
            "uuid": ("123e4567-e89b-12d3-a456-426614174000", "xyz"),
            "ip": ("10.0.0.1", "999.1.1.1"),
            "cidr": ("10.0.0.0/8", "10.0.0.1/8"),
            "date": ("2026-01-02", "2026-13-40"),
            "datetime": ("2026-01-02T03:04:05Z", "yesterday"),
            "semver": ("1.2.3-rc.1", "1.2"),
            "unknown": ("x", "x"),
        }
        for fmt, (good, wrong) in formats.items():
            ft = Type("string", c={"format": fmt})
            if fmt != "unknown":
                assert ok(ft, good) == good
            bad(ft, wrong)
        bad(Type("string", c={"format": "date"}), "01/02/2026")

    def test_timestamps_and_durations(self) -> None:
        ts = define_type("TS", {"kind": "timestamp", "min": "2026-01-01T00:00:00Z", "max": "2026-12-31T00:00:00Z"}, {})
        assert ok(ts, "2026-06-01T00:00:00Z") is not None
        bad(ts, "2025-06-01T00:00:00Z")
        bad(ts, "2027-06-01T00:00:00Z")
        bad(ts, 5)
        d = define_type("D", {"kind": "duration", "max": "PT1H"}, {})
        assert ok(d, "PT30M") is not None
        bad(d, "PT2H")
        bad(d, 5)
        assert ok(BUILTIN["timestamp"], "2026-06-01T00:00:00Z") is not None

    def test_enums(self) -> None:
        e = named(E={"kind": "enum", "values": ["a", "b"]})["E"]
        assert ok(e, "a") == ok(e, "a") and ok(e, "a") != ok(e, "b")
        bad(e, "c")
        bad(e, 1)

    def test_quantities(self) -> None:
        q = named(Money={"kind": "quantity", "base": "integer", "units": ["usd", "eur"], "min": 0})["Money"]
        assert isinstance(ok(q, {"value": 5, "unit": "usd"}), Quantity)
        for raw in (
            {"value": 5, "unit": "gbp"},
            {"unit": "usd"},
            {"value": 5, "extra": 1},
            "5",
            {"value": -1, "unit": "usd"},
        ):
            bad(q, raw)
        one = define_type("Meters", {"kind": "quantity", "units": ["m"]}, {})
        assert ok(one, {"value": 1.5}).unit == "m"

    def test_collections(self) -> None:
        lst = define_type("L", {"kind": "list", "of": "integer", "min_items": 1, "max_items": 2}, {})
        assert ok(lst, [1]) == [1]
        for raw in ([], [1, 2, 3], "x", ["a"]):
            bad(lst, raw)
        st = define_type("S", {"kind": "set", "of": "string"}, {})
        assert isinstance(ok(st, ["a", "b"]), SetVal)
        bad(st, ["a", "a"])
        mp = define_type("M", {"kind": "map", "of": "integer", "max_entries": 1, "key_pattern": "^k"}, {})
        assert ok(mp, {"k1": 1}) == {"k1": 1}
        for raw in ({"k1": 1, "k2": 2}, {"x": 1}, [1], {"k1": "x"}):
            bad(mp, raw)

    def test_objects(self) -> None:
        o = define_type(
            "O",
            {
                "kind": "object",
                "fields": {
                    "a": {"type": "integer"},
                    "b": {"type": "string", "required": False},
                    "c": {"type": "integer", "default": 7},
                },
            },
            {},
        )
        assert ok(o, {"a": 1}) == {"a": 1, "c": 7}
        assert ok(o, {"a": 1, "b": "x"})["b"] == "x"
        bad(o, {"b": "x"})
        bad(o, {"a": 1, "z": 1})
        bad(o, [1])
        open_o = define_type("P", {"kind": "object", "closed": False, "fields": {}}, {})
        assert ok(open_o, {"z": 1}) == {}

    def test_unions_and_unknown_kinds(self) -> None:
        u = named(U={"kind": "union", "of": ["integer", "boolean"]})["U"]
        assert ok(u, 1) == 1 and ok(u, True) is True
        bad(u, "x")
        bad(Type("mystery"), 1)


class TestQuantityBounds:
    DECLS = (
        "schema: cpl.declarations/1.0\ntypes:\n"
        "  Money: {kind: quantity, base: integer, units: [cents, dollars], max: 10000,\n"
        "          conversions: {dollars: {to: cents, factor: 100}}}\n"
        "inputs:\n  price: {type: Money}\n"
    )

    def verdict(self, project: Project, value: int, unit: str) -> str:
        ev = project.evaluator(BARE_HEAD + "default: allow\nrules: []\n", decls=self.DECLS)
        return ev.evaluate(make_env(price={"value": value, "unit": unit}), []).outcome

    def test_the_bound_is_applied_in_a_common_unit(self, project: Project) -> None:
        assert self.verdict(project, 9_999, "cents") == "allow"
        assert self.verdict(project, 99, "dollars") == "allow"
        assert self.verdict(project, 9_999, "dollars") == "deny"  # 999,900 cents
        assert self.verdict(project, 10_001, "cents") == "deny"


class TestEmailFormat:
    """The email format check costs no more than the length of its input."""

    def test_the_email_check_is_linear(self, project: Project) -> None:
        decls = "schema: cpl.declarations/1.0\ntypes:\n  Mail: {kind: string, format: email}\ninputs:\n  mail: {type: Mail}\n"
        ev = project.evaluator(BARE_HEAD + "default: allow\nrules: []\n", decls=decls)
        hostile = "a@" + "a." * 80_000 + " "
        assert ev.evaluate(make_env(mail=hostile), []).outcome == "deny"
        assert ev.evaluate(make_env(mail="a@b.co"), []).outcome == "allow"
