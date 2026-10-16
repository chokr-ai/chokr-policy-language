"""Declaration files, imports, parameters, tables, constants, functions, computed values."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import BARE_HEAD, Project, authoring_code, make_env, policy_error

from cplang import AuthoringError, CplLimits, load_declarations
from cplang.compile import Scope, compile_expression
from cplang.declarations import DeclarationSet, sha256_file
from cplang.runtime import Ctx, InputView
from cplang.values import EnumVal, EvalError, Quantity

FULL = """
schema: cpl.declarations/1.0
namespace: com.example.app
version: 4
types:
  Tier:      {kind: enum, ordered: true, values: [low, medium, high]}
  Region:    {kind: string, pattern: "^[A-Z]{2}$"}
  Quantity:  {kind: quantity, base: number, dimension: count, units: [items, boxes],
              conversions: {boxes: {to: items, factor: 12}}, min: 0}
  Contact:   {kind: object, fields: {email: {type: string}, region: {type: Region, required: false}}}
attributes:
  quantity:  {type: Quantity, source: derived}
  tier:      {type: Tier, source: asserted}
  regions:   {type: "set<Region>", source: asserted, required: false}
  note:      {type: string, required: false}
constants:
  review_tiers: {type: "set<Tier>", value: [high]}
  base_limit:   {type: integer, value: 10}
  double_limit: {type: integer, expr: "const.base_limit * 2"}
parameters:
  quantity_limit: {type: Quantity, default: {value: 100, unit: items}}
  enabled:        {type: boolean, default: true}
tables:
  limits_by_tier: {key: Tier, value: number, rows: {low: 1000, medium: 100, high: 10}}
functions:
  within_limit: {params: {q: number, t: Tier}, returns: boolean, body: "q <= table.limits_by_tier[t]"}
conditions:
  is_large: {when: {expr: "attributes.quantity > param.quantity_limit"}}
  at_least:
    params: {n: number}
    when: {expr: "attributes.quantity.value >= n"}
computed:
  ratio:
    type: number
    expr: "attributes.quantity.value / table.limits_by_tier[attributes.tier]"
    requires: [quantity, tier]
reason_codes: {OVER_LIMIT: {description: "Above the limit", severity: high}}
"""


def load(project: Project, text: str = FULL, **kw: Any) -> DeclarationSet:
    path = project.write("d.decl.yaml", text)
    kw.setdefault("roots", [project.root])
    return load_declarations([path], **kw)


def evaluate(decls: DeclarationSet, src: str, env: Any = None) -> Any:
    scope = Scope(decls)
    compiled = compile_expression(src, scope)
    return compiled.fn(Ctx(InputView(env or make_env(), [], decls), CplLimits())).v


def authoring_error(fn: Any) -> AuthoringError:
    with pytest.raises(AuthoringError) as e:
        fn()
    return e.value


class TestLoading:
    def test_full_example(self, project: Project) -> None:
        d = load(project)
        assert d.version == 4 and set(d.types) == {"Tier", "Region", "Quantity", "Contact"}
        assert d.resolved_params["quantity_limit"] == Quantity(100, "items", "Quantity")
        assert d.const("double_limit") == (d.types.get("integer") or d.const("double_limit")[0], 20)
        assert d.tables["limits_by_tier"].lookup(EnumVal("Tier", "high")) == 10
        assert "com.example.app/OVER_LIMIT" in d.open_values["reason_codes"]
        assert d.to_dict()["attributes"]["quantity"]["source"] == "derived"

    def test_unknown_key_and_bad_schema_are_located(self, project: Project) -> None:
        err = authoring_error(lambda: load(project, "schema: cpl.declarations/1.0\nbogus: 1\n"))
        assert (err.code, err.line) == ("DECLARATION_INVALID", 2)
        err = authoring_error(lambda: load(project, "schema: other/1\n"))
        assert err.code == "DECLARATION_INVALID"

    def test_yaml_hazards_are_refused(self, project: Project) -> None:
        for text in (
            "schema: &a cpl.declarations/1.0\n",
            "schema: cpl.declarations/1.0\nschema: x\n",
            "schema: !custom cpl.declarations/1.0\n",
            "schema: cpl.declarations/1.0\nversion: .nan\n",
        ):
            assert authoring_error(lambda t=text: load(project, t)).code == "DECLARATION_INVALID"

    def test_reserved_and_bad_names(self, project: Project) -> None:
        text = "schema: cpl.declarations/1.0\nconstants:\n  param: {type: integer, value: 1}\n"
        assert authoring_error(lambda: load(project, text)).code == "DECLARATION_INVALID"

    def test_vocabulary_alias_schema(self, project: Project) -> None:
        d = load(project, "schema: cpl.declarations/1.0\nnamespace: acme\nreason_codes: {X: {}}\n")
        assert set(d.open_values["reason_codes"]) == {"acme/X"}

    def test_empty_declaration_set_works(self) -> None:
        assert evaluate(DeclarationSet(), "1 + 1") == 2


class TestTypes:
    def test_attribute_validation(self, project: Project) -> None:
        d = load(project)
        assert d.validate_attributes({"quantity": {"value": 5, "unit": "items"}, "tier": "low"}) == []
        bad = d.validate_attributes({"quantity": {"value": -1, "unit": "items"}, "tier": "nope", "regions": ["us"]})
        assert bad == ["quantity", "regions", "tier"]
        assert d.validate_attributes({"undeclared": 1}) == []
        assert d.validate_attributes({"undeclared": 1}, strict=True) == ["undeclared"]

    def test_required_attribute_and_error_never_leaks_values(self, project: Project) -> None:
        text = FULL.replace(
            "tier:      {type: Tier, source: asserted}", "tier:      {type: Tier, source: asserted, required: true}"
        )
        d = load(project, text)
        assert d.validate_attributes({}) == ["tier"]
        with pytest.raises(EvalError) as e:
            d.typed_attribute("tier", "SECRET-VALUE")
        assert "SECRET-VALUE" not in str(e.value)

    @pytest.mark.parametrize("value", [True, "5", None, 1.5e400])
    def test_booleans_and_strings_are_not_numbers(self, project: Project, value: Any) -> None:
        d = load(project, "schema: cpl.declarations/1.0\nattributes:\n  score: {type: number, source: asserted}\n")
        with pytest.raises(EvalError):
            d.typed_attribute("score", value)

    def test_scale_min_max_and_object_closed(self, project: Project) -> None:
        text = """
        schema: cpl.declarations/1.0
        types:
          Money: {kind: number, scale: 2, min: 0, max: 100}
          Item: {kind: object, fields: {a: {type: integer}, b: {type: string, required: false, default: x}}}
        attributes:
          price: {type: Money, source: asserted}
          item: {type: Item, source: asserted}
          nums: {type: "list<integer>", source: asserted}
        """
        d = load(project, text)
        assert d.typed_attribute("price", Decimal("1.25")) == Decimal("1.25")
        for bad in (Decimal("1.255"), -1, 101):
            with pytest.raises(EvalError):
                d.typed_attribute("price", bad)
        assert d.typed_attribute("item", {"a": 1}) == {"a": 1, "b": "x"}
        with pytest.raises(EvalError):
            d.typed_attribute("item", {"a": 1, "c": 2})
        with pytest.raises(EvalError):
            d.typed_attribute("item", {"b": "y"})
        assert d.typed_attribute("nums", [1, 2]) == [1, 2]

    def test_type_errors_in_declarations(self, project: Project) -> None:
        for text in (
            "schema: cpl.declarations/1.0\nattributes:\n  a: {type: nothere}\n",
            "schema: cpl.declarations/1.0\nattributes:\n  a: {type: any}\n",
            "schema: cpl.declarations/1.0\ntypes:\n  A: {kind: object, fields: {x: {type: B}}}\n  B: {kind: object, "
            "fields: {y: {type: A}}}\n",
            "schema: cpl.declarations/1.0\ntypes:\n  E: {kind: enum, values: [a, a]}\n",
            "schema: cpl.declarations/1.0\ntypes:\n  Q: {kind: quantity, units: [a], conversions: {a: {to: z, "
            "factor: 1}}}\n",
        ):
            assert authoring_error(lambda t=text: load(project, t)).code in ("TYPE_ERROR", "DECLARATION_INVALID")

    def test_type_depth_limit(self, project: Project) -> None:
        text = 'schema: cpl.declarations/1.0\nattributes:\n  a: {type: "list<list<list<integer>>>"}\n'
        assert authoring_error(lambda: load(project, text, limits=CplLimits(max_type_depth=3))).code == "TYPE_ERROR"
        load(project, text, limits=CplLimits(max_type_depth=4))

    def test_ordered_enum_and_unordered_enum(self, project: Project) -> None:
        d = load(project)
        assert evaluate(d, "Tier.high > Tier.low") is True
        text = "schema: cpl.declarations/1.0\ntypes:\n  Color: {kind: enum, values: [red, blue]}\n"
        plain = load(project, text)
        assert authoring_error(lambda: evaluate(plain, "Color.red < Color.blue")).code == "TYPE_ERROR"
        assert evaluate(plain, "Color.red == Color.red") is True
        d.strict_inputs = True
        assert authoring_error(lambda: evaluate(d, "Tier.high == Color.red")).code in (
            "DECLARATION_UNKNOWN_NAME",
            "TYPE_ERROR",
        )

    def test_enum_does_not_coerce_from_string(self, project: Project) -> None:
        d = load(project)
        assert authoring_error(lambda: evaluate(d, 'Tier.high == "high"')).code == "TYPE_ERROR"


class TestQuantities:
    def test_static_conversion_and_unit_mismatch(self, project: Project) -> None:
        d = load(project)
        env = make_env(attributes={"quantity": {"value": 2, "unit": "boxes"}, "tier": "low"})
        assert evaluate(d, "attributes.quantity > param.quantity_limit", env) is False  # 24 items vs 100
        env = make_env(attributes={"quantity": {"value": 9, "unit": "boxes"}, "tier": "low"})
        assert evaluate(d, "attributes.quantity > param.quantity_limit", env) is True  # 108 items
        assert evaluate(d, "attributes.quantity.value", env) == 9

    def test_mismatched_units_without_conversion_fail(self, project: Project) -> None:
        text = FULL.replace("conversions: {boxes: {to: items, factor: 12}}, ", "")
        d = load(project, text)
        env = make_env(attributes={"quantity": {"value": 2, "unit": "boxes"}, "tier": "low"})
        with pytest.raises(EvalError, match="unit mismatch"):
            evaluate(d, "attributes.quantity > param.quantity_limit", env)

    def test_quantity_addition_converts(self, project: Project) -> None:
        d = load(project)
        env = make_env(attributes={"quantity": {"value": 1, "unit": "boxes"}, "tier": "low"})
        assert evaluate(d, "(attributes.quantity + param.quantity_limit).value", env) == 112

    def test_unit_shorthand(self, project: Project) -> None:
        text = (
            "schema: cpl.declarations/1.0\ntypes:\n  Q: {kind: quantity, units: [kg]}\nattributes:\n"
            "  weight: {type: Q, source: asserted, unit: kg}\n"
        )
        d = load(project, text)
        assert d.typed_attribute("weight", 5) == Quantity(5, "kg", "Q")


class TestParameters:
    def test_unbound_and_invalid(self, project: Project) -> None:
        text = "schema: cpl.declarations/1.0\nparameters:\n  limit: {type: integer}\n"
        assert authoring_error(lambda: load(project, text)).code == "PARAM_UNBOUND"
        # `min` is a constraint of a named type, so on a parameter it is rejected rather than ignored
        bad = "schema: cpl.declarations/1.0\nparameters:\n  limit: {type: integer, min: 1}\n"
        assert authoring_error(lambda: load(project, bad)).code == "DECLARATION_INVALID"
        text = (
            "schema: cpl.declarations/1.0\ntypes:\n  Pos: {kind: integer, min: 1}\nparameters:\n"
            "  limit: {type: Pos, default: 5}\n"
        )
        assert load(project, text, bindings=[{"limit": 7}]).resolved_params["limit"] == 7
        assert authoring_error(lambda: load(project, text, bindings=[{"limit": 0}])).code == "PARAM_INVALID"
        assert authoring_error(lambda: load(project, text, bindings=[{"limit": "x"}])).code == "PARAM_INVALID"
        assert authoring_error(lambda: load(project, text, bindings=[{"nope": 1}])).code == ("DECLARATION_UNKNOWN_NAME")

    def test_invalid_default_is_an_error(self, project: Project) -> None:
        text = "schema: cpl.declarations/1.0\nparameters:\n  limit: {type: integer, default: abc}\n"
        assert authoring_error(lambda: load(project, text)).code == "PARAM_INVALID"

    def test_binding_precedence_later_wins(self, project: Project) -> None:
        text = "schema: cpl.declarations/1.0\nparameters:\n  limit: {type: integer, default: 1}\n"
        d = load(project, text, bindings=[{"limit": 2}, {"limit": 3}])
        assert d.resolved_params["limit"] == 3

    def test_changing_a_parameter_changes_the_fingerprint_part(self, project: Project) -> None:
        a = load(project, bindings=[{"enabled": False}]).fingerprint_parts()
        b = load(project).fingerprint_parts()
        assert a != b and a["declarations"] == b["declarations"]


class TestImports:
    def test_relative_import_and_alias(self, project: Project) -> None:
        project.write(
            "common/units.decl.yaml", "schema: cpl.declarations/1.0\nconstants:\n  ten: {type: integer, value: 10}\n"
        )
        main = project.write(
            "main.decl.yaml",
            """
            schema: cpl.declarations/1.0
            imports:
              - {from: ./common/units.decl.yaml, as: units}
            constants:
              twenty: {type: integer, expr: "const.units.ten * 2"}
        """,
        )
        d = load_declarations([main], roots=[project.root])
        assert d.const("twenty")[1] == 20 and d.const("ten")[1] == 10

    @pytest.mark.parametrize(
        "ref,code",
        [
            ("../outside.decl.yaml", "IMPORT_FORBIDDEN"),
            ("https://example.com/x.yaml", "IMPORT_FORBIDDEN"),
            ("http://127.0.0.1/x.yaml", "IMPORT_FORBIDDEN"),
            ("/etc/passwd", "IMPORT_FORBIDDEN"),
            ("C:/x.yaml", "IMPORT_FORBIDDEN"),
            ("workspace:app@4", "IMPORT_FORBIDDEN"),
            ("./missing.decl.yaml", "IMPORT_NOT_FOUND"),
            ("pack:generic@1", "IMPORT_NOT_FOUND"),
        ],
    )
    def test_refused_imports(self, project: Project, ref: str, code: str) -> None:
        (project.root.parent / "outside.decl.yaml").write_text("schema: cpl.declarations/1.0\n", "utf-8")
        text = f'schema: cpl.declarations/1.0\nimports:\n  - {{from: "{ref}"}}\n'
        err = authoring_error(lambda: load(project, text, roots=[project.root]))
        assert err.code == code and err.line == 3

    def test_cycle_and_depth(self, project: Project) -> None:
        project.write("a.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./b.decl.yaml}]\n")
        project.write("b.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./a.decl.yaml}]\n")
        err = authoring_error(lambda: load_declarations([project.root / "a.decl.yaml"], roots=[project.root]))
        assert err.code == "IMPORT_CYCLE"
        project.write("c.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./d.decl.yaml}]\n")
        project.write("d.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./e.decl.yaml}]\n")
        project.write("e.decl.yaml", "schema: cpl.declarations/1.0\n")
        c = project.root / "c.decl.yaml"
        assert authoring_error(lambda: load_declarations([c], roots=[project.root], max_import_depth=2)).code == (
            "IMPORT_FORBIDDEN"
        )
        load_declarations([c], roots=[project.root], max_import_depth=3)

    def test_diamond_loads_once(self, project: Project) -> None:
        project.write("base.decl.yaml", "schema: cpl.declarations/1.0\nconstants:\n  one: {type: integer, value: 1}\n")
        project.write("l.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./base.decl.yaml}]\n")
        project.write("r.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./base.decl.yaml}]\n")
        top = project.write(
            "top.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./l.decl.yaml}, {from: ./r.decl.yaml}]\n"
        )
        d = load_declarations([top], roots=[project.root])
        assert len(d.files) == 4

    def test_digest_pin(self, project: Project) -> None:
        sub = project.write(
            "sub.decl.yaml", "schema: cpl.declarations/1.0\nconstants:\n  x: {type: integer, value: 1}\n"
        )
        digest = sha256_file(sub.read_bytes())
        ok = project.write(
            "ok.decl.yaml", f'schema: cpl.declarations/1.0\nimports: [{{from: ./sub.decl.yaml, digest: "{digest}"}}]\n'
        )
        load_declarations([ok], roots=[project.root])
        bad = project.write(
            "bad.decl.yaml",
            'schema: cpl.declarations/1.0\nimports: [{from: ./sub.decl.yaml, digest: "sha256:' + "0" * 64 + '"}]\n',
        )
        assert authoring_error(lambda: load_declarations([bad], roots=[project.root])).code == "IMPORT_DIGEST_MISMATCH"

    def test_with_binds_imported_parameters_below_other_layers(self, project: Project) -> None:
        project.write(
            "lib.decl.yaml", "schema: cpl.declarations/1.0\nparameters:\n  cap: {type: integer, default: 1}\n"
        )
        top = project.write(
            "top.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./lib.decl.yaml, with: {cap: 5}}]\n"
        )
        assert load_declarations([top], roots=[project.root]).resolved_params["cap"] == 5
        assert load_declarations([top], roots=[project.root], bindings=[{"cap": 9}]).resolved_params["cap"] == 9

    def test_only_hides_the_rest(self, project: Project) -> None:
        project.write(
            "lib.decl.yaml",
            "schema: cpl.declarations/1.0\nconstants:\n  a: {type: integer, value: 1}\n"
            "  b: {type: integer, value: 2}\n",
        )
        top = project.write(
            "top.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./lib.decl.yaml, only: [a]}]\n"
        )
        d = load_declarations([top], roots=[project.root])
        assert ("constants", "b") in d.private and ("constants", "a") not in d.private

    def test_policies_cannot_name_private_declarations(self, project: Project) -> None:
        project.write(
            "lib.decl.yaml",
            "schema: cpl.declarations/1.0\n"
            "constants:\n  a: {type: integer, value: 1}\n  b: {type: integer, value: 2}\n"
            "  hidden: {type: integer, value: 3, private: true}\n"
            "conditions:\n  over_hidden: {params: {}, when: {expr: 'arguments.n > const.hidden'}}\n"
            "shortcuts:\n  tool_is: {path: arguments.tool, private: true}\n",
        )

        def load(when: str, imports: str = "{from: lib.decl.yaml, only: [a, b, over_hidden]}", extra: str = "") -> Any:
            text = (
                BARE_HEAD
                + f"default: deny\nimports: [{imports}]\n{extra}rules:\n  - {{id: r, outcome: allow, when: {when}}}\n"
            )
            return project.policy(text)

        assert load("{expr: 'arguments.n > const.a'}")
        assert load("{use: over_hidden, with: {}}")  # a declared condition still uses its private dependencies
        for when in (
            "{expr: 'arguments.n > const.hidden'}",
            "{arguments.n: {gt: {ref: const.hidden}}}",
            "{tool_is: send}",
        ):
            assert authoring_code(lambda w=when: load(w)) == "DECLARATION_UNKNOWN_NAME"
        assert authoring_code(lambda: load("{expr: 'arguments.n > const.b'}", "{from: lib.decl.yaml, only: [a]}"))
        assert authoring_code(
            lambda: load("{expr: 'arguments.n > const.lib.hidden'}", "{from: lib.decl.yaml, as: lib}")
        )
        own = "conditions:\n  mine: {params: {}, when: {expr: 'arguments.n > const.hidden'}}\n"
        assert authoring_code(lambda: load("{use: mine, with: {}}", extra=own)) == "DECLARATION_UNKNOWN_NAME"

    def test_pack_resolver(self, project: Project) -> None:
        pack = project.write(
            "pack/generic.decl.yaml", "schema: cpl.declarations/1.0\nnamespace: generic\nreason_codes: {SHARED: {}}\n"
        )
        top = project.write("top.decl.yaml", 'schema: cpl.declarations/1.0\nimports: [{from: "pack:generic@1"}]\n')
        d = load_declarations([top], roots=[project.root], pack_resolver=lambda ref: pack)
        assert "generic/SHARED" in d.open_values["reason_codes"]


class TestConflicts:
    A = "schema: cpl.declarations/1.0\nattributes:\n  tier: {type: string, source: asserted}\n"

    def test_identical_redeclaration_is_accepted(self, project: Project) -> None:
        project.write("a.decl.yaml", self.A)
        top = project.write(
            "top.decl.yaml",
            "schema: cpl.declarations/1.0\nimports: [{from: ./a.decl.yaml}]\n"
            "attributes:\n  tier: {type: string, source: asserted}\n",
        )
        assert "tier" in load_declarations([top], roots=[project.root]).attributes

    def test_different_redeclaration_conflicts_and_rename_resolves(self, project: Project) -> None:
        project.write("a.decl.yaml", self.A)
        top = project.write(
            "top.decl.yaml",
            "schema: cpl.declarations/1.0\nimports: [{from: ./a.decl.yaml}]\n"
            "attributes:\n  tier: {type: integer, source: asserted}\n",
        )
        assert authoring_error(lambda: load_declarations([top], roots=[project.root])).code == "DECLARATION_CONFLICT"
        renamed = project.write(
            "r.decl.yaml",
            "schema: cpl.declarations/1.0\nimports: "
            "[{from: ./a.decl.yaml, rename: {tier: risk_level}}]\nattributes:\n"
            "  tier: {type: integer, source: asserted}\n",
        )
        d = load_declarations([renamed], roots=[project.root])
        assert set(d.attributes) == {"risk_level", "tier"}


class TestTables:
    def test_lookup_and_absent(self, project: Project) -> None:
        d = load(project)
        env = make_env(attributes={"quantity": {"value": 5, "unit": "items"}, "tier": "high"})
        assert evaluate(d, "table.limits_by_tier[attributes.tier]", env) == 10
        assert evaluate(d, "default(table.limits_by_tier[attributes.tier], 0)", env) == 10
        assert evaluate(d, "fn.within_limit(5, Tier.high)", env) is True
        assert evaluate(d, "fn.within_limit(50, Tier.high)", env) is False

    def test_missing_key_is_absent(self, project: Project) -> None:
        text = "schema: cpl.declarations/1.0\ntables:\n  t: {key: string, value: integer, rows: {a: 1}}\n"
        d = load(project, text)
        assert str(evaluate(d, 'table.t["zzz"]')) == "ABSENT"
        assert evaluate(d, 'table.t["a"]') == 1

    def test_csv_and_digest(self, project: Project) -> None:
        csv_path = project.write("data/limits.csv", "key,value\nlow,5\nhigh,1\n")
        digest = sha256_file(csv_path.read_bytes())
        text = (
            "schema: cpl.declarations/1.0\ntypes:\n  T: {kind: enum, values: [low, high]}\ntables:\n"
            f'  lim: {{key: T, value: integer, source: ./data/limits.csv, format: csv, digest: "{digest}"}}\n'
        )
        d = load(project, text)
        assert d.tables["lim"].lookup(EnumVal("T", "low")) == 5 and d.table_files["lim"] == digest
        assert d.fingerprint_parts()["tables"] == {"lim": digest}
        bad = text.replace(digest, "sha256:" + "1" * 64)
        assert authoring_error(lambda: load(project, bad)).code == "IMPORT_DIGEST_MISMATCH"

    def test_object_rows_from_csv(self, project: Project) -> None:
        project.write("data/p.csv", "key,price,active\na,1.5,true\nb,2,false\n")
        text = (
            "schema: cpl.declarations/1.0\ntypes:\n  Row: {kind: object, fields: {price: {type: number}, "
            "active: {type: boolean}}}\ntables:\n  p: {key: string, value: Row, source: ./data/p.csv}\n"
        )
        d = load(project, text)
        assert d.tables["p"].lookup("a") == {"price": Decimal("1.5"), "active": True}

    def test_invalid_tables(self, project: Project) -> None:
        for body in (
            "{key: string, value: integer, rows: {a: x}}",
            "{key: string, value: integer}",
            "{key: string, value: integer, source: ../x.csv}",
            "{key: any, value: integer, rows: {}}",
            "{key: string, value: integer, source: https://x/y.csv}",
        ):
            text = f"schema: cpl.declarations/1.0\ntables:\n  t: {body}\n"
            assert authoring_error(lambda t=text: load(project, t)).code in (
                "TABLE_INVALID",
                "IMPORT_FORBIDDEN",
                "TYPE_ERROR",
            )

    def test_row_limit(self, project: Project) -> None:
        text = "schema: cpl.declarations/1.0\ntables:\n  t: {key: string, value: integer, rows: {a: 1, b: 2, c: 3}}\n"
        assert authoring_error(lambda: load(project, text, limits=CplLimits(max_table_rows=2))).code == "TABLE_INVALID"
        load(project, text, limits=CplLimits(max_table_rows=3))


class TestFunctionsConstantsComputed:
    def test_recursion_is_refused(self, project: Project) -> None:
        text = (
            "schema: cpl.declarations/1.0\nfunctions:\n  f: {params: {n: integer}, returns: integer, "
            'body: "fn.g(n)"}\n  g: {params: {n: integer}, returns: integer, body: "fn.f(n)"}\n'
        )
        assert authoring_error(lambda: load(project, text)).code == "TYPE_ERROR"

    def test_function_return_type_and_arity(self, project: Project) -> None:
        text = 'schema: cpl.declarations/1.0\nfunctions:\n  f: {params: {n: integer}, returns: string, body: "n + 1"}\n'
        assert authoring_error(lambda: load(project, text)).code == "TYPE_ERROR"
        d = load(project)
        assert authoring_error(lambda: evaluate(d, "fn.within_limit(1)")).code == "TYPE_ERROR"
        assert authoring_error(lambda: evaluate(d, 'fn.within_limit("x", Tier.low)')).code == "TYPE_ERROR"

    def test_call_depth_limit(self, project: Project) -> None:
        text = (
            "schema: cpl.declarations/1.0\nfunctions:\n  a: {params: {n: integer}, returns: integer, "
            'body: "n + 1"}\n  b: {params: {n: integer}, returns: integer, body: "fn.a(n) + 1"}\n'
            '  c: {params: {n: integer}, returns: integer, body: "fn.b(n) + 1"}\n'
        )
        d = load(project, text)
        compiled = compile_expression("fn.c(1)", Scope(d))
        ok = Ctx(InputView(make_env(), [], d), CplLimits(max_call_depth=3))
        assert compiled.fn(ok).v == 4
        with pytest.raises(EvalError, match="call depth"):
            compiled.fn(Ctx(InputView(make_env(), [], d), CplLimits(max_call_depth=2)))

    def test_constant_cycle_and_envelope_access_refused(self, project: Project) -> None:
        text = (
            'schema: cpl.declarations/1.0\nconstants:\n  a: {type: integer, expr: "const.b"}\n'
            '  b: {type: integer, expr: "const.a"}\n'
        )
        assert authoring_error(lambda: load(project, text)).code == "DECLARATION_INVALID"
        text = 'schema: cpl.declarations/1.0\nconstants:\n  a: {type: integer, expr: "arguments.x"}\n'
        assert authoring_error(lambda: load(project, text)).code == "TYPE_ERROR"

    def test_computed_requires_and_trust(self, project: Project) -> None:
        d = load(project)
        env = make_env(
            attributes={"quantity": {"value": 5, "unit": "items"}, "tier": "high"},
            sources={"quantity": "derived", "tier": "asserted"},
        )
        assert evaluate(d, "computed.ratio", env) == Decimal("0.5")
        compiled = compile_expression("computed.ratio", Scope(d))
        out = compiled.fn(Ctx(InputView(env, [], d), CplLimits()))
        assert out.trusted is False  # built from a derived (untrusted) attribute
        assert str(evaluate(d, "computed.ratio", make_env(attributes={"tier": "high"}))) == "ABSENT"

    def test_computed_cycle(self, project: Project) -> None:
        text = (
            'schema: cpl.declarations/1.0\ncomputed:\n  a: {type: integer, expr: "computed.b"}\n'
            '  b: {type: integer, expr: "computed.a"}\n'
        )
        assert authoring_error(lambda: load(project, text)).code == "TYPE_ERROR"


class TestLock:
    def test_require_lock(self, project: Project) -> None:
        from cplang.declarations import _Loader, write_lock

        project.write("sub.decl.yaml", "schema: cpl.declarations/1.0\n")
        top = project.write("top.decl.yaml", "schema: cpl.declarations/1.0\nimports: [{from: ./sub.decl.yaml}]\n")
        d = load_declarations([top], roots=[project.root])
        loader = _Loader([project.root], CplLimits(), 16, None, None, False, None)
        loader.load(top)
        lock_path: Path = project.root / "cpl.decl.lock"
        write_lock(d, loader.lock_rows, lock_path)
        import json

        lock = json.loads(lock_path.read_text("utf-8"))
        load_declarations([top], roots=[project.root], lock=lock, require_lock=True)
        project.write("sub.decl.yaml", "schema: cpl.declarations/1.0\nversion: 2\n")
        assert (
            authoring_error(lambda: load_declarations([top], roots=[project.root], lock=lock, require_lock=True)).code
            == "IMPORT_DIGEST_MISMATCH"
        )
        assert (
            authoring_error(
                lambda: load_declarations([top], roots=[project.root], lock={"imports": []}, require_lock=True)
            ).code
            == "IMPORT_DIGEST_MISMATCH"
        )


class TestStandardNames:
    @pytest.mark.parametrize("name", ["kind", "resource", "audience", "depth", "action_uri", "call_chain", "any"])
    def test_a_shortcut_cannot_take_a_standard_name(self, project: Project, name: str) -> None:
        decls = f"schema: cpl.declarations/1.0\nshortcuts:\n  {name}: {{path: arguments.x}}\n"
        assert (
            authoring_code(lambda: project.policy(BARE_HEAD + "default: allow\nrules: []\n", decls=decls))
            == "DECLARATION_INVALID"
        )

    @pytest.mark.parametrize("name", ["kind", "resource", "actor"])
    def test_an_input_cannot_take_a_standard_name(self, project: Project, name: str) -> None:
        decls = f"schema: cpl.declarations/1.0\ninputs:\n  {name}: {{type: string}}\n"
        assert (
            authoring_code(lambda: project.policy(BARE_HEAD + "default: allow\nrules: []\n", decls=decls))
            == "DECLARATION_INVALID"
        )


class TestDeclarationShapes:
    def decls(self, body: str) -> str:
        return "schema: cpl.declarations/1.0\n" + body

    def test_an_unknown_key_in_an_entry_is_an_error(self, project: Project) -> None:
        body = self.decls("attributes:\n  a: {type: string, mx: 20}\n")
        assert policy_error(project, BARE_HEAD + "default: allow\nrules: []\n", decls=body) == "DECLARATION_INVALID"

    def test_a_flag_must_be_a_real_boolean(self, project: Project) -> None:
        body = self.decls("attributes:\n  a: {type: string, required: 'false'}\n")
        assert policy_error(project, BARE_HEAD + "default: allow\nrules: []\n", decls=body) == "DECLARATION_INVALID"

    @pytest.mark.parametrize(
        "spec", ["{from: d.decl.yaml, only: foo}", "{from: d.decl.yaml, rename: [a]}", "{from: d.decl.yaml, nope: 1}"]
    )
    def test_import_options_have_the_right_shape(self, project: Project, spec: str) -> None:
        project.write("d.decl.yaml", self.decls("constants:\n  foo: {type: integer, value: 1}\n"))
        text = BARE_HEAD + f"default: allow\nimports:\n  - {spec}\nrules: []\n"
        assert policy_error(project, text) == "DECLARATION_INVALID"

    def test_two_table_keys_that_mean_the_same_number_are_an_error(self, project: Project) -> None:
        body = self.decls('tables:\n  t: {key: integer, value: string, rows: {"1": a, "01": b}}\n')
        assert policy_error(project, BARE_HEAD + "default: allow\nrules: []\n", decls=body) == "TABLE_INVALID"
