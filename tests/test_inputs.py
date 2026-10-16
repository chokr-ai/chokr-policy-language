"""User-declared inputs and shortcuts: any top-level name is accepted by default, and strict checking is opt-in."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import Project, make_env
from typer.testing import CliRunner

from cplang import AuthoringError, RuleEvaluator
from cplang.cli import app
from cplang.lint import lint

HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\n'
DECLS = (
    "schema: cpl.declarations/1.0\n"
    "types:\n"
    "  Tier: {kind: enum, values: [free, pro]}\n"
    "  Customer: {kind: object, fields: {tier: {type: Tier}, spend: {type: number}, name: {type: string}}}\n"
    "inputs:\n"
    "  customer: {type: Customer}\n"
    "  region: {type: string}\n"
    "shortcuts:\n"
    "  region_matches: {path: region, glob: {sep: '.'}}\n"
)
RUNTIME = {"customer": {"tier": "pro", "spend": 120, "name": "ada"}, "region": "eu.west"}


def rule(when: str, extra: str = "") -> str:
    return HEAD + extra + f"rules:\n  - {{id: r, outcome: allow, when: {when}}}\n"


def decide(project: Project, text: str, **kw: object) -> str:
    action = make_env(**RUNTIME)
    return RuleEvaluator(project.policy(text, **kw)).evaluate(action, []).outcome


def test_any_top_level_name_is_accepted_without_declarations(project: Project) -> None:
    text = rule("{customer.spend: {gt: 100}, expr: 'customer.name == \"ada\"'}")
    assert decide(project, text) == "allow"


def test_strict_inputs_rejects_undeclared_names(project: Project) -> None:
    for text in (rule("{customer.spend: {gt: 100}}"), rule("{expr: 'customer.spend > 1'}")):
        with pytest.raises(AuthoringError) as e:
            project.policy(text, strict_inputs=True)
        assert e.value.code in ("SCHEMA_INVALID", "DECLARATION_UNKNOWN_NAME")


def test_a_bare_custom_field_is_a_condition_key_in_open_mode_only(project: Project) -> None:
    assert decide(project, rule("{region: eu.west}")) == "allow"
    assert decide(project, rule("{region: eu.west}"), decls=DECLS, strict_inputs=True) == "allow"
    with pytest.raises(AuthoringError):
        project.policy(rule("{region: eu.west}"), strict_inputs=True)
    with pytest.raises(AuthoringError):
        project.policy(rule("{'not a path': 1}"))


def test_declared_inputs_pass_strict_checking_and_are_typed(project: Project) -> None:
    ok = rule("{customer.spend: {gt: 100}, region: eu.west}")
    assert decide(project, ok, decls=DECLS, strict_inputs=True) == "allow"
    for bad in ("{expr: 'customer.nope == 1'}", "{expr: 'customer.name > 1'}", "{expr: 'customer.tier == 5'}"):
        with pytest.raises(AuthoringError) as e:
            project.policy(rule(bad), decls=DECLS)
        assert e.value.code == "TYPE_ERROR"


def test_declared_enum_members_can_be_compared(project: Project) -> None:
    assert decide(project, rule("{expr: 'customer.tier == Tier.pro'}"), decls=DECLS) == "allow"


def test_shortcuts_are_user_defined_condition_keys(project: Project) -> None:
    assert decide(project, rule("{region_matches: ['eu.*', 'us.*']}"), decls=DECLS) == "allow"
    assert decide(project, rule("{region_matches: 'us.*'}"), decls=DECLS) == "deny"


def test_invalid_input_and_shortcut_declarations(project: Project) -> None:
    base = "schema: cpl.declarations/1.0\n"
    for text in (
        base + "inputs:\n  x: {}\n",
        base + "inputs:\n  X: {type: string}\n",
        base + "inputs:\n  x: {type: nonsense}\n",
        base + "shortcuts:\n  s: {glob: {}}\n",
        base + "shortcuts:\n  s: {path: a, bogus: 1}\n",
        base + "shortcuts:\n  s: {path: a, glob: {bogus: 1}}\n",
    ):
        with pytest.raises(AuthoringError):
            project.policy(HEAD + "rules: []\n", decls=text)


def test_the_fingerprint_covers_declared_inputs(project: Project) -> None:
    plain = "schema: cpl.declarations/1.0\nconstants:\n  k: {type: integer, value: 1}\n"
    with_inputs = plain + "inputs:\n  region: {type: string}\n"
    text = HEAD + "rules: []\n"
    assert project.policy(text, decls=plain).fingerprint != project.policy(text, decls=with_inputs).fingerprint


def test_declarations_show_inputs_and_shortcuts(project: Project) -> None:
    shown = project.policy(HEAD + "rules: []\n", decls=DECLS).decls.to_dict()
    assert shown["inputs"] == {"customer": "Customer", "region": "string"}
    assert shown["shortcuts"]["region_matches"]["path"] == "region"


def test_lint_reports_undeclared_inputs_but_not_local_names(project: Project) -> None:
    text = rule("{expr: 'customer.spend > 1 && any([1, 2], it > 1)'}")
    found = [(f.code, f.message) for f in lint(project.policy(text))]
    assert found == [
        ("undeclared-input", "`customer` is not a declared input; add it under `inputs:` in a declaration file")
    ]
    assert lint(project.policy(text, decls=DECLS)) == []


def test_lint_knows_condition_parameters_and_enum_roots(project: Project) -> None:
    decls = DECLS + "conditions:\n  at_least: {params: {n: number}, when: {expr: 'customer.spend >= n'}}\n"
    text = rule("{use: at_least, with: {n: 5}}")
    assert lint(project.policy(text, decls=decls)) == []


def test_cli_strict_inputs_check_and_open_mode(tmp_path: Path) -> None:
    runner = CliRunner()
    policy = tmp_path / "p.policy.yaml"
    policy.write_text(rule("{customer.spend: {gt: 100}}"), "utf-8", newline="\n")
    assert runner.invoke(app, ["policy", "validate", str(policy)]).exit_code == 0
    assert runner.invoke(app, ["policy", "validate", str(policy), "--strict-inputs"]).exit_code == 1
    assert runner.invoke(app, ["policy", "lint", str(policy), "--strict-inputs"]).exit_code == 1
    failed = runner.invoke(app, ["policy", "check", str(policy), "--json"])
    assert failed.exit_code == 1 and json.loads(failed.output)["result"] == "FAILED"
    opened = runner.invoke(app, ["policy", "check", str(policy), "--open-inputs", "--json"])
    assert opened.exit_code == 1 and json.loads(opened.output)["findings"][0]["code"] == "undeclared-input"
    decl = tmp_path / "d.decl.yaml"
    decl.write_text(DECLS, "utf-8", newline="\n")
    ok = runner.invoke(app, ["policy", "check", str(policy), "--decl", str(decl)])
    assert ok.exit_code == 0 and ok.output.startswith("OK fingerprint=")
    clean = tmp_path / "c.policy.yaml"
    clean.write_text(
        rule("{customer.spend: {gt: 100}}", "imports:\n  - {from: ./d.decl.yaml}\n"), "utf-8", newline="\n"
    )
    assert runner.invoke(app, ["policy", "check", str(clean)]).exit_code == 0


def test_cli_eval_and_test_accept_strict_inputs(tmp_path: Path) -> None:
    runner = CliRunner()
    policy = tmp_path / "p.policy.yaml"
    policy.write_text(rule("{customer.spend: {gt: 100}}"), "utf-8", newline="\n")
    action = tmp_path / "a.yaml"
    action.write_text('customer: {spend: 200}\ntimestamp: "2026-01-01T00:00:00Z"\n', "utf-8", newline="\n")
    assert runner.invoke(app, ["eval", "--policy", str(policy), "--action", str(action)]).exit_code == 0
    assert (
        runner.invoke(app, ["eval", "--policy", str(policy), "--action", str(action), "--strict-inputs"]).exit_code == 2
    )
    fixtures = tmp_path / "p.fixtures.yaml"
    fixtures.write_text(
        "schema: cpl.fixtures/1.0\ncases:\n  - name: a\n    action: {customer: {spend: 200}}\n    expect: {outcome: allow}\n",
        "utf-8",
        newline="\n",
    )
    assert runner.invoke(app, ["test", "--policy", str(policy), "--fixtures", str(fixtures)]).exit_code == 0
    assert (
        runner.invoke(app, ["test", "--policy", str(policy), "--fixtures", str(fixtures), "--strict-inputs"]).exit_code
        == 2
    )


def test_the_prover_uses_declared_input_types(project: Project) -> None:
    pytest.importorskip("z3")
    from cplang.prove import prove

    decls = (
        "schema: cpl.declarations/1.0\n"
        "types:\n"
        "  Customer: {kind: object, fields: {spend: {type: number, required: false}, name: {type: string, required: false}}}\n"
        "inputs:\n  customer: {type: Customer}\n  region: {type: string}\n"
    )
    wide = project.policy(rule("{customer.spend: {gt: 10}}"), decls=decls, name="w.policy.yaml")
    narrow = project.policy(rule("{customer.spend: {gt: 100}}"), decls=decls, name="n.policy.yaml")
    found = prove(wide, narrow)
    assert found.result == "exceeds_boundary" and found.counterexample is not None
    assert prove(narrow, wide).result == "within_boundary"
    names = project.policy(rule("{customer.name: bob, region: eu}"), decls=decls, name="s.policy.yaml")
    assert prove(names, narrow).result in ("exceeds_boundary", "unsupported")


def test_trace_reports_an_input_that_does_not_match_its_type_like_evaluate(project: Project) -> None:
    policy = project.policy(rule("{expr: 'customer.spend > 1'}"), decls=DECLS)
    bad = make_env(customer={"spend": "lots", "tier": "pro", "name": "x"})
    evaluator = RuleEvaluator(policy)
    assert evaluator.evaluate(bad, []).reason_codes[0] == "EVALUATION_ERROR"
    verdict, _events = evaluator.trace(bad, [])
    assert verdict.outcome == "deny" and verdict.reason_codes[0] == "EVALUATION_ERROR"


CUSTOM_TYPES = (
    "schema: cpl.declarations/1.0\n"
    "types:\n"
    "  Email: {kind: string, format: email}\n"
    "  Score: {kind: integer, min: 0, max: 10}\n"
    "  Tags: {kind: set, of: string, max_items: 3}\n"
    "  Money: {kind: quantity, base: number, units: [usd, eur]}\n"
    "inputs:\n"
    "  contact: {type: Email}\n"
    "  score: {type: Score}\n"
    "  tags: {type: Tags}\n"
    "parameters:\n"
    "  min_score: {type: Score, default: 5}\n"
    "functions:\n"
    "  double: {params: {n: Score}, returns: integer, body: 'n * 2'}\n"
)


def test_users_can_declare_their_own_types_and_they_are_enforced(project: Project) -> None:
    text = rule("{expr: 'score >= param.min_score && fn.double(score) > 1 && \"a\" in tags'}")
    policy = project.policy(text, decls=CUSTOM_TYPES, strict_inputs=True)
    evaluator = RuleEvaluator(policy)
    good = make_env(contact="ada@example.com", score=7, tags=["a", "b"])
    assert evaluator.evaluate(good, []).outcome == "allow"
    for bad in (
        {"contact": "not-an-email", "score": 7, "tags": ["a"]},
        {"contact": "ada@example.com", "score": 11, "tags": ["a"]},
        {"contact": "ada@example.com", "score": 7, "tags": ["a", "b", "c", "d"]},
    ):
        verdict = evaluator.evaluate(make_env(**bad), [])
        assert verdict.reason_codes[0] == "EVALUATION_ERROR"


def test_a_parameter_of_a_custom_type_is_checked_when_loading(project: Project) -> None:
    with pytest.raises(AuthoringError) as e:
        project.policy(rule("{expr: 'true'}"), decls=CUSTOM_TYPES, config_params=[{"min_score": 99}])
    assert e.value.code == "PARAM_INVALID"


@pytest.mark.parametrize("name", ["string", "integer", "list", "optional", "any", "kind", "arguments", "param"])
def test_language_names_cannot_be_redefined_as_types(project: Project, name: str) -> None:
    decls = f"schema: cpl.declarations/1.0\ntypes:\n  {name}: {{kind: string}}\n"
    with pytest.raises(AuthoringError) as e:
        project.policy(HEAD + "rules: []\n", decls=decls)
    assert e.value.code == "DECLARATION_INVALID"


def test_an_input_and_a_type_cannot_share_a_name(project: Project) -> None:
    decls = (
        "schema: cpl.declarations/1.0\ntypes:\n  customer: {kind: enum, values: [a, b]}\n"
        "inputs:\n  customer: {type: string}\n"
    )
    with pytest.raises(AuthoringError) as e:
        project.policy(HEAD + "rules: []\n", decls=decls)
    assert e.value.code == "DECLARATION_CONFLICT"


def test_a_type_mismatch_names_the_input_and_field_but_not_the_value(project: Project) -> None:
    evaluator = RuleEvaluator(project.policy(rule("{expr: 'customer.spend > 1'}"), decls=DECLS))
    missing = evaluator.evaluate(make_env(customer={"tier": "pro", "name": "x"}), [])
    assert missing.reasons[0]["message"] == "input 'customer': missing field 'spend'"
    wrong = evaluator.evaluate(make_env(customer={"tier": "pro", "name": "x", "spend": "secret-value"}), [])
    message = wrong.reasons[0]["message"]
    assert "customer" in message and "spend" in message and "secret-value" not in message
