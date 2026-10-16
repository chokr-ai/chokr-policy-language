"""The policy linter."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import BARE_HEAD, Project
from typer.testing import CliRunner

from cplang.cli import app
from cplang.lint import lint

HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\n'
runner = CliRunner()


def codes(project: Project, text: str, **kw: object) -> list[tuple[str, str | None]]:
    return [(f.code, f.rule) for f in lint(project.policy(text, **kw))]


def test_a_clean_policy_has_no_findings(project: Project) -> None:
    text = HEAD + "rules:\n  - {id: a, outcome: allow, match: {kind: [read]}}\n  - {id: b, outcome: deny}\n"
    assert codes(project, text) == []


def test_unused_variables(project: Project) -> None:
    text = HEAD + (
        "rules:\n  - id: r\n    outcome: allow\n    let: {used: 'arguments.n + 1', other: 'arguments.n * 2', dead: '1'}\n"
        "    when: {expr: 'var.used > 1 && var.other > 1'}\n"
    )
    assert codes(project, text) == [("unused-variable", "r")]


def test_variables_used_only_in_explanations_or_later_lets_count_as_used(project: Project) -> None:
    text = HEAD + (
        "rules:\n  - id: r\n    outcome: deny\n    let: {a: 'arguments.n', b: 'var.a + 1'}\n"
        "    explain: 'value {var.b}'\n"
    )
    assert codes(project, text) == []


def test_rules_after_a_catch_all_are_unreachable_unless_deny_overrides(project: Project) -> None:
    rules = "rules:\n  - {id: all, outcome: allow}\n  - {id: later, outcome: deny, match: {kind: [read]}}\n"
    assert codes(project, HEAD + "strategy: first_match\n" + rules) == [("unreachable-rule", "later")]
    assert codes(project, HEAD + "strategy: deny_overrides\n" + rules) == []


def test_rules_after_an_unconditional_rule_with_the_same_match_are_unreachable(project: Project) -> None:
    rules = (
        "rules:\n  - {id: read, outcome: allow, match: {kind: [read]}}\n"
        "  - {id: narrower, outcome: deny, match: {kind: [read]}, when: {arguments.x: 1}}\n"
        "  - {id: other, outcome: deny, match: {kind: [write]}}\n"
    )
    assert codes(project, HEAD + "strategy: first_match\n" + rules) == [("unreachable-rule", "narrower")]
    gated = rules.replace("match: {kind: [read]}}\n", "match: {kind: [read]}, when: {arguments.y: 1}}\n", 1)
    assert codes(project, HEAD + "strategy: first_match\n" + gated) == []  # the first rule may not fire


def test_priority_order_decides_which_rule_is_first(project: Project) -> None:
    rules = (
        "rules:\n  - {id: specific, outcome: deny, priority: 1, match: {kind: [read]}}\n"
        "  - {id: all, outcome: allow, priority: 9}\n"
    )
    assert codes(project, HEAD + "strategy: priority\n" + rules) == [("unreachable-rule", "specific")]


def test_duplicate_and_conflicting_rules(project: Project) -> None:
    rules = (
        "rules:\n  - {id: a, outcome: allow, match: {kind: [read]}}\n  - {id: b, outcome: allow, match: {kind: [read]}}\n"
        "  - {id: c, outcome: deny, match: {kind: [read]}}\n"
    )
    assert codes(project, HEAD + rules) == [("duplicate-rule", "b"), ("conflicting-rules", "c")]


def test_disabled_rules_are_reported_but_not_compared(project: Project) -> None:
    rules = "rules:\n  - {id: a, outcome: allow, match: {kind: [read]}}\n  - {id: b, outcome: allow, enabled: false, match: {kind: [read]}}\n"
    assert codes(project, HEAD + rules) == [("disabled-rule", "b")]


def test_unused_declarations(project: Project) -> None:
    decls = (
        "schema: cpl.declarations/1.0\nparameters:\n  used: {type: integer, default: 1}\n  spare: {type: integer, default: 2}\n"
        "constants:\n  k: {type: integer, value: 3}\n"
        "tables:\n  t: {key: string, value: integer, rows: {a: 1}}\n"
    )
    text = HEAD + "rules:\n  - {id: r, outcome: allow, when: {expr: 'arguments.n <= param.used'}}\n"
    found = [(f.code, f.message) for f in lint(project.policy(text, decls=decls))]
    assert sorted(found) == [
        ("unused-declaration", "const 'k' is declared but never used"),
        ("unused-declaration", "param 'spare' is declared but never used"),
        ("unused-declaration", "table 't' is declared but never used"),
    ]


def test_declarations_used_by_other_declarations_are_not_reported(project: Project) -> None:
    decls = (
        "schema: cpl.declarations/1.0\nparameters:\n  base: {type: integer, default: 1}\n"
        "computed:\n  double: {type: integer, expr: 'param.base * 2'}\n"
    )
    text = HEAD + "rules:\n  - {id: r, outcome: allow, when: {expr: 'computed.double > 1'}}\n"
    assert codes(project, text, decls=decls) == []


def test_lint_command(tmp_path: Path) -> None:
    policy = tmp_path / "p.policy.yaml"
    policy.write_text(
        HEAD + "strategy: first_match\nrules:\n  - {id: all, outcome: allow}\n  - {id: late, outcome: deny}\n", "utf-8"
    )
    plain = runner.invoke(app, ["policy", "lint", str(policy)])
    assert plain.exit_code == 0 and "unreachable-rule" in plain.output
    strict = runner.invoke(app, ["policy", "lint", str(policy), "--strict", "--json"])
    body = json.loads(strict.output)
    assert strict.exit_code == 1 and body["result"] == "WARNINGS" and body["findings"][0]["rule"] == "late"
    bad = tmp_path / "bad.policy.yaml"
    bad.write_text(HEAD + "rules:\n  - {id: r, outcome: nope}\n", "utf-8")
    assert runner.invoke(app, ["policy", "lint", str(bad)]).exit_code == 1
    clean = tmp_path / "clean.policy.yaml"
    clean.write_text(HEAD + "rules: []\n", "utf-8")
    assert runner.invoke(app, ["policy", "lint", str(clean)]).output.strip() == "no findings"


class TestLint:
    def test_an_identical_rule_after_the_first_is_unreachable_under_first_match(self, project: Project) -> None:
        from cplang.lint import lint

        text = (
            BARE_HEAD
            + "default: allow\nstrategy: first_match\nrules:\n"
            + "  - {id: a, outcome: deny, match: {kind: [x]}}\n  - {id: b, outcome: allow, match: {kind: [x]}}\n"
        )
        findings = lint(project.policy(text))
        assert [(f.code, f.rule) for f in findings if f.code == "unreachable-rule"] == [("unreachable-rule", "b")]
