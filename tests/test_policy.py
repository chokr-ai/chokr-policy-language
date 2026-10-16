"""Policy documents: strict validation, positions, policy sets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.conftest import BARE_HEAD, DENY_DEFAULT, Project, authoring_code, policy_error

from cplang import AuthoringError, CplLimits, load_policy

BASE = """
cpl: "1.0"
id: pol
version: 1
default: deny
"""


def rules(*rule_blocks: str) -> str:
    return BASE + "rules:\n" + "".join(rule_blocks)


R_OK = """
  - id: r1
    match: {kind: [tool_call]}
    outcome: allow
"""


def load_error(project: Project, text: str, **kw: Any) -> AuthoringError:
    with pytest.raises(AuthoringError) as e:
        project.policy(text, **kw)
    return e.value


class TestValidation:
    def test_minimal_policy_loads(self, project: Project) -> None:
        p = project.policy(BASE)
        assert (p.id, p.default, p.strategy, p.mode, p.rules) == ("pol", "deny", "deny_overrides", "enforce", [])
        assert p.fingerprint.startswith("sha256:")

    @pytest.mark.parametrize(
        "text,code,line",
        [
            (BASE + "bogus: 1\n", "SCHEMA_INVALID", 5),
            ('schema_version: "2.0"\nid: x\n', "SCHEMA_INVALID", 1),
            ('cpl: "1.0"\n', "SCHEMA_INVALID", 1),
            (BASE.replace("default: deny", "default: maybe"), "SCHEMA_INVALID", 4),
            (BASE + "strategy: random\n", "SCHEMA_INVALID", 5),
            (BASE + "mode: shadow\n", "SCHEMA_INVALID", 5),
            (BASE + "rules: nope\n", "SCHEMA_INVALID", 5),
            (rules("  - {outcome: allow}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: permit}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, color: red}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, priority: high}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: 'bad id!', outcome: allow}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, when: {'bogus key': 1}}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, when: {kind: {frobnicate: 1}}}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, when: [a]}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, when: {kind: {}}}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: ask}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: modify}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, modify: {apply_suggested: true}}\n"), "SCHEMA_INVALID", 6),
            (rules("  - {id: r, outcome: allow, match: {var.x: [a]}}\n"), "DECLARATION_UNKNOWN_NAME", 6),
        ],
    )
    def test_rejected_with_a_line(self, project: Project, text: str, code: str, line: int) -> None:
        err = load_error(project, text)
        assert (err.code, err.line) == (code, line)

    def test_duplicate_rule_id(self, project: Project) -> None:
        err = load_error(project, rules(R_OK, R_OK))
        assert err.code == "DECLARATION_CONFLICT" and err.line == 11

    def test_duplicate_yaml_key_anchor_and_tag(self, project: Project) -> None:
        for text in (
            BASE + "id: again\n",
            BASE + "x: &a 1\n",
            BASE + "x: !tag 1\n",
            BASE + "x: .inf\n",
            BASE + "<<: {a: 1}\n",
        ):
            assert load_error(project, text).code == "SCHEMA_INVALID"

    def test_admission_keys_are_requirements_not_gates(self, project: Project) -> None:
        for where in (
            "any: [{deny: {arguments.n: 1}}]",
            "all: [{deny: {arguments.n: 1}}]",
            "not: {deny: {arguments.n: 1}}",
        ):
            text = rules(f"  - {{id: r, outcome: allow, when: {{{where}}}}}\n")
            assert load_error(project, text).code == "SCHEMA_INVALID"

    def test_ask_needs_an_approval_block(self, project: Project) -> None:
        text = rules("  - {id: r, outcome: allow, when: {thresholds: [{path: arguments.n, gt: 5, outcome: ask}]}}\n")
        assert load_error(project, text).code == "SCHEMA_INVALID"
        ok = rules(
            "  - {id: r, outcome: allow, when: {thresholds: [{path: arguments.n, gt: 5, outcome: ask}], "
            "approval: {timeout_seconds: 60}}}\n"
        )
        assert project.policy(ok).rules[0].admission.approval == {"timeout_seconds": 60, "on_timeout": "deny"}

    @pytest.mark.parametrize(
        "approval",
        [
            "{timeout_seconds: 0}",
            "{timeout_seconds: 60, on_timeout: allow}",
            "{timeout_seconds: 60, on_timeout: nope}",
            "{timeout_seconds: 60, fatigue_threshold: 5}",
            "{timeout_seconds: 60, fatigue_threshold: 0, fatigue_window_seconds: 5}",
            "{on_timeout: deny}",
            "{timeout_seconds: 60, extra: 1}",
        ],
    )
    def test_approval_validation(self, project: Project, approval: str) -> None:
        text = rules(f"  - {{id: r, outcome: ask, when: {{approval: {approval}}}}}\n")
        assert load_error(project, text).code == "SCHEMA_INVALID"

    def test_escalate_and_fatigue_are_accepted(self, project: Project) -> None:
        text = rules(
            "  - {id: r, outcome: ask, when: {approval: {timeout_seconds: 9, on_timeout: escalate, "
            "fatigue_threshold: 5, fatigue_window_seconds: 600}}}\n"
        )
        assert project.policy(text).rules[0].admission.approval["on_timeout"] == "escalate"

    def test_limits_on_entries(self, project: Project) -> None:
        rows = ", ".join("{path: arguments.n, gt: 1, outcome: watch}" for _ in range(65))
        assert (
            load_error(project, rules(f"  - {{id: r, outcome: allow, when: {{thresholds: [{rows}]}}}}\n")).code
            == "SCHEMA_INVALID"
        )
        ok = ", ".join("{path: arguments.n, gt: 1, outcome: watch}" for _ in range(64))
        project.policy(rules(f"  - {{id: r, outcome: allow, when: {{thresholds: [{ok}]}}}}\n"))

    def test_params_must_be_declared(self, project: Project) -> None:
        assert load_error(project, BASE + "params: {nope: 1}\n").code == "DECLARATION_UNKNOWN_NAME"

    def test_disabled_rules_are_still_validated(self, project: Project) -> None:
        text = rules("  - {id: r, outcome: nope, enabled: false}\n")
        assert load_error(project, text).code == "SCHEMA_INVALID"

    def test_expression_errors_are_located(self, project: Project) -> None:
        text = rules('  - id: r\n    outcome: allow\n    when: {expr: "1 +"}\n')
        err = load_error(project, text)
        assert err.code == "EXPRESSION_SYNTAX" and err.line == 8

    def test_type_error_in_a_rule_is_a_load_error(self, project: Project) -> None:
        text = rules('  - {id: r, outcome: allow, when: {expr: "\\"a\\" == 1"}}\n')
        assert load_error(project, text).code == "TYPE_ERROR"

    def test_reasons(self, project: Project) -> None:
        ok = rules("  - {id: r, outcome: deny, reason: ACTION_FORBIDDEN}\n")
        assert project.policy(ok).warnings == []
        bare = rules("  - {id: r, outcome: deny, reason: MY_CODE}\n")
        assert load_error(project, bare).code == "VOCABULARY_UNKNOWN_VALUE"
        custom = rules("  - {id: r, outcome: deny, reason: acme/OVER_LIMIT}\n")
        p = project.policy(custom)
        assert [w["code"] for w in p.warnings] == ["VOCABULARY_UNKNOWN_VALUE"] and p.warnings[0]["line"] == 6
        assert load_error(project, custom, strict=True).code == "VOCABULARY_UNKNOWN_VALUE"
        decl = "schema: cpl.declarations/1.0\nnamespace: acme\nreason_codes: {OVER_LIMIT: {}}\n"
        assert project.policy(custom, decls=decl, strict=True).warnings == []

    def test_explain_placeholders(self, project: Project) -> None:
        bad = rules("  - {id: r, outcome: deny, explain: 'x {nothere.y}'}\n")
        assert load_error(project, bad, strict_inputs=True).code == "SCHEMA_INVALID"
        project.policy(bad)
        bad_signal = rules("  - {id: r, outcome: deny, explain: 'x {signal.bogus}'}\n")
        assert load_error(project, bad_signal).code == "SCHEMA_INVALID"
        project.policy(rules("  - {id: r, outcome: deny, explain: 'ok {{literal}} {target.name} {signal.code}'}\n"))

    def test_rule_without_when_or_match_matches_everything(self, project: Project) -> None:
        p = project.policy(rules("  - {id: r, outcome: allow}\n"))
        assert p.rules[0].match is None


class TestPolicySets:
    def test_root_plus_fragments_sorted_by_path(self, project: Project) -> None:
        root = project.write("a.policy.yaml", rules(R_OK))
        frag = project.write("b.rules.yaml", 'cpl: "1.0"\nfragment: true\nrules:\n  - {id: f1, outcome: deny}\n')
        p = load_policy([frag, root], roots=[project.root])
        assert [r.id for r in p.rules] == ["r1", "f1"]
        assert len(p.files) == 2

    def test_zero_or_two_roots_are_refused(self, project: Project) -> None:
        a = project.write("a.policy.yaml", BASE)
        b = project.write("b.policy.yaml", BASE.replace("id: pol", "id: pol2"))
        with pytest.raises(AuthoringError, match="exactly one"):
            load_policy([a, b], roots=[project.root])
        frag = project.write("f.rules.yaml", 'cpl: "1.0"\nfragment: true\nrules: []\n')
        with pytest.raises(AuthoringError, match="exactly one"):
            load_policy([frag], roots=[project.root])
        with pytest.raises(AuthoringError):
            load_policy([], roots=[project.root])

    def test_rule_id_collision_across_files(self, project: Project) -> None:
        root = project.write("a.policy.yaml", rules(R_OK))
        frag = project.write("b.rules.yaml", 'cpl: "1.0"\nfragment: true\nrules:\n  - {id: r1, outcome: deny}\n')
        with pytest.raises(AuthoringError) as e:
            load_policy([root, frag], roots=[project.root])
        assert e.value.code == "DECLARATION_CONFLICT"

    def test_fragment_cannot_set_default_strategy_or_mode(self, project: Project) -> None:
        root = project.write("a.policy.yaml", BASE)
        frag = project.write("b.rules.yaml", 'cpl: "1.0"\nfragment: true\ndefault: allow\nrules: []\n')
        with pytest.raises(AuthoringError):
            load_policy([root, frag], roots=[project.root])

    def test_imported_fragment_with_alias_prefixes_ids(self, project: Project) -> None:
        project.write("base.rules.yaml", 'cpl: "1.0"\nfragment: true\nrules:\n  - {id: deny-all, outcome: deny}\n')
        root = project.write("a.policy.yaml", BASE + "imports:\n  - {from: ./base.rules.yaml, as: base}\n")
        p = load_policy([root], roots=[project.root])
        assert [r.id for r in p.rules] == ["base.deny-all"]

    def test_policy_level_declaration_import_and_params(self, project: Project) -> None:
        project.write(
            "lib.decl.yaml",
            "schema: cpl.declarations/1.0\nparameters:\n  cap: {type: integer, default: 1}\n"
            'conditions:\n  big: {when: {expr: "arguments.n > param.cap"}}\n',
        )
        text = BASE + (
            "imports:\n  - {from: ./lib.decl.yaml}\nparams: {cap: 10}\nrules:\n"
            "  - {id: r, outcome: deny, when: {use: big}}\n"
        )
        p = project.policy(text)
        assert p.decls.resolved_params["cap"] == 10 and p.rules[0].gate is not None

    def test_vocabulary_shorthand(self, project: Project) -> None:
        project.write("v.decl.yaml", "schema: cpl.declarations/1.0\nnamespace: acme\nreason_codes: {X: {}}\n")
        p = project.policy(BASE + "vocabulary: ./v.decl.yaml\n")
        assert "acme/X" in p.decls.open_values["reason_codes"]
        with pytest.raises(AuthoringError):
            project.policy(BASE + "vocabulary: ./v.decl.yaml\nimports: []\n", name="q.policy.yaml")


class TestFingerprint:
    TEXT = rules("  - {id: r, outcome: deny, description: first, when: {kind: [a]}}\n")

    def test_stable_under_comments_key_order_and_description(self, project: Project) -> None:
        a = project.policy(self.TEXT).fingerprint
        reordered = (
            'id: pol\ncpl: "1.0"\n# a comment\ndefault: deny\nversion: 1\nrules:\n'
            "  - {outcome: deny, when: {kind: [a]}, id: r, description: totally different text}\n"
        )
        assert project.policy(reordered, name="o.policy.yaml").fingerprint == a

    @pytest.mark.parametrize(
        "change",
        [
            lambda t: t.replace("kind: [a]", "kind: [b]"),
            lambda t: t.replace("outcome: deny", "outcome: allow"),
            lambda t: t.replace("version: 1", "version: 2"),
            lambda t: t.replace("default: deny", "default: allow"),
            lambda t: t.replace("id: r,", "id: r2,"),
            lambda t: t + "  - {id: extra, outcome: allow}\n",
        ],
    )
    def test_changes_with_semantics(self, project: Project, change: Any) -> None:
        assert (
            project.policy(change(self.TEXT), name="c.policy.yaml").fingerprint != project.policy(self.TEXT).fingerprint
        )

    def test_changes_with_declarations_params_and_vocabulary_version(self, project: Project) -> None:
        decl = "schema: cpl.declarations/1.0\nversion: 1\nparameters:\n  cap: {type: integer, default: 1}\n"
        a = project.policy(self.TEXT, decls=decl).fingerprint
        assert project.policy(self.TEXT, decls=decl.replace("version: 1", "version: 2")).fingerprint != a
        assert project.policy(self.TEXT, decls=decl, config_params=[{"cap": 2}]).fingerprint != a
        assert project.policy(self.TEXT, decls=decl).fingerprint == a

    def test_changes_with_a_table_digest(self, project: Project) -> None:
        project.write("t.csv", "key,value\na,1\n")
        decl = "schema: cpl.declarations/1.0\ntables:\n  t: {key: string, value: integer, source: ./t.csv}\n"
        a = project.policy(self.TEXT, decls=decl).fingerprint
        project.write("t.csv", "key,value\na,2\n")
        assert project.policy(self.TEXT, decls=decl).fingerprint != a

    def test_json_policy_has_the_same_fingerprint_as_yaml(self, project: Project) -> None:
        yaml_fp = project.policy(self.TEXT).fingerprint
        json_text = (
            '{"cpl": "1.0", "id": "pol", "version": 1, "default": "deny", "rules": [{"id": "r", '
            '"outcome": "deny", "when": {"kind": ["a"]}}]}'
        )
        assert project.policy(json_text, name="j.policy.json").fingerprint == yaml_fp


def test_load_from_a_path_object(project: Project) -> None:
    path: Path = project.write("x.policy.yaml", BASE)
    assert load_policy([path], roots=[project.root]).id == "pol"


class TestImports:
    def test_imports_inside_an_imported_fragment_are_loaded(self, project: Project) -> None:
        frag = 'cpl: "1.0"\nfragment: true\n'
        project.write("f2.policy.yaml", frag + "rules:\n  - {id: from-f2, outcome: deny}\n")
        project.write("f1.policy.yaml", frag + "imports:\n  - {from: f2.policy.yaml}\nrules: []\n")
        root = project.policy(BARE_HEAD + "default: allow\nimports:\n  - {from: f1.policy.yaml}\nrules: []\n")
        assert [r.id for r in root.rules] == ["from-f2"]

    def test_a_fragment_imported_twice_is_loaded_once(self, project: Project) -> None:
        frag = 'cpl: "1.0"\nfragment: true\n'
        project.write("shared.policy.yaml", frag + "rules:\n  - {id: shared, outcome: deny}\n")
        project.write("a.policy.yaml", frag + "imports:\n  - {from: shared.policy.yaml}\nrules: []\n")
        root = project.policy(
            BARE_HEAD
            + "default: allow\nimports:\n  - {from: a.policy.yaml}\n  - {from: shared.policy.yaml}\nrules: []\n"
        )
        assert [r.id for r in root.rules] == ["shared"]

    def test_a_named_condition_cannot_be_defined_twice(self, project: Project) -> None:
        cond = "conditions:\n  is_admin: {when: {actor.role: admin}}\n"
        project.write("f.policy.yaml", 'cpl: "1.0"\nfragment: true\n' + cond + "rules: []\n")
        text = BARE_HEAD + "default: allow\nimports:\n  - {from: f.policy.yaml}\n" + cond + "rules: []\n"
        assert authoring_code(lambda: project.policy(text)) == "DECLARATION_CONFLICT"


class TestFingerprintCoverage:
    RATE = DENY_DEFAULT + "  - {id: r, outcome: allow, when: {max_calls_per_window: {}}}\n"

    def test_the_rate_default_changes_the_fingerprint(self, project: Project) -> None:
        a = project.policy(self.RATE, default_rate=(10, 60)).fingerprint
        b = project.policy(self.RATE, default_rate=(20, 60)).fingerprint
        assert a != b

    def test_a_limit_that_changes_decisions_changes_the_fingerprint(self, project: Project) -> None:
        text = DENY_DEFAULT + "  - {id: r, outcome: allow}\n"
        assert project.policy(text).fingerprint != project.policy(text, limits=CplLimits(max_eval_steps=5)).fingerprint


class TestMalformedPolicies:
    @pytest.mark.parametrize(
        "extra",
        [
            "conditions:\n  c: 5\nrules: []\n",
            "params: [1]\nrules: []\n",
            "rules:\n  - {id: r, outcome: allow, when: []}\n",
            "rules:\n  - {id: r, outcome: allow, when: 0}\n",
            "risk_tiers:\n  - {id: a, when: {kind: x}}\n  - {id: a, when: {kind: y}}\nrules: []\n",
            "rules:\n  - {id: r, outcome: allow, when: {expr: 'arguments.n > 99999999999999999999'}}\n",
            "rules:\n  - {id: r, outcome: allow, when: {arguments.n: {gt: 1e1000000}}}\n",
        ],
    )
    def test_each_is_an_authoring_error_not_a_raw_exception(self, project: Project, extra: str) -> None:
        with pytest.raises(AuthoringError):
            project.policy(BARE_HEAD + "default: deny\n" + extra)

    @pytest.mark.parametrize("version", ["[1]", "true", "null", '""'])
    def test_version_is_an_integer_or_a_string(self, project: Project, version: str) -> None:
        text = f'cpl: "1.0"\nid: p\nversion: {version}\nrules: []\n'
        assert policy_error(project, text) == "SCHEMA_INVALID"

    def test_an_empty_id_is_rejected(self, project: Project) -> None:
        assert policy_error(project, 'cpl: "1.0"\nid: ""\nrules: []\n') == "SCHEMA_INVALID"

    def test_a_rule_that_can_never_match_is_reported(self, project: Project) -> None:
        text = DENY_DEFAULT + "  - {id: r, outcome: allow, match: {kind: []}}\n"
        assert [w["code"] for w in project.policy(text).warnings] == ["RULE_NEVER_MATCHES"]
