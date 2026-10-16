"""The prover. Skipped when the optional `prove` extra (z3) is not installed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import Project, make_env, make_signal
from typer.testing import CliRunner

from cplang import RuleEvaluator
from cplang.cli import app
from cplang.profile import Profile

z3 = pytest.importorskip("z3")
from cplang.prove import prove  # noqa: E402

runner = CliRunner()
HARD = Profile(hard_signal_codes=frozenset({"scan.hard"}))
HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\n'


def doc(rules: str, extra: str = "") -> str:
    return HEAD + extra + "rules:\n" + rules


READ = '  - {id: reads, outcome: allow, match: {action_uri: ["app:read"]}}\n'
WRITE = '  - {id: writes, outcome: allow, match: {action_uri: ["app:write"]}}\n'


class TestBoundary:
    def test_a_subset_is_within_the_boundary(self, project: Project) -> None:
        cand = project.policy(doc(READ), name="c.policy.yaml")
        bound = project.policy(doc(READ + WRITE), name="b.policy.yaml")
        r = prove(cand, bound)
        assert (r.result, r.exit_code, r.counterexample) == ("within_boundary", 0, None)
        assert "action_uri" in r.coverage

    def test_one_added_permitted_action_is_found_and_replays(self, project: Project) -> None:
        cand = project.policy(doc(READ + WRITE), name="c.policy.yaml")
        bound = project.policy(doc(READ), name="b.policy.yaml")
        r = prove(cand, bound)
        assert (r.result, r.exit_code, r.reason_code) == ("exceeds_boundary", 1, "boundary_exceeded")
        ce = r.counterexample or {}
        assert ce["action"]["action_uri"] == "app:write"
        assert ce["outcome_candidate"] in ("allow", "watch", "modify") and ce["outcome_boundary"] == "deny"
        # replay on the real evaluators (the model-fidelity property)
        env = make_env(action_uri=ce["action"]["action_uri"])
        assert RuleEvaluator(cand).evaluate(env, []).outcome == "allow"
        assert RuleEvaluator(bound).evaluate(env, []).outcome == "deny"

    def test_numeric_limits(self, project: Project) -> None:
        cand = project.policy(
            doc("  - {id: r, outcome: allow, when: {arguments.n: {lte: 10}}}\n"), name="c.policy.yaml"
        )
        bound = project.policy(
            doc("  - {id: r, outcome: allow, when: {arguments.n: {lte: 5}}}\n"), name="b.policy.yaml"
        )
        r = prove(cand, bound)
        n = r.counterexample["action"]["arguments"]["n"]  # type: ignore[index]
        assert r.result == "exceeds_boundary" and 5 < n <= 10
        assert prove(bound, cand).result == "within_boundary"

    def test_strings_globs_and_membership(self, project: Project) -> None:
        cand = project.policy(
            doc("  - {id: r, outcome: allow, match: {target.name: ['db*']}, when: {environment.env: [prod, dev]}}\n"),
            name="c.policy.yaml",
        )
        bound = project.policy(
            doc("  - {id: r, outcome: allow, match: {target.name: ['db*']}, when: {environment.env: [dev]}}\n"),
            name="b.policy.yaml",
        )
        r = prove(cand, bound)
        assert r.result == "exceeds_boundary" and r.counterexample["action"]["environment"]["env"] == "prod"  # type: ignore[index]
        assert r.counterexample["action"]["target"]["name"].startswith("db")  # type: ignore[index]

    def test_absent_never_matches_so_it_cannot_exceed(self, project: Project) -> None:
        cand = project.policy(doc("  - {id: r, outcome: allow, when: {arguments.n: {ne: 5}}}\n"), name="c.policy.yaml")
        bound = project.policy(
            doc("  - {id: r, outcome: allow, when: {arguments.n: {exists: true}}}\n"), name="b.policy.yaml"
        )
        assert prove(cand, bound).result == "within_boundary"  # `ne` on an absent field does not match

    def test_deny_overrides_wins_and_reordering_does_not_change_the_result(self, project: Project) -> None:
        deny = '  - {id: d, outcome: deny, match: {action_uri: ["app:write"]}}\n'
        a = project.policy(doc(READ + WRITE + deny), name="a.policy.yaml")
        b = project.policy(doc(deny + WRITE + READ), name="b.policy.yaml")
        bound = project.policy(doc(READ), name="bd.policy.yaml")
        ra, rb = prove(a, bound), prove(b, bound)
        assert ra.result == rb.result == "within_boundary"
        first = project.policy(doc(WRITE + deny, extra="strategy: first_match\n"), name="fm.policy.yaml")
        assert prove(first, bound).result == "exceeds_boundary"  # first_match lets the earlier allow win

    def test_priority_strategy(self, project: Project) -> None:
        text = doc(
            '  - {id: low, outcome: deny, priority: 1, match: {action_uri: ["app:read"]}}\n'
            '  - {id: high, outcome: allow, priority: 9, match: {action_uri: ["app:read"]}}\n',
            extra="strategy: priority\n",
        )
        cand = project.policy(text, name="c.policy.yaml")
        empty = project.policy(doc(""), name="e.policy.yaml")
        assert prove(cand, empty).result == "exceeds_boundary"

    def test_thresholds_and_default_allow(self, project: Project) -> None:
        cand = project.policy(
            doc(
                "  - id: r\n    outcome: allow\n    when:\n      thresholds:\n"
                "        - {path: arguments.n, gt: 10, outcome: deny}\n",
                extra="",
            ),
            name="c.policy.yaml",
        )
        wide = project.policy(HEAD.replace("default: deny", "default: allow") + "rules: []\n", name="w.policy.yaml")
        assert prove(cand, wide).result == "within_boundary"
        assert prove(wide, cand).result == "exceeds_boundary"

    def test_monitor_mode_is_permitted_by_design(self, project: Project) -> None:
        cand = project.policy(doc("  - {id: r, outcome: deny, mode: monitor}\n"), name="c.policy.yaml")
        empty = project.policy(doc(""), name="e.policy.yaml")
        assert prove(cand, empty).result == "exceeds_boundary"


class TestHonestLimits:
    @pytest.mark.parametrize(
        "when",
        [
            "expr: 'matches(arguments.s, \"a+\")'",
            "arguments.s: {regex: 'a+'}",
            "arguments.s: {glob: 'a*', case_insensitive: true}",
            "signal: {code_prefix: 'sql.'}",
            "time.window: {from: '01:00', to: '02:00'}",
        ],
    )
    def test_unmodeled_shapes_are_unsupported_never_guessed(self, project: Project, when: str) -> None:
        cand = project.policy(doc(f"  - {{id: r, outcome: allow, when: {{{when}}}}}\n"), name="c.policy.yaml")
        bound = project.policy(doc(READ), name="b.policy.yaml")
        r = prove(cand, bound)
        assert (r.result, r.exit_code) == ("unsupported", 3) and r.reason_code and r.detail

    def test_a_type_conflict_is_unsupported(self, project: Project) -> None:
        cand = project.policy(
            doc(
                "  - {id: a, outcome: allow, when: {arguments.v: {gt: 1}}}\n"
                "  - {id: b, outcome: allow, when: {arguments.v: 'x'}}\n"
            ),
            name="c.policy.yaml",
        )
        assert prove(cand, project.policy(doc(READ), name="b.policy.yaml")).reason_code == "type_conflict"

    def test_too_many_rules_is_inconclusive(self, project: Project) -> None:
        many = "".join(f'  - {{id: r{i}, outcome: allow, match: {{action_uri: ["app:a{i}"]}}}}\n' for i in range(1025))
        big = project.policy(doc(many), name="big.policy.yaml")
        small = project.policy(doc(READ), name="s.policy.yaml")
        r = prove(big, small)
        assert (r.result, r.reason_code, r.exit_code) == ("inconclusive", "resource_limit", 3)
        assert prove(small, small, max_rules=1).result == "within_boundary"
        assert prove(big, small, max_rules=1025).reason_code != "resource_limit"

    def test_a_timeout_is_inconclusive(self, project: Project) -> None:
        cand = project.policy(doc(READ + WRITE), name="c.policy.yaml")
        bound = project.policy(doc(READ), name="b.policy.yaml")
        r = prove(cand, bound, timeout_ms=1)
        assert r.result in ("exceeds_boundary", "inconclusive")  # a trivial instance may beat 1 ms


class TestNoBypassAndDiff:
    def test_hard_deny_signals_cannot_be_bypassed_in_enforce_mode(self, project: Project) -> None:
        allow_all = project.policy(doc("  - {id: all, outcome: allow}\n"), name="a.policy.yaml", profile=HARD)
        r = prove(allow_all, allow_all, mode="no_bypass")
        assert r.result == "within_boundary"

    def test_document_monitor_mode_is_reported_as_a_bypass(self, project: Project) -> None:
        mon = project.policy(
            doc("  - {id: all, outcome: allow}\n", extra="mode: monitor\n"), name="m.policy.yaml", profile=HARD
        )
        r = prove(mon, mon, mode="no_bypass")
        assert r.result == "exceeds_boundary" and r.reason_code == "hard_deny_bypassed"
        assert r.counterexample["signals"]  # type: ignore[index]

    def test_diff_lists_what_a_change_newly_permits(self, project: Project) -> None:
        old = project.policy(doc(READ), name="o.policy.yaml")
        new = project.policy(doc(READ + WRITE), name="n.policy.yaml")
        r = prove(new, old, mode="diff")
        assert r.result == "exceeds_boundary" and r.counterexample["action"]["action_uri"] == "app:write"  # type: ignore[index]
        assert prove(old, new, mode="diff").result == "within_boundary"


class TestCli:
    def write(self, tmp_path: Path, name: str, text: str) -> Path:
        p = tmp_path / name
        p.write_text(text, "utf-8", newline="\n")
        return p

    def test_json_exit_codes_and_fixture_emission(self, tmp_path: Path) -> None:
        cand = self.write(tmp_path, "cand.policy.yaml", doc(READ + WRITE))
        bound = self.write(tmp_path, "bound.policy.yaml", doc(READ))
        out = tmp_path / "fx"
        r = runner.invoke(
            app,
            [
                "policy",
                "prove",
                "--candidate",
                str(cand),
                "--boundary",
                str(bound),
                "--json",
                "--emit-fixture",
                str(out),
            ],
        )
        body: dict[str, Any] = json.loads(r.output)
        assert r.exit_code == 1 and body["result"] == "exceeds_boundary" and body["counterexample"]["action"]
        fixtures = list(out.glob("*.fixtures.json"))
        assert len(fixtures) == 1
        again = runner.invoke(app, ["test", "--policy", str(cand), "--fixtures", str(fixtures[0])])
        assert again.exit_code == 0, again.output  # the counterexample is a regression test
        ok = runner.invoke(app, ["policy", "prove", "--candidate", str(bound), "--boundary", str(cand)])
        assert ok.exit_code == 0 and "within_boundary" in ok.output

    def test_modes_and_errors(self, tmp_path: Path) -> None:
        old = self.write(tmp_path, "old.policy.yaml", doc(READ))
        new = self.write(tmp_path, "new.policy.yaml", doc(READ + WRITE))
        assert runner.invoke(app, ["policy", "prove", "--diff", str(old), str(new)]).exit_code == 1
        assert runner.invoke(app, ["policy", "prove"]).exit_code == 2
        bad = self.write(tmp_path, "bad.policy.yaml", doc("  - {id: x, outcome: nope}\n"))
        assert runner.invoke(app, ["policy", "prove", "--candidate", str(bad), "--boundary", str(bad)]).exit_code == 2


def test_the_signal_helper_is_importable() -> None:
    assert make_signal


class TestSoundness:
    def test_paths_that_differ_only_by_dot_or_underscore_are_separate_variables(self, project: Project) -> None:
        cand = project.policy(
            doc("  - {id: r, outcome: allow, when: {arguments.a.b: x, arguments.a_b: y}}\n"), name="c.policy.yaml"
        )
        bound = project.policy(
            doc("  - {id: r, outcome: allow, when: {arguments.a.b: x, arguments.a_b: x}}\n"), name="b.policy.yaml"
        )
        assert prove(cand, bound).result == "exceeds_boundary"

    def test_signal_codes_that_differ_only_by_dot_or_underscore_are_separate(self, project: Project) -> None:
        cand = project.policy(
            doc("  - {id: r, outcome: allow, when: {all: [{signal: {code: a.b}}, {signal: {code: a_b}}]}}\n"),
            name="c.policy.yaml",
        )
        bound = project.policy(doc(READ), name="b.policy.yaml")
        assert prove(cand, bound).result == "exceeds_boundary"

    def test_overlapping_modify_rules_are_not_modeled(self, project: Project) -> None:
        mod = "  - {id: %s, outcome: modify, modify: {edits: [{op: redact, json_pointer: /arguments/x}]}}\n"
        cand = project.policy(doc(mod % "m1" + mod % "m2"), name="c.policy.yaml")
        bound = project.policy(doc(READ), name="b.policy.yaml")
        assert prove(cand, bound).result == "unsupported"

    def test_a_clean_proof_states_what_it_assumes(self, project: Project) -> None:
        cand = project.policy(doc(READ), name="c.policy.yaml")
        bound = project.policy(doc(READ + WRITE), name="b.policy.yaml")
        assert "well-typed" in (prove(cand, bound).detail or "")
