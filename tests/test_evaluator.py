"""Evaluation semantics."""

from __future__ import annotations

import itertools
import threading
from decimal import Decimal
from typing import Any

import pytest
from tests.conftest import ALLOW_DEFAULT, BARE_HEAD, DENY_DEFAULT, Project, at, make_env, make_signal, outcome_of

from cplang import Action, RuleEvaluator, Signal
from cplang.ratelimit import InMemoryRateLimiter

HEAD = 'cpl: "1.0"\nid: pol\nversion: 1\n'


def doc(rules_text: str, *, default: str = "deny", extra: str = "") -> str:
    return HEAD + f"default: {default}\n{extra}rules:\n{rules_text}"


APPROVAL = "approval: {timeout_seconds: 60}"


class TestResolution:
    RULES = {
        "allow": "  - {id: r-allow, outcome: allow, match: {kind: [tool_call]}}\n",
        "watch": "  - {id: r-watch, outcome: watch, match: {kind: [tool_call]}}\n",
        "modify": (
            "  - {id: r-modify, outcome: modify, match: {kind: [tool_call]}, modify: "
            "{edits: [{op: redact, json_pointer: /a}]}}\n"
        ),
        "ask": f"  - {{id: r-ask, outcome: ask, match: {{kind: [tool_call]}}, when: {{{APPROVAL}}}}}\n",
        "deny": "  - {id: r-deny, outcome: deny, match: {kind: [tool_call]}}\n",
    }
    ORDER = ["allow", "watch", "modify", "ask", "deny"]  # weakest to strongest

    @pytest.mark.parametrize("a,b", list(itertools.combinations(ORDER, 2)))
    def test_strictest_wins_for_every_pair(self, project: Project, a: str, b: str) -> None:
        for first, second in ((a, b), (b, a)):
            ev = project.evaluator(doc(self.RULES[first] + self.RULES[second]))
            v = ev.evaluate(make_env({"a": 1}), [])
            assert v.outcome == b, (first, second)

    def test_no_match_uses_the_default(self, project: Project) -> None:
        for default in ("deny", "allow"):
            ev = project.evaluator(doc(self.RULES["allow"].replace("tool_call", "other"), default=default))
            v = ev.evaluate(make_env(), [])
            assert outcome_of(v) == (default, ["NO_MATCHING_RULE"]) and v.matched_rules == []

    def test_all_allow_is_policy_satisfied(self, project: Project) -> None:
        v = project.evaluator(doc(self.RULES["allow"])).evaluate(make_env(), [])
        assert outcome_of(v) == ("allow", ["POLICY_SATISFIED"])

    def test_reordering_rules_never_changes_the_verdict(self, project: Project) -> None:
        env = make_env({"a": 1})
        verdicts = set()
        for i, order in enumerate(itertools.permutations(self.ORDER)):
            ev = project.evaluator(doc("".join(self.RULES[k] for k in order)), name=f"p{i}.policy.yaml")
            v = ev.evaluate(env, [])
            wire = v.to_wire()
            for volatile in ("verdict_id", "latency_ms"):
                wire.pop(volatile, None)
            wire["policy"].pop("fingerprint")
            verdicts.add(repr(sorted(wire.items(), key=lambda kv: kv[0])))
            if i > 40:
                break
        assert len(verdicts) == 1

    def test_matched_rules_reasons_and_codes_are_canonical(self, project: Project) -> None:
        ev = project.evaluator(doc(self.RULES["deny"] + self.RULES["allow"] + self.RULES["watch"]))
        v = ev.evaluate(make_env(), [])
        assert v.matched_rules == ["r-allow", "r-deny", "r-watch"]
        assert v.reason_codes == ["RULE_DENY", "POLICY_ADVISORY", "POLICY_SATISFIED"]
        assert [r["source"] for r in v.reasons] == ["rule:r-deny", "rule:r-watch", "rule:r-allow"]

    def test_first_match_stops_at_the_first_matching_rule(self, project: Project) -> None:
        text = doc(self.RULES["allow"] + self.RULES["deny"], extra="strategy: first_match\n")
        v = project.evaluator(text).evaluate(make_env(), [])
        assert (v.outcome, v.matched_rules) == ("allow", ["r-allow"])
        reverse = doc(self.RULES["deny"] + self.RULES["allow"], extra="strategy: first_match\n")
        assert project.evaluator(reverse, name="q.policy.yaml").evaluate(make_env(), []).outcome == "deny"

    def test_priority_strategy(self, project: Project) -> None:
        rules = (
            "  - {id: low, outcome: deny, priority: 1, match: {kind: [tool_call]}}\n"
            "  - {id: high, outcome: allow, priority: 10, match: {kind: [tool_call]}}\n"
            "  - {id: tie-a, outcome: deny, match: {kind: [tool_call]}}\n"
        )
        v = project.evaluator(doc(rules, extra="strategy: priority\n")).evaluate(make_env(), [])
        assert (v.outcome, v.matched_rules) == ("allow", ["high"])
        ties = (
            "  - {id: a, outcome: deny, match: {kind: [tool_call]}}\n"
            "  - {id: b, outcome: allow, match: {kind: [tool_call]}}\n"
        )
        v2 = project.evaluator(doc(ties, extra="strategy: priority\n"), name="t.policy.yaml").evaluate(make_env(), [])
        assert v2.matched_rules == ["a"]  # a tie keeps declared order

    def test_disabled_rules_never_contribute(self, project: Project) -> None:
        text = doc("  - {id: off, outcome: deny, enabled: false}\n" + self.RULES["allow"])
        assert project.evaluator(text).evaluate(make_env(), []).outcome == "allow"

    def test_signals_order_does_not_change_the_verdict(self, project: Project) -> None:
        rules = (
            "  - {id: a, outcome: deny, when: {signal: {code: loop.one}}, explain: '{signal.source}'}\n"
            "  - {id: b, outcome: deny, when: {signal: {code: loop.two}}}\n"
        )
        ev = project.evaluator(doc(rules))
        env = make_env()
        s1, s2 = make_signal(env, "loop.one", source="g1"), make_signal(env, "loop.one", source="g0")
        wires = [ev.evaluate(env, order).to_wire() for order in ([s1, s2], [s2, s1])]
        for w in wires:
            w.pop("verdict_id")
        assert wires[0] == wires[1] and wires[0]["explanation"] == "g0"


class TestHardDenyAndMonitor:
    def test_monitor_downgrades_blocking_outcomes_to_watch(self, project: Project) -> None:
        for outcome, extra in (("deny", ""), ("ask", f", when: {{{APPROVAL}}}")):
            text = doc(f"  - {{id: r, outcome: {outcome}, mode: monitor{extra}}}\n")
            v = project.evaluator(text, name=f"{outcome}.policy.yaml").evaluate(make_env(), [])
            assert (v.outcome, v.would_block, v.would_have_been) == ("watch", True, outcome)
            assert v.reason_codes[0] == "MONITOR_WOULD_BLOCK"

    def test_monitor_modify_becomes_watch_without_edits(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: modify, mode: monitor, modify: {edits: [{op: redact, json_pointer: /a}]}}\n")
        v = project.evaluator(text).evaluate(make_env({"a": 1}), [])
        assert (v.outcome, v.would_block, v.modifications) == ("watch", False, None)

    def test_a_monitor_rule_does_not_weaken_an_enforce_rule(self, project: Project) -> None:
        text = doc("  - {id: m, outcome: deny, mode: monitor}\n  - {id: e, outcome: deny}\n")
        v = project.evaluator(text).evaluate(make_env(), [])
        assert (v.outcome, v.would_block) == ("deny", False)

    def test_would_have_been_is_the_strictest_suppressed(self, project: Project) -> None:
        text = doc(
            f"  - {{id: a, outcome: ask, mode: monitor, when: {{{APPROVAL}}}}}\n"
            "  - {id: b, outcome: deny, mode: monitor}\n"
        )
        v = project.evaluator(text).evaluate(make_env(), [])
        assert (v.outcome, v.would_have_been) == ("watch", "deny")

    def test_mode_precedence_rule_then_file_then_config(self, project: Project) -> None:
        text = doc("  - {id: a, outcome: deny}\n  - {id: b, outcome: deny, mode: enforce}\n")
        assert project.evaluator(text, rules_mode="monitor").policy.rules[0].mode == "monitor"
        assert project.evaluator(text, rules_mode="monitor").policy.rules[1].mode == "enforce"
        file_level = doc("  - {id: a, outcome: deny}\n", extra="mode: monitor\n")
        assert (
            project.evaluator(file_level, name="f.policy.yaml", rules_mode="enforce").policy.rules[0].mode == "monitor"
        )


def rule_with(when: str, outcome: str = "allow", extra: str = "") -> str:
    return doc(f"  - {{id: r, outcome: {outcome}, when: {{{when}}}{extra}}}\n")


class TestAdmission:
    def run(self, project: Project, when: str, env: Any = None, signals: list[Any] | None = None, **kw: Any) -> Any:
        env = env or make_env({"n": 5})
        ev = project.evaluator(rule_with(when), **kw)
        return ev.evaluate(env, signals if signals is not None else [])

    def test_deny_condition(self, project: Project) -> None:
        v = self.run(project, "deny: {arguments.n: {gt: 3}}")
        assert outcome_of(v) == ("deny", ["ACTION_FORBIDDEN"])
        assert self.run(project, "deny: {arguments.n: {gt: 30}}").outcome == "allow"
        assert self.run(project, "deny: {arguments.missing: {gt: 30}}").outcome == "deny"  # absent fails closed
        opt_out = "deny: {all: [{arguments.missing: {exists: true}}, {arguments.missing: {gt: 30}}]}"
        assert self.run(project, opt_out).outcome == "allow"  # an author can let an absent value pass explicitly

    def test_threshold_on_absent_value_trips(self, project: Project) -> None:
        when = "thresholds: [{outcome: deny, path: arguments.missing, gt: 4, reason: THRESHOLD_EXCEEDED}]"
        assert outcome_of(self.run(project, when)) == ("deny", ["THRESHOLD_EXCEEDED"])

    def test_parameters(self, project: Project) -> None:
        when = "immutable_params: {mode: safe}, bounded_params: {n: {min: 1, max: 10}}"
        assert self.run(project, when, make_env({"mode": "safe", "n": 10})).outcome == "allow"
        assert self.run(project, when, make_env({"mode": "safe", "n": 1})).outcome == "allow"  # inclusive
        assert self.run(project, when, make_env({"mode": "fast", "n": 5})).reason_codes == ["PARAM_IMMUTABLE_VIOLATION"]
        assert self.run(project, when, make_env({"mode": "safe", "n": 11})).reason_codes == ["PARAM_OUT_OF_BOUNDS"]
        assert self.run(project, when, make_env({"mode": "safe", "n": "5"})).reason_codes == ["PARAM_OUT_OF_BOUNDS"]
        assert self.run(project, when, make_env({"mode": "safe", "n": True})).reason_codes == ["PARAM_OUT_OF_BOUNDS"]
        assert self.run(project, when, make_env({"n": 5})).reason_codes == ["PARAM_IMMUTABLE_VIOLATION"]
        pointer = "bounded_params: {/a/b: {max: 3}}"
        assert self.run(project, pointer, make_env({"a": {"b": 3}})).outcome == "allow"
        assert self.run(project, pointer, make_env({"a": {"b": 4}})).reason_codes == ["PARAM_OUT_OF_BOUNDS"]

    def test_rate_limit_uses_check_live_and_peek_otherwise(self, project: Project) -> None:
        calls: list[str] = []

        class Spy(InMemoryRateLimiter):
            def check(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
                calls.append(f"check {key}")
                return super().check(key, limit, window_seconds, now_us=now_us)

            def peek(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
                calls.append("peek")
                return super().peek(key, limit, window_seconds, now_us=now_us)

        ev = project.evaluator(rule_with("max_calls_per_window: {limit: 2, window_seconds: 60}"), rate_limiter=Spy())
        results = [ev.evaluate(make_env(), []).reason_codes for _ in range(3)]
        assert results == [["POLICY_SATISFIED"], ["POLICY_SATISFIED"], ["RATE_LIMIT_EXCEEDED"]]
        assert calls == ["check pol/r/agent-1"] * 3
        calls.clear()
        verdict, _ = ev.trace(make_env(), [])
        assert verdict.reason_codes == ["RATE_LIMIT_EXCEEDED"] and calls == ["peek"]

    def test_rate_limit_defaults_and_errors(self, project: Project) -> None:
        class Broken:
            def check(self, *a: Any, **k: Any) -> bool:
                raise RuntimeError("down")

            peek = check

        ev = project.evaluator(rule_with("max_calls_per_window: {}"), rate_limiter=Broken())
        v = ev.evaluate(make_env(), [])
        assert v.outcome == "deny" and v.reason_codes == ["EVALUATION_ERROR"]
        assert v.reasons[0]["message"] == "RuntimeError"  # only the exception type name

    def test_rate_limit_window_slides(self, project: Project) -> None:
        ev = project.evaluator(rule_with("max_calls_per_window: {limit: 1, window_seconds: 10}"))
        first = make_env()
        assert ev.evaluate(first, []).outcome == "allow"
        assert ev.evaluate(first, []).outcome == "deny"
        later = at(first, "2026-01-01T12:00:11Z")
        assert ev.evaluate(later, []).outcome == "allow"

    def test_rule_reason_applies_at_steps_2_and_13_only(self, project: Project) -> None:
        env = make_env({"n": 5})
        text = doc("  - {id: r, outcome: deny, reason: ACTION_FORBIDDEN, when: {bounded_params: {n: {max: 1}}}}\n")
        v = project.evaluator(text).evaluate(env, [])
        assert v.reason_codes == ["PARAM_OUT_OF_BOUNDS"]  # step 7 ignores the rule reason
        text = doc("  - {id: r, outcome: deny, reason: RULE_ASK}\n")
        assert project.evaluator(text, name="x.policy.yaml").evaluate(env, []).reason_codes == ["RULE_ASK"]


class TestThresholds:
    def test_threshold_outcomes_and_default_reason(self, project: Project) -> None:
        ev = project.evaluator(
            doc(
                f"  - id: r\n    outcome: allow\n    when:\n      {APPROVAL}\n      thresholds:\n"
                "        - {path: arguments.n, gt: 100, outcome: deny}\n"
                "        - {path: arguments.n, gt: 10, outcome: ask}\n"
                "        - {path: arguments.n, gt: 5, outcome: watch, reason: acme/NOTICE}\n"
            )
        )
        assert outcome_of(ev.evaluate(make_env({"n": 500}), [])) == ("deny", ["THRESHOLD_EXCEEDED"])
        v = ev.evaluate(make_env({"n": 50}), [])
        assert (v.outcome, v.reason_codes) == ("ask", ["THRESHOLD_EXCEEDED"])
        assert v.obligations == [
            {
                "type": "human_approval",
                "params": {
                    "approval": {"timeout_seconds": 60, "on_timeout": "deny"},
                    "path": "arguments.n",
                    "value": 50,
                    "threshold": 10,
                },
            }
        ]
        v = ev.evaluate(make_env({"n": 7}), [])
        assert (v.outcome, v.reason_codes) == ("watch", ["acme/NOTICE"])
        assert ev.evaluate(make_env({"n": 5}), []).outcome == "allow"
        assert ev.evaluate(make_env({}), []).outcome == "deny"  # absent trips every threshold: the strongest wins

    def test_strictest_triggered_threshold_wins_with_ties_by_order(self, project: Project) -> None:
        ev = project.evaluator(
            doc(
                "  - id: r\n    outcome: allow\n    when:\n      thresholds:\n"
                "        - {path: arguments.n, gt: 1, outcome: watch, reason: acme/A}\n"
                "        - {path: arguments.n, gt: 1, outcome: deny, reason: acme/B}\n"
                "        - {path: arguments.n, gt: 1, outcome: deny, reason: acme/C}\n"
            )
        )
        v = ev.evaluate(make_env({"n": 2}), [])
        assert (v.outcome, v.reason_codes) == ("deny", ["acme/B"])

    def test_expression_thresholds_and_refs(self, project: Project) -> None:
        decl = (
            "schema: cpl.declarations/1.0\nparameters:\n  limit: {type: integer, default: 10}\n"
            "tables:\n  caps: {key: string, value: integer, rows: {gold: 100, basic: 5}}\n"
        )
        text = doc(
            "  - id: r\n    outcome: allow\n    let: {cap: 'table.caps[arguments.tier]'}\n    when:\n"
            f"      {APPROVAL}\n      thresholds:\n"
            "        - {path: arguments.n, gt: {ref: param.limit}, outcome: ask}\n"
            "        - {expr: 'arguments.n > var.cap', outcome: deny}\n"
        )
        ev = project.evaluator(text, decls=decl)
        assert ev.evaluate(make_env({"n": 7, "tier": "basic"}), []).outcome == "deny"  # 7 > 5
        v = ev.evaluate(make_env({"n": 7, "tier": "gold"}), [])
        assert v.outcome == "allow"
        v = ev.evaluate(make_env({"n": 50, "tier": "gold"}), [])
        assert v.outcome == "ask" and v.obligations[0]["params"]["threshold"] == 10
        deny = ev.evaluate(make_env({"n": 200, "tier": "gold"}), [])
        assert deny.outcome == "deny"
        ev2 = project.evaluator(text, decls=decl, config_params=[{"limit": 1000}], name="lim.policy.yaml")
        assert ev2.evaluate(make_env({"n": 50, "tier": "gold"}), []).outcome == "allow"  # the limit is tunable
        assert ev.policy.fingerprint != ev2.policy.fingerprint

    def test_expr_threshold_obligation_carries_the_source(self, project: Project) -> None:
        text = doc(
            f"  - id: r\n    outcome: allow\n    when:\n      {APPROVAL}\n      thresholds:\n"
            "        - {expr: 'arguments.n > 3', outcome: ask}\n"
        )
        v = project.evaluator(text).evaluate(make_env({"n": 4}), [])
        assert v.obligations[0]["params"] == {
            "approval": {"timeout_seconds": 60, "on_timeout": "deny"},
            "expr": "arguments.n > 3",
        }

    def test_obligations_are_filtered_by_the_final_outcome(self, project: Project) -> None:
        text = doc(
            f"  - id: a\n    outcome: allow\n    when:\n      {APPROVAL}\n      thresholds:\n"
            "        - {path: arguments.n, gt: 1, outcome: ask}\n"
            "  - {id: b, outcome: deny, obligations: [{type: notify, params: {to: ops}}]}\n"
        )
        v = project.evaluator(text).evaluate(make_env({"n": 5}), [])
        assert v.outcome == "deny"
        assert v.obligations == [{"type": "notify", "params": {"to": "ops"}}]  # human_approval dropped


class TestConditions:
    def match(self, project: Project, when: str, env: Any = None, signals: list[Any] | None = None) -> bool:
        ev = project.evaluator(doc(f"  - {{id: r, outcome: allow, when: {{{when}}}}}\n"), name="c.policy.yaml")
        return ev.evaluate(env or make_env({"n": 5, "s": "abc", "xs": [1, 2]}), signals or []).outcome == "allow"

    @pytest.mark.parametrize(
        "when,expected",
        [
            ("arguments.n: 5", True),
            ("arguments.n: {eq: 5}", True),
            ("arguments.n: {ne: 5}", False),
            ("arguments.n: {gt: 4}", True),
            ("arguments.n: {gte: 5}", True),
            ("arguments.n: {lt: 5}", False),
            ("arguments.n: {lte: 5}", True),
            ("arguments.n: {between: [5, 9]}", True),
            ("arguments.n: {between: [6, 9]}", False),
            ("arguments.n: [1, 5]", True),
            ("arguments.n: {in: [1, 2]}", False),
            ("arguments.n: {nin: [1, 2]}", True),
            ("arguments.s: {regex: '^a.c$'}", True),
            ("arguments.s: {regex: '^b'}", False),
            ("arguments.s: {glob: 'a*'}", True),
            ("arguments.s: {glob: 'b*'}", False),
            ("arguments.s: {exists: true}", True),
            ("arguments.zz: {exists: false}", True),
            ("arguments.zz: {exists: true}", False),
            ("arguments.s: {contains: b}", True),
            ("arguments.xs: {contains: 2}", True),
            ("arguments.s: {starts_with: ab}", True),
            ("arguments.s: {len_gt: 2}", True),
            ("arguments.s: {len_gt: 3}", False),
            ("arguments.s: {len_lt: 4}", True),
            ("arguments.n: {gt: 1, lt: 9}", True),
            ("arguments.n: {gt: 1, lt: 3}", False),
            ("arguments.n: {gt: 9, negate: true}", True),
            ("arguments.s: {glob: 'A*', case_insensitive: true}", True),
            ("any: [{arguments.n: 1}, {arguments.s: abc}]", True),
            ("all: [{arguments.n: 5}, {arguments.s: abc}]", True),
            ("all: [{arguments.n: 5}, {arguments.s: zzz}]", False),
            ("not: {arguments.n: 4}", True),
            ("expr: 'arguments.n * 2 == 10'", True),
            ("kind: [tool_call]", True),
            ("action_uri: {in: ['app:act']}", True),
            ("default: true", True),
        ],
    )
    def test_operators(self, project: Project, when: str, expected: bool) -> None:
        assert self.match(project, when) is expected

    @pytest.mark.parametrize(
        "when",
        [
            "arguments.zz: 5",
            "arguments.zz: {gt: 1}",
            "arguments.zz: {ne: 5}",
            "arguments.zz: {nin: [1]}",
            "arguments.zz: {regex: a}",
            "arguments.zz: {glob: '*'}",
            "arguments.zz: {gt: 9, negate: true}",
            "not: {arguments.zz: 5}",
            "all: [{arguments.zz: 5}, {arguments.n: 5}]",
            "expr: 'arguments.zz > 1'",
            "arguments.zz: {between: [1, 2]}",
            "arguments.zz: [1, 2]",
            "arguments.n: {gt: {ref: arguments.zz}}",
        ],
    )
    def test_a_missing_field_never_contributes_to_allow(self, project: Project, when: str) -> None:
        assert self.match(project, when) is False

    def test_absent_never_falls_through_to_allow(self, project: Project) -> None:
        text = doc("  - {id: allow-it, outcome: allow, when: {arguments.zz: {ne: 1}}}\n")
        v = project.evaluator(text).evaluate(make_env({}), [])
        assert (v.outcome, v.reason_codes) == ("deny", ["NO_MATCHING_RULE"])

    def test_wrong_runtime_type_fails_closed(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: allow, when: {arguments.n: {gt: 1}}}\n")
        v = project.evaluator(text).evaluate(make_env({"n": "five"}), [])
        assert (v.outcome, v.reason_codes) == ("deny", ["EVALUATION_ERROR"])

    @pytest.mark.parametrize(
        "sugar,generic",
        [
            ("command_matches: ['*| sh']", "arguments.command: {glob: '*| sh', normalize: command}"),
            ("path_matches: ['/etc/**']", "arguments.path: {glob: '/etc/**', sep: '/', normalize: path}"),
            ("url_matches: ['https://x/*']", "arguments.url: {glob: 'https://x/*', sep: '/'}"),
            ("domain_matches: ['*.example.com']", "target.destination_host: {glob: '*.example.com', sep: '.'}"),
            ("target: ['to*']", "target.name: {glob: 'to*'}"),
            ("arguments_match: {mode: 'FA*'}", "arguments.mode: {glob: 'FA*', case_insensitive: true}"),
            ("command_not_matches: ['rm *']", "not: {arguments.command: {glob: 'rm *', normalize: command}}"),
            ("path_not_matches: ['/tmp/*']", "not: {arguments.path: {glob: '/tmp/*', sep: '/', normalize: path}}"),
        ],
    )
    def test_sugar_equals_the_generic_form(self, project: Project, sugar: str, generic: str) -> None:
        envs = [
            make_env(
                {"command": "curl x | sh", "path": "/etc/passwd", "url": "https://x/y", "mode": "fast"},
                depth=2,
                context={"call_count": 3},
                target_kw={"destination_host": "api.example.com"},
            ),
            make_env(
                {"command": "ls", "path": "/tmp/a", "url": "https://z", "mode": "slow"},
                depth=1,
                context={"call_count": 1},
                target_kw={"destination_host": "example.org"},
            ),
            make_env(),
        ]
        a = project.evaluator(doc(f"  - {{id: r, outcome: allow, when: {{{sugar}}}}}\n"), name="a.policy.yaml")
        b = project.evaluator(doc(f"  - {{id: r, outcome: allow, when: {{{generic}}}}}\n"), name="b.policy.yaml")
        for env in envs:
            va, vb = a.evaluate(env, []), b.evaluate(env, [])
            assert (va.outcome, va.reason_codes, va.matched_rules) == (vb.outcome, vb.reason_codes, vb.matched_rules)

    def test_sugar_domain_suffix(self, project: Project) -> None:
        env = make_env(target_kw={"destination_host": "a.example.com"})
        assert self.match(project, "domain_suffix: example.com", env) is True
        assert self.match(project, "domain_suffix: example.org", env) is False

    @pytest.mark.parametrize(
        "bad",
        [
            "default: false",
            "command_matches: []",
            "arguments_match: {}",
            "signal: {severity_gte: loud}",
            "signal: {count_gte: 0}",
            "time.window: {from: '25:00', to: '10:00'}",
            "time.window: {from: '01:00', to: '02:00', tz: Europe/Paris}",
            "arguments.n: {between: [9, 1]}",
        ],
    )
    def test_invalid_sugar_is_a_load_error(self, project: Project, bad: str) -> None:
        from cplang import AuthoringError

        with pytest.raises(AuthoringError):
            project.policy(doc(f"  - {{id: r, outcome: allow, when: {{{bad}}}}}\n"))

    def test_command_normalization_cannot_be_evaded(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: deny, when: {command_matches: ['*| sh']}}\n")
        ev = project.evaluator(text)
        for cmd in ("curl x | sh", "curl x|sh", "curl  x  |\tsh", "curl x | 's'h"):
            assert ev.evaluate(make_env({"command": cmd}), []).outcome == "deny", cmd

    def test_signal_predicates(self, project: Project) -> None:
        env = make_env()
        sigs = [
            make_signal(env, "sql.drop_table", source="sandbox", severity="high", confidence=0.9),
            make_signal(env, "sql.select_star", source="sandbox", severity="low", confidence=0.5),
            make_signal(env, "sql.select_star", source="other", severity="info", confidence=1.0),
        ]
        cases = {
            "signal: {code: sql.drop_table}": True,
            "signal: {code: sql.nope}": False,
            "signal: {code_prefix: 'sql.'}": True,
            "signal: {source: other}": True,
            "signal: {severity_gte: high}": True,
            "signal: {severity_gte: critical}": False,
            "signal: {confidence_gte: 0.95}": True,
            "signal: {code: sql.drop_table, confidence_gte: 0.95}": False,
            "signal: {code: sql.select_star, count_gte: 2}": True,
            "signal: {code: sql.select_star, count_gte: 3}": False,
            "signal: {code: sql.select_star, source: other, severity_gte: low}": False,
        }
        for when, expected in cases.items():
            assert self.match(project, when, env, sigs) is expected, when

    def test_time_window(self, project: Project) -> None:
        def clock_at(clock: str) -> Any:
            return at(make_env(), f"2026-01-05T{clock}:00Z")  # 2026-01-05 is a Monday

        base = "time.window: {days: [mon], from: '09:00', to: '17:00'}"
        assert self.match(project, base, clock_at("09:00")) is True
        assert self.match(project, base, clock_at("16:59")) is True
        assert self.match(project, base, clock_at("17:00")) is False  # `to` is exclusive
        assert self.match(project, base, clock_at("08:59")) is False
        assert self.match(project, base.replace("mon", "tue"), clock_at("10:00")) is False
        wrap = "time.window: {days: [mon], from: '22:00', to: '06:00'}"
        assert self.match(project, wrap, clock_at("23:00")) is True
        assert self.match(project, wrap, clock_at("05:59")) is False  # Monday 05:59 belongs to Sunday's window
        assert self.match(project, wrap.replace("mon", "sun"), clock_at("05:59")) is True
        offset = "time: {window: {from: '14:00', to: '15:00', tz: '+02:00'}}"
        assert self.match(project, offset, clock_at("12:30")) is True


class TestExplanation:
    def test_templates_operator_and_agent_views(self, project: Project) -> None:
        text = doc(
            "  - id: r\n    outcome: deny\n    when: {signal: {code: sql.sig}}\n"
            "    explain: 'tool {target.name} n={arguments.n} first={signal.evidence.excerpt} {{literal}} "
            "miss={arguments.zz}'\n"
        )
        env = make_env({"n": 5}, target="db")
        sig = make_signal(env, "sql.sig", evidence={"excerpt": "DROP"})
        v = project.evaluator(text).evaluate(env, [sig])
        assert v.explanation == "tool db n=5 first=DROP {literal} miss=n/a"
        assert v.hint["message"] == "tool db n=[withheld] first=[withheld] {literal} miss=n/a"
        assert v.hint["code"] == "RULE_DENY"

    def test_decimals_render_without_exponent(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: deny, explain: 'n={arguments.n} t={arguments.t}'}\n")
        v = project.evaluator(text).evaluate(make_env({"n": 1e2, "t": 2.50}), [])
        assert v.explanation == "n=100 t=2.5"

    def test_text_is_cut_at_512(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: deny, explain: 'x{arguments.s}'}\n")
        v = project.evaluator(text).evaluate(make_env({"s": "y" * 2000}), [])
        assert len(v.explanation) == 512

    def test_every_non_allow_verdict_has_an_explanation_and_a_hint(self, project: Project) -> None:
        for outcome, extra in (("deny", ""), ("ask", f", when: {{{APPROVAL}}}")):
            v = project.evaluator(
                doc(f"  - {{id: r, outcome: {outcome}{extra}}}\n"), name=f"{outcome}.policy.yaml"
            ).evaluate(make_env(), [])
            assert v.explanation and v.hint and v.hint["code"] == v.reason_codes[0]
        ask = project.evaluator(
            doc(f"  - {{id: r, outcome: ask, when: {{{APPROVAL}}}}}\n"), name="a.policy.yaml"
        ).evaluate(make_env(), [])
        assert ask.hint["next_steps"] == [{"kind": "request_approval"}]
        allow = project.evaluator(doc("  - {id: r, outcome: allow}\n"), name="al.policy.yaml").evaluate(make_env(), [])
        assert allow.hint is None

    def test_agent_hint_never_leaks_policy_internals(self, project: Project) -> None:
        text = doc("  - {id: secret-rule-name, outcome: deny, when: {arguments.n: {gt: 1}}}\n")
        v = project.evaluator(text).evaluate(make_env({"n": 99}), [])
        assert "secret-rule-name" not in str(v.hint) and "99" not in str(v.hint)

    def test_rule_hint_overrides_next_steps(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: deny, hint: {next_steps: [{kind: narrow_request}]}}\n")
        v = project.evaluator(text).evaluate(make_env(), [])
        assert v.hint["next_steps"] == [{"kind": "narrow_request"}]

    def test_risk_tier(self, project: Project) -> None:
        text = doc(
            "  - {id: r, outcome: allow}\n",
            extra=(
                "risk_tiers:\n  - {id: critical, when: {action_uri: "
                "{in: ['app:purge']}}}\n  - {id: elevated, when: "
                "{kind: [db_query]}}\ndefault_risk_tier: low\n"
            ),
        )
        ev = project.evaluator(text)
        assert ev.evaluate(make_env(action_uri="app:purge"), []).risk_tier == "critical"
        assert ev.evaluate(make_env(kind="db_query"), []).risk_tier == "elevated"
        assert ev.evaluate(make_env(), []).risk_tier == "low"
        plain = project.evaluator(doc(""), name="n.policy.yaml")
        assert plain.evaluate(make_env(), []).risk_tier == "standard"

    def test_trace_is_the_same_decision(self, project: Project) -> None:
        text = doc(
            "  - {id: a, outcome: deny, match: {kind: [other]}}\n"
            "  - {id: b, outcome: allow, let: {x: 'arguments.n + 1'}, when: {expr: 'var.x == 6'}}\n"
        )
        ev = project.evaluator(text)
        env = make_env({"n": 5})
        verdict, events = ev.trace(env, [])
        plain = ev.evaluate(env, [])
        assert (verdict.outcome, verdict.reason_codes) == (plain.outcome, plain.reason_codes)
        assert events[0] == {"rule": "a", "match": "false"}
        assert events[1]["let"] == {"x": "6"} and events[1]["when"] == "true" and events[1]["decided_at_step"] == 13


class TestViews:
    def test_state_and_origin_views(self, project: Project) -> None:
        ev = project.evaluator(
            doc(
                "  - {id: depth, outcome: deny, when: {state.run.depth: {gte: 2}}}\n"
                "  - {id: chain, outcome: deny, when: {state.chain: {contains: agent-b}}}\n"
                "  - {id: origin, outcome: deny, when: {origin.runtime: x}}\n"
                "  - {id: ctx, outcome: deny, when: {state.session.tainted: true}}\n",
            ),
            name="s.policy.yaml",
        )
        assert ev.evaluate(make_env(depth=2), []).matched_rules == ["depth"]
        assert ev.evaluate(make_env(call_chain=["agent-a", "agent-b"]), []).matched_rules == ["chain"]
        assert ev.evaluate(make_env(context={"session": {"tainted": True}}), []).matched_rules == ["ctx"]
        assert ev.evaluate(make_env(), []).matched_rules == []
        env = make_env(origin={"runtime": "x"})
        assert ev.evaluate(env, []).matched_rules == ["origin"]

    def test_attributes_are_typed_and_untrusted_when_derived(self, project: Project) -> None:
        decl = (
            "schema: cpl.declarations/1.0\nattributes:\n  qty: {type: integer, source: either}\n"
            "  tier: {type: string, source: asserted}\n"
        )
        text = doc(
            "  - {id: r, outcome: deny, explain: 'q={attributes.qty} t={attributes.tier}', "
            "when: {attributes.qty: {gt: 3}}}\n"
        )
        ev = project.evaluator(text, decls=decl)
        env = make_env(attributes={"qty": 5, "tier": "gold"}, sources={"qty": "derived", "tier": "asserted"})
        v = ev.evaluate(env, [])
        assert v.explanation == "q=5 t=gold" and v.hint["message"] == "q=[withheld] t=gold"
        bad = make_env(attributes={"qty": "five"})
        assert ev.evaluate(bad, []).reason_codes == ["EVALUATION_ERROR"]


class TestErrors:
    def test_function_exception_gives_the_posture_verdict_with_only_the_type_name(self, project: Project) -> None:
        from cplang import FunctionRegistry

        def boom(action: Any, args: dict[str, Any]) -> Any:
            raise ValueError("secret detail")

        reg = FunctionRegistry()
        reg.register("acme/boom", boom)
        text = doc("  - {id: r, outcome: allow, when: {expr: 'acme/boom(1)'}}\n")
        ev = project.evaluator(text, plugins=reg)
        v = ev.evaluate(make_env(), [])
        assert (v.outcome, v.reason_codes) == ("deny", ["EVALUATION_ERROR"])
        assert v.reasons[0]["message"] == "ValueError" and "secret" not in str(v.to_wire())
        flagged = project.evaluator(text, plugins=reg, posture="allow_and_flag", name="fl.policy.yaml")
        assert flagged.evaluate(make_env(), []).outcome == "watch"

    def test_step_budget_overflow_denies(self, project: Project) -> None:
        from cplang import CplLimits

        text = doc("  - {id: r, outcome: allow, when: {expr: '1 + 2 + 3 + 4 + 5 == 15'}}\n")
        ok = project.evaluator(text, limits=CplLimits(max_eval_steps=100))
        assert ok.evaluate(make_env(), []).outcome == "allow"
        tiny = project.evaluator(text, limits=CplLimits(max_eval_steps=5), name="t.policy.yaml")
        assert tiny.evaluate(make_env(), []).reason_codes == ["EVALUATION_ERROR"]

    def test_decimal_text_is_preserved_from_the_envelope(self, project: Project) -> None:
        text = doc("  - {id: r, outcome: allow, when: {arguments.v: {eq: 0.3}}}\n")
        ev = project.evaluator(text)
        assert ev.evaluate(make_env({"v": 0.3}), []).outcome == "allow"
        assert ev.evaluate(make_env({"v": 0.1 + 0.2}), []).outcome == "deny"  # a genuine binary-float sum differs


class TestModifications:
    def edit(self, op: str, pointer: str, **kw: Any) -> str:
        extra = "".join(f", {k}: {v}" for k, v in kw.items())
        return f"{{op: {op}, json_pointer: {pointer}{extra}}}"

    def test_disjoint_edits_compose_and_sort(self, project: Project) -> None:
        text = doc(
            f"  - {{id: b, outcome: modify, modify: {{edits: [{self.edit('redact', '/b')}]}}}}\n"
            f"  - {{id: a, outcome: modify, modify: {{edits: [{self.edit('redact', '/a')}]}}}}\n"
        )
        v = project.evaluator(text).evaluate(make_env(), [])
        assert v.outcome == "modify"
        assert v.modifications == {
            "edits": [{"op": "redact", "json_pointer": "/a"}, {"op": "redact", "json_pointer": "/b"}]
        }

    @pytest.mark.parametrize("p1,p2", [("/a", "/a"), ("/a", "/a/b"), ("/a/b", "/a"), ("''", "/a")])
    def test_overlapping_edits_deny(self, project: Project, p1: str, p2: str) -> None:
        e1, e2 = self.edit("set", p1, value="1"), self.edit("set", p2, value="2")
        text = doc(
            f"  - {{id: a, outcome: modify, modify: {{edits: [{e1}]}}}}\n"
            f"  - {{id: b, outcome: modify, modify: {{edits: [{e2}]}}}}\n"
        )
        v = project.evaluator(text).evaluate(make_env(), [])
        assert v.outcome == "deny" and v.reason_codes[0] == "EVALUATION_ERROR"
        assert v.reasons[0]["message"] == "modification_overlap" and v.modifications is None

    def test_identical_edits_merge_and_a_pointer_prefix_needs_a_slash_boundary(self, project: Project) -> None:
        same = self.edit("redact", "/a")
        text = doc(
            f"  - {{id: a, outcome: modify, modify: {{edits: [{same}]}}}}\n"
            f"  - {{id: b, outcome: modify, modify: {{edits: [{same}]}}}}\n"
        )
        assert project.evaluator(text).evaluate(make_env(), []).modifications == {
            "edits": [{"op": "redact", "json_pointer": "/a"}]
        }
        near = doc(
            f"  - {{id: a, outcome: modify, modify: {{edits: [{self.edit('redact', '/ab')}]}}}}\n"
            f"  - {{id: b, outcome: modify, modify: {{edits: [{self.edit('redact', '/a')}]}}}}\n"
        )
        assert project.evaluator(near, name="n.policy.yaml").evaluate(make_env(), []).outcome == "modify"

    def test_wholesale_replacement_overlaps_everything(self, project: Project) -> None:
        text = doc(
            "  - {id: a, outcome: modify, modify: {replace: {x: 1}}}\n"
            f"  - {{id: b, outcome: modify, modify: {{edits: [{self.edit('redact', '/a')}]}}}}\n"
        )
        assert project.evaluator(text).evaluate(make_env(), []).outcome == "deny"
        alone = doc("  - {id: a, outcome: modify, modify: {replace: {x: 1}}}\n")
        assert project.evaluator(alone, name="w.policy.yaml").evaluate(make_env(), []).modifications == {
            "replace": {"x": 1}
        }

    def test_apply_suggested_uses_the_signals_the_rule_matched(self, project: Project) -> None:
        env = make_env({"a": "SECRET"})
        text = doc(
            "  - {id: r, outcome: modify, modify: {apply_suggested: true}, when: {signal: {code_prefix: 'secret.'}}}\n"
        )
        hit = make_signal(
            env, "secret.pattern", suggested={"op": "redact", "json_pointer": "/a", "placeholder": "[REDACTED:key]"}
        )
        unrelated = make_signal(env, "other.code", suggested={"op": "drop_field", "json_pointer": "/z"})
        v = project.evaluator(text).evaluate(env, [unrelated, hit])
        assert v.modifications == {"edits": [{"op": "redact", "json_pointer": "/a", "placeholder": "[REDACTED:key]"}]}

    def test_modifications_only_when_the_final_outcome_is_modify(self, project: Project) -> None:
        text = doc(
            f"  - {{id: a, outcome: modify, modify: {{edits: [{self.edit('redact', '/a')}]}}}}\n"
            "  - {id: b, outcome: deny}\n"
        )
        v = project.evaluator(text).evaluate(make_env(), [])
        assert (v.outcome, v.modifications) == ("deny", None)


class TestResultRules:
    def test_a_rule_on_the_tool_response_runs_after_the_action(self, project: Project) -> None:
        text = (
            ALLOW_DEFAULT + "  - {id: leak, outcome: deny, when: {expr: \"contains(arguments.response, 'SECRET')\"}}\n"
        )
        ev = project.evaluator(text)
        env = make_env({"response": "has a SECRET inside"})
        assert ev.evaluate_result(env, []).outcome == "deny"

    def test_condition_style_response_checks_also_run(self, project: Project) -> None:
        text = ALLOW_DEFAULT + "  - {id: leak, outcome: deny, when: {arguments.response: {contains: SECRET}}}\n"
        assert project.evaluator(text).evaluate_result(make_env({"response": "SECRET"}), []).outcome == "deny"

    def test_a_name_that_only_looks_like_a_result_is_not_one(self, project: Project) -> None:
        text = ALLOW_DEFAULT + "  - {id: r, outcome: deny, when: {arguments.tool: get_result}}\n"
        ev = project.evaluator(text)
        assert ev.evaluate_result(make_env({"tool": "get_result"}), []).outcome == "allow"
        assert ev.evaluate(make_env({"tool": "get_result"}), []).outcome == "deny"


class TestTraceIsReadOnly:
    LIMITED = (
        ALLOW_DEFAULT + "  - {id: r, outcome: allow, when: {max_calls_per_window: {limit: 1, window_seconds: 3600}}}\n"
    )

    def test_tracing_does_not_count_calls_and_does_not_disable_counting(self, project: Project) -> None:
        ev = project.evaluator(self.LIMITED, rate_limiter=InMemoryRateLimiter())
        for _ in range(3):
            ev.trace(make_env(), [])
        assert ev.evaluate(make_env(), []).outcome == "allow"
        assert ev.evaluate(make_env(), []).outcome == "deny"

    def test_a_concurrent_trace_never_switches_counting_off(self, project: Project) -> None:
        ev = project.evaluator(self.LIMITED, rate_limiter=InMemoryRateLimiter())
        stop = threading.Event()

        def trace_forever() -> None:
            while not stop.is_set():
                ev.trace(make_env(), [])

        worker = threading.Thread(target=trace_forever)
        worker.start()
        try:
            outcomes = [ev.evaluate(make_env(), []).outcome for _ in range(200)]
        finally:
            stop.set()
            worker.join()
        assert outcomes.count("allow") == 1


class TestEveryFailureIsARefusal:
    def policy(self, project: Project) -> RuleEvaluator:
        return project.evaluator(ALLOW_DEFAULT + "  - {id: r, outcome: allow, when: {kind: [x]}}\n")

    def test_values_that_cannot_be_hashed_still_get_a_verdict(self, project: Project) -> None:
        ev = self.policy(project)
        for odd in (Decimal("1.5"), Decimal("NaN"), {1, 2}):
            verdict = ev.evaluate(
                Action({"timestamp": "2026-01-01T00:00:00Z", "kind": "x", "arguments": {"a": odd}}), []
            )
            assert verdict.input_digest.startswith("sha256:")

    def test_a_missing_timestamp_is_a_refusal(self, project: Project) -> None:
        verdict = self.policy(project).evaluate(Action({"kind": "x"}), [])
        assert verdict.outcome == "deny" and verdict.reason_codes == ["EVALUATION_ERROR"]

    def test_absurd_nesting_is_a_refusal(self, project: Project) -> None:
        nested: dict[str, Any] = {}
        for _ in range(5000):
            nested = {"a": nested}
        verdict = self.policy(project).evaluate(
            Action({"timestamp": "2026-01-01T00:00:00Z", "kind": "x", "arguments": nested}), []
        )
        assert verdict.outcome == "deny" and verdict.reason_codes == ["EVALUATION_ERROR"]

    def test_a_signal_with_an_unknown_severity_is_a_refusal_not_an_exception(self, project: Project) -> None:
        text = DENY_DEFAULT + "  - {id: r, outcome: allow, when: {signal: {code: s, severity_gte: low}}}\n"
        verdict = project.evaluator(text).evaluate(make_env(), [Signal(code="s", source="x", severity="HIGH")])
        assert verdict.outcome == "deny"


class TestVerdictsOwnTheirData:
    def test_editing_a_verdict_does_not_change_the_next_one(self, project: Project) -> None:
        text = (
            DENY_DEFAULT
            + "  - id: r\n    outcome: modify\n    modify: {edits: [{op: redact, json_pointer: /arguments/a}]}\n"
        )
        ev = project.evaluator(text)
        first = ev.evaluate(make_env({"a": 1}), [])
        assert first.modifications is not None
        first.modifications["edits"][0]["json_pointer"] = "/arguments/other"  # type: ignore[typeddict-item]
        second = ev.evaluate(make_env({"a": 1}), [])
        assert second.modifications is not None
        assert second.modifications["edits"][0]["json_pointer"] == "/arguments/a"  # type: ignore[typeddict-item]


class TestMonitorRules:
    def test_a_monitor_rule_does_not_hide_an_enforced_rule_under_first_match(self, project: Project) -> None:
        text = (
            BARE_HEAD
            + "default: allow\nstrategy: first_match\nrules:\n"
            + "  - {id: watching, outcome: deny, mode: monitor, match: {kind: [tool_call]}}\n"
            + "  - {id: enforcing, outcome: deny, match: {kind: [tool_call]}}\n"
        )
        verdict = project.evaluator(text).evaluate(make_env(), [])
        assert verdict.outcome == "deny" and "enforcing" in verdict.matched_rules

    def test_a_fragment_follows_the_mode_of_the_root_document(self, project: Project) -> None:
        project.write("f.policy.yaml", 'cpl: "1.0"\nfragment: true\nrules:\n  - {id: from-fragment, outcome: deny}\n')
        root = BARE_HEAD + "default: allow\nmode: monitor\nimports:\n  - {from: f.policy.yaml}\nrules: []\n"
        assert [r.mode for r in project.policy(root).rules] == ["monitor"]


class TestThresholdStrength:
    def test_a_threshold_never_weakens_the_rule_outcome(self, project: Project) -> None:
        text = (
            DENY_DEFAULT
            + "  - id: r\n    outcome: deny\n    when:\n      thresholds:\n"
            + "        - {expr: 'arguments.n > 5', outcome: watch}\n"
        )
        assert project.evaluator(text).evaluate(make_env({"n": 10}), []).outcome == "deny"


class TestSignalsSharingAnId:
    def test_suggested_edits_of_every_matching_signal_are_kept(self, project: Project) -> None:
        text = (
            DENY_DEFAULT
            + "  - id: r\n    outcome: modify\n    modify: {apply_suggested: true}\n"
            + "    when: {signal: {code_prefix: pii}}\n"
        )
        signals = [
            Signal(
                code="pii.a",
                source="s",
                severity="high",
                suggested_modification={"op": "redact", "json_pointer": "/arguments/a"},
            ),
            Signal(
                code="pii.b",
                source="s",
                severity="high",
                suggested_modification={"op": "redact", "json_pointer": "/arguments/b"},
            ),
        ]
        verdict = project.evaluator(text).evaluate(make_env({"a": "x", "b": "y"}), signals)
        pointers = [e["json_pointer"] for e in (verdict.modifications or {}).get("edits", [])]  # type: ignore[typeddict-item]
        assert pointers == ["/arguments/a", "/arguments/b"]

    def test_applying_nothing_is_a_refusal_not_an_empty_modify(self, project: Project) -> None:
        text = (
            DENY_DEFAULT
            + "  - id: r\n    outcome: modify\n    modify: {apply_suggested: true}\n"
            + "    when: {signal: {code: pii.a}}\n"
        )
        verdict = project.evaluator(text).evaluate(make_env(), [Signal(code="pii.a", source="s", severity="high")])
        assert verdict.outcome == "deny"


class TestResultPathRateLimits:
    def test_checking_a_response_does_not_count_the_call_again(self, project: Project) -> None:
        text = (
            ALLOW_DEFAULT
            + "  - id: r\n    outcome: allow\n    when:\n      signal: {code: s}\n"
            + "      max_calls_per_window: {limit: 2, window_seconds: 3600}\n"
        )
        ev = project.evaluator(text, rate_limiter=InMemoryRateLimiter())
        signals = [Signal(code="s", source="x", severity="low")]
        assert ev.evaluate(make_env(), signals).outcome == "allow"
        assert ev.evaluate_result(make_env(), signals).outcome == "allow"
        assert ev.evaluate(make_env(), signals).outcome == "allow"  # the second counted call, not the third


class TestParameterComparison:
    def test_the_number_1_5_and_the_text_1_5_are_different_values(self, project: Project) -> None:
        text = ALLOW_DEFAULT + "  - {id: r, outcome: allow, when: {immutable_params: {n: 1.5}}}\n"
        ev = project.evaluator(text)
        assert ev.evaluate(make_env({"n": 1.5}), []).outcome == "allow"
        assert ev.evaluate(make_env({"n": "1.5"}), []).outcome == "deny"


class TestResponseGuards:
    GUARDED = (
        BARE_HEAD
        + "default: deny\nrules:\n  - id: r\n    outcome: allow\n    match: {kind: [tool_call]}\n"
        + "    when:\n      deny: {arguments.response: {contains: SECRET}}\n"
    )

    def test_a_guard_on_the_response_waits_until_the_response_exists(self, project: Project) -> None:
        ev = project.evaluator(self.GUARDED)
        assert ev.evaluate(make_env({"tool": "x"}), []).outcome == "allow"
        assert ev.evaluate_result(make_env({"tool": "x", "response": "fine"}), []).outcome == "allow"
        assert ev.evaluate_result(make_env({"tool": "x", "response": "a SECRET"}), []).outcome == "deny"

    def test_a_guard_on_another_missing_field_still_denies_before_the_call(self, project: Project) -> None:
        text = self.GUARDED.replace("arguments.response", "arguments.amount").replace("contains: SECRET", "gt: 100")
        assert project.evaluator(text).evaluate(make_env({"tool": "x"}), []).outcome == "deny"

    @staticmethod
    def mixed(guard: str) -> str:
        return (
            BARE_HEAD + "default: deny\nrules:\n  - id: r\n    outcome: allow\n    when:\n      deny: " + guard + "\n"
        )

    def test_the_other_half_of_an_any_guard_still_fails_closed_before_the_call(self, project: Project) -> None:
        ev = project.evaluator(
            self.mixed("{any: [{arguments.amount: {gt: 100}}, {arguments.response: {contains: SECRET}}]}")
        )
        assert ev.evaluate(make_env({}), []).outcome == "deny"  # amount is missing
        assert ev.evaluate(make_env({"amount": 5}), []).outcome == "allow"
        assert ev.evaluate(make_env({"amount": 500}), []).outcome == "deny"
        assert ev.evaluate_result(make_env({"amount": 5, "response": "a SECRET"}), []).outcome == "deny"

    def test_a_negated_response_check_waits_too(self, project: Project) -> None:
        ev = project.evaluator(self.mixed("{not: {arguments.response: {contains: OK}}}"))
        assert ev.evaluate(make_env({}), []).outcome == "allow"
        assert ev.evaluate_result(make_env({"response": "fine"}), []).outcome == "deny"
        assert ev.evaluate_result(make_env({"response": "all OK"}), []).outcome == "allow"


class TestRefusalRecords:
    def test_inputs_without_a_canonical_form_still_have_different_digests(self, project: Project) -> None:
        ev = project.evaluator(BARE_HEAD + "default: allow\nrules: []\n")

        def digest(value: Any) -> str:
            data = {"timestamp": "2026-01-01T00:00:00Z", "kind": "x", "arguments": {"a": value}}
            return ev.evaluate(Action(data), []).input_digest

        assert digest(Decimal("1.5")) != digest(Decimal("2.5"))
        assert digest({1, 2}) != digest({1, 3})
        assert digest(Decimal("1.5")) == digest(Decimal("1.5"))
