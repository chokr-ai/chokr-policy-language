from __future__ import annotations

from tests.conftest import Project, make_env, make_signal, outcome_of

BASIC = """
cpl: "1.0"
id: pol_example
version: 7
mode: enforce
default: deny
rules:
  - id: block-drop-table
    description: Deny destructive SQL
    match: {kind: [db_query]}
    when: {signal: {code: "sql.drop_table"}}
    outcome: deny
    reason: RULE_DENY
    explain: "Destructive SQL ({signal.evidence.excerpt}) is not allowed."
  - id: allow-reads
    match: {action_uri: ["app:read"]}
    outcome: allow
"""


def test_smoke_default_deny_and_allow(project: Project) -> None:
    ev = project.evaluator(BASIC)
    read = make_env(action_uri="app:read")
    v = ev.evaluate(read, [])
    assert outcome_of(v) == ("allow", ["POLICY_SATISFIED"])
    assert v.matched_rules == ["allow-reads"]
    other = make_env(action_uri="app:write")
    v2 = ev.evaluate(other, [])
    assert outcome_of(v2) == ("deny", ["NO_MATCHING_RULE"])


def test_smoke_signal_rule_and_explain(project: Project) -> None:
    ev = project.evaluator(BASIC)
    env = make_env(kind="db_query", action_uri="app:read")
    sig = make_signal(env, "sql.drop_table", evidence={"excerpt": "DROP TABLE users"})
    v = ev.evaluate(env, [sig])
    assert v.outcome == "deny"
    assert v.explanation == "Destructive SQL (DROP TABLE users) is not allowed."
    assert v.policy["id"] == "pol_example" and v.policy["fingerprint"].startswith("sha256:")
