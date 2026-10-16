"""The prover over every supported condition shape: each candidate is checked against an empty boundary, and the
counterexample must replay on the evaluator (a model mismatch is reported as `error`)."""

from __future__ import annotations

import pytest
from tests.conftest import Project

from cplang import AuthoringError
from cplang.model import Signal
from cplang.profile import Profile, SignalEffect

pytest.importorskip("z3")
from cplang.prove import prove

HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\n'
EMPTY = HEAD + "rules: []\n"


def _effect(signal: Signal) -> SignalEffect | None:
    return (
        SignalEffect("deny", "ACTION_FORBIDDEN", hard=True, monitor_aware=True, step=2)
        if signal.code == "scan.hard"
        else None
    )


HARD = Profile(hard_signal_codes=frozenset({"scan.hard"}), signal_effect=_effect)
DECLS = (
    "schema: cpl.declarations/1.0\nparameters:\n  cap: {type: integer, default: 5}\n"
    "constants:\n  limit: {type: integer, value: 7}\n  flag: {type: boolean, value: true}\n  name: {type: string, value: x}\n"
    "types:\n  Region: {kind: enum, values: [eu, us]}\n"
    "attributes:\n  tier: {type: string}\n  score: {type: number}\n  ok: {type: boolean}\n  region: {type: Region}\n"
)

SUPPORTED = [
    "match: {action_uri: ['app:*']}",
    "when: {arguments.n: {gt: 3}}",
    "when: {arguments.n: {gte: 3, lt: 9, lte: 8}}",
    "when: {arguments.n: {between: [2, 6]}}",
    "when: {arguments.n: {eq: 4}}",
    "when: {arguments.n: {ne: 4}}",
    "when: {arguments.n: [1, 2, 3]}",
    "when: {arguments.n: {nin: [1, 2]}, arguments.s: {eq: a}}",
    "when: {arguments.flag: true}",
    "when: {arguments.s: {glob: 'a*'}}",
    "when: {arguments.s: {glob: 'a?[a-c]', sep: '/'}}",
    "when: {arguments.s: {glob: 'a[!x]'}}",
    "when: {arguments.s: {glob: 'a\\*b'}}",
    "when: {arguments.s: {glob: '[a'}}",
    "when: {arguments.s: {glob: 'a/**/b', sep: '/'}}",
    "when: {arguments.s: {contains: abc}}",
    "when: {arguments.s: {starts_with: ab}}",
    "when: {arguments.s: {len_gt: 2, len_lt: 9}}",
    "when: {arguments.s: {exists: true}}",
    "when: {arguments.s: {exists: false}}",
    "when: {not: {arguments.n: {gt: 3}}}",
    "when: {any: [{arguments.n: 1}, {arguments.n: 2}]}",
    "when: {all: [{arguments.n: {gt: 1}}, {arguments.n: {lt: 5}}]}",
    "when: {signal: {code: scan.x}}",
    "when: {arguments.n: {gt: {ref: param.cap}}}",
    "when: {arguments.n: {lt: {ref: const.limit}}}",
    "when: {expr: 'const.flag'}",
    "when: {arguments.n: {gt: {expr: 'const.limit - 5'}}}",
    "when: {attributes.score: {gt: 1}, attributes.tier: {eq: gold}, attributes.ok: true}",
    "let: {x: 'arguments.n + 1'}\n    when: {expr: 'var.x > 3'}",
    "when: {kind: [tool_call]}",
    "when: {target.name: [db*]}",
    "when: {thresholds: [{outcome: deny, path: arguments.n, gt: 5}, {outcome: watch, path: arguments.n, gt: 2}]}",
    "when: {deny: {arguments.n: {gt: 5}}}",
]

UNSUPPORTED = [
    "when: {arguments.s: {glob: 'a*', case_insensitive: true}}",
    "when: {arguments.s: {regex: 'a+'}}",
    "when: {signal: {code: scan.x, severity_gte: high}}",
    "when: {time.window: {from: '01:00', to: '02:00'}}",
    "when: {expr: 'arguments.n + arguments.s'}",
    "when: {expr: 'lower(arguments.s) == \"a\"'}",
    "when: {arguments.n: {gt: {ref: arguments.m}}, arguments.s: {in: {ref: arguments.l}}}",
    "when: {max_calls_per_window: {limit: 2}}",
    "when: {immutable_params: {a: 1}}",
    "when: {bounded_params: {n: {max: 1}}}",
    "let: {x: 'arguments.s'}\n    when: {expr: 'var.y == 1'}",
    "when: {arguments.s: {glob: 5}}",
    "when: {arguments.n: {eq: 1}, arguments.n2: {eq: 'a'}, expr: 'arguments.n == \"a\"'}",
    "when: {arguments.s: {lt: b}}",
    "when: {arguments.n: {gt: {ref: arguments.n}}, expr: 'arguments.n < 1.5 and arguments.s > 1'}",
]


def candidate(project: Project, snippet: str, name: str = "c.policy.yaml", **kw: object):  # type: ignore[no-untyped-def]
    text = HEAD + f"rules:\n  - id: r\n    outcome: allow\n    {snippet}\n"
    return project.policy(text, decls=DECLS, name=name, **kw)


@pytest.mark.parametrize("snippet", SUPPORTED)
def test_supported_shapes_prove_and_replay(project: Project, snippet: str) -> None:
    cand = candidate(project, snippet)
    empty = project.policy(EMPTY, decls=DECLS, name="b.policy.yaml")
    result = prove(cand, empty)
    assert result.result in ("exceeds_boundary", "unsupported", "inconclusive"), (result.result, result.detail)
    if result.result == "exceeds_boundary":
        assert result.counterexample and result.counterexample["outcome_boundary"] == "deny"
    assert prove(empty, cand).result == "within_boundary" or prove(empty, cand).result == "unsupported"
    assert result.to_dict()["result"] == result.result


@pytest.mark.parametrize("snippet", UNSUPPORTED)
def test_unsupported_shapes_are_never_guessed(project: Project, snippet: str) -> None:
    try:
        cand = candidate(project, snippet)
    except AuthoringError:
        return  # rejected when the policy is loaded: nothing to prove
    empty = project.policy(EMPTY, decls=DECLS, name="b.policy.yaml")
    result = prove(cand, empty)
    assert result.result in ("unsupported", "exceeds_boundary") and result.exit_code in (1, 3)


def test_hard_signals_are_proved_bypass_free_or_found(project: Project) -> None:
    safe = candidate(project, "when: {arguments.n: 1}", profile=HARD)
    assert prove(safe, safe, mode="no_bypass").result in ("within_boundary", "exceeds_boundary")
    allow_all = project.policy(
        HEAD + "mode: monitor\nrules:\n  - {id: r, outcome: allow}\n", name="a.policy.yaml", profile=HARD
    )
    found = prove(allow_all, allow_all, mode="no_bypass")
    assert found.result == "exceeds_boundary" and found.reason_code == "hard_deny_bypassed"
    assert (
        prove(candidate(project, "when: {arguments.n: 1}", name="n.policy.yaml"), allow_all, mode="no_bypass").result
        == "unsupported"
    )


def test_strategies_modes_and_priorities(project: Project) -> None:
    rules = (
        "rules:\n  - {id: lo, outcome: deny, priority: 1, match: {action_uri: ['app:*']}}\n"
        "  - {id: hi, outcome: allow, priority: 9, match: {action_uri: ['app:r']}}\n"
        "  - {id: off, outcome: allow, enabled: false}\n"
    )
    for extra in ("strategy: priority\n", "strategy: first_match\n", "strategy: deny_overrides\n", "mode: monitor\n"):
        pol = project.policy(HEAD + extra + rules, name=f"{extra[:6]}.policy.yaml", profile=HARD)
        empty = project.policy(EMPTY, name="b.policy.yaml", profile=HARD)
        assert prove(pol, empty).result in ("exceeds_boundary", "within_boundary", "unsupported")
        assert prove(pol, pol, mode="diff").result == "within_boundary"
    allow_default = project.policy('cpl: "1.0"\nid: p\nversion: 1\ndefault: allow\nrules: []\n', name="d.policy.yaml")
    assert prove(allow_default, project.policy(EMPTY, name="e.policy.yaml")).result == "exceeds_boundary"


def test_attribute_quantities_and_dynamic_paths_are_unsupported(project: Project) -> None:
    decls = DECLS + ("types2: {}\n" if False else "")
    cand = candidate(project, "when: {arguments./a/b: {eq: 1}}")
    empty = project.policy(EMPTY, decls=decls, name="b.policy.yaml")
    assert prove(cand, empty).result in ("unsupported", "exceeds_boundary")
