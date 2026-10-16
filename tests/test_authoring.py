"""Authoring errors and the accepted forms of every rule key, condition key and operator."""

from __future__ import annotations

import pytest
from tests.conftest import Project

from cplang import AuthoringError

HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\n'
APPROVAL = "approval: {timeout_seconds: 60}"


def doc(rule: str, extra: str = "") -> str:
    return HEAD + extra + "rules:\n  - " + rule + "\n"


INVALID_RULES = [
    "just-a-string",
    "{id: r, outcome: allow, bogus: 1}",
    "{outcome: allow}",
    "{id: 'bad id!', outcome: allow}",
    "{id: r, outcome: nope}",
    "{id: r, outcome: allow, priority: x}",
    "{id: r, outcome: allow, enabled: maybe}",
    "{id: r, outcome: allow, mode: loud}",
    "{id: r, outcome: allow, when: [1]}",
    "{id: r, outcome: allow, let: [1]}",
    "{id: r, outcome: allow, let: {BAD: '1'}}",
    "{id: r, outcome: allow, let: {x: 5}}",
    "{id: r, outcome: allow, let: {x: '1 +'}}",
    "{id: r, outcome: ask}",
    "{id: r, outcome: allow, reason: 5}",
    "{id: r, outcome: allow, reason: lowercase}",
    "{id: r, outcome: allow, explain: 5}",
    "{id: r, outcome: allow, explain: 'x {signal.bogus}'}",
    "{id: r, outcome: allow, hint: [1]}",
    "{id: r, outcome: modify}",
    "{id: r, outcome: allow, modify: {apply_suggested: true}}",
    "{id: r, outcome: modify, modify: [1]}",
    "{id: r, outcome: modify, modify: {bogus: 1}}",
    "{id: r, outcome: modify, modify: {apply_suggested: false}}",
    "{id: r, outcome: modify, modify: {replace: 1}}",
    "{id: r, outcome: modify, modify: {edits: []}}",
    "{id: r, outcome: modify, modify: {edits: [{op: nope, json_pointer: /a}]}}",
    "{id: r, outcome: modify, modify: {edits: [{op: set, json_pointer: a}]}}",
    "{id: r, outcome: allow, obligations: x}",
    "{id: r, outcome: allow, obligations: [{type: 5}]}",
    "{id: r, outcome: allow, obligations: [{type: bogus}]}",
    "{id: r, outcome: allow, obligations: [{type: notify, extra: 1}]}",
    "{id: r, outcome: allow, when: {deny: 5}}",
    "{id: r, outcome: allow, when: {immutable_params: {}}}",
    "{id: r, outcome: allow, when: {bounded_params: {}}}",
    "{id: r, outcome: allow, when: {bounded_params: {n: {}}}}",
    "{id: r, outcome: allow, when: {bounded_params: {n: {min: x}}}}",
    "{id: r, outcome: allow, when: {max_calls_per_window: {limit: 0}}}",
    "{id: r, outcome: allow, when: {max_calls_per_window: {bogus: 1}}}",
    "{id: r, outcome: ask, when: {approval: {}}}",
    "{id: r, outcome: ask, when: {approval: {timeout_seconds: 5, on_timeout: allow}}}",
    "{id: r, outcome: ask, when: {approval: {timeout_seconds: 5, fatigue_threshold: 0, fatigue_window_seconds: 5}}}",
    "{id: r, outcome: ask, when: {approval: {timeout_seconds: 5, fatigue_threshold: 3}}}",
    "{id: r, outcome: allow, when: {thresholds: []}}",
    "{id: r, outcome: allow, when: {thresholds: [5]}}",
    "{id: r, outcome: allow, when: {thresholds: [{outcome: allow, path: arguments.n, gt: 1}]}}",
    "{id: r, outcome: allow, when: {thresholds: [{outcome: deny, expr: 'arguments.n > 1', path: arguments.n}]}}",
    "{id: r, outcome: allow, when: {thresholds: [{outcome: deny}]}}",
    "{id: r, outcome: allow, when: {thresholds: [{outcome: deny, path: arguments.n}]}}",
    "{id: r, outcome: allow, when: {thresholds: [{outcome: deny, path: arguments.n, gt: 1, reason: bad}]}}",
    "{id: r, outcome: allow, when: {'bogus key': 1}}",
    "{id: r, outcome: allow, match: [1]}",
    "{id: r, outcome: allow, when: {any: []}}",
    "{id: r, outcome: allow, when: {any: 5}}",
    "{id: r, outcome: allow, when: {expr: 5}}",
    "{id: r, outcome: allow, when: {use: nope, with: {}}}",
    "{id: r, outcome: allow, when: {default: false}}",
    "{id: r, outcome: allow, when: {arguments.n: {}}}",
    "{id: r, outcome: allow, when: {arguments.n: {bogus: 1}}}",
    "{id: r, outcome: allow, when: {arguments.n: {exists: 1}}}",
    "{id: r, outcome: allow, when: {arguments.n: {between: [1]}}}",
    "{id: r, outcome: allow, when: {arguments.n: {between: [5, 1]}}}",
    "{id: r, outcome: allow, when: {arguments.n: {eq: {a: 1, b: 2, c: 3}, bogus: 1}}}",
    "{id: r, outcome: allow, when: {arguments.n: {eq: {bad: 1}}}}",
    "{id: r, outcome: allow, when: {arguments.n: {eq: null}}}",
    "{id: r, outcome: allow, when: {signal: 5}}",
    "{id: r, outcome: allow, when: {signal: {bogus: 1}}}",
    "{id: r, outcome: allow, when: {signal: {code: a, facts: {}}}}",
    "{id: r, outcome: allow, when: {signal: {code: a, facts: {k: 1.5}}}}",
    "{id: r, outcome: allow, when: {signal: {code: a, severity_gte: nope}}}",
    "{id: r, outcome: allow, when: {signal: {code: a, count_gte: 0}}}",
    "{id: r, outcome: allow, when: {signal: {code: a, confidence_gte: 2}}}",
    "{id: r, outcome: allow, when: {signal: {code: 'nope.thing/x y'}}}",
    "{id: r, outcome: allow, when: {time.window: 5}}",
    "{id: r, outcome: allow, when: {time.window: {from: '09:00'}}}",
    "{id: r, outcome: allow, when: {time.window: {from: '9:00', to: '17:00'}}}",
    "{id: r, outcome: allow, when: {time.window: {from: '09:00', to: '17:00', days: [xyz]}}}",
    "{id: r, outcome: allow, when: {time.window: {from: '09:00', to: '17:00', tz: Europe/Paris}}}",
    "{id: r, outcome: allow, when: {target: []}}",
    "{id: r, outcome: allow, when: {arguments_match: {}}}",
    "{id: r, outcome: allow, when: {domain_suffix: ''}}",
    "{id: r, outcome: allow, when: {arguments.n: {gt: {ref: 'arguments.m', extra: 1}}}}",
    "{id: r, outcome: allow, when: {'1bad': 1}}",
]


@pytest.mark.parametrize("rule", INVALID_RULES)
def test_invalid_rules_are_rejected(project: Project, rule: str) -> None:
    with pytest.raises(AuthoringError):
        project.policy(doc(rule))


VALID_RULES = [
    "{id: r, outcome: allow}",
    "{id: r, outcome: watch, description: d, priority: 3, enabled: false, mode: monitor, hint: {a: b}}",
    "{id: r, outcome: allow, match: {kind: [tool_call], action_uri: ['app:*'], target: ['t*']}}",
    "{id: r, outcome: allow, let: {a: '1 + 1', b: 'var.a * 2'}, when: {expr: 'var.b == 4'}}",
    "{id: r, outcome: deny, reason: RULE_DENY, explain: 'denied {arguments.n} {{x}} {signal.code} {signal.evidence.k}'}",
    "{id: r, outcome: allow, obligations: [{type: notify}, {type: acme/audit, params: {a: 1}}]}",
    "{id: r, outcome: modify, modify: {apply_suggested: true}}",
    "{id: r, outcome: modify, modify: {replace: {a: 1}}}",
    "{id: r, outcome: modify, modify: {edits: [{op: redact, json_pointer: /a}, {op: set, json_pointer: '', value: 1}]}}",
    "{id: r, outcome: allow, when: {all: [{arguments.n: 1}, {not: {arguments.m: 2}}], any: [{arguments.q: true}]}}",
    "{id: r, outcome: allow, when: {arguments.n: [1, 2, 3]}}",
    "{id: r, outcome: allow, when: {arguments.n: {gt: 1, lte: 10, ne: 5, negate: true}}}",
    "{id: r, outcome: allow, when: {arguments.n: {between: [1, 10]}, arguments.s: {in: [a, b], nin: [c]}}}",
    "{id: r, outcome: allow, when: {arguments.s: {glob: 'a*', sep: '/', case_insensitive: true, normalize: path}}}",
    "{id: r, outcome: allow, when: {arguments.s: {contains: x, starts_with: y, len_gt: 1, len_lt: 9, exists: true}}}",
    "{id: r, outcome: allow, when: {arguments.s: {regex: '^a+$'}}}",
    "{id: r, outcome: allow, when: {arguments.n: {gt: {ref: 'arguments.m'}}, arguments.s: {eq: {literal: x}}}}",
    "{id: r, outcome: allow, when: {arguments.n: {eq: {expr: 'arguments.m + 1'}}}}",
    "{id: r, outcome: allow, when: {arguments./a/b: {eq: 1}}}",
    "{id: r, outcome: allow, when: {default: true}}",
    "{id: r, outcome: allow, when: {}}",
    "{id: r, outcome: allow, when: {signal: {code: scan.x, severity_gte: high, count_gte: 2, confidence_gte: 0.5,"
    " source: s, facts: {k: [a, b], j: true}}}}",
    "{id: r, outcome: allow, when: {signal: {code_prefix: scan.}}}",
    "{id: r, outcome: allow, when: {time.window: {from: '09:00', to: '17:00', days: [mon, tue], tz: '+02:00'}}}",
    "{id: r, outcome: allow, when: {time: {window: {from: '22:00', to: '06:00'}}}}",
    "{id: r, outcome: allow, when: {command_matches: ['ls*'], path_matches: ['/a/**'], domain_matches: ['*.x'],"
    " url_matches: ['https://*'], response_matches: [x]}}",
    "{id: r, outcome: allow, when: {command_not_matches: [x], path_not_matches: [y], response_not_matches: z}}",
    "{id: r, outcome: allow, when: {arguments_match: {q: 'a*', r: 'b*'}, domain_suffix: example.com}}",
    "{id: r, outcome: allow, when: {deny: {arguments.n: {gt: 1}}, immutable_params: {a: 1}, "
    "bounded_params: {n: {min: 1, max: 5}}, max_calls_per_window: {limit: 3, window_seconds: 60}}}",
    "{id: r, outcome: ask, when: {approval: {timeout_seconds: 5, on_timeout: escalate, fatigue_threshold: 3,"
    " fatigue_window_seconds: 60}}}",
    "{id: r, outcome: allow, when: {thresholds: [{outcome: deny, path: arguments.n, gt: 5, reason: THRESHOLD_EXCEEDED},"
    " {outcome: watch, expr: 'arguments.n > 2'}, {outcome: watch, path: arguments.m, exists: true}]}}",
    "{id: r, outcome: allow, when: {arguments.n: {eq: 1.5}, arguments.s: {eq: ''}, arguments.b: {eq: true}}}",
]


@pytest.mark.parametrize("rule", VALID_RULES)
def test_accepted_rule_forms(project: Project, rule: str) -> None:
    project.policy(doc(rule))
