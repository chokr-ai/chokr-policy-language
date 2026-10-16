---
title: Limits and Guards
description: Bound amounts, fix parameters, cap call rates and refuse risky values with guards on a rule.
---

A guard is a check that runs after a rule applies. Rules with an `allow` outcome carry most guards. When a guard trips, the rule stops granting and the verdict becomes `deny` (or `ask` for a threshold that asks).

```yaml
cpl: "1.0"
id: limits-intro
version: 1
default: deny
rules:
  - id: pay-within-limits
    match: {kind: [payment]}
    when:
      bounded_params: {amount: {min: 1, max: 1000}}
    outcome: allow
```
{: data-title="intro.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: inside-the-bounds
    action: {kind: payment, arguments: {amount: 250}}
    expect: {outcome: allow}

  - name: above-the-bounds
    action: {kind: payment, arguments: {amount: 5000}}
    expect: {outcome: deny, reason_codes: [PARAM_OUT_OF_BOUNDS]}

  - name: no-amount-at-all
    action: {kind: payment}
    expect: {outcome: deny, reason_codes: [PARAM_OUT_OF_BOUNDS]}
```
{: data-title="intro.fixtures.yaml"}

A guard keeps the rule's conditions simple. The condition says when the rule applies, and the guard says what must also be true. A missing value never passes a guard, as the last case shows.

## Guards at a Glance

| Guard | Trips when | Reason code |
| --- | --- | --- |
| `deny` | The condition is true | `ACTION_FORBIDDEN` or your `reason` |
| `immutable_params` | A named argument is missing or differs | `PARAM_IMMUTABLE_VIOLATION` |
| `bounded_params` | A named number is missing or outside `min` and `max` | `PARAM_OUT_OF_BOUNDS` |
| `max_calls_per_window` | The actor made too many calls | `RATE_LIMIT_EXCEEDED` |
| `thresholds` | A listed check trips | `THRESHOLD_EXCEEDED` or the entry's `reason` |

Guards run in this order, and the first one that trips decides: `deny`, `immutable_params`, `bounded_params`, `max_calls_per_window`, `thresholds`.

## Refuse a Condition

`deny` takes any condition. Use it for a combination that must never pass even when the rule would otherwise apply:

```yaml
cpl: "1.0"
id: refuse
version: 1
default: deny
rules:
  - id: transfers
    match: {kind: [transfer]}
    when:
      target: ledger
      deny:
        any:
          - arguments.currency: {nin: [usd, eur]}
          - expr: "arguments.to == arguments.from"
    outcome: allow
```
{: data-title="refuse.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: normal-transfer
    action: {kind: transfer, target: {name: ledger}, arguments: {currency: usd, from: a, to: b}}
    expect: {outcome: allow}

  - name: transfer-to-self
    action: {kind: transfer, target: {name: ledger}, arguments: {currency: usd, from: a, to: a}}
    expect: {outcome: deny, reason_codes: [ACTION_FORBIDDEN]}

  - name: unknown-currency
    action: {kind: transfer, target: {name: ledger}, arguments: {currency: gbp, from: a, to: b}}
    expect: {outcome: deny, reason_codes: [ACTION_FORBIDDEN]}

  - name: currency-left-out
    action: {kind: transfer, target: {name: ledger}, arguments: {from: a, to: b}}
    expect: {outcome: deny, reason_codes: [ACTION_FORBIDDEN]}
```
{: data-title="refuse.fixtures.yaml"}

The last case matters. A `deny` guard on a field the action does not carry denies, so leaving a field out never skips a check. To let a missing field through, test for it first:

```yaml
deny:
  all:
    - arguments.currency: {exists: true}
    - arguments.currency: {nin: [usd, eur]}
```

## Fix and Bound Parameters

`immutable_params` lists arguments that must equal a given value. `bounded_params` lists numeric arguments with a `min`, a `max` or both. Names are argument names, or a JSON pointer such as `/options/retries` for nested ones.

```yaml
cpl: "1.0"
id: params
version: 1
default: deny
rules:
  - id: db-query
    match: {kind: [tool_call]}
    when:
      target: database
      immutable_params: {mode: read_only, /options/timeout_ms: 5000}
      bounded_params: {limit: {max: 100}}
    outcome: allow
```
{: data-title="params.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: as-configured
    action:
      kind: tool_call
      target: {name: database}
      arguments: {mode: read_only, limit: 50, options: {timeout_ms: 5000}}
    expect: {outcome: allow}

  - name: the-agent-changed-the-mode
    action:
      kind: tool_call
      target: {name: database}
      arguments: {mode: read_write, limit: 50, options: {timeout_ms: 5000}}
    expect: {outcome: deny, reason_codes: [PARAM_IMMUTABLE_VIOLATION]}

  - name: limit-too-high
    action:
      kind: tool_call
      target: {name: database}
      arguments: {mode: read_only, limit: 500, options: {timeout_ms: 5000}}
    expect: {outcome: deny, reason_codes: [PARAM_OUT_OF_BOUNDS]}
```
{: data-title="params.fixtures.yaml"}

## Limit the Call Rate

`max_calls_per_window` allows at most `limit` calls per `window_seconds` for each actor. The count is kept per policy, rule and `actor.subject`.

```yaml
cpl: "1.0"
id: rate
version: 1
default: deny
rules:
  - id: search
    match: {kind: [tool_call]}
    when:
      target: web_search
      max_calls_per_window: {limit: 2, window_seconds: 60}
    outcome: allow
```
{: data-title="rate.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: first-call
    action: {kind: tool_call, target: {name: web_search}, actor: {subject: agent-1}}
    expect: {outcome: allow}
```
{: data-title="rate.fixtures.yaml"}

The counter lives in the evaluator, in memory, and a call is counted when the rule applies. The commands `cplang test`, `cplang eval` and `cplang policy explain` only peek at the count and never use it up, so a fixture always sees the first call. To see the limit work, call an evaluator from Python:

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, load_policy

evaluator = RuleEvaluator(load_policy([Path("rate.policy.yaml")], roots=[Path(".")]))


def call(subject: str) -> str:
    action = Action(
        {
            "kind": "tool_call",
            "target": {"name": "web_search"},
            "actor": {"subject": subject},
            "timestamp": "2026-01-05T10:00:00Z",
        }
    )
    verdict = evaluator.evaluate(action, [])
    return f"{subject}: {verdict.outcome} {verdict.reason_codes[0]}"


for subject in ("agent-1", "agent-1", "agent-1", "agent-2"):
    print(call(subject))
```
{: data-title="rate_demo.py"}

```console
agent-1: allow POLICY_SATISFIED
agent-1: allow POLICY_SATISFIED
agent-1: deny RATE_LIMIT_EXCEEDED
agent-2: allow POLICY_SATISFIED
```
{: data-output="rate_demo.py"}

Each actor has its own count. Share one evaluator across requests, because a new evaluator starts every count from zero. To keep counts in a shared store, give the evaluator your own limiter. See [Embedding](/embedding/).

> Window sizes are measured on the action's `timestamp`, not on the clock of the machine.
{: .note}

## Thresholds

`thresholds` is a list of checks, each with its own outcome. Use it for graded limits, such as "ask above 500, refuse above 1000". An entry names a `path` and one operator, or uses an `expr`.

```yaml
cpl: "1.0"
id: graded
version: 1
default: deny
rules:
  - id: payments
    match: {kind: [payment]}
    when:
      approval: {timeout_seconds: 900}
      thresholds:
        - {path: arguments.amount, gt: 1000, outcome: deny, reason: THRESHOLD_EXCEEDED}
        - {path: arguments.amount, gt: 500, outcome: ask}
        - {expr: "arguments.items > 20", outcome: watch}
    outcome: allow
```
{: data-title="graded.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: small
    action: {kind: payment, arguments: {amount: 100, items: 2}}
    expect: {outcome: allow}

  - name: mid-sized-needs-a-person
    action: {kind: payment, arguments: {amount: 700, items: 2}}
    expect: {outcome: ask}

  - name: huge
    action: {kind: payment, arguments: {amount: 5000, items: 2}}
    expect: {outcome: deny, reason_codes: [THRESHOLD_EXCEEDED]}

  - name: many-items-are-flagged
    action: {kind: payment, arguments: {amount: 100, items: 30}}
    expect: {outcome: watch}
```
{: data-title="graded.fixtures.yaml"}

When several entries trip, the strongest wins: `deny`, then `ask`, then `watch`. A threshold only ever tightens a rule. It can turn `allow` into `ask`, but it can never loosen a `deny` rule. A threshold that asks needs an `approval` block next to it, as shown.

## Guards on a Response

A guard that reads `arguments.response` cannot be checked before the tool has run. The engine skips it in the first pass and checks it when you call `evaluate_result` with the response in place. See [Embedding](/embedding/).

> ▶ Next: [Modifying Actions](/modifying/)
{: .next}
