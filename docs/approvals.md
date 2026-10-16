---
title: Approvals
description: Pause an action until a person approves it, and carry follow-up duties in the verdict.
---

Use the `ask` outcome when a person should decide. The engine does not run the approval. It returns a verdict that says approval is needed, and your application collects the answer.

```yaml
cpl: "1.0"
id: approvals-intro
version: 1
default: deny
rules:
  - id: large-payments-need-a-person
    match: {kind: [payment]}
    when:
      expr: "arguments.amount > 100"
      approval: {timeout_seconds: 900}
    outcome: ask
```
{: data-title="intro.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: large-payment
    action: {kind: payment, arguments: {amount: 500}}
    expect:
      outcome: ask
      reason_codes: [RULE_ASK]
      obligations:
        - {type: human_approval, params: {approval: {timeout_seconds: 900, on_timeout: deny}}}
```
{: data-title="intro.fixtures.yaml"}

An `ask` rule must carry an `approval` block inside `when`. A policy without one does not load, so an approval can never be forgotten.

## The Approval Block

| Key | Meaning |
| --- | --- |
| `timeout_seconds` | How long the request stays open. Required, at least 1 |
| `on_timeout` | `deny` (default) or `escalate` |
| `fatigue_threshold` | How many requests before the host should slow the reviewer down |
| `fatigue_window_seconds` | The period over which those requests are counted |

`on_timeout: allow` is refused when the policy loads. A request that nobody answers must never turn into a grant.

```yaml
approval:
  timeout_seconds: 900
  on_timeout: escalate
  fatigue_threshold: 5
  fatigue_window_seconds: 3600
```

The engine copies the block into the verdict, so the application knows how long to wait and what to do when time runs out.

## Read the Obligation

An `ask` verdict has an obligation of type `human_approval`. Its `params.approval` holds your block:

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, load_policy

policy = load_policy([Path("intro.policy.yaml")], roots=[Path(".")])
verdict = RuleEvaluator(policy).evaluate(
    Action({"kind": "payment", "arguments": {"amount": 500}, "timestamp": "2026-01-05T10:00:00Z"}), []
)

if verdict.outcome == "ask":
    for duty in verdict.obligations:
        if duty["type"] == "human_approval":
            print("wait up to", duty["params"]["approval"]["timeout_seconds"], "seconds")
```
{: data-title="approve.py"}

```console
wait up to 900 seconds
```
{: data-output="approve.py"}

## Obligations

An obligation is a duty that comes with a verdict. Add your own to any rule with `obligations`:

```yaml
cpl: "1.0"
id: duties
version: 1
default: deny
rules:
  - id: large-payments-need-a-person
    match: {kind: [payment]}
    when:
      expr: "arguments.amount > 100"
      approval: {timeout_seconds: 900}
    outcome: ask
    obligations:
      - {type: notify, params: {channel: finance}}

  - id: small-payments-are-logged
    match: {kind: [payment]}
    when: {expr: "arguments.amount <= 100"}
    outcome: allow
    obligations:
      - {type: notify, params: {channel: ledger}}
```
{: data-title="duties.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: small-payment-notifies-the-ledger
    action: {kind: payment, arguments: {amount: 20}}
    expect:
      outcome: allow
      obligations:
        - {type: notify, params: {channel: ledger}}
```
{: data-title="duties.fixtures.yaml"}

| Type | Meaning |
| --- | --- |
| `human_approval` | Added by the engine to an `ask` verdict |
| `redact` | Remove or mask data before it is used |
| `notify` | Tell someone, with `params` naming where |
| `namespace/name` | A duty your own application defines, such as `acme/page_oncall` |

The engine reports obligations and never performs them. Your application does the work. An obligation of type `human_approval` is only reported when the final outcome is `ask`.

## Thresholds That Ask

A threshold can raise a verdict to `ask` when a value passes a limit. It needs an `approval` block as well. See [Limits and Guards](/limits/).

> ▶ Next: [Limits and Guards](/limits/)
{: .next}
