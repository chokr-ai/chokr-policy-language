---
title: Modifying Actions
description: Return edits that remove, mask or replace parts of an action so it can go ahead safely.
---

Use the `modify` outcome when an action is acceptable once part of it is removed or changed. The engine does not change anything. It returns the edits, and your application applies them before it carries on.

```yaml
cpl: "1.0"
id: redact
version: 1
default: allow
rules:
  - id: mask-card-numbers
    match: {kind: [message]}
    when: {signal: {code: pii.card}}
    outcome: modify
    modify:
      edits:
        - {op: redact, json_pointer: /arguments/body, placeholder: "[card removed]"}
```
{: data-title="redact.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: card-number-in-a-message
    action: {kind: message, arguments: {body: "card 4111 1111 1111 1111"}}
    signals: [{code: pii.card, severity: high}]
    expect: {outcome: modify, reason_codes: [POLICY_ADVISORY]}

  - name: clean-message
    action: {kind: message, arguments: {body: "hello"}}
    expect: {outcome: allow}
```
{: data-title="redact.fixtures.yaml"}

A `modify` rule must carry a `modify` block. It holds exactly one of `edits`, `replace` or `apply_suggested`.

## Edits

`edits` is a list of changes. Each names a JSON pointer, which is a `/`-separated path into the action such as `/arguments/body`:

| Operation | Needs | Effect |
| --- | --- | --- |
| `redact` | `json_pointer`, optional `placeholder` | Replace the value with a placeholder |
| `replace` | `json_pointer`, `value` | Replace the value |
| `set` | `json_pointer`, `value` | Set the value, creating it when it is missing |
| `drop_field` | `json_pointer` | Remove the field |

```yaml
cpl: "1.0"
id: edits
version: 1
default: allow
rules:
  - id: clean-outgoing-message
    match: {kind: [message]}
    when: {signal: {code: pii.card}}
    outcome: modify
    modify:
      edits:
        - {op: redact, json_pointer: /arguments/body, placeholder: "[card removed]"}
        - {op: drop_field, json_pointer: /arguments/attachment}
        - {op: set, json_pointer: /arguments/channel, value: internal}
```
{: data-title="edits.policy.yaml"}

Read the edits from the verdict and apply them:

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, Signal, load_policy

evaluator = RuleEvaluator(load_policy([Path("edits.policy.yaml")], roots=[Path(".")]))
action = Action(
    {
        "kind": "message",
        "timestamp": "2026-01-05T10:00:00Z",
        "arguments": {"body": "card 4111", "attachment": "scan.png", "channel": "external"},
    }
)
verdict = evaluator.evaluate(action, [Signal(code="pii.card")])
print(verdict.outcome)
for edit in (verdict.modifications or {}).get("edits", []):
    print(edit["op"], edit["json_pointer"])
```
{: data-title="apply.py"}

```console
modify
drop_field /arguments/attachment
redact /arguments/body
set /arguments/channel
```
{: data-output="apply.py"}

The edits come back sorted by pointer, so the same verdict always lists them in the same order.

## Replace the Whole Action

`replace` gives a complete new action. Use it when the safe form is easier to write than a list of edits:

```yaml
modify: {replace: {kind: export, arguments: {rows: 10}}}
```

## Take the Scanner's Suggestion

A signal can carry a `suggested_modification`. Use `apply_suggested: true` to adopt the suggestion of every signal that matched the rule:

```yaml
cpl: "1.0"
id: suggested
version: 1
default: allow
rules:
  - id: use-the-scanner-fix
    match: {kind: [note]}
    when: {signal: {code_prefix: "pii."}}
    outcome: modify
    modify: {apply_suggested: true}
```
{: data-title="suggested.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: scanner-suggests-a-redaction
    action: {kind: note, arguments: {body: "mail bob@example.test"}}
    signals:
      - code: pii.email
        severity: medium
        suggested_modification: {op: redact, json_pointer: /arguments/body, placeholder: "[email]"}
    expect: {outcome: modify}
```
{: data-title="suggested.fixtures.yaml"}

## Conflicts Refuse

When rules ask for changes that touch the same part of the action, the engine cannot choose between them. Edits whose pointers overlap, a `replace` beside any other change, and a `modify` that ends up with no change at all all produce a `deny` with the reason `EVALUATION_ERROR`:

```yaml
cpl: "1.0"
id: conflict
version: 1
default: allow
rules:
  - id: drop-all-arguments
    match: {kind: [message]}
    outcome: modify
    modify: {edits: [{op: drop_field, json_pointer: /arguments}]}

  - id: mask-the-body
    match: {kind: [message]}
    when: {arguments.body: {exists: true}}
    outcome: modify
    modify: {edits: [{op: redact, json_pointer: /arguments/body}]}
```
{: data-title="conflict.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: overlapping-edits-are-refused
    action: {kind: message, arguments: {body: hello}}
    expect: {outcome: deny, reason_codes: [EVALUATION_ERROR, POLICY_ADVISORY, POLICY_ADVISORY]}
```
{: data-title="conflict.fixtures.yaml"}

Keep edits for one field in one rule, and the problem never appears.

## Modify Beside Other Outcomes

`modify` ranks above `allow` and `watch`, and below `ask` and `deny`. When another rule asks or denies, that outcome wins and the edits are dropped.

> ▶ Next: [Combining Rules](/decisions/)
{: .next}
