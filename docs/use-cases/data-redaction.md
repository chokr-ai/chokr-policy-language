---
title: Data Redaction
description: Remove personal data and secrets from what an agent sends or receives, instead of blocking the whole action.
---

Blocking is the blunt tool. Often the action is fine once a card number or an email address is gone. The `modify` outcome returns the edits, and your application applies them. This page covers messages that leave and replies that come back.

Scanners find the data and report signals. The policy decides what each kind of data means.

## Redact Before Sending

A message is allowed once personal data is masked. Card numbers are never sent, even masked:

```yaml
cpl: "1.0"
id: outbound-messages
version: 1
default: deny
rules:
  - id: send-messages
    match: {kind: [message]}
    when: {actor.type: agent}
    outcome: allow

  - id: mask-emails
    match: {kind: [message]}
    when: {signal: {code: pii.email}}
    outcome: modify
    modify:
      edits:
        - {op: redact, json_pointer: /arguments/body, placeholder: "[email removed]"}
    obligations:
      - {type: notify, params: {channel: privacy-log}}

  - id: no-card-numbers
    match: {kind: [message]}
    when: {signal: {code: pii.card, confidence_gte: 0.7}}
    outcome: deny
    explain: "Card numbers must never leave."
```
{: data-title="outbound-messages.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: clean-message
    action: {kind: message, actor: {type: agent}, arguments: {body: "Your order has shipped."}}
    expect: {outcome: allow}

  - name: message-with-an-email
    action: {kind: message, actor: {type: agent}, arguments: {body: "Contact bob@example.test"}}
    signals: [{code: pii.email, source: scanner, severity: medium}]
    expect: {outcome: modify, matched_rules: [mask-emails, send-messages]}

  - name: message-with-a-card
    action: {kind: message, actor: {type: agent}, arguments: {body: "Card 4111 1111 1111 1111"}}
    signals: [{code: pii.card, source: scanner, severity: critical, confidence: 0.99}]
    expect: {outcome: deny, matched_rules: [no-card-numbers, send-messages]}

  - name: email-and-card-in-one-message
    action: {kind: message, actor: {type: agent}, arguments: {body: "bob@example.test 4111 1111 1111 1111"}}
    signals:
      - {code: pii.email, severity: medium}
      - {code: pii.card, severity: critical, confidence: 0.99}
    expect: {outcome: deny}
```
{: data-title="outbound-messages.fixtures.yaml"}

The last case shows how outcomes combine: `deny` is stronger than `modify`, so the card number wins and no edits are returned.

## Apply the Edits

The engine returns the edits and your application applies them. A small helper does it for the three operations you will use most:

```python
import copy
from pathlib import Path

from cplang import Action, RuleEvaluator, Signal, load_policy


def apply(document: dict, edits: list[dict]) -> dict:
    result = copy.deepcopy(document)
    for edit in edits:
        *path, last = edit["json_pointer"].strip("/").split("/")
        node = result
        for part in path:
            node = node[part]
        if edit["op"] == "drop_field":
            node.pop(last, None)
        elif edit["op"] == "redact":
            node[last] = edit.get("placeholder", "[redacted]")
        else:
            node[last] = edit["value"]
    return result


evaluator = RuleEvaluator(load_policy([Path("outbound-messages.policy.yaml")], roots=[Path(".")]))
message = {
    "kind": "message",
    "actor": {"type": "agent"},
    "arguments": {"body": "Contact bob@example.test"},
    "timestamp": "2026-01-05T10:00:00Z",
}
verdict = evaluator.evaluate(Action(message), [Signal(code="pii.email", source="scanner", severity="medium")])
if verdict.outcome == "modify" and verdict.modifications:
    message = apply(message, list(verdict.modifications["edits"]))
print(verdict.outcome, "->", message["arguments"]["body"])
print("duties:", [duty["type"] for duty in verdict.obligations])
```
{: data-title="redact.py"}

```console
modify -> [email removed]
duties: ['notify']
```
{: data-output="redact.py"}

Send the edited message. Perform the duties, here a note in the privacy log.

## Check Replies

Data also comes back: a tool reply can contain a key, a token or a record that the agent should not see. Evaluate the reply with `evaluate_result`. See [Embedding](/embedding/).

```yaml
cpl: "1.0"
id: replies
version: 1
default: allow
rules:
  - id: no-keys-in-replies
    match: {kind: [tool_call]}
    when:
      response_matches: ["*BEGIN PRIVATE KEY*", "*AKIA[0-9A-Z]*"]
    outcome: deny
    reason: RULE_DENY

  - id: mask-emails-in-replies
    match: {kind: [tool_call]}
    when: {signal: {code: pii.email}}
    outcome: modify
    modify:
      edits:
        - {op: redact, json_pointer: /arguments/response, placeholder: "[removed]"}
```
{: data-title="replies.policy.yaml"}

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, Signal, load_policy

evaluator = RuleEvaluator(load_policy([Path("replies.policy.yaml")], roots=[Path(".")]))
base = {"kind": "tool_call", "arguments": {"query": "config"}, "timestamp": "2026-01-05T10:00:00Z"}


def check(response: str, signals: list[Signal]) -> str:
    action = Action({**base, "arguments": {**base["arguments"], "response": response}})
    return evaluator.evaluate_result(action, signals).outcome


print(check("db_user=app", []))
print(check("-----BEGIN PRIVATE KEY-----", []))
print(check("mail bob@example.test", [Signal(code="pii.email", severity="low")]))
```
{: data-title="replies.py"}

```console
allow
deny
modify
```
{: data-output="replies.py"}

`response_matches` compares text. A reply that is not text is an error and the verdict is a `deny`, so turn a structured reply into a string before you evaluate it.

## Ask for Bulk Exports

Redaction works for single records. A bulk export needs a person, even when every field is clean:

```yaml
cpl: "1.0"
id: exports
version: 1
default: deny
rules:
  - id: small-exports
    match: {kind: [export]}
    when: {expr: "arguments.rows <= 1000"}
    outcome: allow

  - id: large-exports-need-approval
    match: {kind: [export]}
    when:
      expr: "arguments.rows > 1000"
      approval: {timeout_seconds: 3600}
    outcome: ask
    obligations:
      - {type: redact, params: {fields: [email, phone]}}
```
{: data-title="exports.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: small-export
    action: {kind: export, arguments: {rows: 200}}
    expect: {outcome: allow}

  - name: large-export
    action: {kind: export, arguments: {rows: 50000}}
    expect: {outcome: ask}
```
{: data-title="exports.fixtures.yaml"}

The `redact` obligation tells the application which fields to remove if the person approves.

> ▶ Next: [Safe Rollout](/use-cases/rollout/)
{: .next}
