---
title: Action
description: The fields of an action that rules can read, and the signal and fixture documents that travel with it.
---

An action is a JSON-like document that describes one thing about to happen. Only `timestamp` is required. You may add any other field, and declare it as an input to give it a type. See [Declarations](/declarations/).

```yaml
id: act-1001
timestamp: "2026-01-05T10:00:00Z"
kind: tool_call
action_uri: "tools:send_payment"
target:
  name: payments
  method: POST
  destination_host: api.bank.example
actor: {type: agent, subject: agent-7}
resource: {type: invoice, id: INV-9, owner: team-finance}
environment: {env: prod}
arguments: {amount: 250, currency: usd}
```
{: data-title="payment.action.yaml"}

```console
$ cplang eval --policy payment.policy.yaml --action payment.action.yaml
```

## Standard Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `timestamp` | string, RFC 3339 | The moment of the action. Required. It is `time.now` |
| `id` | string | An identifier, copied to the verdict as `action_id` |
| `kind` | string | What sort of action this is, such as `tool_call` or `read` |
| `action_uri` | string | A name for the exact operation |
| `target.name` | string | The tool, service or system acted on |
| `target.protocol` | string | The protocol used |
| `target.server` | string | The server hosting the target |
| `target.resource` | string | The resource within the target |
| `target.destination_host` | string | The host a request goes to |
| `target.method` | string | The method of a request |
| `target.path` | string | The path of a request |
| `actor.type` | string | What sort of actor: a person, an agent, a service |
| `actor.subject` | string | The identity of the actor. Rate limits count per subject |
| `environment.env` | string | The environment, such as `prod` |
| `resource.type` | string | The kind of resource acted on |
| `resource.id` | string | The identifier of the resource |
| `resource.owner` | string | The owner of the resource |
| `resource.count` | integer | How many items the action touches |
| `audience` | string | Who the result is for |
| `depth` | integer | How deep in a chain of agent calls this action is |
| `arguments` | object | The arguments of the call, as the tool receives them |
| `arguments.response` | any | The tool's reply. It exists only after the call |
| `attributes` | object | Declared attributes, such as a classification |
| `origin`, `state`, `context`, `ext`, `call_chain` | any | Host-defined data. The engine does not interpret them |

A field that is not present is absent. `target` is an object, and the `target` shortcut compares `target.name`.

## Signals

A signal is passed beside the action, never inside it.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `code` | string | required | The name of the finding |
| `source` | string | `host` | Who reported it |
| `severity` | `info`, `low`, `medium`, `high`, `critical` | `high` | How serious it is |
| `confidence` | number from 0 to 1 | `1.0` | How sure the reporter is |
| `facts` | mapping | | Details that rules can test |
| `evidence` | mapping | | Material for people. Rules never read it |
| `suggested_modification` | edit | | An edit for `apply_suggested` |
| `id` | string | | An identifier |

Pass signals in a file with `cplang eval --signals signals.yaml`:

```yaml
- code: scan.malware
  source: scanner
  severity: high
  confidence: 0.98
  facts: {family: macro}
```
{: data-title="signals.yaml"}

## Fixture Files

A fixture file wraps actions and expectations, see [Testing Policies](/testing/). Inside a fixture, an action may leave out `timestamp`, and the `now` of the file fills it in. With `cplang eval`, use `--now` for the same effect.

## JSON Schemas

```console
$ cplang schema action
```

Prints the JSON Schema of an action. The schemas of `signal`, `verdict`, `fixtures` and `policy` print the same way.

> ▶ Next: [Verdict](/reference/verdict/)
{: .next}
