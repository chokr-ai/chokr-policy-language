---
title: Verdict
description: The fields of a verdict, the reason codes and what each outcome asks of your application.
---

A verdict is the decision for one action. Print it with `cplang eval --json`, or call `verdict.to_wire()` in Python. The JSON Schema is `cplang schema verdict`.

```json
{
  "outcome": "ask",
  "action_id": "act-1001",
  "verdict_id": "ver_01M523WSA8JM5GP2K0AW1207CE",
  "matched_rules": ["large-payments-need-a-human"],
  "reasons": [
    {"code": "RULE_ASK", "source": "rule:large-payments-need-a-human", "message": "A policy rule requires approval for this action."}
  ],
  "reason_codes": ["RULE_ASK"],
  "explanation": "A policy rule requires approval for this action.",
  "hint": {"code": "RULE_ASK", "message": "A policy rule requires approval for this action.", "next_steps": [{"kind": "request_approval"}]},
  "obligations": [
    {"type": "human_approval", "params": {"approval": {"timeout_seconds": 900, "on_timeout": "deny"}}}
  ],
  "modifications": null,
  "risk_tier": "standard",
  "policy": {"id": "agent-tool-calls", "version": 1, "fingerprint": "sha256:..."},
  "input_digest": "sha256:...",
  "would_block": false,
  "would_have_been": null
}
```

## Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `outcome` | `allow`, `watch`, `modify`, `ask`, `deny` | The decision |
| `action_id` | string | The `id` of the action, or an empty string |
| `verdict_id` | string | A unique identifier of this verdict |
| `matched_rules` | list of strings | The ids of the rules that applied, sorted |
| `reasons` | list | `{code, source, message}` for each reason |
| `reason_codes` | list of strings | The codes of `reasons`, strongest first |
| `explanation` | string or null | Text for the operator |
| `hint` | object or null | Guidance for the caller: `code`, `message`, `next_steps` |
| `obligations` | list | `{type, params}` duties for your application |
| `modifications` | object or null | `{edits}` or `{replace}` for a `modify` verdict |
| `risk_tier` | string or null | The label from the policy's risk tiers |
| `policy` | object | `{id, version, fingerprint}` of the policy that decided |
| `input_digest` | string | A `sha256:` digest of the canonical action |
| `would_block` | boolean | True when monitor mode held back a blocking outcome |
| `would_have_been` | string or null | The outcome monitor mode held back |

A `reason` has a `source` that tells where it came from: `rule:<id>` for a rule, `core` for the engine itself and `signal:<source>` for a signal effect of the host.

## What Each Outcome Asks of You

| Outcome | Your application |
| --- | --- |
| `allow` | Carry on |
| `watch` | Carry on, and record the action for review |
| `modify` | Apply `modifications`, then carry on with the changed action |
| `ask` | Pause. Start the approval in the `human_approval` obligation |
| `deny` | Stop. Give `hint` to the caller |

Perform every obligation that comes with the verdict. The engine reports duties and never performs them.

## Reason Codes

| Code | Meaning |
| --- | --- |
| `POLICY_SATISFIED` | The policy allows this action |
| `POLICY_ADVISORY` | The action is allowed with a flag, or with edits |
| `RULE_ASK` | A rule requires approval |
| `RULE_DENY` | A rule denies the action |
| `NO_MATCHING_RULE` | No rule applied, so the default decided |
| `ACTION_FORBIDDEN` | A `deny` guard tripped |
| `PARAM_IMMUTABLE_VIOLATION` | A fixed argument was changed or is missing |
| `PARAM_OUT_OF_BOUNDS` | A bounded argument is out of range or missing |
| `RATE_LIMIT_EXCEEDED` | The actor made too many calls |
| `THRESHOLD_EXCEEDED` | A threshold tripped |
| `MONITOR_WOULD_BLOCK` | Monitor mode held back a blocking outcome |
| `EVALUATION_ERROR` | The policy could not be evaluated, so the action is refused |

Your declarations can add namespaced codes such as `acme.finance/OVER_BUDGET`.

## Hints and Trust

`explanation` is for the operator and may contain values from the action. `hint.message` goes back to the caller, so values that came from the action are replaced with `[withheld]`. `evidence` of a signal is never copied into text for the caller.

## Fingerprint and Digest

`policy.fingerprint` identifies the exact compiled policy: its rules, declarations, parameters and the host functions it uses. `input_digest` identifies the exact action. Store both with the verdict to replay a decision later and get the same answer.

> ▶ Next: [Command Line](/reference/cli/)
{: .next}
