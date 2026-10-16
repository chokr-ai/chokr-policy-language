---
title: Policy File
description: Every key of a policy file, a rule, an approval block, a threshold and an import.
---

A policy file is a YAML or JSON document. This page lists every key. For tutorials, see [Basics](/basics/) and [Rules](/rules/).

```yaml
cpl: "1.0"
id: reference-example
version: 1
description: One of every kind of rule.
default: deny
strategy: deny_overrides
default_risk_tier: routine
risk_tiers:
  - id: critical
    when: {arguments.amount: {gt: 10000}}
rules:
  - id: small-spend
    description: Small spends are allowed.
    priority: 0
    enabled: true
    match: {kind: [spend]}
    let: {limit: "100"}
    when:
      expr: "arguments.amount <= var.limit"
      bounded_params: {amount: {min: 1}}
    outcome: allow
    reason: POLICY_SATISFIED
    explain: "Spend of {arguments.amount} is within {var.limit}."
    hint: {next_steps: [{kind: continue}]}
    obligations:
      - {type: notify, params: {channel: ledger}}
```
{: data-title="reference.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: small-spend
    action: {kind: spend, arguments: {amount: 50}}
    expect: {outcome: allow, matched_rules: [small-spend], risk_tier: routine}
```
{: data-title="reference.fixtures.yaml"}

## Top-Level Keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `cpl` | string | required | The language version, `"1.0"` |
| `id` | string | | The name of the policy, reported in every verdict |
| `version` | integer or string | | The version of the policy, reported in every verdict |
| `description` | string | | Free text |
| `default` | `allow`, `deny` | `deny` | The outcome when no rule applies |
| `strategy` | `deny_overrides`, `first_match`, `priority` | `deny_overrides` | How outcomes combine |
| `mode` | `enforce`, `monitor` | `enforce` | Report instead of block |
| `rules` | list | | The rules, at most 4096 |
| `imports` | list | | Files to import, see below |
| `vocabulary` | string | | Short form for a single import |
| `params` | mapping | | Values for declared parameters |
| `conditions` | mapping | | Named conditions, `{params?, when}` |
| `risk_tiers` | list | | `{id, when}` entries, first match wins |
| `default_risk_tier` | string | `standard` | The tier when none matches |
| `fragment` | boolean | `false` | Marks a file of shared rules |
| `ext` | mapping | | Free data the engine ignores |

A fragment cannot set `default`, `strategy` or `mode`. A policy set has exactly one file that is not a fragment.

## Rule Keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | string | required | Letters, digits, `.`, `_`, `-`; unique; at most 128 characters |
| `outcome` | `allow`, `watch`, `modify`, `ask`, `deny` | required | The result when the rule applies |
| `description` | string | | Free text |
| `match` | mapping | applies to all | Selects actions. Lists are lists of patterns |
| `when` | mapping | always true | Conditions and guards |
| `let` | mapping | | Named values read as `var.name` |
| `reason` | string | outcome's standard code | A reason code for the verdict |
| `explain` | string | | Text for the operator, with `{placeholders}` |
| `hint` | mapping | | Guidance for the caller: `message`, `next_steps` |
| `modify` | mapping | | Required with `modify`, forbidden otherwise |
| `obligations` | list | | `{type, params?}` duties |
| `priority` | integer | `0` | Order under the `priority` strategy |
| `enabled` | boolean | `true` | Switch a rule off |
| `mode` | `enforce`, `monitor` | policy's mode | Report instead of block |
| `ext` | mapping | | Free data the engine ignores |

## Keys of `when`

Any [condition](/reference/conditions/) can appear in `when`. These keys are guards and are allowed only here:

| Key | Value |
| --- | --- |
| `deny` | A condition. The rule denies when it is true |
| `immutable_params` | `{name: value}`. Each argument must equal its value |
| `bounded_params` | `{name: {min?, max?}}`. Each argument must be a number in range |
| `max_calls_per_window` | `{limit, window_seconds}`, integers of at least 1 |
| `thresholds` | A list of threshold entries |
| `approval` | An approval block |

### Approval Block

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `timeout_seconds` | integer | required | How long the request stays open, at least 1 |
| `on_timeout` | `deny`, `escalate` | `deny` | What happens when nobody answers |
| `fatigue_threshold` | integer | | Requests per window before the host slows the reviewer |
| `fatigue_window_seconds` | integer | | The window of `fatigue_threshold` |

### Threshold Entry

| Key | Meaning |
| --- | --- |
| `outcome` | `deny`, `ask` or `watch`. Required |
| `reason` | A reason code. Default `THRESHOLD_EXCEEDED` |
| `path` and an operator | Compare a path, for example `{path: arguments.amount, gt: 500}` |
| `expr` | A boolean expression, instead of `path` and an operator |

## Keys of `modify`

Exactly one of:

| Key | Value |
| --- | --- |
| `edits` | A non-empty list of `{op, json_pointer, value?, placeholder?}` |
| `replace` | A mapping that replaces the whole action |
| `apply_suggested` | `true`. Adopts the suggestions of matching signals |

`op` is `redact`, `replace`, `set` or `drop_field`. `json_pointer` is `""` or starts with `/`.

## Keys of an Import

| Key | Type | Meaning |
| --- | --- | --- |
| `from` | string | A relative path. Required |
| `only` | list of strings | The names to take |
| `as` | string | An alias for the names |
| `with` | mapping | Values for the file's parameters |
| `digest` | string | The expected `sha256:` digest |
| `rename` | mapping | Attribute renames, `{old: new}` |

## Obligation Types

`human_approval`, `redact` and `notify` are built in. A custom type is written `namespace/name`, for example `acme/page_oncall`.

## Strategies

| Strategy | Rules evaluated | Decides |
| --- | --- | --- |
| `deny_overrides` | All | The strongest outcome |
| `first_match` | In written order, until one applies | The first rule that applies |
| `priority` | By `priority`, highest first, ties in written order, until one applies | The first rule that applies |

## Outcome Strength

| Outcome | Rank | Standard reason code |
| --- | --- | --- |
| `allow` | 0 | `POLICY_SATISFIED` |
| `watch` | 1 | `POLICY_ADVISORY` |
| `modify` | 2 | `POLICY_ADVISORY` |
| `ask` | 3 | `RULE_ASK` |
| `deny` | 4 | `RULE_DENY` |

## Documents Next to Policies

| Document | `schema` | Described in |
| --- | --- | --- |
| Declarations | `cpl.declarations/1.0` | [Declarations](/declarations/) |
| Fixtures | `cpl.fixtures/1.0` | [Testing Policies](/testing/) |

Every document has a JSON Schema: `cplang schema policy`, `action`, `signal`, `verdict` and `fixtures`.

> ▶ Next: [Conditions](/reference/conditions/)
{: .next}
