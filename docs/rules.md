---
title: Rules
description: The parts of a rule, from the id to the outcome, with a tested example of each.
---

A policy is an ordered list of rules. Each rule answers one question: for this kind of action, under these conditions, what should happen?

```yaml
cpl: "1.0"
id: spending
version: 1
default: allow
rules:
  - id: big-spend
    description: Spending above the limit is refused.
    match: {kind: [tool_call]}
    let:
      amount: "arguments.amount"
      over: "arguments.amount - 100"
    when:
      expr: "var.amount > 100"
    outcome: deny
    explain: "Spend of {var.amount} is over the limit by {var.over}."
```
{: data-title="spending.policy.yaml"}

Only `id` and `outcome` are required. Every other key narrows when the rule applies or describes what it does.

## Identify a Rule

### id

Give every rule a stable `id` made of letters, digits, dots, underscores and hyphens. Verdicts report the ids of the rules that decided, and tests refer to them, so do not rename a rule without a reason.

```yaml
- id: big-spend
```

Ids must be unique inside a policy. The check fails on a duplicate.

### description

`description` is free text for people. The engine ignores it.

```yaml
- id: big-spend
  description: Spending above the limit is refused.
```

## Select Actions

### match

`match` chooses the actions a rule is about. It is usually the first thing a reader looks at, so keep it short. The most common key is `kind`:

```yaml
match: {kind: [tool_call]}
```

Every list in `match` is a list of patterns, and `*` matches any run of characters:

```yaml
match: {kind: ["tool_*", read]}   # tool_call, tool_result, read
```

A rule without `match` applies to every action. An empty list never matches, and the check warns you about it.

### when

`when` holds the conditions on the content of the action. Every entry must hold, in the same way as in `match`. Entries can be paths, expressions, signals and combinators. See [Conditions](/conditions/) for all of them.

```yaml
when:
  actor.type: agent
  expr: "arguments.amount > 100"
```

## Name Intermediate Values

### let

Use `let` to compute a value once and use it several times. Each name is lowercase and is read as `var.<name>` in expressions and in `explain` text. A later entry can use an earlier one.

```yaml
let:
  amount: "arguments.amount"
  over: "arguments.amount - 100"
when:
  expr: "var.over > 0"
```

## Decide

### outcome

`outcome` is the result when the rule applies: `allow`, `watch`, `modify`, `ask` or `deny`.

| `allow` | `watch` | `modify` | `ask` |
| --- | --- | --- | --- |
| `deny` |   |   |   |

An `ask` rule needs an `approval` block, see [Approvals](/approvals/). A `modify` rule needs a `modify` block, see [Modifying Actions](/modifying/).

### reason

`reason` replaces the standard reason code of the outcome. Use it to tell different denials apart:

```yaml
- id: big-spend
  outcome: deny
  reason: RULE_DENY
```

A reason is either a standard code or a code your declarations define in a namespace, such as `acme.finance/OVER_LIMIT`. See [Declarations](/declarations/).

## Explain

### explain

`explain` is the text shown to the operator. Put values in braces. A literal brace is written twice.

```yaml
explain: "Spend of {var.amount} is over the limit by {var.over}."
```

Placeholders read any path of the action, a `let` value (`var.name`) or a field of the signal that matched, for example `{signal.code}`.

### hint

`hint` adds guidance for the caller of the policy, such as the next steps an agent can take. Values that come from the action are withheld from the hint message, so the caller never receives its own input back dressed as policy text.

```yaml
hint: {next_steps: [{kind: reduce_amount}]}
```

## Control Evaluation

### enabled

Set `enabled: false` to switch a rule off without deleting it. The check reports the rule as disabled.

```yaml
- id: legacy-block
  enabled: false
  outcome: deny
```

### priority

`priority` is an integer, `0` by default. It orders rules when the policy uses the `priority` strategy. See [Combining Rules](/decisions/).

```yaml
- id: emergency-stop
  priority: 100
  outcome: deny
```

### mode

`mode` is `enforce` or `monitor`. A rule in `monitor` mode reports what it would have decided but never blocks. Use it to roll a new rule out safely. See [Safe Rollout](/use-cases/rollout/).

```yaml
- id: new-limit
  mode: monitor
  outcome: deny
```

## Test the Rules

Check every rule with a case that triggers it, and a case that leaves it out:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: large-spend-is-denied
    action: {kind: tool_call, arguments: {amount: 250}}
    expect: {outcome: deny, reason_codes: [RULE_DENY], matched_rules: [big-spend]}

  - name: small-spend-is-allowed
    action: {kind: tool_call, arguments: {amount: 20}}
    expect: {outcome: allow, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="spending.fixtures.yaml"}

Here the default is `allow`, so the small spend reports `NO_MATCHING_RULE`. The reason code tells you that no rule decided the outcome.

> ▶ Next: [Conditions](/conditions/)
{: .next}
