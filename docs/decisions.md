---
title: Combining Rules
description: Choose how matching rules become one outcome, run rules in monitor mode and label actions with risk tiers.
---

Several rules can apply to one action. The policy `strategy` says how their outcomes combine. The default is `deny_overrides`: every rule is evaluated and the strongest outcome wins.

```yaml
cpl: "1.0"
id: strongest-wins
version: 1
default: deny
rules:
  - id: staff-may-delete
    match: {kind: [delete]}
    when: {actor.type: staff}
    outcome: allow

  - id: nothing-is-deleted-in-production
    match: {kind: [delete]}
    when: {environment.env: prod}
    outcome: deny
```
{: data-title="strongest.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: staff-delete-in-staging
    action: {kind: delete, actor: {type: staff}, environment: {env: staging}}
    expect: {outcome: allow, matched_rules: [staff-may-delete]}

  - name: staff-delete-in-production
    action: {kind: delete, actor: {type: staff}, environment: {env: prod}}
    expect: {outcome: deny, matched_rules: [nothing-is-deleted-in-production, staff-may-delete]}
```
{: data-title="strongest.fixtures.yaml"}

Both rules apply to the second action. `deny` is stronger than `allow`, so it wins, and the verdict lists both rules. The order of rules in the file does not matter.

## The Default

When no rule applies, the policy `default` decides. It is `allow` or `deny` and is `deny` unless you say otherwise.

```yaml
default: deny
```

The reason code of a default decision is `NO_MATCHING_RULE`, so you can always tell it apart from a decision a rule made.

> Use `default: deny` for anything that grants access. Use `default: allow` only for a policy that lists what to forbid, such as a deny list of dangerous commands.
{: .note}

## Strategies

| Strategy | Behaviour |
| --- | --- |
| `deny_overrides` | Every rule is evaluated, the strongest outcome wins (default) |
| `first_match` | Rules are evaluated in order and the first one that applies decides |
| `priority` | Rules are sorted by `priority`, highest first, and the first one that applies decides |

### First Match

Use `first_match` when the order of rules is the logic, like a firewall table:

```yaml
cpl: "1.0"
id: ordered
version: 1
default: deny
strategy: first_match
rules:
  - id: admins-can-do-anything
    when: {actor.type: admin}
    outcome: allow

  - id: nobody-else-deletes
    match: {kind: [delete]}
    outcome: deny

  - id: everyone-else-reads
    match: {kind: [read]}
    outcome: allow
```
{: data-title="ordered.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: admin-delete
    action: {kind: delete, actor: {type: admin}}
    expect: {outcome: allow, matched_rules: [admins-can-do-anything]}

  - name: staff-delete
    action: {kind: delete, actor: {type: staff}}
    expect: {outcome: deny, matched_rules: [nobody-else-deletes]}

  - name: staff-read
    action: {kind: read, actor: {type: staff}}
    expect: {outcome: allow, matched_rules: [everyone-else-reads]}
```
{: data-title="ordered.fixtures.yaml"}

Only the rule that decided is listed in `matched_rules`. Move a rule and the policy changes, so keep the most specific rules first.

### Priority

Use `priority` when rules come from several files and the file order is not a good place to put the logic. Give each rule a number. Higher numbers go first, and rules with the same number keep their written order:

```yaml
cpl: "1.0"
id: ranked
version: 1
default: allow
strategy: priority
rules:
  - id: everyday-allow
    outcome: allow

  - id: emergency-stop
    priority: 100
    when: {environment.env: lockdown}
    outcome: deny
```
{: data-title="ranked.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: normal-day
    action: {kind: read, environment: {env: prod}}
    expect: {outcome: allow, matched_rules: [everyday-allow]}

  - name: lockdown
    action: {kind: read, environment: {env: lockdown}}
    expect: {outcome: deny, matched_rules: [emergency-stop]}
```
{: data-title="ranked.fixtures.yaml"}

## Monitor Mode

Monitor mode reports what a rule would have done without doing it. A blocking outcome (`ask` or `deny`) becomes `watch`, and the verdict says what was held back. Use it to try a new rule on real traffic before you enforce it.

Set `mode: monitor` on one rule, or on the whole policy:

```yaml
cpl: "1.0"
id: trial
version: 1
default: allow
rules:
  - id: new-size-limit
    mode: monitor
    match: {kind: [upload]}
    when: {expr: "arguments.size_mb > 100"}
    outcome: deny
```
{: data-title="trial.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: oversized-upload-is-only-flagged
    action: {kind: upload, arguments: {size_mb: 250}}
    expect:
      outcome: watch
      would_block: true
      would_have_been: deny
      reason_codes: [MONITOR_WOULD_BLOCK, RULE_DENY]
```
{: data-title="trial.fixtures.yaml"}

The verdict has `would_block: true` and `would_have_been: deny`, so a dashboard can show how many actions the new rule would stop. See [Safe Rollout](/use-cases/rollout/) for a complete rollout.

## Risk Tiers

A risk tier is a label on the verdict, chosen by conditions. Use it to route actions, for example to choose how closely to log them. The first tier whose condition holds is used. Without a match, the tier is `default_risk_tier`, or `standard`.

```yaml
cpl: "1.0"
id: tiers
version: 1
default: allow
default_risk_tier: low
risk_tiers:
  - id: critical
    when: {environment.env: prod, arguments.amount: {gt: 10000}}
  - id: elevated
    when: {environment.env: prod}
rules:
  - id: everything-else
    outcome: allow
```
{: data-title="tiers.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: large-production-payment
    action: {kind: pay, environment: {env: prod}, arguments: {amount: 50000}}
    expect: {outcome: allow, risk_tier: critical}

  - name: ordinary-production-action
    action: {kind: pay, environment: {env: prod}, arguments: {amount: 10}}
    expect: {outcome: allow, risk_tier: elevated}

  - name: staging
    action: {kind: pay, environment: {env: staging}, arguments: {amount: 10}}
    expect: {outcome: allow, risk_tier: low}
```
{: data-title="tiers.fixtures.yaml"}

## Order of Strength

When outcomes meet under `deny_overrides`, the strongest wins:

| Rank | Outcome |
| --- | --- |
| 0 | `allow` |
| 1 | `watch` |
| 2 | `modify` |
| 3 | `ask` |
| 4 | `deny` |

> ▶ Next: [Declarations](/declarations/)
{: .next}
