---
title: Payments
description: Pay within limits that depend on the customer tier, ask a person above them and keep an audit trail.
---

Money is where a mistake costs the most. A payment policy keeps limits in a table, asks a person when a payment is unusual and refuses what no limit covers.

## Limits by Tier

Keep the limits in a declaration file, so a finance team can change them without touching a rule:

```yaml
schema: cpl.declarations/1.0
namespace: example.payments
version: 1
tables:
  auto_limit:
    key: string
    value: integer
    rows: {basic: 100, plus: 1000, pro: 10000}
parameters:
  review_above:
    type: integer
    default: 5000
```
{: data-title="payments.decl.yaml"}

```yaml
cpl: "1.0"
id: payments
version: 1
imports:
  - {from: ./payments.decl.yaml}
default: deny
rules:
  - id: within-the-tier-limit
    match: {kind: [payment]}
    when:
      expr: "arguments.amount <= table.auto_limit[actor.type]"
    outcome: allow
```
{: data-title="payments.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: basic-customer-small-payment
    action: {kind: payment, actor: {type: basic}, arguments: {amount: 80}}
    expect: {outcome: allow}

  - name: basic-customer-over-the-limit
    action: {kind: payment, actor: {type: basic}, arguments: {amount: 400}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}

  - name: pro-customer
    action: {kind: payment, actor: {type: pro}, arguments: {amount: 9000}}
    expect: {outcome: allow}
```
{: data-title="payments.fixtures.yaml"}

## Ask Above the Limit

A payment over its limit should not end in a flat refusal. Send it to a person, and refuse it outright above a hard ceiling. A threshold list does both in one rule:

```yaml
cpl: "1.0"
id: payments
version: 2
imports:
  - {from: ./payments.decl.yaml}
default: deny
rules:
  - id: within-the-tier-limit
    match: {kind: [payment]}
    when:
      expr: "arguments.amount <= table.auto_limit[actor.type]"
    outcome: allow

  - id: above-the-tier-limit
    match: {kind: [payment]}
    when:
      expr: "arguments.amount > table.auto_limit[actor.type]"
      approval: {timeout_seconds: 3600, on_timeout: deny}
      thresholds:
        - {path: arguments.amount, gt: 50000, outcome: deny, reason: THRESHOLD_EXCEEDED}
    outcome: ask
    explain: "A payment of {arguments.amount} is above the {actor.type} limit."
```
{: data-title="payments.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: within-limit
    action: {kind: payment, actor: {type: basic}, arguments: {amount: 80}}
    expect: {outcome: allow}

  - name: above-limit-asks
    action: {kind: payment, actor: {type: basic}, arguments: {amount: 400}}
    expect: {outcome: ask, matched_rules: [above-the-tier-limit]}

  - name: far-above-is-refused
    action: {kind: payment, actor: {type: pro}, arguments: {amount: 90000}}
    expect: {outcome: deny, reason_codes: [THRESHOLD_EXCEEDED]}

  - name: unknown-tier
    action: {kind: payment, actor: {type: gold}, arguments: {amount: 10}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="payments.fixtures.yaml"}

A tier that is not in the table has no limit, so neither rule applies and the default denies it.

## Fix the Payee

An agent should pay the account it was told to pay. Mark the payee and currency as fixed, so any change refuses the call:

```yaml
cpl: "1.0"
id: payee
version: 1
default: deny
rules:
  - id: invoice-payment
    match: {kind: [payment]}
    when:
      target: invoices
      immutable_params: {payee: "ACME-001", currency: usd}
      bounded_params: {amount: {min: 1, max: 5000}}
    outcome: allow
```
{: data-title="payee.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: as-instructed
    action: {kind: payment, target: {name: invoices}, arguments: {payee: ACME-001, currency: usd, amount: 250}}
    expect: {outcome: allow}

  - name: payee-was-swapped
    action: {kind: payment, target: {name: invoices}, arguments: {payee: ZETA-999, currency: usd, amount: 250}}
    expect: {outcome: deny, reason_codes: [PARAM_IMMUTABLE_VIOLATION]}

  - name: amount-is-negative
    action: {kind: payment, target: {name: invoices}, arguments: {payee: ACME-001, currency: usd, amount: -5}}
    expect: {outcome: deny, reason_codes: [PARAM_OUT_OF_BOUNDS]}
```
{: data-title="payee.fixtures.yaml"}

## Label the Risk

Add risk tiers, so that a log or a dashboard can tell the large payments apart:

```yaml
cpl: "1.0"
id: payment-risk
version: 1
default: deny
default_risk_tier: routine
risk_tiers:
  - id: high
    when: {arguments.amount: {gt: 10000}}
  - id: notable
    when: {arguments.amount: {gt: 1000}}
rules:
  - id: payments
    match: {kind: [payment]}
    when: {arguments.amount: {lte: 5000}}
    outcome: allow
```
{: data-title="payment-risk.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: routine
    action: {kind: payment, arguments: {amount: 50}}
    expect: {outcome: allow, risk_tier: routine}

  - name: notable
    action: {kind: payment, arguments: {amount: 3000}}
    expect: {outcome: allow, risk_tier: notable}

  - name: high-is-denied-and-labelled
    action: {kind: payment, arguments: {amount: 20000}}
    expect: {outcome: deny, risk_tier: high}
```
{: data-title="payment-risk.fixtures.yaml"}

## Keep a Record

Every verdict carries the policy `id`, `version` and `fingerprint`, a digest of the input and the reasons. Store `verdict.to_wire()` next to the payment. Months later you can show which version of the policy decided and why. See [Verdict](/reference/verdict/).

> ▶ Next: [Data Redaction](/use-cases/data-redaction/)
{: .next}
