---
title: Declarations
description: Share parameters, constants, tables, functions and named conditions between rules, and declare typed inputs.
---

A declaration file holds the pieces that rules share. It is a second kind of YAML file, and a policy imports it. Use declarations for limits you want to change in one place, lookup tables, helper formulas and the shape of your own input data.

```yaml
schema: cpl.declarations/1.0
namespace: example.billing
version: 1
parameters:
  max_refund:
    type: integer
    default: 200
```
{: data-title="billing.decl.yaml"}

```yaml
cpl: "1.0"
id: refunds
version: 1
imports:
  - {from: ./billing.decl.yaml}
default: deny
rules:
  - id: small-refunds
    match: {kind: [refund]}
    when: {expr: "arguments.amount <= param.max_refund"}
    outcome: allow
```
{: data-title="refunds.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: within-the-limit
    action: {kind: refund, arguments: {amount: 150}}
    expect: {outcome: allow}

  - name: over-the-limit
    action: {kind: refund, arguments: {amount: 250}}
    expect: {outcome: deny}
```
{: data-title="refunds.fixtures.yaml"}

The policy imports the file with `imports`, and reads the parameter as `param.max_refund`. Check declaration files with `cplang decl check` and show the merged result with `cplang decl show`.

## Parameters

A parameter is a named setting with a type and a default. Rules read it as `param.name`.

A parameter has `type`, `default` and `required`. A required parameter without a default must be given a value by whoever loads the policy.

Change the value without touching a rule, from the command line with `--param`:

```yaml
kind: refund
timestamp: "2026-01-05T10:00:00Z"
arguments: {amount: 150}
```
{: data-title="refund.action.yaml"}

```console
$ cplang eval --policy refunds.policy.yaml --action refund.action.yaml
allow POLICY_SATISFIED  rules=['small-refunds']
$ cplang eval --policy refunds.policy.yaml --action refund.action.yaml --param max_refund=100
deny NO_MATCHING_RULE  rules=[]
```
{: data-run="true"}

## Constants

A constant is a fixed value with a type. It holds either a `value` or an `expr` that may use other constants:

```yaml
schema: cpl.declarations/1.0
namespace: example.limits
constants:
  base_limit: {type: integer, value: 10}
  double_limit: {type: integer, expr: "const.base_limit * 2"}
  review_regions: {type: "set<string>", value: [eu, us]}
```
{: data-title="limits.decl.yaml"}

Read a constant as `const.name`. The difference to a parameter is that a constant is not meant to be overridden.

## Tables

A table maps keys to values. Use one for a lookup such as a limit per tier. Index it with square brackets:

```yaml
schema: cpl.declarations/1.0
namespace: example.tiers
tables:
  daily_limit:
    key: string
    value: integer
    rows: {basic: 100, plus: 1000, pro: 10000}
```
{: data-title="tiers.decl.yaml"}

```yaml
cpl: "1.0"
id: tier-limits
version: 1
imports:
  - {from: ./tiers.decl.yaml}
default: deny
rules:
  - id: within-the-tier-limit
    match: {kind: [transfer]}
    when:
      expr: "arguments.amount <= table.daily_limit[arguments.tier]"
    outcome: allow
```
{: data-title="tiers.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: basic-within-its-limit
    action: {kind: transfer, arguments: {tier: basic, amount: 90}}
    expect: {outcome: allow}

  - name: basic-over-its-limit
    action: {kind: transfer, arguments: {tier: basic, amount: 500}}
    expect: {outcome: deny}

  - name: pro-within-its-limit
    action: {kind: transfer, arguments: {tier: pro, amount: 5000}}
    expect: {outcome: allow}

  - name: unknown-tier-has-no-limit
    action: {kind: transfer, arguments: {tier: gold, amount: 1}}
    expect: {outcome: deny}
```
{: data-title="tiers.fixtures.yaml"}

A key that is not in the table is absent, so the comparison is false and the rule does not apply.

Large tables can live in a file. Use `source` with a file name, `format: csv` and a `digest` to pin the content. Table files are never fetched from the network.

## Functions

A function is a named formula with typed parameters. It can use tables and constants but not itself:

```yaml
schema: cpl.declarations/1.0
namespace: example.math
functions:
  within_ratio:
    params: {part: number, whole: number}
    returns: boolean
    body: "whole > 0 && part / whole <= 0.25"
```
{: data-title="math.decl.yaml"}

Call it as `fn.name(...)`:

```yaml
cpl: "1.0"
id: ratios
version: 1
imports:
  - {from: ./math.decl.yaml}
default: deny
rules:
  - id: small-share
    match: {kind: [allocate]}
    when:
      expr: "fn.within_ratio(arguments.part, arguments.whole)"
    outcome: allow
```
{: data-title="ratios.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: ten-percent
    action: {kind: allocate, arguments: {part: 10, whole: 100}}
    expect: {outcome: allow}

  - name: half
    action: {kind: allocate, arguments: {part: 50, whole: 100}}
    expect: {outcome: deny}

  - name: empty-whole
    action: {kind: allocate, arguments: {part: 1, whole: 0}}
    expect: {outcome: deny}
```
{: data-title="ratios.fixtures.yaml"}

The declared `returns` type is checked when the file loads.

## Named Conditions

A named condition is a reusable `when` block with parameters. Define it once and use it in any rule:

```yaml
schema: cpl.declarations/1.0
namespace: example.conditions
conditions:
  at_least:
    params: {n: number}
    when: {expr: "arguments.quantity >= n"}
  in_business_hours:
    when:
      time.window: {from: "08:00", to: "18:00", days: [mon, tue, wed, thu, fri]}
```
{: data-title="conditions.decl.yaml"}

```yaml
cpl: "1.0"
id: orders
version: 1
imports:
  - {from: ./conditions.decl.yaml}
default: deny
rules:
  - id: bulk-orders-in-hours
    match: {kind: [order]}
    when:
      use: in_business_hours
    outcome: allow

  - id: bulk-orders-need-approval
    match: {kind: [order]}
    when:
      use: at_least
      with: {n: 100}
      approval: {timeout_seconds: 3600}
    outcome: ask
```
{: data-title="orders.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: ordinary-order-in-hours
    action: {kind: order, arguments: {quantity: 5}}
    expect: {outcome: allow}

  - name: bulk-order-needs-a-person
    action: {kind: order, arguments: {quantity: 500}}
    expect: {outcome: ask}
```
{: data-title="orders.fixtures.yaml"}

`with` gives a value to every parameter, and nothing else. The check refuses a missing or extra name.

## Typed Inputs

Rules can read any field of an action without setup. Declare an input to give a field of your own a type. The loader then checks the data on every decision, and a value of the wrong type denies with `EVALUATION_ERROR`:

```yaml
schema: cpl.declarations/1.0
namespace: example.crm
types:
  Customer:
    kind: object
    fields:
      tier: {type: string}
      spend: {type: number, required: false}
inputs:
  customer: {type: Customer}
```
{: data-title="crm.decl.yaml"}

```yaml
cpl: "1.0"
id: discounts
version: 1
imports:
  - {from: ./crm.decl.yaml}
default: deny
rules:
  - id: gold-customers
    match: {kind: [quote]}
    when:
      customer.tier: gold
    outcome: allow
```
{: data-title="discounts.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: gold-customer
    action: {kind: quote, customer: {tier: gold}}
    expect: {outcome: allow}

  - name: other-customer
    action: {kind: quote, customer: {tier: basic}}
    expect: {outcome: deny}

  - name: malformed-customer
    action: {kind: quote, customer: {tier: 7}}
    expect: {outcome: deny, reason_codes: [EVALUATION_ERROR]}
```
{: data-title="discounts.fixtures.yaml"}

`cplang policy check` treats an undeclared custom field as an error, so a typo in a field name is caught. See [Types](/types/) for every kind of type.

> `cplang test` and `cplang eval` accept fields that are not declared, so a draft policy runs right away. Add `--strict-inputs` to reject them, as `cplang policy check` always does.
{: .note}

## Shortcuts

A shortcut gives a short condition key to a path. Use it when many rules test the same field:

```yaml
shortcuts:
  tier_is: {path: customer.tier}
```

A rule can then write `when: {tier_is: [gold, silver]}`.

## Vocabulary

A declaration file can name the reason codes, signal codes, obligation types, risk tiers, environments and resource types your organisation uses. The names are placed in the file's `namespace`:

```yaml
schema: cpl.declarations/1.0
namespace: example.finance
reason_codes:
  OVER_BUDGET: {description: The team budget is used up}
signal_codes:
  fraud.suspected: {description: The fraud model flagged this action}
```
{: data-title="finance.decl.yaml"}

A rule then writes `reason: example.finance/OVER_BUDGET`. A namespaced code that is not declared is reported by `cplang policy check`, so a misspelt code is caught.

## Privacy

Mark an entry `private: true` to keep it for the file that declares it. A policy cannot name it, but other declarations in the same file can still depend on it. An import can also list the names it wants with `only`. See [Imports](/imports/).

> ▶ Next: [Types](/types/)
{: .next}
