---
title: Types
description: Describe the shape of your own data with scalars, enums, quantities, collections and objects.
---

A type says what a value may be. Declare types in a declaration file, give them to inputs, parameters and tables, and the engine checks the data on every decision. A value of the wrong type never reaches a rule. The decision is a `deny` with the reason `EVALUATION_ERROR`.

```yaml
schema: cpl.declarations/1.0
namespace: example.tickets
types:
  Priority: {kind: enum, ordered: true, values: [low, medium, high]}
  Ticket:
    kind: object
    fields:
      id: {type: string}
      priority: {type: Priority}
      tags: {type: "set<string>", required: false}
inputs:
  ticket: {type: Ticket}
constants:
  urgent: {type: Priority, value: high}
```
{: data-title="tickets.decl.yaml"}

```yaml
cpl: "1.0"
id: tickets
version: 1
imports:
  - {from: ./tickets.decl.yaml}
default: deny
rules:
  - id: escalate-urgent
    match: {kind: [route]}
    when:
      expr: "ticket.priority >= const.urgent"
    outcome: allow
```
{: data-title="tickets.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: urgent-ticket
    action: {kind: route, ticket: {id: T-1, priority: high}}
    expect: {outcome: allow}

  - name: low-priority-ticket
    action: {kind: route, ticket: {id: T-2, priority: low}}
    expect: {outcome: deny}

  - name: unknown-priority-is-refused
    action: {kind: route, ticket: {id: T-3, priority: critical}}
    expect: {outcome: deny, reason_codes: [EVALUATION_ERROR]}
```
{: data-title="tickets.fixtures.yaml"}

Because `Priority` is ordered, `>=` compares by position in the list.

## Type Names

Use a type wherever a type is expected: `type:` on an input, parameter, attribute, table or field, and in the `of:` of a collection. Write generic types with angle brackets:

| Written | Meaning |
| --- | --- |
| `string`, `integer`, `number`, `boolean` | The scalar types |
| `timestamp`, `duration` | A moment and a length of time |
| `list<string>` | A list of strings |
| `set<Region>` | A list without duplicates |
| `map<string,number>` | Names to numbers, with string keys |
| `optional<number>` | A number that may be absent |
| `Ticket` | A type you declared |

The language's own type names and its standard field names, such as `string` and `arguments`, are reserved. A declared type cannot reuse them.

## Scalars with Limits

Add limits to a scalar to narrow it. Declare the limited type once and use it everywhere:

```yaml
schema: cpl.declarations/1.0
namespace: example.scalars
types:
  Email: {kind: string, format: email}
  Region: {kind: string, pattern: "^[A-Z]{2}$"}
  Score: {kind: integer, min: 0, max: 10}
  Money: {kind: number, min: 0, scale: 2}
  Deadline: {kind: timestamp, min: "2026-01-01T00:00:00Z"}
  Window: {kind: duration, max: "PT8H"}
```
{: data-title="scalars.decl.yaml"}

| Kind | Limits |
| --- | --- |
| `string` | `min_len`, `max_len`, `pattern`, `format` |
| `integer` | `min`, `max` |
| `number` | `min`, `max`, `scale` (decimal places) |
| `timestamp`, `duration` | `min`, `max` |

The `format` of a string is one of `email`, `uri`, `uuid`, `ip`, `cidr`, `date`, `datetime` or `semver`.

> A `pattern` searches for a match, like a regular expression search anywhere in the text. Anchor it with `^` and `$` to match the whole value.
{: .note}

## Enums

An enum lists the names a value may take. Names are lowercase identifiers. Add `ordered: true` to make the names comparable, from first to last:

```yaml
types:
  Priority: {kind: enum, ordered: true, values: [low, medium, high]}
  Channel: {kind: enum, values: [email, chat]}
```

An unordered enum supports `==` and `!=`. Ordering such as `<` is an error until you set `ordered: true`.

## Quantities

A quantity is a number with a unit. Declare the units and how they convert. The engine then compares across units for you:

```yaml
schema: cpl.declarations/1.0
namespace: example.shipping
types:
  Weight:
    kind: quantity
    base: number
    dimension: mass
    units: [g, kg]
    conversions:
      kg: {to: g, factor: 1000}
    min: 0
parameters:
  max_weight: {type: Weight, default: {value: 5, unit: kg}}
inputs:
  parcel: {type: "map<string,Weight>"}
```
{: data-title="shipping.decl.yaml"}

```yaml
cpl: "1.0"
id: shipping
version: 1
imports:
  - {from: ./shipping.decl.yaml}
default: deny
rules:
  - id: light-parcels
    match: {kind: [ship]}
    when:
      expr: "parcel.contents <= param.max_weight"
    outcome: allow
```
{: data-title="shipping.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: four-kilograms-in-grams
    action: {kind: ship, parcel: {contents: {value: 4000, unit: g}}}
    expect: {outcome: allow}

  - name: six-kilograms
    action: {kind: ship, parcel: {contents: {value: 6, unit: kg}}}
    expect: {outcome: deny}

  - name: unknown-unit
    action: {kind: ship, parcel: {contents: {value: 1, unit: lb}}}
    expect: {outcome: deny, reason_codes: [EVALUATION_ERROR]}
```
{: data-title="shipping.fixtures.yaml"}

A quantity value is written `{value: 4000, unit: g}`. Bounds such as `min` are in the first listed unit. Two quantities can be compared only when they have the same `dimension`.

## Collections

| Kind | Written | Limits |
| --- | --- | --- |
| `list` | `{kind: list, of: string}` | `min_items`, `max_items` |
| `set` | `{kind: set, of: string}` | `min_items`, `max_items`, no duplicates |
| `map` | `{kind: map, of: number}` | `max_entries`, `key_pattern` |

A map has string keys. For an unordered group of items, use a set so that a duplicate is rejected.

## Objects

An object lists its fields. A field is required unless you set `required: false`, and it may have a `default`. An object is closed by default: a field that is not listed is an error. Set `closed: false` to allow extra fields.

```yaml
types:
  Contact:
    kind: object
    closed: false
    fields:
      email: {type: Email}
      phone: {type: string, required: false}
```

## Unions

A union accepts a value that matches any one of its members:

```yaml
types:
  Identifier: {kind: union, of: [integer, string]}
```

## Attributes

An attribute is a named fact about the action that carries a type, a source and a unit. Declare attributes for values that a classifier or an upstream system provides:

```yaml
attributes:
  sensitivity: {type: Priority, source: asserted, required: false}
```

`source` is `asserted` (supplied by the caller), `derived` (computed by your system) or `either`. Rules read an attribute as `attributes.name`.

## Check Types Without Running

`cplang policy types` prints the inferred type of every `let` and `computed` value. `cplang policy check` reports a comparison that cannot work, such as a number against text. Here `size(...)` is known to be an integer, so the comparison fails when the policy loads:

```yaml
cpl: "1.0"
id: type-error
version: 1
default: deny
rules:
  - id: wrong
    match: {kind: [check]}
    when:
      expr: "size(arguments.items) > 'five'"
    outcome: allow
```
{: data-title="typeerror.policy.yaml" data-error="TYPE_ERROR"}

A field without a declared type is not checked until a decision runs, so declare the inputs you rely on. See [Declarations](/declarations/).

> ▶ Next: [Imports](/imports/)
{: .next}
