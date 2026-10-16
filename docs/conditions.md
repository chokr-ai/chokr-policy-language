---
title: Conditions
description: Test the content of an action with paths, operators, combinators, expressions, signals and time windows.
---

A condition tests one fact about an action. A `when` block holds conditions, and the rule applies only when every one of them holds.

```yaml
cpl: "1.0"
id: conditions-intro
version: 1
default: deny
rules:
  - id: staff-read-internal
    match: {kind: [read]}
    when:
      resource.type: internal
      actor.type: [staff, admin]
    outcome: allow
```
{: data-title="intro.policy.yaml"}

The first entry compares `resource.type` with a value. The second compares `actor.type` with a list, which means "is one of". Entries in a block are joined with "and".

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: staff-can-read
    action: {kind: read, resource: {type: internal}, actor: {type: staff}}
    expect: {outcome: allow}

  - name: guests-cannot
    action: {kind: read, resource: {type: internal}, actor: {type: guest}}
    expect: {outcome: deny}
```
{: data-title="intro.fixtures.yaml"}

## Paths

A key such as `resource.type` is a path into the action. Dots step into objects. Use brackets for a computed or numbered part in an expression, such as `arguments.items[0]`.

The standard roots of an action are `kind`, `target`, `action_uri`, `resource`, `audience`, `environment`, `actor`, `origin`, `arguments`, `state`, `time`, `ext`, `depth`, `call_chain` and `context`. See the [action reference](/reference/action/).

> Prefer your own field names? Declare them as inputs to get type checking. See [Declarations](/declarations/).
{: .note}

## Operators

Write an operator as a mapping under the path. A plain value is shorthand for `eq`, and a list is shorthand for `in`:

```yaml
resource.type: public                 # eq
actor.type: [staff, admin]            # in
arguments.amount: {gt: 100}           # an operator
arguments.amount: {gte: 10, lt: 100}  # several operators, all must hold
```

### Compare Values

| `eq` | `ne` | `in` | `nin` |
| --- | --- | --- | --- |
| `gt` | `gte` | `lt` | `lte` |
| `between` | | | |

`between` takes `[low, high]` and includes both ends:

```yaml
cpl: "1.0"
id: compare
version: 1
default: deny
rules:
  - id: small
    match: {kind: [spend]}
    when: {arguments.amount: {between: [1, 100]}}
    outcome: allow

  - id: not-production
    match: {kind: [deploy]}
    when: {environment.env: {nin: [prod, production]}}
    outcome: allow

  - id: weekday-or-staging
    match: {kind: [release]}
    when:
      environment.env: {ne: prod}
      arguments.attempt: {lte: 3}
    outcome: allow
```
{: data-title="compare.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: low-edge-is-included
    action: {kind: spend, arguments: {amount: 1}}
    expect: {outcome: allow}

  - name: high-edge-is-included
    action: {kind: spend, arguments: {amount: 100}}
    expect: {outcome: allow}

  - name: above-the-range
    action: {kind: spend, arguments: {amount: 101}}
    expect: {outcome: deny}

  - name: staging-deploys
    action: {kind: deploy, environment: {env: staging}}
    expect: {outcome: allow}

  - name: production-deploys-are-refused
    action: {kind: deploy, environment: {env: prod}}
    expect: {outcome: deny}

  - name: third-attempt-release
    action: {kind: release, environment: {env: staging}, arguments: {attempt: 3}}
    expect: {outcome: allow}
```
{: data-title="compare.fixtures.yaml"}

### Match Text

| `glob` | `regex` | `contains` | `starts_with` |
| --- | --- | --- | --- |
| `len_gt` | `len_lt` | | |

- `glob` matches the whole value. `*` is any run of characters, `?` is one character and `[a-z]` is a class.
- `regex` searches for a match anywhere in the value. Anchor the pattern with `^` and `$` to match the whole value.
- `contains` and `starts_with` test text, and `contains` also tests whether a list holds a value.
- `len_gt` and `len_lt` compare the length of text, a list or a map.

```yaml
cpl: "1.0"
id: text
version: 1
default: deny
rules:
  - id: report-files
    match: {kind: [read]}
    when: {arguments.name: {glob: "report-*.csv"}}
    outcome: allow

  - id: ticket-ids
    match: {kind: [lookup]}
    when: {arguments.id: {regex: "^TCK-[0-9]{4}$"}}
    outcome: allow

  - id: tagged
    match: {kind: [label]}
    when:
      arguments.tags: {contains: reviewed}
      arguments.title: {starts_with: "Fix", len_lt: 80}
    outcome: allow
```
{: data-title="text.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: glob-matches-whole-name
    action: {kind: read, arguments: {name: report-2026.csv}}
    expect: {outcome: allow}

  - name: glob-does-not-match-a-longer-name
    action: {kind: read, arguments: {name: report-2026.csv.bak}}
    expect: {outcome: deny}

  - name: anchored-regex
    action: {kind: lookup, arguments: {id: TCK-1234}}
    expect: {outcome: allow}

  - name: anchored-regex-rejects-extra-text
    action: {kind: lookup, arguments: {id: "xTCK-1234"}}
    expect: {outcome: deny}

  - name: list-contains-and-text-rules
    action: {kind: label, arguments: {tags: [reviewed, urgent], title: "Fix the login form"}}
    expect: {outcome: allow}
```
{: data-title="text.fixtures.yaml"}

> Regular expressions run in linear time, so a pattern can never stall a decision. Look-around and back-references are not available.
{: .note}

### Test for Presence

`exists: true` is true when the action carries the field. `exists: false` is true when it does not:

```yaml
arguments.reason: {exists: true}
```

## Modifiers

Modifiers change how an operator compares. Put them next to the operator:

| Modifier | Effect |
| --- | --- |
| `negate: true` | Inverts the result of the operators beside it |
| `case_insensitive: true` | Compares without regard to case in `glob` |
| `sep: "/"` | Makes `*` and `?` stop at the separator, and `**` cross it |
| `normalize: path` | Cleans the path first: `..` and `.` segments are resolved |
| `normalize: command` | Folds quotes and spacing in a shell command first |

```yaml
arguments.path: {glob: "/srv/app/**", sep: "/", normalize: path}
```

See [Matching](/matching/) for the shortcut keys that apply these for you.

## Combine Conditions

Use `all`, `any` and `not` to build larger conditions. Each takes conditions, and they nest:

```yaml
cpl: "1.0"
id: combine
version: 1
default: deny
rules:
  - id: trusted-or-small
    match: {kind: [export]}
    when:
      any:
        - actor.type: admin
        - all:
            - arguments.rows: {lt: 1000}
            - not: {resource.type: restricted}
    outcome: allow
```
{: data-title="combine.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: admins-export-anything
    action: {kind: export, actor: {type: admin}, resource: {type: restricted}, arguments: {rows: 50000}}
    expect: {outcome: allow}

  - name: small-open-exports
    action: {kind: export, actor: {type: staff}, resource: {type: open}, arguments: {rows: 10}}
    expect: {outcome: allow}

  - name: small-restricted-exports-are-refused
    action: {kind: export, actor: {type: staff}, resource: {type: restricted}, arguments: {rows: 10}}
    expect: {outcome: deny}
```
{: data-title="combine.fixtures.yaml"}

## Missing Fields

A condition on a field the action does not carry is false, so the rule does not apply. That holds under `not` and `negate` too: `not: {arguments.amount: 5}` does not apply to an action without an amount. This is the safe reading for an `allow` rule, because a missing field never grants access. Test for a missing field with `exists: false`.

```yaml
cpl: "1.0"
id: missing
version: 1
default: deny
rules:
  - id: small-amounts
    match: {kind: [spend]}
    when: {arguments.amount: {lte: 100}}
    outcome: allow
```
{: data-title="missing.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: no-amount-no-grant
    action: {kind: spend}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="missing.fixtures.yaml"}

Guards work the other way round: a `deny` guard or a threshold on a missing field denies. See [Limits and Guards](/limits/).

## Other Kinds of Condition

| Key | Tests |
| --- | --- |
| `expr` | A text expression, see [Expressions](/expressions/) |
| `signal` | A finding reported by a scanner, see [Signals](/signals/) |
| `time.window` | The time of day and the day of the week, see below |
| `use` | A named condition from a declaration file, see [Declarations](/declarations/) |

### Time Windows

`time.window` is true when the action's `timestamp` falls inside the window. `days` is optional and defaults to every day. `tz` is `UTC` or a fixed offset such as `+05:30`.

```yaml
cpl: "1.0"
id: office-hours
version: 1
default: deny
rules:
  - id: deploys-in-office-hours
    match: {kind: [deploy]}
    when:
      time.window: {from: "08:00", to: "18:00", days: [mon, tue, wed, thu, fri]}
    outcome: allow
```
{: data-title="hours.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
cases:
  - name: monday-morning
    action: {kind: deploy, timestamp: "2026-01-05T10:00:00Z"}
    expect: {outcome: allow}

  - name: monday-night
    action: {kind: deploy, timestamp: "2026-01-05T23:00:00Z"}
    expect: {outcome: deny}

  - name: sunday
    action: {kind: deploy, timestamp: "2026-01-04T10:00:00Z"}
    expect: {outcome: deny}
```
{: data-title="hours.fixtures.yaml"}

> The clock is the `timestamp` of the action, not the time on the machine. Set it from your own clock.
{: .note}

> ▶ Next: [Matching](/matching/)
{: .next}
