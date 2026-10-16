---
title: Conditions
description: Every condition key, operator, modifier and shortcut, with the type each one expects.
---

A condition tests one fact. Entries of `match` and `when` are joined with "and". For tutorials, see [Conditions](/conditions/) and [Matching](/matching/).

```yaml
cpl: "1.0"
id: conditions-reference
version: 1
default: deny
rules:
  - id: showcase
    match: {kind: [tool_call]}
    when:
      target: shell
      actor.type: [agent, service]
      arguments.count: {between: [1, 10]}
      arguments.note: {exists: false}
      not: {environment.env: prod}
    outcome: allow
```
{: data-title="reference.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: all-conditions-hold
    action: {kind: tool_call, target: {name: shell}, actor: {type: agent}, environment: {env: dev}, arguments: {count: 3}}
    expect: {outcome: allow}

  - name: not-in-production
    action: {kind: tool_call, target: {name: shell}, actor: {type: agent}, environment: {env: prod}, arguments: {count: 3}}
    expect: {outcome: deny}
```
{: data-title="reference.fixtures.yaml"}

## Forms of a Condition Entry

| Written | Means |
| --- | --- |
| `path: value` | `path` equals `value` |
| `path: [a, b]` | `path` is one of the values. In `match`, each is a pattern |
| `path: {op: value}` | The operator holds. Several operators must all hold |
| `expr: "..."` | The expression is true |
| `signal: {...}` | A signal satisfies every key |
| `time.window: {...}` | The `timestamp` is inside the window |
| `use: name`, `with: {...}` | A named condition |
| `any: [...]`, `all: [...]`, `not: {...}` | Combinators |
| `default: true` | Always true |

An empty block is true. A value is a string, a number, a boolean, a list, or one of `{ref: name}`, `{expr: "..."}` and `{literal: value}`.

## Operators

| Operator | Value | True when |
| --- | --- | --- |
| `eq` | any | The path equals the value |
| `ne` | any | The path differs from the value |
| `in` | list | The path equals one member |
| `nin` | list | The path equals no member |
| `gt`, `gte`, `lt`, `lte` | number, text, time | The comparison holds |
| `between` | `[low, high]` | The path is from `low` to `high`, ends included |
| `regex` | string | A linear-time regular expression finds a match anywhere |
| `glob` | string | The pattern matches the whole value |
| `contains` | any | A text holds the text, or a list holds the member |
| `starts_with` | string | The text starts with the value |
| `len_gt`, `len_lt` | integer | The length of text, list or map compares to the value |
| `exists` | `true` or `false` | The field is present, or absent |

A missing path makes the condition absent, and an absent condition counts as false. That holds under `not` and `negate: true` too, so `not: {arguments.x: 1}` does not apply to an action without `arguments.x`. Only `exists: false` is true for a missing path. An operator name with a `/` calls a registered host function.

## Modifiers

| Modifier | Value | Applies to | Effect |
| --- | --- | --- | --- |
| `negate` | `true` | All operators beside it | Inverts the result |
| `case_insensitive` | `true` | `glob` | Ignores case |
| `sep` | a character | `glob` | `*`, `?` and classes stop at it. `**` crosses it |
| `normalize` | `path`, `command` | `glob` | Cleans the value before comparing |

## Glob Patterns

| Pattern | Matches |
| --- | --- |
| `*` | Any run of characters, except `sep` when it is set |
| `**` | Any run of characters, including `sep` (needs `sep`) |
| `?` | One character |
| `[abc]`, `[a-z]` | One character from the set |
| `[!abc]` | One character outside the set |
| `\x` | The character `x` |

Text is compared in Unicode normal form. A pattern always matches the whole value.

## Shortcut Keys

| Key | Reads | Options applied |
| --- | --- | --- |
| `target` | `target.name` | |
| `command_matches` | `arguments.command` | `normalize: command` |
| `path_matches` | `arguments.path` | `sep: "/"`, `normalize: path` |
| `domain_matches` | `target.destination_host` | `sep: "."` |
| `url_matches` | `arguments.url` | `sep: "/"` |
| `response_matches` | `arguments.response` | |
| `command_not_matches` | `arguments.command` | Negated `command_matches` |
| `path_not_matches` | `arguments.path` | Negated `path_matches` |
| `response_not_matches` | `arguments.response` | Negated `response_matches` |
| `arguments_match` | Named arguments | `{name: pattern}`, case-insensitive, all must match |
| `domain_suffix` | `target.destination_host` | The domain or any subdomain of it |

Each shortcut that takes patterns accepts one pattern or a list.

## Signal Condition

| Key | Value | True when |
| --- | --- | --- |
| `code` | string | The signal code is equal |
| `code_prefix` | string | The signal code starts with the text |
| `source` | string | The source is equal |
| `severity_gte` | `info`, `low`, `medium`, `high`, `critical` | The severity is at least this |
| `confidence_gte` | number from 0 to 1 | The confidence is at least this |
| `count_gte` | integer, at least 1 | At least this many signals satisfy the other keys |
| `facts` | `{name: value or [values]}` | Each fact has one of the values |

## Time Window

| Key | Value | Default |
| --- | --- | --- |
| `from` | `HH:MM` | required |
| `to` | `HH:MM` | required |
| `days` | list of `mon` to `sun` | every day |
| `tz` | `UTC` or `+HH:MM`, `-HH:MM` | `UTC` |

A zone name such as a city is not supported. Use a fixed offset.

## Roots

A key may start with any of these names:

| Root | Holds |
| --- | --- |
| `kind`, `action_uri`, `audience`, `depth` | Top-level fields of the action |
| `target`, `resource`, `actor`, `environment` | Standard objects of the action, see [Action](/reference/action/) |
| `origin`, `state`, `context`, `ext`, `call_chain` | Host-defined data |
| `arguments` | The arguments of the call |
| `time` | `time.now`, the action's timestamp |
| `attributes` | Declared attributes of the action |
| `param`, `const`, `table`, `computed`, `fn` | Declarations |
| `var` | `let` values of the rule |

Any name declared under `inputs:` is also a root.

> ▶ Next: [Expressions](/reference/expressions/)
{: .next}
