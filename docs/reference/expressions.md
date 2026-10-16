---
title: Expressions
description: The syntax, operators, functions and limits of expressions.
---

An expression is a formula in a string. It reads the action, declared values and `let` values, and it returns a value. For a tutorial, see [Expressions](/expressions/).

Evaluate an expression against the first case of a fixture file with `--fixtures`:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: example
    action: {kind: test, arguments: {items: [1, 2, 3]}}
    expect: {outcome: deny}
```
{: data-title="example.fixtures.yaml" data-check="false"}

```console
$ cplang expr eval 'size(arguments.items) > 2 && default(arguments.mode, "safe") == "safe"' --fixtures example.fixtures.yaml
true  (boolean, untrusted)
```
{: data-run="true"}

## Literals

| Kind | Written | Notes |
| --- | --- | --- |
| Boolean | `true`, `false` | |
| Integer | `42`, `-7` | Signed 64 bits. An overflow is an error |
| Number | `2.5`, `1e3` | Exact decimal, not a binary float |
| String | `"text"`, `'text'` | Escapes: `\n \t \r \\ \" \' \/ \uXXXX` |
| List | `[1, 2, 3]` | |
| Map | `{a: 1, "b c": 2}` | Keys are names or strings |

## Operators

From tightest to loosest:

| Level | Operators | Notes |
| --- | --- | --- |
| 1 | `.`  `[ ]`  `( )` | Field, index, call |
| 2 | `!`  `-` | Not, negate |
| 3 | `*`  `/`  `%` | `/` always gives a number. Division by zero is an error |
| 4 | `+`  `-` | `+` also joins strings and adds a duration to a timestamp |
| 5 | `<`  `<=`  `>`  `>=`  `==`  `!=`  `in` | Comparisons do not chain |
| 6 | `&&` | Stops at the first false operand |
| 7 | `\|\|` | Stops at the first true operand |
| 8 | `? :` | Only at the top of an expression or inside parentheses |

`in` tests membership in a list, a substring of a string and a key of a map.

## Paths

A path starts with a root and follows fields with `.` or computed parts with `[ ]`:

```
arguments.items[0].name
table.limits[arguments.tier]
```

A path that does not exist is absent. See [Missing values](#missing-values).

## Functions

| Function | Arguments | Result |
| --- | --- | --- |
| `size(x)`, `count(x)` | text, list, map | integer length |
| `abs(n)` | number | number |
| `min(a, b, ...)`, `max(...)` | one list, or 2 to 8 values | the smallest or largest |
| `sum(list)` | list of numbers | number |
| `round(n, digits)` | number, integer | number, half to even |
| `floor(n)`, `ceil(n)` | number | integer |
| `lower(s)`, `upper(s)`, `trim(s)` | string | string |
| `starts_with(s, p)`, `ends_with(s, p)` | strings | boolean |
| `contains(x, y)` | text and text, or list and member | boolean |
| `matches(s, pattern)` | string, literal pattern | boolean, a search |
| `split(s, sep)` | string, non-empty string | list of strings |
| `join(list, sep)` | list of strings, string | string |
| `keys(map)`, `values(map)` | map | list |
| `timestamp(s)` | RFC 3339 string | timestamp |
| `duration(s)` | ISO 8601 string such as `PT30M` | duration |
| `date_diff(a, b, unit)` | two timestamps, `seconds`, `minutes`, `hours` or `days` | whole units from `b` to `a`, negative when `a` is earlier |
| `has(path)` | path | boolean, true when present |
| `default(path, fallback)` | path, value | the value, or the fallback when absent |
| `coalesce(a, b, ...)` | one or more | the first value that is present |
| `fn.name(...)` | declared function arguments | the declared return type |
| `namespace/name(...)` | host function arguments | any JSON value |

`timestamp("...")` and `duration("...")` with a literal argument are checked when the policy loads.

## Macros

| Macro | Result |
| --- | --- |
| `filter(list, predicate)` | The members for which the predicate is true |
| `map(list, expression)` | The list of results |
| `all(list, predicate)` | True when every member satisfies it |
| `any(list, predicate)` | True when some member satisfies it |

The member is `it`. Name it with a third argument: `all(list, n, n > 0)`.

## Missing Values

A missing path is absent. An operator or a function that receives an absent value returns absent, and an absent condition counts as false. `has`, `default` and `coalesce` handle absent values on purpose. A `?:` with an absent test is absent.

## Trust

Every value is trusted or untrusted. A value read from the action is untrusted, because the caller controls it. Constants, parameters and literals are trusted. A result is untrusted when any input is. Text that goes back to the caller, such as a hint message, leaves out untrusted values.

## Limits

| Limit | Default |
| --- | --- |
| Nodes in an expression | 256 |
| Steps in one evaluation | 10,000 |
| Nesting depth of an expression | 64 |
| Calls of declared functions nested | 8 |
| Length of a regular expression | 1,024 characters |
| Length of a text value | 1,048,576 characters |

A policy over a size limit does not load. A run over a step limit is a `deny` with the reason `EVALUATION_ERROR`. See [Python API](/reference/python-api/#limits).

> ▶ Next: [Action](/reference/action/)
{: .next}
