---
title: Expressions
description: Compute with numbers, text, lists, time and collections inside a rule, and handle missing values safely.
---

An expression is a short formula in a string. Use one when a plain condition cannot say what you mean, for example "the amount is more than twice the limit" or "every file is a markdown file".

```yaml
cpl: "1.0"
id: expressions-intro
version: 1
default: deny
rules:
  - id: small-batches
    match: {kind: [send_email]}
    when:
      expr: "size(arguments.recipients) <= 10"
    outcome: allow
```
{: data-title="intro.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: three-recipients
    action: {kind: send_email, arguments: {recipients: [a@x.test, b@x.test, c@x.test]}}
    expect: {outcome: allow}

  - name: no-recipient-list
    action: {kind: send_email}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="intro.fixtures.yaml"}

Put an expression under the `expr` key of `when`, in a `let` entry, in a threshold or in an `explain` placeholder. Expressions never change anything. They read the action and return a value.

## Try an Expression

Use `cplang expr eval` to try an expression without a policy. It prints the value, its type and whether the value comes from trusted data:

```console
$ cplang expr eval '1 + 2 * 3'
7  (integer, trusted)
```
{: data-run="true"}

Wrap the expression in single quotes so the shell leaves the double quotes inside it alone:

```console
$ cplang expr eval 'upper("abc") + "-" + lower("XYZ")'
ABC-xyz  (string, trusted)
```
{: data-run="true"}

## Values

| Type | Examples |
| --- | --- |
| `boolean` | `true`, `false` |
| `integer` | `42`, `-7` |
| `number` | `2.5`, `1e3` |
| `string` | `"text"`, `'text'` |
| `list` | `[1, 2, 3]` |
| `map` | `{a: 1, b: "two"}` |

Integers are exact and limited to 64 bits. An overflow is an error, not a wrap-around. Numbers with a decimal point are exact decimals, so `0.1 + 0.2` is `0.3`:

```console
$ cplang expr eval '0.1 + 0.2'
0.3  (number, trusted)
```
{: data-run="true"}

## Operators

From the tightest binding to the loosest:

| Operators | Meaning |
| --- | --- |
| `.` `[ ]` `( )` | Field, index, call |
| `!` `-` | Not, negate |
| `*` `/` `%` | Multiply, divide, remainder |
| `+` `-` | Add, subtract, join text |
| `<` `<=` `>` `>=` `==` `!=` `in` | Compare, membership |
| `&&` | And |
| `\|\|` | Or |
| `? :` | Choose |

Comparisons do not chain. Write `a < b && b < c`, not `a < b < c`. A division always gives a number, and dividing by zero is an error.

```console
$ cplang expr eval '7 / 2'
3.5  (number, trusted)
$ cplang expr eval '2 in [1, 2, 3]'
true  (boolean, trusted)
$ cplang expr eval 'true ? "yes" : "no"'
yes  (string, trusted)
```
{: data-run="true"}

## Functions

### Numbers

| `abs` | `min` | `max` | `sum` |
| --- | --- | --- | --- |
| `round` | `floor` | `ceil` | |

`round(x, digits)` rounds half to even. `min` and `max` take a list or up to eight values.

```console
$ cplang expr eval 'round(3.14159, 3)'
3.142  (number, trusted)
$ cplang expr eval 'max([4, 9, 2])'
9  (integer, trusted)
```
{: data-run="true"}

### Text

| `lower` | `upper` | `trim` | `split` |
| --- | --- | --- | --- |
| `join` | `contains` | `starts_with` | `ends_with` |
| `matches` | | | |

`matches(text, pattern)` searches with a regular expression. The pattern must be a literal string, so it can be checked when the policy loads.

```console
$ cplang expr eval 'split("a,b,c", ",")'
[a, b, c]  (list, trusted)
$ cplang expr eval 'matches("abc123", "[0-9]+")'
true  (boolean, trusted)
```
{: data-run="true"}

### Collections

| `size` | `count` | `keys` | `values` |
| --- | --- | --- | --- |

`size` and `count` measure text, lists and maps.

### Time

`timestamp("...")` reads an RFC 3339 time. `duration("...")` reads an ISO 8601 duration such as `PT30M`. `date_diff(a, b, unit)` counts whole `seconds`, `minutes`, `hours` or `days` from `b` to `a`.

```console
$ cplang expr eval 'date_diff(timestamp("2026-01-03T00:00:00Z"), timestamp("2026-01-01T00:00:00Z"), "days")'
2  (integer, trusted)
$ cplang expr eval 'timestamp("2026-01-05T10:00:00Z") + duration("PT1H")'
2026-01-05T11:00:00.000000Z  (timestamp, trusted)
```
{: data-run="true"}

`time.now` is the `timestamp` of the action. Compare it with a time from the action to build expiry rules:

```yaml
cpl: "1.0"
id: expiry
version: 1
default: deny
rules:
  - id: valid-token
    match: {kind: [api_call]}
    when:
      expr: "timestamp(arguments.expires) > time.now"
    outcome: allow

  - id: fresh-enough
    match: {kind: [read_cache]}
    when:
      expr: "date_diff(time.now, timestamp(arguments.stored_at), 'minutes') < 30"
    outcome: allow
```
{: data-title="expiry.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: token-still-valid
    action: {kind: api_call, arguments: {expires: "2026-01-05T12:00:00Z"}}
    expect: {outcome: allow}

  - name: token-expired
    action: {kind: api_call, arguments: {expires: "2026-01-05T09:00:00Z"}}
    expect: {outcome: deny}

  - name: cache-entry-is-fresh
    action: {kind: read_cache, arguments: {stored_at: "2026-01-05T09:45:00Z"}}
    expect: {outcome: allow}

  - name: cache-entry-is-stale
    action: {kind: read_cache, arguments: {stored_at: "2026-01-05T08:00:00Z"}}
    expect: {outcome: deny}
```
{: data-title="expiry.fixtures.yaml"}

## Collections

`filter`, `map`, `all` and `any` work on a list. The element is called `it` unless you name it:

```console
$ cplang expr eval 'filter([1, 2, 3, 4], it > 2)'
[3, 4]  (list, trusted)
$ cplang expr eval 'map([1, 2, 3], it * 2)'
[2, 4, 6]  (list, trusted)
$ cplang expr eval 'all([1, 2, 3], n, n > 1)'
false  (boolean, trusted)
```
{: data-run="true"}

```yaml
cpl: "1.0"
id: attachments
version: 1
default: deny
rules:
  - id: documents-only
    match: {kind: [send_email]}
    when:
      expr: "all(arguments.files, f, ends_with(lower(f), '.pdf') || ends_with(lower(f), '.txt'))"
    outcome: allow
```
{: data-title="attachments.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: pdf-and-text
    action: {kind: send_email, arguments: {files: [report.PDF, notes.txt]}}
    expect: {outcome: allow}

  - name: an-executable-is-in-the-list
    action: {kind: send_email, arguments: {files: [report.pdf, setup.exe]}}
    expect: {outcome: deny}
```
{: data-title="attachments.fixtures.yaml"}

## Missing Values

A path the action does not carry is absent. Absent spreads: an operator or function that receives an absent value returns absent, and a condition that is absent is false. Three functions handle it on purpose:

| Function | Result |
| --- | --- |
| `has(path)` | `true` when the value is present |
| `default(path, fallback)` | The value, or the fallback when absent |
| `coalesce(a, b, c)` | The first value that is present |

```console
$ cplang expr eval 'default(arguments.limit, 100)'
100  (integer, trusted)
$ cplang expr eval 'has(arguments.limit)'
false  (boolean, untrusted)
```
{: data-run="true"}

> Use `default` for limits and `has` for optional fields. Never use `default` to supply a value that would make an `allow` rule easier to satisfy.
{: .note}

## Named Values

Use `let` to compute a value once. See [Rules](/rules/#let). A `let` value is read as `var.name`, and it can use the ones declared before it.

## Trusted and Untrusted Data

Every value remembers whether it came from the action, which an agent may control, or from the policy itself. `cplang expr eval` reports it, and text such as hints leaves untrusted values out. See [Verdict](/reference/verdict/).

## Errors Refuse

An expression that fails while it runs does not guess. Dividing by zero, overflowing an integer or going past a limit makes the whole verdict a `deny` with the reason `EVALUATION_ERROR`, even when the policy default is `allow`:

```yaml
cpl: "1.0"
id: division
version: 1
default: allow
rules:
  - id: ratio-too-high
    match: {kind: [report]}
    when:
      expr: "arguments.failed / arguments.total > 0.1"
    outcome: deny
```
{: data-title="division.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: normal
    action: {kind: report, arguments: {failed: 1, total: 100}}
    expect: {outcome: allow}

  - name: zero-total-is-refused
    action: {kind: report, arguments: {failed: 1, total: 0}}
    expect: {outcome: deny, reason_codes: [EVALUATION_ERROR]}
```
{: data-title="division.fixtures.yaml"}

Guard such a division with a test that runs first. `&&` stops at the first false operand, so `arguments.total > 0 && arguments.failed / arguments.total > 0.1` never divides by zero.

## Limits

An expression has at most 256 nodes, runs at most 10,000 steps and may nest 64 levels. A policy that goes past the size limits does not load. Hosts can raise or lower the limits. See [Embedding](/embedding/).

> ▶ Next: [Signals](/signals/)
{: .next}
