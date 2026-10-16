---
title: Error Codes
description: The codes the language reports when a file is wrong or a decision fails, with the usual cause and the fix.
---

Two kinds of problem exist. An authoring error is a mistake in a file, and the engine reports it when the file loads. An evaluation error is a failure while deciding, and the engine refuses the action.

## Authoring Errors

The command line prints them as `FAILED: CODE file:line:column message`. `load_policy` raises them as `AuthoringError` with the same fields.

| Code | Usual cause | Fix |
| --- | --- | --- |
| `SCHEMA_INVALID` | A key, value or structure is not allowed, such as an unknown outcome | Read the message. It names the key and says what is expected |
| `EXPRESSION_SYNTAX` | An expression cannot be parsed. The message has a column | Fix the expression at that column |
| `EXPRESSION_LIMIT` | An expression is nested too deeply or is too large | Split it with `let` values or a declared function |
| `TYPE_ERROR` | A comparison or call mixes types, or a value does not match its declared type | Fix the types, or declare the input |
| `DECLARATION_INVALID` | A declaration file has a bad key, name, schema or value | Check the file against [Declarations](/declarations/) |
| `DECLARATION_UNKNOWN_NAME` | A rule uses a name that is not declared, or is private to its file | Declare it, import it, or add it to `only` |
| `DECLARATION_CONFLICT` | A name is used twice, such as two rules with the same id | Rename one |
| `IMPORT_NOT_FOUND` | An imported file cannot be read | Check the path and the roots |
| `IMPORT_FORBIDDEN` | An import leaves the roots, is absolute, is nested too deeply or uses the network | Use a relative path inside a root |
| `IMPORT_CYCLE` | Files import each other in a loop | Remove the loop |
| `IMPORT_DIGEST_MISMATCH` | An imported file differs from its pinned digest or its lock entry | Review the change, then update the digest |
| `VOCABULARY_UNKNOWN_VALUE` | A namespaced code or signal is not declared | Declare it in a declaration file |
| `FINGERPRINT_MISMATCH` | The fingerprint differs from `--pin` | Review the change, then update the pin |

## Examples

An `ask` rule without an approval block:

```yaml
cpl: "1.0"
id: missing-approval
version: 1
default: deny
rules:
  - id: needs-a-person
    match: {kind: [payment]}
    outcome: ask
```
{: data-title="missing-approval.policy.yaml" data-error="SCHEMA_INVALID"}

An expression that stops in the middle:

```yaml
cpl: "1.0"
id: bad-syntax
version: 1
default: deny
rules:
  - id: broken
    match: {kind: [payment]}
    when: {expr: "arguments.amount >"}
    outcome: allow
```
{: data-title="bad-syntax.policy.yaml" data-error="EXPRESSION_SYNTAX"}

A name that no declaration defines:

```yaml
cpl: "1.0"
id: unknown-name
version: 1
default: deny
rules:
  - id: limit
    match: {kind: [payment]}
    when: {expr: "arguments.amount <= param.max_amount"}
    outcome: allow
```
{: data-title="unknown-name.policy.yaml" data-error="DECLARATION_UNKNOWN_NAME"}

An import that is not there:

```yaml
cpl: "1.0"
id: missing-import
version: 1
imports:
  - {from: ./nothing.decl.yaml}
default: deny
rules: []
```
{: data-title="missing-import.policy.yaml" data-error="IMPORT_NOT_FOUND"}

## Warnings

A warning is a problem that does not stop a policy from loading. `cplang policy check` fails on any warning.

| Code | Severity | Meaning |
| --- | --- | --- |
| `unused-variable` | warning | A `let` value is never used |
| `unreachable-rule` | warning | Under `first_match` or `priority`, an earlier rule always decides first |
| `duplicate-rule` | warning | Two rules have the same conditions and the same outcome |
| `conflicting-rules` | warning | Two rules have the same conditions and different outcomes |
| `undeclared-input` | warning | A rule reads a name that is neither standard nor declared |
| `disabled-rule` | info | A rule has `enabled: false` |
| `unused-declaration` | info | A parameter, constant or table is never used |
| `RULE_NEVER_MATCHES` | warning | A `match` list is empty, so the rule never applies |
| `VOCABULARY_UNKNOWN_VALUE` | warning | A namespaced code is not declared |

## Evaluation Errors

An evaluation error never raises in your application. The verdict is a `deny` with the reason code `EVALUATION_ERROR` (a `watch` with `posture="allow_and_flag"`). The `message` of the reason says what happened:

| Cause | Example |
| --- | --- |
| Arithmetic | Division by zero, integer overflow |
| Type | An input of the wrong declared type, text used as a number |
| Limit | More steps than `max_eval_steps` |
| Text | `response_matches` on a reply that is not text |
| Modifications | Overlapping edits, or a `modify` with no change |
| Host function | A function that is not registered, or that raised |
| Missing timestamp | An action without a `timestamp` |

Fixtures that end in an evaluation error fail unless they expect `EVALUATION_ERROR` in `reason_codes`.

## Other Codes

| Code | Meaning |
| --- | --- |
| `NAMESPACE_VIOLATION` | A function name is not `namespace/name` |
| `CANONICALIZATION_ERROR` | A value cannot be written as canonical JSON |
| `INTERNAL_ERROR` | A bug in the engine. The command exits with `3` |

> ▶ Next: [Cheatsheet](/reference/cheatsheet/)
{: .next}
