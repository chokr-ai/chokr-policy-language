---
title: Signals
description: Let scanners and checkers report findings about an action, and write rules that react to them.
---

A signal is a named finding about an action. Something outside the language, such as a malware scanner, a prompt checker or a data-loss detector, produces it. The policy decides what each finding means.

```yaml
cpl: "1.0"
id: signals-intro
version: 1
default: allow
rules:
  - id: injection-suspected
    when: {signal: {code: prompt.injection, severity_gte: medium}}
    outcome: deny
```
{: data-title="intro.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: no-signals
    action: {kind: tool_call}
    expect: {outcome: allow}

  - name: serious-finding
    action: {kind: tool_call}
    signals: [{code: prompt.injection, severity: high}]
    expect: {outcome: deny}

  - name: minor-finding
    action: {kind: tool_call}
    signals: [{code: prompt.injection, severity: low}]
    expect: {outcome: allow}
```
{: data-title="intro.fixtures.yaml"}

The policy keeps the decision, and the scanner keeps the detection. Replacing a scanner never means rewriting rules.

## The Shape of a Signal

| Field | Meaning |
| --- | --- |
| `code` | The name of the finding, such as `scan.malware` |
| `source` | Who reported it, such as `scanner` (default `host`) |
| `severity` | `info`, `low`, `medium`, `high` or `critical` (default `high`) |
| `confidence` | A number from 0 to 1 (default `1.0`) |
| `facts` | A map of details the rules can read |
| `evidence` | Material for people, never read by rules |
| `suggested_modification` | An edit the scanner proposes, see [Modifying Actions](/modifying/) |

Pass signals next to the action. On the command line use `--signals file.yaml`. In fixtures use `signals:`. In Python pass a list of `Signal` objects to `evaluate`.

## Match Signals

The `signal` condition takes one or more of these keys. All of them must hold for one signal:

| Key | True when |
| --- | --- |
| `code` | The signal has exactly this code |
| `code_prefix` | The code starts with this text |
| `source` | The signal came from this source |
| `severity_gte` | The severity is at least this level |
| `confidence_gte` | The confidence is at least this number |
| `count_gte` | At least this many signals satisfy the other keys |
| `facts` | Every named fact has the given value, or one of the listed values |

```yaml
cpl: "1.0"
id: signal-keys
version: 1
default: allow
rules:
  - id: any-scanner-finding
    when: {signal: {code_prefix: "scan.", severity_gte: high}}
    outcome: ask
    reason: RULE_ASK
    explain: "A {signal.source} reported {signal.code}."
    obligations:
      - {type: notify, params: {channel: security}}

  - id: repeated-warnings
    when: {signal: {code: spam.suspected, count_gte: 3}}
    outcome: deny

  - id: confident-pii
    when:
      signal:
        code: pii.detected
        confidence_gte: 0.9
        facts: {kind: [email, phone]}
    outcome: deny
```
{: data-title="keys.policy.yaml" data-error="SCHEMA_INVALID"}

The first rule asks for approval, so it needs an `approval` block. Add one:

```yaml
cpl: "1.0"
id: signal-keys
version: 1
default: allow
rules:
  - id: any-scanner-finding
    when:
      signal: {code_prefix: "scan.", severity_gte: high}
      approval: {timeout_seconds: 600}
    outcome: ask
    explain: "A {signal.source} reported {signal.code}."
    obligations:
      - {type: notify, params: {channel: security}}

  - id: repeated-warnings
    when: {signal: {code: spam.suspected, count_gte: 3}}
    outcome: deny

  - id: confident-pii
    when:
      signal:
        code: pii.detected
        confidence_gte: 0.9
        facts: {kind: [email, phone]}
    outcome: deny
```
{: data-title="keys.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: scanner-finding-needs-approval
    action: {kind: tool_call}
    signals: [{code: scan.macro, source: scanner, severity: critical}]
    expect: {outcome: ask, reason_codes: [RULE_ASK]}

  - name: three-spam-signals
    action: {kind: tool_call}
    signals:
      - {code: spam.suspected, severity: low}
      - {code: spam.suspected, severity: low}
      - {code: spam.suspected, severity: low}
    expect: {outcome: deny}

  - name: two-spam-signals-are-not-enough
    action: {kind: tool_call}
    signals:
      - {code: spam.suspected, severity: low}
      - {code: spam.suspected, severity: low}
    expect: {outcome: allow}

  - name: confident-email
    action: {kind: tool_call}
    signals: [{code: pii.detected, confidence: 0.95, facts: {kind: email}}]
    expect: {outcome: deny}

  - name: unsure-email
    action: {kind: tool_call}
    signals: [{code: pii.detected, confidence: 0.4, facts: {kind: email}}]
    expect: {outcome: allow}
```
{: data-title="keys.fixtures.yaml"}

> Name signal codes in families such as `scan.`, `prompt.` and `pii.`. A prefix rule then covers a whole family, including codes a scanner adds later.
{: .note}

## Use Signal Text in Explanations

When a rule matches on a signal, `explain` can read the first matching signal as `{signal.code}`, `{signal.source}`, `{signal.severity}` and `{signal.confidence}`. Evidence is for people and is withheld from text that goes back to the caller.

## Signals and Decisions

A signal never decides by itself. A rule must read it. This keeps one place, the policy, where every decision is written down and tested.

> ▶ Next: [Approvals](/approvals/)
{: .next}
