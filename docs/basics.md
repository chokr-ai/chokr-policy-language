---
title: Basics
description: How a policy turns an action into a verdict, how to write one and how to run it.
---

A policy is a list of rules written as data. The engine reads an action, applies the rules and returns a verdict. The same action always gets the same verdict, so every decision can be tested and replayed.

```yaml
cpl: "1.0"
id: documents
version: 1
default: deny
rules:
  - id: read-public
    match: {kind: [read]}
    when: {resource.type: public}
    outcome: allow
```
{: data-title="documents.policy.yaml"}

Each rule says which actions it is about (`match`), which extra conditions must hold (`when`) and what happens (`outcome`).

## How It Works

### Actions, Signals and Verdicts

Three kinds of data move through the engine:

| Data | What it is | Who supplies it |
| --- | --- | --- |
| Action | The thing about to happen, as a JSON-like document | Your application |
| Signal | A named finding about the action, such as `scan.malware` | A scanner or checker you run |
| Verdict | The decision, with reason codes and the rules that decided | The engine |

An action needs a `timestamp` and any fields you choose. Rules read those fields by path, for example `resource.type` or `arguments.size_kb`.

> Rule: set the `timestamp` from your own clock, never from the request. Time windows and rate limits read it.
{: .note}

### Outcomes

Every verdict carries one of five outcomes, from weakest to strongest:

| Outcome | Meaning |
| --- | --- |
| `allow` | Go ahead |
| `watch` | Go ahead, and flag the action for review |
| `modify` | Go ahead after the listed edits are applied |
| `ask` | Wait for a person to approve |
| `deny` | Refuse |

When several rules match, the strongest outcome wins. A `deny` always beats an `allow`. See [Combining Rules](/decisions/) to change that.

### Defaults

When no rule matches, the policy `default` applies. It is either `allow` or `deny`. Use `deny` so that a missing rule never grants access.

## Writing Policies

### Match and When

`match` selects the actions a rule is about. `when` adds conditions on the content of the action. Both are mappings, and every entry must hold for the rule to apply:

```yaml
cpl: "1.0"
id: documents
version: 2
default: deny
rules:
  - id: read-public
    match: {kind: [read]}
    when: {resource.type: public}
    outcome: allow

  - id: large-upload-needs-approval
    match: {kind: [write]}
    when:
      expr: "arguments.size_kb > 512"
      approval: {timeout_seconds: 3600}
    outcome: ask

  - id: malware-found
    when: {signal: {code: scan.malware, severity_gte: high}}
    outcome: deny
```
{: data-title="documents.policy.yaml"}

The second rule uses an expression. The third reads a signal and has no `match`, so it applies to every kind of action.

> An `ask` rule needs an `approval` block in `when`. Without it the policy does not load.
{: .note}

### Test the Rules

Add a case for every rule, and one for the default:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: public-read
    action: {kind: read, resource: {type: public}}
    expect: {outcome: allow, matched_rules: [read-public]}

  - name: big-upload
    action: {kind: write, arguments: {size_kb: 900}}
    expect: {outcome: ask, reason_codes: [RULE_ASK]}

  - name: small-upload-has-no-rule
    action: {kind: write, arguments: {size_kb: 10}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}

  - name: malware-beats-everything
    action: {kind: read, resource: {type: public}}
    signals: [{code: scan.malware, severity: critical}]
    expect: {outcome: deny, matched_rules: [malware-found, read-public]}
```
{: data-title="documents.fixtures.yaml"}

The last case shows the strongest-outcome rule at work: both rules match, and `deny` wins.

## Running Policies

### From the Command Line

Use the command line while you write policies and in CI:

```console
$ cplang policy check documents.policy.yaml    # validate and lint
$ cplang test --policy documents.policy.yaml --fixtures documents.fixtures.yaml
$ cplang eval --policy documents.policy.yaml --action action.yaml
```

| `policy check` | `policy validate` | `policy lint` | `policy fmt` |
| --- | --- | --- | --- |
| `policy explain` | `policy fingerprint` | `policy types` | `policy prove` |
| `test` | `eval` | `expr eval` | `schema` |
| `decl check` | `decl show` | `decl fmt` | `decl lock` |

Add `--json` to any command for machine-readable output. See the [command line reference](/reference/cli/) for every option.

### From Python

Load the policy once, keep the evaluator and call it for every action:

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, Signal, load_policy

policy = load_policy([Path("documents.policy.yaml")], roots=[Path(".")])
evaluator = RuleEvaluator(policy)

action = Action({"kind": "read", "resource": {"type": "public"}, "timestamp": "2026-01-05T10:00:00Z"})
verdict = evaluator.evaluate(action, [Signal(code="scan.malware", source="scanner", severity="low")])
print(verdict.outcome, verdict.reason_codes, verdict.matched_rules)
```
{: data-title="decide.py"}

Expected output:

```console
allow ['POLICY_SATISFIED'] ['read-public']
```
{: data-output="decide.py"}

The evaluator is thread-safe. Reuse one instance for the life of the process. See [Embedding](/embedding/) for host functions, limits and error handling.

## Output and Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | The check passed, or `eval` returned `allow`, `watch` or `modify` |
| `1` | The check failed, or `eval` returned `deny` or `ask` |
| `2` | Bad usage or unreadable input, such as a missing file |
| `3` | An internal error |

> ▶ Next: [Rules](/rules/)
{: .next}
