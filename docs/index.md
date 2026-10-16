---
title: CHOKR Policy Language
description: Write rules as data, test them offline and get a verdict for every action an AI agent or program is about to take.
---

<div class="hero" markdown="1">

# CHOKR Policy Language {#top}

A small, declarative language for governing what AI agents and programs may do. You write the rules as YAML. The engine reads an action and returns a verdict: `allow`, `watch`, `modify`, `ask` or `deny`.
{: .lead}

<div class="actions">
  <a class="btn primary" href="/quickstart/">Quickstart</a>
  <a class="btn" href="/basics/">Read the basics</a>
</div>

</div>

```yaml
cpl: "1.0"
id: agent-tool-calls
version: 1
default: deny                         # anything not allowed is denied
rules:
  - id: small-payments
    match: {kind: [tool_call]}
    when: {arguments.tool: send_payment, expr: "arguments.amount <= 100"}
    outcome: allow

  - id: large-payments-need-a-human
    match: {kind: [tool_call]}
    when:
      arguments.tool: send_payment
      expr: "arguments.amount > 100"
      approval: {timeout_seconds: 900}
    outcome: ask
```
{: data-title="agent-tool-calls.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: small-payment
    action: {kind: tool_call, arguments: {tool: send_payment, amount: 40}}
    expect: {outcome: allow}

  - name: large-payment
    action: {kind: tool_call, arguments: {tool: send_payment, amount: 4000}}
    expect: {outcome: ask}
```
{: data-title="agent-tool-calls.fixtures.yaml"}

```console
$ cplang test --policy agent-tool-calls.policy.yaml --fixtures agent-tool-calls.fixtures.yaml
✓ small-payment                                    allow
✓ large-payment                                    ask
2 passed, 0 failed
```
{: data-run="true"}

## What You Get

<div class="cards" markdown="1">

<div class="card" markdown="1">

### Readable
Rules are data that people other than the author can read, review and change.

</div>

<div class="card" markdown="1">

### Deterministic
The same action always gets the same verdict, so decisions can be tested and replayed.

</div>

<div class="card" markdown="1">

### Testable
Fixture files pin the decisions you expect, and one command runs them offline.

</div>

<div class="card" markdown="1">

### Safe by default
A missing field never grants access, and a failure inside a policy refuses the action.

</div>

</div>

## Where to Go

| Start here | Then |
| --- | --- |
| [Quickstart](/quickstart/) | [Installation](/installation/) |
| [Basics](/basics/) | [Rules](/rules/) |
| [Conditions](/conditions/) | [Testing Policies](/testing/) |
| [Agent Tool Calls](/use-cases/agent-tools/) | [Embedding](/embedding/) |

Use it when a program must make allow or deny decisions that other people need to read, review or change. The language works with any agent framework or tool-calling protocol, because it only sees the action you hand it.
