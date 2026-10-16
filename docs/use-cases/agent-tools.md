---
title: Agent Tool Calls
description: Govern what an AI agent may do with its tools, from an allow list of tools to approvals and injection signals.
---

An AI agent acts through tools: searches, file reads, payments, messages. Each tool call is an action. A policy sits between the agent and its tools, and every call gets a verdict before it runs.

This page builds one policy in four steps. Each step adds one rule and one test.

## Allow Known Tools

Start from `default: deny`. Allow the tools the agent needs and nothing else:

```yaml
cpl: "1.0"
id: agent-tools
version: 1
default: deny
rules:
  - id: read-only-tools
    description: Search and read tools are always fine.
    match: {kind: [tool_call]}
    when: {arguments.tool: [web_search, read_file]}
    outcome: allow
```
{: data-title="agent-tools.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: search-is-allowed
    action: {kind: tool_call, arguments: {tool: web_search, query: weather}}
    expect: {outcome: allow, matched_rules: [read-only-tools]}

  - name: an-unlisted-tool-is-denied
    action: {kind: tool_call, arguments: {tool: delete_database}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="agent-tools.fixtures.yaml"}

The tool name travels in `arguments.tool`. Your application decides where the name goes. Pick one place and use it in every rule.

## Limit What a Tool May Do

Allow a tool only within bounds. Small payments go through. Large payments wait for a person:

```yaml
cpl: "1.0"
id: agent-tools
version: 2
default: deny
rules:
  - id: read-only-tools
    description: Search and read tools are always fine.
    match: {kind: [tool_call]}
    when: {arguments.tool: [web_search, read_file]}
    outcome: allow

  - id: small-payments
    match: {kind: [tool_call]}
    when:
      arguments.tool: send_payment
      expr: "arguments.amount <= 100"
    outcome: allow

  - id: large-payments-need-a-human
    match: {kind: [tool_call]}
    when:
      arguments.tool: send_payment
      expr: "arguments.amount > 100"
      approval: {timeout_seconds: 900}
    outcome: ask
```
{: data-title="agent-tools.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: search-is-allowed
    action: {kind: tool_call, arguments: {tool: web_search, query: weather}}
    expect: {outcome: allow, matched_rules: [read-only-tools]}

  - name: an-unlisted-tool-is-denied
    action: {kind: tool_call, arguments: {tool: delete_database}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}

  - name: small-payment
    action: {kind: tool_call, arguments: {tool: send_payment, amount: 40}}
    expect: {outcome: allow, matched_rules: [small-payments]}

  - name: large-payment-asks-a-person
    action: {kind: tool_call, arguments: {tool: send_payment, amount: 4000}}
    expect: {outcome: ask, matched_rules: [large-payments-need-a-human]}

  - name: payment-with-no-amount
    action: {kind: tool_call, arguments: {tool: send_payment}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="agent-tools.fixtures.yaml"}

The last case matters. A payment without an `amount` matches neither payment rule, because a missing field never satisfies a condition. The default denies it.

## React to Findings

Add a scanner for prompt injection and let its findings override everything. Because `deny` is stronger than `allow`, one rule is enough:

```yaml
cpl: "1.0"
id: agent-tools
version: 3
default: deny
rules:
  - id: read-only-tools
    description: Search and read tools are always fine.
    match: {kind: [tool_call]}
    when: {arguments.tool: [web_search, read_file]}
    outcome: allow

  - id: small-payments
    match: {kind: [tool_call]}
    when:
      arguments.tool: send_payment
      expr: "arguments.amount <= 100"
    outcome: allow

  - id: large-payments-need-a-human
    match: {kind: [tool_call]}
    when:
      arguments.tool: send_payment
      expr: "arguments.amount > 100"
      approval: {timeout_seconds: 900}
    outcome: ask

  - id: prompt-injection-suspected
    when: {signal: {code: prompt.injection, severity_gte: medium}}
    outcome: deny
    explain: "A {signal.source} flagged {signal.code} at {signal.severity} severity."
    hint:
      next_steps: [{kind: stop_and_report}]
```
{: data-title="agent-tools.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: search-is-allowed
    action: {kind: tool_call, arguments: {tool: web_search, query: weather}}
    expect: {outcome: allow, matched_rules: [read-only-tools]}

  - name: small-payment
    action: {kind: tool_call, arguments: {tool: send_payment, amount: 40}}
    expect: {outcome: allow}

  - name: injection-stops-a-search
    action: {kind: tool_call, arguments: {tool: web_search, query: weather}}
    signals: [{code: prompt.injection, source: guard, severity: high}]
    expect: {outcome: deny, matched_rules: [prompt-injection-suspected, read-only-tools]}

  - name: a-weak-finding-is-ignored
    action: {kind: tool_call, arguments: {tool: web_search, query: weather}}
    signals: [{code: prompt.injection, source: guard, severity: low}]
    expect: {outcome: allow}
```
{: data-title="agent-tools.fixtures.yaml"}

The `explain` text is for the operator who reads the log. The `hint` is for the agent: it receives next steps and a message that leaves out any value taken from the action.

## Cap the Pace

An agent in a loop can call a tool thousands of times. Add a rate limit to the allow rule, and a bound on the arguments:

```yaml
cpl: "1.0"
id: agent-pace
version: 1
default: deny
rules:
  - id: bounded-search
    match: {kind: [tool_call]}
    when:
      arguments.tool: web_search
      bounded_params: {max_results: {min: 1, max: 20}}
      max_calls_per_window: {limit: 30, window_seconds: 60}
    outcome: allow
```
{: data-title="agent-pace.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: normal-search
    action: {kind: tool_call, actor: {subject: agent-7}, arguments: {tool: web_search, max_results: 10}}
    expect: {outcome: allow}

  - name: oversized-search
    action: {kind: tool_call, actor: {subject: agent-7}, arguments: {tool: web_search, max_results: 5000}}
    expect: {outcome: deny, reason_codes: [PARAM_OUT_OF_BOUNDS]}
```
{: data-title="agent-pace.fixtures.yaml"}

Counts are kept per actor. Set `actor.subject` to the agent's identity, and one noisy agent cannot use up the budget of the others. See [Limits and Guards](/limits/).

## Use It in the Agent Loop

The loop asks the evaluator before every tool call:

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, load_policy

evaluator = RuleEvaluator(load_policy([Path("agent-tools.policy.yaml")], roots=[Path(".")]))


def guard(tool: str, arguments: dict[str, object], timestamp: str) -> str:
    action = Action({"kind": "tool_call", "arguments": {"tool": tool, **arguments}, "timestamp": timestamp})
    verdict = evaluator.evaluate(action, [])
    return verdict.outcome


print(guard("send_payment", {"amount": 40}, "2026-01-05T10:00:00Z"))
print(guard("send_payment", {"amount": 4000}, "2026-01-05T10:00:00Z"))
print(guard("delete_database", {}, "2026-01-05T10:00:00Z"))
```
{: data-title="loop.py"}

```console
allow
ask
deny
```
{: data-output="loop.py"}

- `allow`: run the tool.
- `ask`: stop and send the request to a person. Run the tool only if they approve.
- `deny`: do not run the tool. Return `verdict.hint` to the agent, so it can choose another step.

> ▶ Next: [Shell Commands](/use-cases/shell-commands/)
{: .next}
