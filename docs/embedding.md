---
title: Embedding
description: Load a policy once, decide every action in your own program and connect host functions, limits and storage.
---

The `cplang` package is a library first. Your application builds an action, asks the evaluator for a verdict and acts on it. The package is fully typed, so a type checker sees the same signatures you read here.

```yaml
cpl: "1.0"
id: assistant
version: 1
default: deny
rules:
  - id: read-notes
    match: {kind: [tool_call]}
    when: {target: notes, arguments.operation: read}
    outcome: allow

  - id: virus-found
    when: {signal: {code: scan.malware, severity_gte: high}}
    outcome: deny
```
{: data-title="assistant.policy.yaml"}

## Load and Decide

`load_policy` reads and checks the files and returns a compiled policy. `RuleEvaluator` decides actions with it:

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, Signal, load_policy

policy = load_policy([Path("assistant.policy.yaml")], roots=[Path(".")])
evaluator = RuleEvaluator(policy)  # reuse it for every request

action = Action(
    {
        "kind": "tool_call",
        "target": {"name": "notes"},
        "arguments": {"operation": "read"},
        "timestamp": "2026-01-05T10:00:00Z",
    }
)
verdict = evaluator.evaluate(action, [Signal(code="scan.malware", source="scanner", severity="low")])
print(verdict.outcome, verdict.reason_codes, verdict.matched_rules)
```
{: data-title="decide.py"}

```console
allow ['POLICY_SATISFIED'] ['read-notes']
```
{: data-output="decide.py"}

| Object | Purpose |
| --- | --- |
| `Action` | The thing about to happen. Needs a `timestamp` |
| `Signal` | A finding, with `code`, `source`, `severity`, `confidence` and `facts` |
| `RuleEvaluator` | Decides actions. Safe to share between threads |
| `Verdict` | The outcome, reasons, matched rules, obligations and modifications |

Use `verdict.to_wire()` to get the verdict as plain JSON-compatible data for logs and APIs.

## Handle Invalid Policies

`load_policy` raises `AuthoringError` for any problem in the files. The error carries a stable code and the location:

```yaml
cpl: "1.0"
id: broken
version: 1
default: deny
rules:
  - id: bad-outcome
    outcome: permit
```
{: data-title="broken.policy.yaml" data-error="SCHEMA_INVALID"}

```python
from pathlib import Path

from cplang import AuthoringError, load_policy

try:
    load_policy([Path("broken.policy.yaml")], roots=[Path(".")])
except AuthoringError as error:
    print(error.code, f"{error.file}:{error.line}", error.message)
```
{: data-title="broken.py"}

```console
SCHEMA_INVALID broken.policy.yaml:7 unknown outcome 'permit'
```
{: data-output="broken.py"}

Load policies at start-up, so an invalid file stops a deploy instead of a request.

## Failures Refuse

`evaluate` never raises for a failure inside a policy. A failing expression, an input of the wrong type or a limit that is passed returns a `deny` with the reason `EVALUATION_ERROR`. Your application needs no `try` block to stay safe.

Pass `posture="allow_and_flag"` to the evaluator when a failure must not block users. The verdict is then a `watch` instead of a `deny`.

## Parameters and Limits

Override declared parameters with `config_params`, and tighten the safety limits with `CplLimits`:

```yaml
schema: cpl.declarations/1.0
namespace: example.budget
parameters:
  max_refund: {type: integer, default: 200}
```
{: data-title="budget.decl.yaml"}

```yaml
cpl: "1.0"
id: budget
version: 1
imports:
  - {from: ./budget.decl.yaml}
default: deny
rules:
  - id: small-refunds
    match: {kind: [refund]}
    when: {expr: "arguments.amount <= param.max_refund"}
    outcome: allow
```
{: data-title="budget.policy.yaml"}

```python
from pathlib import Path

from cplang import Action, CplLimits, RuleEvaluator, load_policy

policy = load_policy(
    [Path("budget.policy.yaml")],
    roots=[Path(".")],
    config_params=[{"max_refund": 50}],
    limits=CplLimits(max_eval_steps=2_000, max_rules=500),
)
action = Action({"kind": "refund", "arguments": {"amount": 100}, "timestamp": "2026-01-05T10:00:00Z"})
print(len(policy.rules), "rule loaded;", RuleEvaluator(policy).evaluate(action, []).outcome)
```
{: data-title="limits.py"}

```console
1 rule loaded; deny
```
{: data-output="limits.py"}

`config_params` binds the parameters the declarations define. A name that no declaration defines is an error. `CplLimits` caps expression size and steps, rule count, table rows, regex length, document size and more. A policy that goes past a size limit does not load, and a run that goes past a step limit is refused.

## Host Functions

A host function is a Python function that expressions can call, for lookups that policy files cannot hold, such as a score from your own service. Register it under `<namespace>/<name>`. It receives the action and a mapping with the call's `args`, and it must return the same result for the same input:

```python
from collections.abc import Mapping
from pathlib import Path

from cplang import Action, FunctionRegistry, JsonValue, RuleEvaluator, load_policy

SCORES = {"example.test": 10, "unknown.test": 90}


def risk(action: Action, arguments: Mapping[str, JsonValue]) -> JsonValue:
    args = arguments.get("args")
    host = args[0] if isinstance(args, list) and args else ""
    return SCORES.get(str(host), 50)


functions = FunctionRegistry()
functions.register("acme/risk", risk)

Path("web.policy.yaml").write_text(
    """cpl: "1.0"
id: web
version: 1
default: deny
rules:
  - id: low-risk-sites
    match: {kind: [http_request]}
    when: {expr: "acme/risk(target.destination_host) < 40"}
    outcome: allow
""",
    encoding="utf-8",
)
evaluator = RuleEvaluator(load_policy([Path("web.policy.yaml")], roots=[Path(".")], plugins=functions))
for host in ("example.test", "unknown.test"):
    action = Action({"kind": "http_request", "target": {"destination_host": host}, "timestamp": "2026-01-05T10:00:00Z"})
    print(host, evaluator.evaluate(action, []).outcome)
```
{: data-title="host_function.py"}

```console
example.test allow
unknown.test deny
```
{: data-output="host_function.py"}

The names and versions of the functions a policy uses are part of its fingerprint. Register the same functions in tests, or the policy cannot be evaluated there.

## Check a Response

Some rules can only decide after the tool has run, because they read the tool's reply as `arguments.response`. Evaluate the action before the call with `evaluate`, and again after it with `evaluate_result`. The first call skips every rule that reads the response. The second considers only rules that read signals or the response, and no match means `allow`:

```yaml
cpl: "1.0"
id: egress
version: 1
default: allow
rules:
  - id: no-private-keys-in-replies
    match: {kind: [tool_call]}
    when:
      response_matches: "*BEGIN PRIVATE KEY*"
    outcome: deny
```
{: data-title="egress.policy.yaml"}

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, load_policy

evaluator = RuleEvaluator(load_policy([Path("egress.policy.yaml")], roots=[Path(".")]))
call = {"kind": "tool_call", "arguments": {"query": "show config"}, "timestamp": "2026-01-05T10:00:00Z"}

print("before:", evaluator.evaluate(Action(call), []).outcome)

reply = {**call, "arguments": {**call["arguments"], "response": "-----BEGIN PRIVATE KEY-----"}}
print("after:", evaluator.evaluate_result(Action(reply), []).outcome)
```
{: data-title="response.py"}

```console
before: allow
after: deny
```
{: data-output="response.py"}

## Trace a Decision

`evaluator.trace(action, signals)` returns the verdict and a list of events with every rule's `match`, `when` and `let` results. It is the call behind `cplang policy explain`. It reads the state of rate limits and never changes it.

## Share Counts Between Processes

Rate limits keep their counts in memory by default. To keep them in a shared store, pass an object with two methods as `rate_limiter`:

```python
class SharedLimiter:
    def check(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
        """Record the call and return whether it is within the limit."""
        ...

    def peek(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool:
        """Return whether a call would be within the limit, recording nothing."""
        ...
```

Give it to the evaluator with `RuleEvaluator(policy, rate_limiter=SharedLimiter())`. Pass `live=False` for a dry run that never records a call.

## Add Host Vocabulary

A `Profile` lets a host add things the standard language does not have. The most useful one is `signal_effect`, which makes a signal decide by itself before any rule runs. A `hard` effect cannot be overruled by an `allow` rule:

```python
from pathlib import Path

from cplang import Action, Profile, RuleEvaluator, Signal, SignalEffect, load_policy


def effect(signal: Signal) -> SignalEffect | None:
    if signal.code == "malware.confirmed":
        return SignalEffect("deny", "ACTION_FORBIDDEN", hard=True)
    return None


profile = Profile(signal_effect=effect)
policy = load_policy([Path("assistant.policy.yaml")], roots=[Path(".")], profile=profile)
evaluator = RuleEvaluator(policy, profile=profile)
action = Action(
    {
        "kind": "tool_call",
        "target": {"name": "notes"},
        "arguments": {"operation": "read"},
        "timestamp": "2026-01-05T10:00:00Z",
    }
)
print(evaluator.evaluate(action, [Signal(code="malware.confirmed", source="scanner")]).reason_codes[0])
```
{: data-title="profile.py"}

```console
ACTION_FORBIDDEN
```
{: data-output="profile.py"}

A profile can also declare extra reason texts, signal families, obligation types, input roots and `when:` keys. Pass the same profile to `load_policy` and to the evaluator.

> ▶ Next: [Agent Tool Calls](/use-cases/agent-tools/)
{: .next}
