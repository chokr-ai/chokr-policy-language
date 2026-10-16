---
title: Safe Rollout
description: Introduce a stricter rule without breaking users, by watching it first, proving its effect and pinning what you ship.
---

A new rule can block good traffic. The language has the tools to find that out before it does. This page follows one change from a first draft to an enforced rule.

The change: uploads above 50 MB are currently allowed. The team wants to refuse them.

## The Policy Today

```yaml
cpl: "1.0"
id: uploads
version: 1
default: deny
rules:
  - id: allow-uploads
    match: {kind: [upload]}
    outcome: allow
```
{: data-title="uploads.policy.yaml"}

## Step 1: Add the Rule in Monitor Mode

Write the new rule and set `mode: monitor`. It reports what it would have decided and blocks nothing:

```yaml
cpl: "1.0"
id: uploads
version: 2
default: deny
rules:
  - id: allow-uploads
    match: {kind: [upload]}
    outcome: allow

  - id: refuse-huge-uploads
    mode: monitor
    match: {kind: [upload]}
    when: {expr: "arguments.size_mb > 50"}
    outcome: deny
    reason: RULE_DENY
```
{: data-title="uploads.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: normal-upload
    action: {kind: upload, arguments: {size_mb: 4}}
    expect: {outcome: allow, would_block: false}

  - name: huge-upload-is-flagged-not-blocked
    action: {kind: upload, arguments: {size_mb: 400}}
    expect:
      outcome: watch
      would_block: true
      would_have_been: deny
      matched_rules: [allow-uploads, refuse-huge-uploads]
```
{: data-title="uploads.fixtures.yaml"}

The huge upload gets `watch`, so it goes through, and the verdict records that it would have been denied.

## Step 2: Count What Would Break

Ship the monitor rule and collect the held-back decisions. The evaluator takes a callback that receives every decision that monitor mode softened:

```python
from collections import Counter
from pathlib import Path

from cplang import Action, RuleEvaluator, load_policy

held_back: Counter[str] = Counter()


def record(action: Action, shadow: list[tuple[str, str]]) -> None:
    for rule_id, outcome in shadow:
        held_back[f"{rule_id}:{outcome}"] += 1


evaluator = RuleEvaluator(load_policy([Path("uploads.policy.yaml")], roots=[Path(".")]), on_suppressed=record)
for size in (4, 12, 75, 400, 9):
    evaluator.evaluate(
        Action({"kind": "upload", "arguments": {"size_mb": size}, "timestamp": "2026-01-05T10:00:00Z"}), []
    )
print(dict(held_back))
```
{: data-title="shadow.py"}

```console
{'refuse-huge-uploads:deny': 2}
```
{: data-output="shadow.py"}

Two of five uploads would have been refused. If that number is acceptable, go on. If not, change the limit and watch again.

## Step 3: Prove the Change

Replace the sample with a proof. The prover compares the old and the new policy over all inputs and reports an action one permits and the other does not. Run it on the change as it will be enforced:

```yaml
cpl: "1.0"
id: uploads
version: 3
default: deny
rules:
  - id: allow-small-uploads
    match: {kind: [upload]}
    when: {expr: "arguments.size_mb <= 50"}
    outcome: allow
```
{: data-title="uploads-enforced.policy.yaml"}

```console
$ cplang policy prove --diff uploads.policy.yaml uploads-enforced.policy.yaml
within_boundary: assumes every input is well-typed and evaluates without error; a failed evaluation is a refusal
```
{: data-run="true"}

The new policy is stricter, so it permits nothing that the old one denied. The result is `within_boundary` and the exit code is `0`. A `1` would mean the change opens something up. See [Testing Policies](/testing/).

## Step 4: Enforce

Remove `mode: monitor`, or use the enforced file above. Keep the fixtures from step 1 and change the expectation for the huge upload:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: normal-upload
    action: {kind: upload, arguments: {size_mb: 4}}
    expect: {outcome: allow}

  - name: huge-upload-is-refused
    action: {kind: upload, arguments: {size_mb: 400}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="uploads-enforced.fixtures.yaml"}

## Step 5: Pin What You Ship

Record the fingerprint of the reviewed policy and make the deployment check it:

```console
$ cplang policy fingerprint uploads-enforced.policy.yaml
sha256:f21337c2d7d004a9aaf0c79229cfc0c9cc610cb1cd5b23c3b5f59b4ad70188c4
$ cplang policy validate uploads-enforced.policy.yaml --pin sha256:f21337c2d7d004a9aaf0c79229cfc0c9cc610cb1cd5b23c3b5f59b4ad70188c4
OK fingerprint=sha256:f21337c2d7d004a9aaf0c79229cfc0c9cc610cb1cd5b23c3b5f59b4ad70188c4
```
{: data-run="true"}

The second command exits with `2` when the policy is not the one that was reviewed. Every verdict carries the same fingerprint, so a log line leads back to the exact file.

## Roll Out a Whole Policy

Set `mode: monitor` at the top of a policy to watch every rule at once. This suits a first deployment, where you want to see what a complete policy would do before it blocks anything:

```yaml
cpl: "1.0"
id: first-deployment
version: 1
mode: monitor
default: deny
rules:
  - id: read-only
    match: {kind: [read]}
    outcome: allow
```
{: data-title="first-deployment.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: a-write-would-be-denied
    action: {kind: write}
    expect:
      outcome: watch
      would_block: true
      would_have_been: deny
      reason_codes: [MONITOR_WOULD_BLOCK, NO_MATCHING_RULE]
```
{: data-title="first-deployment.fixtures.yaml"}

Even the default decision is softened, so nothing is blocked until you remove the line.

> ▶ Next: [Policy File](/reference/policy-file/)
{: .next}
