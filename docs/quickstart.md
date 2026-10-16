---
title: Quickstart
description: Write a first policy, check it, test it and get a verdict from the command line.
---

Write a policy, check it, test it and ask it for a decision. The walk-through takes four small files and four commands.

Install the package:

```console
$ pip install chokr-policy-language
```

Then confirm the command is available:

```console
$ cplang --version
```

> Prefer `uv` or an isolated tool install? See [Installation](/installation/) for every route and for the optional prover.
{: .note}

### Create a Policy

A policy is a YAML file. It lists rules, and it says what happens when no rule applies. Create `hello.policy.yaml`:

```yaml
cpl: "1.0"
id: hello
version: 1
default: deny              # anything not allowed is denied
rules:
  - id: allow-reads
    match: {kind: [read]}  # which actions this rule is about
    outcome: allow
```
{: data-title="hello.policy.yaml"}

The `cpl` key names the language version. `id` and `version` identify the policy in every verdict. `default` is the outcome when no rule matches, and `deny` is the safe choice. Each rule has a stable `id`, a `match` block that selects actions and an `outcome`.

### Check the Policy

Run the check before anything else. It validates the file and reports likely mistakes:

```console
$ cplang policy check hello.policy.yaml
OK fingerprint=sha256:2f3c1b8f5a7d0e9c4b6a8d1e3f5a7c9b0d2e4f6a8c0b1d3e5f7a9c1b3d5e7f90
```
{: data-run="true"}

The fingerprint identifies this exact policy. It changes whenever a rule changes, so you can pin it in a deployment.

### Decide an Action

An action describes what is about to happen. It needs a `timestamp` and any other fields you choose. Create `read.action.yaml` and `write.action.yaml`:

```yaml
kind: read
timestamp: "2026-01-05T10:00:00Z"
```
{: data-title="read.action.yaml"}

```yaml
kind: write
timestamp: "2026-01-05T10:00:00Z"
```
{: data-title="write.action.yaml"}

Ask the policy for a verdict on the read:

```console
$ cplang eval --policy hello.policy.yaml --action read.action.yaml
allow POLICY_SATISFIED  rules=['allow-reads']
```
{: data-run="true"}

The line shows the outcome, the reason code and the rules that decided. The write matches no rule, so the default applies:

```console
$ cplang eval --policy hello.policy.yaml --action write.action.yaml
deny NO_MATCHING_RULE  rules=[]
```
{: data-run="true"}

`eval` exits with `0` for `allow`, `watch` and `modify`, and with `1` for `deny` and `ask`. Use the exit code in scripts.

### Write a Test

Keep the expected decisions next to the policy. Create `hello.fixtures.yaml`:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: reads-are-allowed
    action: {kind: read}
    expect: {outcome: allow, matched_rules: [allow-reads]}

  - name: writes-are-denied
    action: {kind: write}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="hello.fixtures.yaml"}

Each case holds an action and the verdict you expect. The `now` value fills in the `timestamp` of every case.

### Run the Tests

```console
$ cplang test --policy hello.policy.yaml --fixtures hello.fixtures.yaml
✓ reads-are-allowed                                allow
✓ writes-are-denied                                deny
2 passed, 0 failed
```
{: data-run="true"}

`test` exits with `1` when any case differs from its expectation, so it fits directly into a CI job.

> ▶ Next: [Installation](/installation/)
{: .next}
