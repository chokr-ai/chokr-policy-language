---
title: Testing Policies
description: Pin the expected decisions in fixture files, explain a verdict step by step and check policy changes in CI.
---

A policy is code that decides what other code may do, so it deserves tests. A fixture file holds actions and the verdicts you expect. `cplang test` runs them offline in milliseconds, and a mismatch is a failing test.

```yaml
cpl: "1.0"
id: uploads
version: 1
default: deny
rules:
  - id: small-uploads
    match: {kind: [upload]}
    when: {expr: "arguments.size_mb <= 25"}
    outcome: allow

  - id: virus-found
    when: {signal: {code: scan.malware}}
    outcome: deny
```
{: data-title="uploads.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
policy: uploads.policy.yaml
now: "2026-01-05T10:00:00Z"
cases:
  - name: small-upload
    action: {kind: upload, arguments: {size_mb: 5}}
    expect: {outcome: allow, matched_rules: [small-uploads]}

  - name: large-upload
    action: {kind: upload, arguments: {size_mb: 500}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}

  - name: virus-in-a-small-upload
    action: {kind: upload, arguments: {size_mb: 5}}
    signals: [{code: scan.malware, severity: critical}]
    expect: {outcome: deny, matched_rules: [small-uploads, virus-found]}
```
{: data-title="uploads.fixtures.yaml"}

```console
$ cplang test --fixtures uploads.fixtures.yaml
✓ small-upload                                     allow
✓ large-upload                                     deny
✓ virus-in-a-small-upload                          deny
3 passed, 0 failed
```
{: data-run="true"}

The `policy` key names the policy under test, relative to the fixture file. Without it, pass `--policy`.

## The Fixture File

| Key | Meaning |
| --- | --- |
| `schema` | Always `cpl.fixtures/1.0` |
| `policy` | The policy file under test, relative to this file |
| `params` | Parameter values for every case of the suite |
| `now` | The `timestamp` given to every action that has none |
| `cases` | The list of cases |

Each case has a `name`, an `action`, optional `signals` and an `expect` block.

## Expectations

Assert only what matters for the case. Every key you leave out is not compared.

| Key | Compared with |
| --- | --- |
| `outcome` | The outcome of the verdict |
| `reason_codes` | The list of reason codes, in order |
| `matched_rules` | The rules that decided, sorted by id |
| `risk_tier` | The risk tier label |
| `would_block` | Whether monitor mode held a decision back |
| `would_have_been` | What monitor mode held back |
| `obligations` | The list of obligations |

> Assert `outcome` in every case and `matched_rules` in the cases that cover a rule. A test that names the rule fails when someone changes which rule decides, even if the outcome stays the same.
{: .note}

A run that ends in an evaluation error fails the case unless you expect it, with `reason_codes: [EVALUATION_ERROR, ...]`. That keeps a broken expression from hiding behind a `deny`.

## Read a Failure

A failing case prints what differed:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: wrong-expectation
    action: {kind: upload, arguments: {size_mb: 500}}
    expect: {outcome: allow}
```
{: data-title="failing.fixtures.yaml" data-check="false"}

```console
$ cplang test --policy uploads.policy.yaml --fixtures failing.fixtures.yaml
✗ wrong-expectation                                deny
  outcome: expected 'allow', got 'deny'
0 passed, 1 failed
```
{: data-run="true"}

The command exits with `1`, so a CI job fails. Pass a directory to `--fixtures` to run every fixture file in it, and add `--json` for a machine-readable report.

## Explain a Decision

`cplang policy explain` runs one case and prints every rule it looked at: whether `match` and `when` held, each `let` value and the rule that decided. Use it when a verdict surprises you:

```console
$ cplang policy explain --policy uploads.policy.yaml --fixtures uploads.fixtures.yaml --case virus-in-a-small-upload
rule small-uploads: match=true when=true -> allow ['POLICY_SATISFIED']
rule virus-found: match=- when=true -> deny ['RULE_DENY']
verdict: deny ['RULE_DENY', 'POLICY_SATISFIED']  rules=['small-uploads', 'virus-found']
```
{: data-run="true"}

Explaining never counts calls against a rate limit.

## Lint

`cplang policy lint` reports mistakes that are valid but probably unintended: unused `let` values, rules that can never apply, duplicate rules, rules hidden by an earlier rule, and unused declarations. `cplang policy check` runs validation and lint together and fails on any warning, which makes it the right command for CI.

```yaml
cpl: "1.0"
id: sloppy
version: 1
default: deny
rules:
  - id: allow-reads
    match: {kind: [read]}
    outcome: allow

  - id: also-allow-reads
    match: {kind: [read]}
    outcome: allow
```
{: data-title="sloppy.policy.yaml" data-error="duplicate-rule"}

## Format

`cplang policy fmt` rewrites files in one canonical style, so diffs show only real changes. Check formatting without changing files:

```console
$ cplang policy fmt --check uploads.policy.yaml
```

The command exits with `1` when a file would change. Formatting never reorders a file that has comments.

## Fingerprint a Policy

The fingerprint is a digest of the compiled policy: its rules, declarations and parameters. Comments and layout do not change it. Print it, or pin it so a deployment refuses a policy that is not the one you reviewed:

```console
$ cplang policy fingerprint uploads.policy.yaml
sha256:0000000000000000000000000000000000000000000000000000000000000000
```
{: data-run="true"}

`cplang policy validate --pin <fingerprint>` exits with `2` when the policy differs. Every verdict carries the fingerprint of the policy that made it, so a decision can always be traced to an exact version.

## Prove a Change

The prover compares policies over all possible actions rather than a list of examples. Install the extra with `pip install "chokr-policy-language[prove]"`. Ask what a change newly permits:

```yaml
cpl: "1.0"
id: uploads-new
version: 2
default: deny
rules:
  - id: small-uploads
    match: {kind: [upload]}
    when: {expr: "arguments.size_mb <= 100"}
    outcome: allow
```
{: data-title="uploads-new.policy.yaml"}

```console
$ cplang policy prove --diff uploads.policy.yaml uploads-new.policy.yaml --emit-fixture counterexamples.fixtures.yaml
exceeds_boundary (boundary_exceeded)
counterexample: {"action": {"arguments": {"size_mb": 26}, "kind": "upload"}, ...}
```

The new policy permits a 26 MB upload that the old one denied, and the exit code is `1`. The result is one of:

| Result | Exit code |
| --- | --- |
| `within_boundary` | `0` |
| `exceeds_boundary` | `1` |
| `error` | `2` |
| `unsupported` or `inconclusive` | `3` |

With `--emit-fixture` the prover writes a counterexample as a fixture, so you can see an action that the new policy permits and the old one did not. Use `--boundary` to check that a policy stays inside a larger policy, and `--no-bypass` to show that a signal that must always deny cannot be overruled.

## A CI Recipe

```console
$ cplang policy check policies/
$ cplang policy fmt --check policies/
$ cplang test --fixtures tests/
```

> ▶ Next: [Embedding](/embedding/)
{: .next}
