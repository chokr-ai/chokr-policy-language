---
title: Imports
description: Split policies into files, share declarations and rule fragments, and pin every imported file.
---

A policy can import declaration files and files of shared rules. Imports keep each file small and let several policies share the same limits, tables and rules.

```yaml
schema: cpl.declarations/1.0
namespace: example.shared
version: 1
parameters:
  limit: {type: integer, default: 10}
  review_cap: {type: integer, default: 99}
```
{: data-title="shared.decl.yaml"}

```yaml
cpl: "1.0"
id: imports-intro
version: 1
imports:
  - {from: ./shared.decl.yaml}
default: deny
rules:
  - id: small-spend
    match: {kind: [spend]}
    when: {expr: "arguments.amount <= param.limit"}
    outcome: allow
```
{: data-title="intro.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: inside-the-shared-limit
    action: {kind: spend, arguments: {amount: 8}}
    expect: {outcome: allow}

  - name: outside-the-shared-limit
    action: {kind: spend, arguments: {amount: 15}}
    expect: {outcome: deny}
```
{: data-title="intro.fixtures.yaml"}

The path in `from` is relative to the file that contains the import. `vocabulary: ./file.decl.yaml` is a short form for a policy with a single import.

## Import Options

| Key | Effect |
| --- | --- |
| `from` | The file to import. Required |
| `only` | A list of names to take. Everything else stays hidden from the policy |
| `as` | An alias. A name can then also be reached as `alias.name` |
| `with` | Values for the imported file's parameters |
| `digest` | The expected `sha256:` digest of the file |
| `rename` | Gives an imported attribute another name: `{old: new}` |

### Choose Names

Use `only` to take part of a file. Names that are not listed cannot be used by the policy:

```yaml
cpl: "1.0"
id: only-limit
version: 1
imports:
  - {from: ./shared.decl.yaml, only: [limit]}
default: deny
rules:
  - id: small-spend
    match: {kind: [spend]}
    when: {expr: "arguments.amount <= param.review_cap"}
    outcome: allow
```
{: data-title="only.policy.yaml" data-error="DECLARATION_UNKNOWN_NAME"}

The check fails because `review_cap` was not listed. Add it to `only`, or drop the `only` key to import every name.

### Set Parameters

Give a value to a parameter of the imported file with `with`, or set it for the whole policy with `params`:

```yaml
cpl: "1.0"
id: tuned
version: 1
imports:
  - {from: ./shared.decl.yaml, with: {limit: 20}}
default: deny
rules:
  - id: small-spend
    match: {kind: [spend]}
    when: {expr: "arguments.amount <= param.limit"}
    outcome: allow
```
{: data-title="tuned.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: the-imported-limit-is-now-twenty
    action: {kind: spend, arguments: {amount: 15}}
    expect: {outcome: allow}
```
{: data-title="tuned.fixtures.yaml"}

The value must match the declared type. A value of the wrong type, or a name the file does not declare, fails the check.

## Share Rules

A fragment is a policy file that holds rules and nothing else. Mark it with `fragment: true`. A policy imports it like a declaration file, and its rules join the policy:

```yaml
cpl: "1.0"
fragment: true
rules:
  - id: no-secrets
    match: {kind: [file_read]}
    when: {path_matches: "/secrets/**"}
    outcome: deny
```
{: data-title="common.policy.yaml" data-check="false"}

```yaml
cpl: "1.0"
id: with-common-rules
version: 1
imports:
  - {from: ./common.policy.yaml}
default: deny
rules:
  - id: read-workspace
    match: {kind: [file_read]}
    when: {path_matches: "/work/**"}
    outcome: allow
```
{: data-title="app.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: workspace-read
    action: {kind: file_read, arguments: {path: /work/notes.md}}
    expect: {outcome: allow}

  - name: shared-rule-blocks-secrets
    action: {kind: file_read, arguments: {path: /secrets/key.pem}}
    expect: {outcome: deny, reason_codes: [RULE_DENY]}
```
{: data-title="app.fixtures.yaml"}

A fragment cannot set `default`, `strategy` or `mode`. The policy that imports it owns those. Rule ids must stay unique across the whole policy, so a clash is an error.

## Where Imports Are Found

Imports stay inside the roots you give. The directory of the policy is a root, and you can add more with `--root` (and `roots=` in Python).

- A path must be relative. An absolute path is refused.
- A path that leaves every root, such as `../../outside.decl.yaml`, is refused with `IMPORT_FORBIDDEN`.
- Nothing is fetched from the network.
- A file that imports itself, directly or through other files, is refused with `IMPORT_CYCLE`.
- A file that several imports reach is loaded once.

```yaml
cpl: "1.0"
id: escape
version: 1
imports:
  - {from: ../outside.decl.yaml}
default: deny
rules: []
```
{: data-title="escape.policy.yaml" data-error="IMPORT_FORBIDDEN"}

## Pin an Import

Add the digest of an imported file to be sure the content never changes behind your back. `cplang decl show` lists the digest of every file it loads:

```console
$ cplang decl show shared.decl.yaml --json
```

A file whose content differs from its pinned digest fails with `IMPORT_DIGEST_MISMATCH`:

```yaml
cpl: "1.0"
id: pinned
version: 1
imports:
  - {from: ./shared.decl.yaml, digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
default: deny
rules: []
```
{: data-title="pinned.policy.yaml" data-error="IMPORT_DIGEST_MISMATCH"}

Line endings are normalised before hashing, so the digest is the same on every platform.

### Lock a Whole Tree

When declaration files import other declaration files, write the digests of all of them to a lock file:

```console
$ cplang decl lock top.decl.yaml --out cpl.decl.lock
```

The lock holds `sha256:` digests and never content. Commit it, and let a host that requires a lock refuse any file that has changed.

> ▶ Next: [Testing Policies](/testing/)
{: .next}
