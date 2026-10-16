---
title: File Access
description: Confine an agent to a workspace, keep secrets out of reach and ask before it writes large or sensitive files.
---

File tools let an agent read and write what it can reach. A policy fences that reach in. Paths are text from the agent, so the policy cleans them before it compares: `..` segments, doubled slashes and backslashes cannot walk out of the fence.

## Confine Reads to a Workspace

Allow reads below one directory and refuse the secrets inside it:

```yaml
cpl: "1.0"
id: files
version: 1
default: deny
rules:
  - id: read-workspace
    match: {kind: [file_read]}
    when:
      path_matches: "/srv/work/**"
      path_not_matches:
        - "/srv/work/secrets/**"
        - "/srv/work/**/.env"
        - "/srv/work/**/*.pem"
    outcome: allow
```
{: data-title="files.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: a-source-file
    action: {kind: file_read, arguments: {path: /srv/work/app/main.py}}
    expect: {outcome: allow}

  - name: walking-out-with-dot-dot
    action: {kind: file_read, arguments: {path: /srv/work/../../etc/passwd}}
    expect: {outcome: deny}

  - name: windows-separators
    action: {kind: file_read, arguments: {path: "\\srv\\work\\secrets\\token.txt"}}
    expect: {outcome: deny}

  - name: nested-dotenv
    action: {kind: file_read, arguments: {path: /srv/work/api/.env}}
    expect: {outcome: deny}

  - name: private-key
    action: {kind: file_read, arguments: {path: /srv/work/keys/server.pem}}
    expect: {outcome: deny}
```
{: data-title="files.fixtures.yaml"}

`/srv/work/../../etc/passwd` is read as `/etc/passwd`, which is outside the fence. The Windows-style path is converted to `/` separators first.

## Write with Care

Writes are riskier than reads. Allow small writes in the scratch area, ask about the rest of the workspace and refuse everything else:

```yaml
cpl: "1.0"
id: files
version: 2
default: deny
rules:
  - id: read-workspace
    match: {kind: [file_read]}
    when:
      path_matches: "/srv/work/**"
      path_not_matches:
        - "/srv/work/secrets/**"
        - "/srv/work/**/.env"
        - "/srv/work/**/*.pem"
    outcome: allow

  - id: write-scratch
    match: {kind: [file_write]}
    when:
      path_matches: "/srv/work/scratch/**"
      bounded_params: {size_kb: {max: 1024}}
    outcome: allow

  - id: write-elsewhere-asks
    match: {kind: [file_write]}
    when:
      path_matches: "/srv/work/**"
      path_not_matches: ["/srv/work/scratch/**", "/srv/work/secrets/**"]
      approval: {timeout_seconds: 1800}
    outcome: ask
    explain: "The agent wants to change {arguments.path}."
```
{: data-title="files.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: a-source-file
    action: {kind: file_read, arguments: {path: /srv/work/app/main.py}}
    expect: {outcome: allow}

  - name: scratch-write
    action: {kind: file_write, arguments: {path: /srv/work/scratch/out.txt, size_kb: 20}}
    expect: {outcome: allow, matched_rules: [write-scratch]}

  - name: huge-scratch-write
    action: {kind: file_write, arguments: {path: /srv/work/scratch/dump.bin, size_kb: 90000}}
    expect: {outcome: deny, reason_codes: [PARAM_OUT_OF_BOUNDS]}

  - name: source-write-needs-approval
    action: {kind: file_write, arguments: {path: /srv/work/app/main.py, size_kb: 4}}
    expect: {outcome: ask, matched_rules: [write-elsewhere-asks]}

  - name: write-to-secrets
    action: {kind: file_write, arguments: {path: /srv/work/secrets/token, size_kb: 1}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}

  - name: write-outside-the-workspace
    action: {kind: file_write, arguments: {path: /etc/cron.d/job, size_kb: 1}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="files.fixtures.yaml"}

## Protect by Name

Sometimes the name of a file matters more than where it is. Refuse whole classes of files wherever they are:

```yaml
cpl: "1.0"
id: sensitive-names
version: 1
default: allow
rules:
  - id: never-touch-credentials
    match: {kind: ["file_*"]}
    when:
      path_matches:
        - "**/.ssh/**"
        - "**/.aws/credentials"
        - "**/id_rsa*"
        - "**/*.kdbx"
    outcome: deny
    reason: RULE_DENY
    explain: "Credential files are never available to the agent."
```
{: data-title="sensitive-names.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: ssh-folder
    action: {kind: file_read, arguments: {path: /home/dev/.ssh/config}}
    expect: {outcome: deny}

  - name: traversal-into-ssh
    action: {kind: file_read, arguments: {path: /home/dev/projects/../.ssh/id_ed25519}}
    expect: {outcome: deny}

  - name: ordinary-file
    action: {kind: file_read, arguments: {path: /home/dev/projects/readme.md}}
    expect: {outcome: allow, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="sensitive-names.fixtures.yaml"}

A policy that lists what to refuse uses `default: allow`. Combine it with the workspace policy above by importing it as a fragment. See [Imports](/imports/).

## Check What Comes Back

A file read returns content. Scan it for secrets before the agent sees it, and deny the reply when a scanner finds one. See [Data Redaction](/use-cases/data-redaction/).

> ▶ Next: [Network Access](/use-cases/network-access/)
{: .next}
