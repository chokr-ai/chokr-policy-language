---
title: Network Access
description: Allow an agent to reach approved hosts only, over secure connections and with safe methods.
---

An agent that can make web requests can also send data out. A network policy lists the hosts it may reach, the ways it may reach them and what needs a person.

Every example reads the destination from `target.destination_host`, the method from `target.method` and the address from `arguments.url`. Your application fills them in.

## Approve Hosts

Allow a list of domains. `domain_suffix` covers the domain and every subdomain, and it does not match a lookalike such as `evil-example.com`:

```yaml
cpl: "1.0"
id: network
version: 1
default: deny
rules:
  - id: approved-hosts
    match: {kind: [http_request]}
    when:
      any:
        - domain_suffix: docs.example.com
        - domain_suffix: api.example.com
        - domain_matches: "cdn.*.example.net"
    outcome: allow
```
{: data-title="network.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: documentation-site
    action: {kind: http_request, target: {destination_host: docs.example.com}}
    expect: {outcome: allow}

  - name: a-subdomain
    action: {kind: http_request, target: {destination_host: v2.api.example.com}}
    expect: {outcome: allow}

  - name: a-lookalike
    action: {kind: http_request, target: {destination_host: evil-api.example.com.attacker.test}}
    expect: {outcome: deny}

  - name: wildcard-label
    action: {kind: http_request, target: {destination_host: cdn.eu.example.net}}
    expect: {outcome: allow}

  - name: unknown-host
    action: {kind: http_request, target: {destination_host: files.attacker.test}}
    expect: {outcome: deny}
```
{: data-title="network.fixtures.yaml"}

## Require Secure Connections

Match the whole address with `url_matches`. A pattern that starts with `https://` refuses plain `http://` as a side effect:

```yaml
cpl: "1.0"
id: network
version: 2
default: deny
rules:
  - id: approved-hosts-over-https
    match: {kind: [http_request]}
    when:
      url_matches:
        - "https://docs.example.com/**"
        - "https://api.example.com/v1/**"
    outcome: allow
```
{: data-title="network.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: secure-docs
    action: {kind: http_request, arguments: {url: "https://docs.example.com/guide/start"}}
    expect: {outcome: allow}

  - name: plain-http
    action: {kind: http_request, arguments: {url: "http://docs.example.com/guide/start"}}
    expect: {outcome: deny}

  - name: wrong-api-version
    action: {kind: http_request, arguments: {url: "https://api.example.com/v0/users"}}
    expect: {outcome: deny}
```
{: data-title="network.fixtures.yaml"}

## Limit Methods and Uploads

Reads are cheap and writes are not. Allow `GET` on approved hosts. Ask before the agent sends data out:

```yaml
cpl: "1.0"
id: network-methods
version: 1
default: deny
rules:
  - id: read-from-approved-hosts
    match: {kind: [http_request]}
    when:
      target.method: [GET, HEAD]
      domain_suffix: example.com
    outcome: allow

  - id: writes-need-approval
    match: {kind: [http_request]}
    when:
      target.method: [POST, PUT, PATCH, DELETE]
      domain_suffix: example.com
      approval: {timeout_seconds: 900}
    outcome: ask

  - id: huge-uploads-never
    match: {kind: [http_request]}
    when:
      expr: "arguments.body_bytes > 1048576"
    outcome: deny
    explain: "Bodies above 1 MiB are refused."
```
{: data-title="network-methods.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: a-read
    action: {kind: http_request, target: {destination_host: api.example.com, method: GET}}
    expect: {outcome: allow}

  - name: a-write-asks
    action: {kind: http_request, target: {destination_host: api.example.com, method: POST}, arguments: {body_bytes: 200}}
    expect: {outcome: ask}

  - name: a-huge-write-is-refused
    action: {kind: http_request, target: {destination_host: api.example.com, method: POST}, arguments: {body_bytes: 9000000}}
    expect: {outcome: deny, matched_rules: [huge-uploads-never, writes-need-approval]}

  - name: write-to-an-unknown-host
    action: {kind: http_request, target: {destination_host: files.attacker.test, method: POST}}
    expect: {outcome: deny, reason_codes: [NO_MATCHING_RULE]}
```
{: data-title="network-methods.fixtures.yaml"}

## Stop Secrets Leaving

A policy cannot read the content of a request, but a scanner can. Pass the scanner's finding as a signal and refuse the request:

```yaml
cpl: "1.0"
id: egress
version: 1
default: deny
rules:
  - id: approved-hosts
    match: {kind: [http_request]}
    when: {domain_suffix: example.com}
    outcome: allow

  - id: secret-in-request
    match: {kind: [http_request]}
    when: {signal: {code_prefix: "secret.", confidence_gte: 0.8}}
    outcome: deny
    explain: "A {signal.source} found a secret ({signal.code}) in the request."
```
{: data-title="egress.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: clean-request
    action: {kind: http_request, target: {destination_host: api.example.com}}
    expect: {outcome: allow}

  - name: api-key-in-the-body
    action: {kind: http_request, target: {destination_host: api.example.com}}
    signals: [{code: secret.api_key, source: scanner, severity: high, confidence: 0.97}]
    expect: {outcome: deny, matched_rules: [approved-hosts, secret-in-request]}
```
{: data-title="egress.fixtures.yaml"}

Even an approved host does not get the secret.

> ▶ Next: [Payments](/use-cases/payments/)
{: .next}
