---
title: Cheatsheet
description: The language on one page, from a minimal policy to every command.
---

A quick reference for the most used parts. Each section links to the page that explains it.

## A Complete Policy

```yaml
cpl: "1.0"
id: cheatsheet
version: 1
default: deny                                   # when no rule applies
rules:
  - id: reads                                   # stable id
    match: {kind: [read]}                       # which actions
    when: {resource.type: public}               # more conditions
    outcome: allow

  - id: big-writes-ask
    match: {kind: [write]}
    when:
      expr: "arguments.size_kb > 512"           # an expression
      approval: {timeout_seconds: 3600}         # needed for ask
    outcome: ask

  - id: limited-search
    match: {kind: [tool_call]}
    when:
      target: web_search                        # shortcut for target.name
      bounded_params: {max_results: {min: 1, max: 20}}
      max_calls_per_window: {limit: 30, window_seconds: 60}
    outcome: allow

  - id: malware
    when: {signal: {code: scan.malware, severity_gte: high}}
    outcome: deny
```
{: data-title="cheatsheet.policy.yaml"}

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: public-read
    action: {kind: read, resource: {type: public}}
    expect: {outcome: allow}

  - name: big-write
    action: {kind: write, arguments: {size_kb: 900}}
    expect: {outcome: ask}

  - name: malware-wins
    action: {kind: read, resource: {type: public}}
    signals: [{code: scan.malware, severity: critical}]
    expect: {outcome: deny}
```
{: data-title="cheatsheet.fixtures.yaml"}

## Outcomes

| Outcome | Rank | Your application |
| --- | --- | --- |
| `allow` | 0 | Carry on |
| `watch` | 1 | Carry on and record it |
| `modify` | 2 | Apply the edits, then carry on |
| `ask` | 3 | Wait for a person |
| `deny` | 4 | Stop |

The strongest outcome wins under the default `deny_overrides` strategy. See [Combining Rules](/decisions/).

## Conditions

```yaml
resource.type: public                      # equals
actor.type: [staff, admin]                 # one of
arguments.n: {gt: 10, lte: 100}            # operators
arguments.n: {between: [1, 10]}            # inclusive
arguments.name: {glob: "report-*.csv"}     # whole value
arguments.id: {regex: "^TCK-[0-9]+$"}      # search; anchor it
arguments.tags: {contains: reviewed}       # list member or substring
arguments.note: {exists: false}            # absent
not: {environment.env: prod}               # combinators: all, any, not
expr: "size(arguments.items) <= 10"        # expression
signal: {code_prefix: "scan.", severity_gte: high}
time.window: {from: "08:00", to: "18:00", days: [mon, tue, wed, thu, fri]}
```

A missing field makes a condition false, even under `not`. See [Conditions](/conditions/).

## Shortcuts

```yaml
target: shell                                  # target.name
command_matches: ["git status*", "ls *"]       # shell-aware
path_matches: "/srv/work/**"                   # dot segments resolved
path_not_matches: "/srv/work/secrets/**"
domain_suffix: example.com                     # domain and subdomains
domain_matches: "cdn.*.example.net"
url_matches: "https://api.example.com/v1/**"
response_matches: "*BEGIN PRIVATE KEY*"        # the tool's reply
```

## Guards

```yaml
deny: {arguments.currency: {nin: [usd, eur]}}
immutable_params: {mode: read_only}
bounded_params: {amount: {min: 1, max: 1000}}
max_calls_per_window: {limit: 30, window_seconds: 60}
thresholds:
  - {path: arguments.amount, gt: 1000, outcome: deny}
  - {path: arguments.amount, gt: 500, outcome: ask}
approval: {timeout_seconds: 900, on_timeout: deny}
```

## Rule Extras

```yaml
let: {over: "arguments.amount - 100"}          # read as var.over
reason: RULE_DENY
explain: "Over by {var.over}."
hint: {next_steps: [{kind: reduce_amount}]}
obligations: [{type: notify, params: {channel: ledger}}]
modify: {edits: [{op: redact, json_pointer: /arguments/body, placeholder: "[removed]"}]}
priority: 10
enabled: false
mode: monitor
```

## Policy Settings

```yaml
strategy: first_match        # deny_overrides (default), first_match, priority
mode: monitor                # report instead of block
default_risk_tier: routine
risk_tiers:
  - id: high
    when: {arguments.amount: {gt: 10000}}
imports:
  - {from: ./shared.decl.yaml, only: [limit], with: {limit: 20}}
```

## Expression Functions

| Group | Functions |
| --- | --- |
| Numbers | `abs` `min` `max` `sum` `round` `floor` `ceil` |
| Text | `lower` `upper` `trim` `split` `join` `contains` `starts_with` `ends_with` `matches` |
| Collections | `size` `count` `keys` `values` `filter` `map` `all` `any` |
| Time | `timestamp` `duration` `date_diff` |
| Missing values | `has` `default` `coalesce` |

## Reason Codes

`POLICY_SATISFIED` `POLICY_ADVISORY` `RULE_ASK` `RULE_DENY` `NO_MATCHING_RULE` `ACTION_FORBIDDEN` `PARAM_IMMUTABLE_VIOLATION` `PARAM_OUT_OF_BOUNDS` `RATE_LIMIT_EXCEEDED` `THRESHOLD_EXCEEDED` `MONITOR_WOULD_BLOCK` `EVALUATION_ERROR`

## Commands

```console
$ cplang policy check policies/                  # validate and lint, for CI
$ cplang policy fmt --check policies/            # formatting
$ cplang test --fixtures tests/                  # expected decisions
$ cplang eval --policy p.yaml --action a.yaml    # decide one action
$ cplang policy explain --policy p.yaml --fixtures f.yaml --case name
$ cplang policy fingerprint p.yaml               # identify a policy
$ cplang policy prove --diff old.yaml new.yaml   # what a change permits
$ cplang expr eval '1 + 2'                       # try an expression
```

## Python

```python
from pathlib import Path

from cplang import Action, RuleEvaluator, Signal, load_policy

evaluator = RuleEvaluator(load_policy([Path("cheatsheet.policy.yaml")], roots=[Path(".")]))
verdict = evaluator.evaluate(
    Action({"kind": "read", "resource": {"type": "public"}, "timestamp": "2026-01-05T10:00:00Z"}), []
)
print(verdict.outcome)
```
{: data-title="cheatsheet.py"}

```console
allow
```
{: data-output="cheatsheet.py"}
