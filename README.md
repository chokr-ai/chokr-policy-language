# CHOKR Policy Language (CPL): AI agent governance as code

CPL is a small, declarative policy-as-code language for governing what AI agents and other programs may do. You write the rules
as data in a YAML (or JSON) file; CPL evaluates them against a description of something that is about to happen, such as
an agent's tool call, and returns a decision: `allow`, `ask` (human approval), `deny` and more.

Use it when a program must make allow/deny style decisions that other people need to read, review or change, and the
decisions must be deterministic, testable and auditable. CPL is a library and a command line tool; your application
asks for a verdict and acts on it. Typical uses: tool-call authorization, human-in-the-loop approval, spend and rate
limits, data-access control, and audit with replay. It works with any agent framework or tool-calling protocol,
including MCP, because it only sees the action you hand it.

CPL decides; it does not enforce. It does not sandbox or intercept anything, so your application must act on the verdict.

Status: alpha (0.0.x). The language and the Python API may change before 1.0.

## Example: govern an AI agent's tool calls

```yaml
cpl: "1.0"
id: agent-tool-calls
version: 1
default: deny                         # fail closed: anything not allowed is denied
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

From a clone of this repository, run its test cases:

```console
$ cplang test --policy examples/agent_tool_call --fixtures examples/agent_tool_call/agent.fixtures.yaml
```

The full policy and its test cases are in [`examples/agent_tool_call`](https://github.com/chokr-ai/chokr-policy-language/tree/main/examples/agent_tool_call).

## Install

```bash
pip install chokr-policy-language            # library and the `cplang` command
pip install "chokr-policy-language[prove]"   # adds the optional prover
uv add chokr-policy-language                 # or add it to a uv project
pipx install chokr-policy-language           # or the command line tool only
```

Python 3.14 or newer. Import name: `cplang`.

## Concepts

- **Action**: what is being decided, a JSON-like document with a `timestamp` and any fields you choose. The
  `timestamp` is the `time.now` of time windows and rate limits, so the host sets it from its own clock, never from the
  agent's request.
- **Signal**: an optional named finding about the action, for example `{code: scan.malware, severity: high}`.
- **Policy**: a YAML/JSON file of rules.
- **Verdict**: `allow`, `watch`, `modify`, `ask` or `deny`, with reason codes and the rules that decided it.

## A policy

```yaml
cpl: "1.0"
id: document-access
version: 1
default: deny                       # outcome when no rule matches
rules:
  - id: read-public
    match: {kind: [read]}           # which actions the rule is about
    when: {resource.type: public}   # further conditions
    outcome: allow

  - id: large-upload-needs-approval
    match: {kind: [write]}
    when:
      expr: "arguments.size_kb > 512"
      approval: {timeout_seconds: 3600}
    outcome: ask

  - id: malware-found
    when: {signal: {code: scan.malware, severity_gte: high}}
    outcome: deny
```

Rules take `id`, `outcome` and optionally `match`, `when`, `let`, `reason`, `explain`, `obligations`, `modify`,
`priority`, `enabled`, `mode`. Conditions read paths of the action (`resource.type`, `customer.tier`) with operators such
as `eq`, `in`, `gt`, `between`, `glob`, `regex`, `exists`, combined with `any`, `all`, `not`. Policies can import
declaration files for shared parameters, constants, tables and types.

A `deny:` or threshold check on a field the action does not carry denies, so leaving a field out never skips a limit.
To let a missing field through, test for it first:
`deny: {all: [{arguments.amount: {exists: true}}, {arguments.amount: {gt: 100}}]}`. A check on the tool's
`arguments.response` waits until the response exists.

Your own fields work without any setup. To have them type-checked, declare them:

```yaml
schema: cpl.declarations/1.0
types:
  Customer: {kind: object, fields: {tier: {type: string}, spend: {type: number, required: false}}}  # fields are required unless marked
inputs:
  customer: {type: Customer}
shortcuts:
  tier_is: {path: customer.tier}    # your own condition key: when: {tier_is: [gold, silver]}
```

Declare your own types under `types:`: `enum`, `object`, `list`, `set`, `map`, `union`, `quantity`, or a constrained
scalar such as `Email: {kind: string, format: email}` or `Score: {kind: integer, min: 0, max: 10}`. A string
`pattern` is searched for, as in JSON Schema, so anchor it to match the whole value: `{kind: string, pattern: "^[A-Z]{2}$"}`. Declared inputs are
checked against their type on every evaluation, and a mismatch denies with `EVALUATION_ERROR`. The language's own type
names (`string`, `list`, ...) and standard field names (`kind`, `arguments`, ...) are reserved and cannot be redefined.

## Use from the command line

```console
$ cplang policy check policy.yaml                         # validate + lint; fails on any problem
$ cplang eval --policy policy.yaml --action action.yaml   # decide one action
allow POLICY_SATISFIED  rules=['read-public']
$ cplang test --policy policy.yaml --fixtures cases.yaml  # check expected decisions
```

`cases.yaml`:

```yaml
schema: cpl.fixtures/1.0
now: "2026-01-05T10:00:00Z"
cases:
  - name: malware-is-denied
    action: {kind: read, resource: {type: public}}
    signals: [{code: scan.malware, severity: critical}]
    expect: {outcome: deny}
```

Other commands: `cplang policy validate|lint|fmt|fingerprint|types|explain|prove`, `cplang expr eval`,
`cplang decl check|show|fmt|lock`, `cplang schema`. Run `cplang --help` for options. `--json` gives machine-readable output.
Exit codes: `0` ok, `1` the check failed (or `eval` returned deny/ask), `2` bad usage or input (an unreadable policy or fixture file), `3` an internal error.

## Use from Python

```python
from pathlib import Path
from cplang import Action, RuleEvaluator, Signal, load_policy

policy = load_policy([Path("policy.yaml")], roots=[Path(".")])  # raises AuthoringError if invalid
evaluator = RuleEvaluator(policy)  # thread-safe; reuse it
verdict = evaluator.evaluate(
    Action({"kind": "read", "resource": {"type": "public"}, "timestamp": "2026-01-05T10:00:00Z"}),
    [Signal(code="scan.malware", source="scanner", severity="low")],
)
print(verdict.outcome, verdict.reason_codes, verdict.matched_rules)
```

`load_policy` also takes `limits=CplLimits(...)`, `profile=Profile(...)` (host reason codes, input names, rule keys) and
`strict_inputs=True` (reject names that are neither standard nor declared). `FunctionRegistry` adds functions callable
from expressions. `verdict.to_wire()` returns JSON-compatible data. The package is fully typed.

More examples: [`examples/agent_tool_call`](https://github.com/chokr-ai/chokr-policy-language/tree/main/examples/agent_tool_call) and [`examples/access`](https://github.com/chokr-ai/chokr-policy-language/tree/main/examples/access).

## Contributing and security

See [CONTRIBUTING.md](https://github.com/chokr-ai/chokr-policy-language/blob/main/CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](https://github.com/chokr-ai/chokr-policy-language/blob/main/SECURITY.md), not in public issues.

## License

Apache License 2.0. Copyright 2026 chokr-ai. See [LICENSE](https://github.com/chokr-ai/chokr-policy-language/blob/main/LICENSE) and [NOTICE](https://github.com/chokr-ai/chokr-policy-language/blob/main/NOTICE).
