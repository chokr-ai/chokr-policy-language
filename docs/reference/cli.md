---
title: Command Line
description: Every cplang command, its options and its exit codes.
---

`cplang` checks, tests, explains and formats policies, and decides single actions. Run `cplang --help` or `cplang <command> --help` for the same text in your terminal.

```console
$ cplang --version
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | The command succeeded. For `eval`, the outcome was `allow`, `watch` or `modify` |
| `1` | The check failed. For `eval`, the outcome was `deny` or `ask` |
| `2` | Bad usage or unreadable input. For `policy validate --pin`, the fingerprint differs |
| `3` | An internal error. For `policy prove`, the result is unsupported or inconclusive |

Every command accepts `--json` for one JSON document on standard output.

## Commands

| `policy check` | `policy validate` | `policy lint` | `policy fmt` |
| --- | --- | --- | --- |
| `policy explain` | `policy fingerprint` | `policy types` | `policy prove` |
| `test` | `eval` | `expr eval` | `schema` |
| `decl check` | `decl show` | `decl fmt` | `decl lock` |
| `conformance` | | | |

## policy check

Validates and lints in one step. It is the command to run in CI: undeclared inputs are errors and any warning fails.

```console
$ cplang policy check <paths>... [--decl FILE] [--root DIR] [--param NAME=VALUE] [--open-inputs] [--json]
```

| Option | Meaning |
| --- | --- |
| `paths` | Policy files or directories |
| `--decl` | A declaration file. Repeatable |
| `--root` | An import root. Repeatable |
| `--param` | A parameter binding. Repeatable |
| `--open-inputs` | Accept names that are not standard or declared as a warning |

## policy validate

Parses, type-checks, compiles and fingerprints a policy set. Exits `0` when valid, `1` when invalid and `2` on a pin mismatch.

```console
$ cplang policy validate <paths>... [--strict | --no-strict] [--strict-inputs] [--pin FINGERPRINT] [--decl FILE] [--root DIR] [--param NAME=VALUE]
```

| Option | Meaning |
| --- | --- |
| `--strict` | Undeclared custom codes are errors |
| `--strict-inputs` | Reject names that are neither standard nor declared under `inputs:` |
| `--pin` | Fail with exit `2` if the fingerprint differs |

## policy lint

Reports unused variables, unreachable rules, duplicate and conflicting rules, disabled rules, unused declarations and undeclared inputs.

```console
$ cplang policy lint <paths>... [--strict] [--strict-inputs] [--decl FILE] [--root DIR] [--param NAME=VALUE]
```

`--strict` exits `1` when there is a warning.

## policy fmt

Rewrites policy files in canonical form. A file with comments keeps its order.

```console
$ cplang policy fmt <paths>... [--check]
```

`--check` exits `1` when a file would change and does not write.

## policy explain

Evaluates one fixture case with a full trace: every rule, condition result, `let` value and the deciding step.

```console
$ cplang policy explain --policy PATH --fixtures FILE [--case NAME] [--decl FILE] [--root DIR]
```

Without `--case`, the first case is explained.

## policy fingerprint

Prints the fingerprint of the compiled policy set.

```console
$ cplang policy fingerprint <paths>...
```

## policy types

Prints the inferred type of every `let` and `computed` value.

```console
$ cplang policy types <paths>... [--decl FILE] [--root DIR]
```

## policy prove

Proves that a policy stays within a boundary. Needs the `prove` extra.

```console
$ cplang policy prove --candidate FILE --boundary FILE
$ cplang policy prove --diff OLD NEW
$ cplang policy prove --no-bypass FILE --hard-signal CODE
```

| Option | Meaning |
| --- | --- |
| `--candidate`, `--boundary` | Prove that the candidate permits nothing the boundary denies |
| `--diff OLD NEW` | Show what the change newly permits |
| `--no-bypass FILE` | Prove that no hard-deny signal is bypassed |
| `--hard-signal CODE` | A signal code that must always deny. Repeatable |
| `--timeout-ms` | Solver timeout. Default 10000 |
| `--emit-fixture FILE` | Write counterexamples as fixtures |

| Exit code | Result |
| --- | --- |
| `0` | `within_boundary` |
| `1` | `exceeds_boundary` |
| `2` | `error` |
| `3` | `unsupported` or `inconclusive` |

## test

Runs fixture actions through the evaluator offline. Rate limits are only peeked at.

```console
$ cplang test --fixtures PATH [--policy PATH] [--decl FILE] [--root DIR] [--strict-inputs] [--json]
```

`--fixtures` takes files or directories. `--policy` defaults to the policy a fixture file names under `policy:`. Exits `1` on any mismatch and `2` for an unreadable fixture or policy.

## eval

Decides one action.

```console
$ cplang eval --policy PATH --action FILE [--signals FILE] [--now TIMESTAMP] [--decl FILE] [--root DIR] [--param NAME=VALUE] [--strict-inputs] [--json]
```

| Option | Meaning |
| --- | --- |
| `--action` | An action file, YAML or JSON. Required |
| `--policy` | Policy files or directories. Required |
| `--signals` | A file with a list of signals |
| `--now` | An RFC 3339 timestamp for an action that has none |
| `--param` | A parameter binding. Repeatable |

Prints `outcome REASON_CODES  rules=[...]`.

## expr eval

Evaluates one expression. Prints its value, its type and whether the value is trusted.

```console
$ cplang expr eval EXPRESSION [--fixtures FILE] [--decl FILE] [--json]
```

Put `--` before an expression that starts with a minus sign.

## decl check

Validates declaration files, and optionally policies against them.

```console
$ cplang decl check <paths>... [--set NAME=VALUE] [--policy FILE] [--json]
```

## decl show

Prints the merged declaration set, with the digest of every file.

```console
$ cplang decl show <paths>... [--set NAME=VALUE] [--json]
```

## decl fmt

Rewrites declaration files in canonical form.

```console
$ cplang decl fmt <paths>... [--check]
```

## decl lock

Writes the `sha256:` digests of every resolved import and table file. Never content.

```console
$ cplang decl lock <paths>... [--out FILE]
```

The default output file is `cpl.decl.lock`.

## schema

Prints a JSON Schema: `policy`, `action`, `signal`, `verdict` or `fixtures`. Without a name, it lists them.

```console
$ cplang schema [NAME]
```

## conformance

Runs the conformance vectors against this implementation. Exits `0` only when every vector passes.

```console
$ cplang conformance [VECTORS] [--report FILE] [--json]
```

> ▶ Next: [Python API](/reference/python-api/)
{: .next}
