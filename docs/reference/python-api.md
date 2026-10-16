---
title: Python API
description: The classes and functions of the cplang package, with their arguments and what they return.
---

Import everything from `cplang`. The package ships type information, so editors and type checkers see every signature.

```python
from cplang import Action, RuleEvaluator, Signal, Verdict, load_policy
```
{: data-title="imports.py"}

For a guided tour, see [Embedding](/embedding/).

## load_policy

```python
load_policy(
    paths: Sequence[Path],
    *,
    decl_paths: Sequence[Path] = (),
    roots: Sequence[Path] | None = None,
    config_params: Sequence[Mapping[str, object]] = (),
    limits: CplLimits | None = None,
    plugins: FunctionRegistry | None = None,
    profile: Profile = NEUTRAL,
    strict: bool = False,
    strict_inputs: bool = False,
    rules_mode: Mode | None = None,
    rules_strategy: Strategy | None = None,
    max_import_depth: int = 16,
    lock: Mapping[str, Any] | None = None,
    require_lock: bool = False,
    default_rate: tuple[int, int] = (100, 60),
) -> CompiledPolicy
```

Loads one policy set: exactly one file that is not a fragment, plus any `fragment: true` files, and everything they import. Raises `AuthoringError` for any problem in the files.

| Argument | Meaning |
| --- | --- |
| `paths` | The policy files |
| `decl_paths` | Extra declaration files |
| `roots` | Directories that imports may reach. Default: the directory of each policy |
| `config_params` | Parameter values, lowest precedence first |
| `limits` | A `CplLimits` |
| `plugins` | A `FunctionRegistry` of host functions |
| `profile` | A `Profile` of host vocabulary |
| `strict` | Undeclared custom codes are errors |
| `strict_inputs` | Reject names that are neither standard nor declared |
| `rules_mode` | The mode for files and rules that set none |
| `rules_strategy` | The strategy to use when the file sets none |
| `max_import_depth` | How deep imports may nest |
| `lock`, `require_lock` | A lock mapping, and whether every import must be in it |
| `default_rate` | The `(limit, window_seconds)` used when a rate limit leaves them out |

### CompiledPolicy

| Attribute | Meaning |
| --- | --- |
| `id`, `version` | From the file |
| `mode`, `default`, `strategy` | The policy-level settings |
| `rules` | The compiled rules |
| `risk_tiers`, `default_risk_tier` | The risk tier definitions |
| `decls` | The `DeclarationSet` |
| `warnings` | A list of `PolicyWarning` dictionaries with `code`, `file`, `line`, `column`, `path` and `message` |
| `fingerprint` | The `sha256:` digest of the compiled policy |
| `limits`, `plugins`, `profile` | What the policy was loaded with |

## RuleEvaluator

```python
RuleEvaluator(
    policy: CompiledPolicy,
    *,
    ids: IdGenerator | None = None,
    rate_limiter: RateLimiter | None = None,
    live: bool = True,
    posture: Posture = "deny",
    on_suppressed: Callable[[Action, list[tuple[str, str]]], None] | None = None,
    profile: Profile | None = None,
)
```

Decides actions with one compiled policy. It is safe to share between threads.

| Argument | Meaning |
| --- | --- |
| `rate_limiter` | Where call counts live. Default: in memory |
| `live` | `False` for a dry run that never records a call |
| `posture` | `deny` (default) or `allow_and_flag`: the result of an evaluation failure |
| `on_suppressed` | Called with the action and the `(rule_id, outcome)` pairs that monitor mode softened |
| `profile` | Host vocabulary. Defaults to the policy's profile |

| Method | Returns |
| --- | --- |
| `evaluate(action, signals)` | A `Verdict`. Never raises for a failure inside a policy |
| `evaluate_result(action, signals)` | A `Verdict` after the action ran: only rules that read signals or the response are considered. No match means `allow` |
| `trace(action, signals)` | `(Verdict, events)` with every rule's `match`, `when` and `let` results. Read-only |

## Data Types

| Type | Fields |
| --- | --- |
| `Action(data)` | `data`, a mapping. Methods: `id`, `timestamp`, `to_wire()`, `digest()` |
| `Signal(code, source="host", severity="high", confidence=1.0, facts=None, evidence=None, suggested_modification=None, id="")` | A frozen dataclass. `to_wire()` |
| `Verdict` | `outcome`, `action_id`, `verdict_id`, `matched_rules`, `reasons`, `reason_codes`, `explanation`, `hint`, `obligations`, `modifications`, `risk_tier`, `policy`, `input_digest`, `would_block`, `would_have_been`. `to_wire()` |

The `timestamp` property of an `Action` raises `ValueError` when the action has none. `evaluate` turns that into a `deny` with the reason `EVALUATION_ERROR`.

### Type Aliases

| Alias | Values |
| --- | --- |
| `Outcome` | `allow`, `watch`, `modify`, `ask`, `deny` |
| `Severity` | `info`, `low`, `medium`, `high`, `critical` |
| `Mode` | `enforce`, `monitor` |
| `Strategy` | `first_match`, `deny_overrides`, `priority` |
| `Posture` | `deny`, `allow_and_flag` |
| `JsonValue` | Any JSON-compatible value |

`Reason`, `Obligation`, `Edit`, `Modifications` and `PolicyRef` are typed dictionaries that describe the parts of a verdict.

## load_declarations

```python
load_declarations(
    paths: Sequence[Path] = (),
    *,
    roots: Sequence[Path] | None = None,
    bindings: Sequence[Mapping[str, object]] = (),
    limits: CplLimits | None = None,
    max_import_depth: int = 16,
    lock: Mapping[str, Any] | None = None,
    require_lock: bool = False,
    plugins: FunctionRegistry | None = None,
) -> DeclarationSet
```

Loads declaration files and everything they import. Use it to check declarations on their own.

## FunctionRegistry

```python
registry = FunctionRegistry()
registry.register("acme/risk", risk_function, version="1")
```

| Method | Meaning |
| --- | --- |
| `register(name, fn, *, version="1")` | Registers `fn` under `namespace/name`. A name twice is an error |
| `has(name)` | True when `name` is registered |
| `resolve(name)` | The function for `name` |

A host function has the type `HostFunction = Callable[[Action, Mapping[str, JsonValue]], JsonValue]`. The arguments of the call arrive in `arguments["args"]`.

## Limits

`CplLimits` is a frozen dataclass. Every field is an integer.

| Field | Default |
| --- | --- |
| `max_expression_nodes` | 256 |
| `max_eval_steps` | 10,000 |
| `max_call_depth` | 8 |
| `max_type_depth` | 8 |
| `max_table_rows` | 100,000 |
| `max_table_bytes` | 67,108,864 |
| `max_regex_pattern_len` | 1,024 |
| `max_value_chars` | 1,048,576 |
| `max_rules` | 4,096 |
| `max_threshold_entries` | 64 |
| `max_explain_chars` | 512 |
| `max_document_bytes` | 1,048,576 |
| `max_document_depth` | 100 |

## Profile

A `Profile` is a frozen dataclass of host extensions. Pass the same profile to `load_policy` and `RuleEvaluator`.

| Field | Meaning |
| --- | --- |
| `reason_codes` | Extra standard reason codes |
| `reason_text` | Messages for reason codes |
| `obligation_types` | Extra obligation types |
| `signal_families` | The allowed first parts of a bare signal code. `None` allows any |
| `signal_effect` | `Callable[[Signal], SignalEffect | None]`: what a signal does before any rule runs |
| `hard_signal_codes` | Codes whose effect is a hard deny, for the prover |
| `roots` | Extra input names that expressions can read |
| `rule_keys` | Extra keys under `when:`, as `RuleKey(parse, check)` |

`SignalEffect(outcome, reason, obligations=(), edits=None, hard=False, monitor_aware=False, step=1)` describes the effect. A `hard` effect cannot be overruled by an `allow`. `Failure(outcome, reason, obligations=(), step=3)` is what a `RuleKey` check returns.

## Rate Limiters

A limiter is any object with these two methods:

```python
def check(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool: ...
def peek(self, key: str, limit: int, window_seconds: int, *, now_us: int) -> bool: ...
```

`check` records the call and returns whether it is within the limit. `peek` only reports.

## Errors

| Class | Raised when |
| --- | --- |
| `CplError` | Base class of every error. Has `code`, `message` and `detail` |
| `AuthoringError` | A policy or declaration file has a problem. Has `code`, `file`, `line`, `column`, `path` and `message` |

`AuthoringErrorInfo` is the typed dictionary form of an authoring error. See [Error Codes](/reference/errors/).

## Constants

| Name | Value |
| --- | --- |
| `cplang.__version__` | The package version |
| `cplang.LANGUAGE_VERSION` | `"1.0"`, the value of the `cpl` key |

> ▶ Next: [Error Codes](/reference/errors/)
{: .next}
