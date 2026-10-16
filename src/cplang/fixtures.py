"""Fixture files: an action, optional signals and the verdict you expect.

```yaml
schema: cpl.fixtures/1.0
policy: agent.policy.yaml           # optional: the policy under test, relative to this file (`--policy` overrides)
params: {limit: 10}                 # optional parameter overrides for this suite
now: "2026-01-01T12:00:00Z"         # optional: the `time.now` of every case
cases:
  - name: allow_read
    action: {kind: tool_call, action_uri: "library:search", target: catalogue, arguments: {q: poetry}}
    signals: [{code: spam.suspected, severity: high, facts: {score: 9}}]
    signals_from: [scanner]         # optional: signals a host-provided function derives from the action
    expect: {outcome: allow, reason_codes: [POLICY_SATISFIED], matched_rules: [allow-search]}
```
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from cplang.errors import AuthoringError
from cplang.evaluator import RuleEvaluator
from cplang.model import SEVERITIES, Action, Signal, Verdict
from cplang.source import Source, read_source
from cplang.values import EvalError, parse_timestamp, render_number, to_wire

FIXTURE_SCHEMA = "cpl.fixtures/1.0"
DEFAULT_NOW = "2026-01-01T12:00:00Z"
SignalProvider = Callable[[Action], list[Signal]]
_SIGNAL_KEYS = {"code", "source", "severity", "confidence", "facts", "evidence", "suggested_modification"}
_EXPECT_KEYS = (
    "outcome",
    "reason_codes",
    "matched_rules",
    "would_block",
    "would_have_been",
    "risk_tier",
    "obligations",
)


@dataclass
class Case:
    """One fixture case: an action, its signals and the expected verdict."""

    name: str
    action: Action
    signals: list[Signal]
    expect: dict[str, Any]
    file: str = ""
    signals_from: tuple[str, ...] = ()


@dataclass
class Suite:
    """A parsed fixture file."""

    file: str
    params: dict[str, Any] = field(default_factory=dict)
    policy: str | None = None
    cases: list[Case] = field(default_factory=list)


@dataclass
class CaseResult:
    """The verdict for a case and the differences from what was expected."""

    case: Case
    verdict: Verdict
    failures: list[str]

    @property
    def passed(self) -> bool:
        """True when the verdict matched the expectation."""
        return not self.failures


def _plain(x: Any) -> Any:
    """Fixture data to action data: decimals become floats (the evaluator restores them from the shortest repr)."""
    if isinstance(x, Decimal):
        as_float = float(x)
        return as_float if Decimal(repr(as_float)) == x else x  # a float only when it loses nothing
    if isinstance(x, dict):
        return {k: _plain(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_plain(v) for v in x]
    return x


def _norm(x: Any) -> Any:
    """Comparison form: every number is its decimal text, so `5`, `5.0` and `Decimal(5)` agree."""
    if type(x) is bool or x is None:
        return x
    if isinstance(x, int | float | Decimal):
        return render_number(Decimal(repr(x)) if isinstance(x, float) else x)
    if isinstance(x, dict):
        return {k: _norm(v) for k, v in x.items()}
    if isinstance(x, list | tuple):
        return [_norm(v) for v in x]
    return x


def _action(raw: Any, name: str, now: str, src: Source, where: tuple[Any, ...]) -> Action:
    if not isinstance(raw, dict):
        raise src.error("SCHEMA_INVALID", "an action is a mapping", *where)
    data = {"id": f"case-{name}", "timestamp": now, **_plain(raw)}
    return Action(data)


def _signals(case: dict[str, Any], src: Source, where: tuple[Any, ...]) -> list[Signal]:
    out: list[Signal] = []
    for i, s in enumerate(case.get("signals") or []):
        if not isinstance(s, dict) or not isinstance(s.get("code"), str) or set(s) - _SIGNAL_KEYS:
            keys = ", ".join(sorted(_SIGNAL_KEYS))
            raise src.error("SCHEMA_INVALID", f"a signal is {{{keys}}} with a code", *where, i)
        severity = s.get("severity", "high")
        if severity not in SEVERITIES:
            raise src.error("SCHEMA_INVALID", f"severity is one of {', '.join(SEVERITIES)}", *where, i, "severity")
        out.append(
            Signal(
                code=s["code"],
                source=s.get("source", "fixture"),
                severity=severity,
                confidence=float(s.get("confidence", 1)),
                facts=_plain(s.get("facts")),
                evidence=_plain(s.get("evidence")),
                suggested_modification=_plain(s.get("suggested_modification")),
                id=f"sig-{len(out):03d}",
            )
        )
    return out


def parse_signals(raw: Any, src: Source) -> list[Signal]:
    """Signals from a document: a list of `{code, source?, severity?, confidence?, facts?, evidence?}`."""
    if not isinstance(raw, list):
        raise src.error("SCHEMA_INVALID", "signals are a list")
    return _signals({"signals": raw}, src, ())


def load_action(path: Path, *, now: str | None = None) -> Action:
    """An action file (YAML or JSON). `now` supplies the timestamp when the file has none."""
    src = read_source(path)
    if not isinstance(src.data, dict):
        raise src.error("SCHEMA_INVALID", "an action is a mapping")
    data = _plain(src.data)
    if "timestamp" not in data:
        if now is None:
            raise src.error("SCHEMA_INVALID", "an action needs a `timestamp` (or pass --now)")
        data["timestamp"] = now
    return Action(data)


def load_signals(path: Path) -> list[Signal]:
    """Read a signals file: a list of signal mappings."""
    src = read_source(path)
    return parse_signals(src.data, src)


def load_suite(path: Path) -> Suite:
    """Parse a fixture file. Raises AuthoringError with a line number for anything malformed."""
    src = read_source(path)
    doc = src.data
    if not isinstance(doc, dict) or doc.get("schema") != FIXTURE_SCHEMA:
        raise src.error("SCHEMA_INVALID", f"a fixture file has `schema: {FIXTURE_SCHEMA}`", "schema")
    for key in doc:
        if key not in {"schema", "params", "policy", "now", "cases", "description"}:
            raise src.error("SCHEMA_INVALID", f"unknown key {key!r}", key)
    now = doc.get("now", DEFAULT_NOW)
    if not isinstance(now, str) or not _is_timestamp(now):
        raise src.error("SCHEMA_INVALID", "now is an RFC 3339 string", "now")
    policy = doc.get("policy")
    if policy is not None:
        if not isinstance(policy, str) or not (path.parent / policy).exists():
            raise src.error("SCHEMA_INVALID", "`policy` is an existing path, relative to the fixture file", "policy")
        policy = str(path.parent / policy)
    cases = doc.get("cases")
    if not isinstance(cases, list) or not cases:
        raise src.error("SCHEMA_INVALID", "a fixture file has at least one case", "cases")
    suite = Suite(str(path), dict(doc.get("params") or {}), policy)
    seen: set[str] = set()
    for i, raw in enumerate(cases):
        where = ("cases", i)
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            raise src.error("SCHEMA_INVALID", "a case needs a `name`", *where)
        if raw["name"] in seen:
            raise src.error("SCHEMA_INVALID", f"duplicate case name {raw['name']!r}", *where, "name")
        seen.add(raw["name"])
        for key in raw:
            if key not in {"name", "description", "action", "signals", "signals_from", "expect"}:
                raise src.error("SCHEMA_INVALID", f"unknown case key {key!r}", *where, key)
        expect = raw.get("expect") or {}
        if not expect or set(expect) - set(_EXPECT_KEYS):
            raise src.error("SCHEMA_INVALID", f"expect takes {', '.join(_EXPECT_KEYS)}", *where, "expect")
        action = _action(raw.get("action") or {}, raw["name"], now, src, (*where, "action"))
        signals = _signals(raw, src, (*where, "signals"))
        names = raw.get("signals_from") or []
        if not isinstance(names, list) or not all(isinstance(g, str) for g in names):
            raise src.error("SCHEMA_INVALID", "`signals_from` is a list of provider names", *where, "signals_from")
        suite.cases.append(Case(raw["name"], action, signals, dict(expect), str(path), tuple(names)))
    return suite


def _is_timestamp(text: str) -> bool:
    try:
        parse_timestamp(text)
    except EvalError:
        return False
    return True


def check_case(case: Case, verdict: Verdict) -> list[str]:
    """Differences between the expectation and the verdict. Only the listed keys are compared, except that an
    evaluation error fails the case unless `reason_codes` is expected explicitly: a deny caused by a broken policy or
    fixture must not pass as the deny the case was written for."""
    failures: list[str] = []
    if "EVALUATION_ERROR" in verdict.reason_codes and "reason_codes" not in case.expect:
        cause = next((r.get("message") for r in verdict.reasons if r.get("code") == "EVALUATION_ERROR"), None)
        failures.append(f"evaluation error: {cause or 'unknown'} (expect reason_codes to test for it)")
    actual: dict[str, Any] = {
        "outcome": verdict.outcome,
        "reason_codes": verdict.reason_codes,
        "matched_rules": verdict.matched_rules,
        "would_block": verdict.would_block,
        "would_have_been": verdict.would_have_been,
        "risk_tier": verdict.risk_tier,
        "obligations": verdict.obligations,
    }
    for key, want in case.expect.items():
        have = actual[key]
        if _norm(to_wire(have)) != _norm(want):
            failures.append(f"{key}: expected {want!r}, got {have!r}")
    return failures


def run_suite(
    suite: Suite, evaluator: RuleEvaluator, providers: Mapping[str, SignalProvider] | None = None
) -> list[CaseResult]:
    """Evaluate every case. A case that lists `signals_from:` also gets the signals those providers derive from its
    action, so a fixture can start from raw input."""
    results = []
    for case in suite.cases:
        signals = list(case.signals)
        failures: list[str] = []
        for name in case.signals_from:
            provider = (providers or {}).get(name)
            if provider is None:
                failures.append(f"signals_from: no provider named {name!r}")
            else:
                signals += provider(case.action)
        verdict, _ = evaluator.trace(case.action, signals)
        results.append(CaseResult(case, verdict, [*failures, *check_case(case, verdict)]))
    return results


def load_suites(paths: Sequence[Path]) -> list[Suite]:
    """Parse several fixture files."""
    files: list[Path] = []
    for p in paths:
        files += sorted(p.rglob("*.fixtures.y*ml")) + sorted(p.rglob("*.fixtures.json")) if p.is_dir() else [p]
    if not files:
        raise AuthoringError("SCHEMA_INVALID", "no fixture files found")
    return [load_suite(f) for f in files]
