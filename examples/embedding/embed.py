"""Embedding the CHOKR Policy Language in a program: load a policy once, decide actions, and register a host function.

This file is type-checked with `mypy --strict` against the installed package, so it also shows what a consumer sees.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from cplang import (
    Action,
    AuthoringError,
    CompiledPolicy,
    FunctionRegistry,
    JsonValue,
    Outcome,
    RuleEvaluator,
    Signal,
    Verdict,
    load_policy,
)

POLICY_DIR = Path(__file__).resolve().parent.parent / "access"


def shout(action: Action, arguments: Mapping[str, JsonValue]) -> JsonValue:
    """A host function usable in expressions as `example/shout(...)`."""
    values = arguments.get("args")
    return str(values[0]).upper() if isinstance(values, list) and values else None


def build_evaluator() -> RuleEvaluator:
    functions = FunctionRegistry()
    functions.register("example/shout", shout)
    policy: CompiledPolicy = load_policy([POLICY_DIR / "access.policy.yaml"], roots=[POLICY_DIR], plugins=functions)
    return RuleEvaluator(policy)


def decide(evaluator: RuleEvaluator, kind: str, resource_type: str, signals: list[Signal]) -> Outcome:
    action = Action({"kind": kind, "resource": {"type": resource_type}, "timestamp": "2026-01-05T10:00:00Z"})
    verdict: Verdict = evaluator.evaluate(action, signals)
    return verdict.outcome


def main() -> None:
    try:
        evaluator = build_evaluator()
    except AuthoringError as error:
        raise SystemExit(f"invalid policy: {error}") from error
    print(decide(evaluator, "read", "public", []))
    print(decide(evaluator, "read", "public", [Signal(code="scan.malware", severity="critical")]))


if __name__ == "__main__":
    main()
