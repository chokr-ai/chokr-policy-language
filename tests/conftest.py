"""Helpers for the tests: write policy files, build actions and signals, load and evaluate."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from cplang import Action, AuthoringError, CompiledPolicy, RuleEvaluator, Signal, Verdict, load_policy
from cplang.ids import IdGenerator

IDS = IdGenerator(now_ms=lambda: 1_767_225_600_000, randbytes=lambda n: bytes(range(n)))
NOW = "2026-01-01T12:00:00Z"
_counter = {"n": 0}


def make_env(
    arguments: dict[str, Any] | None = None,
    *,
    kind: str = "tool_call",
    action_uri: str = "app:act",
    target: str = "tool",
    attributes: dict[str, Any] | None = None,
    sources: dict[str, str] | None = None,
    **fields: Any,
) -> Action:
    _counter["n"] += 1
    data: dict[str, Any] = {
        "id": f"act-{_counter['n']:04d}",
        "timestamp": NOW,
        "kind": kind,
        "action_uri": action_uri,
        "target": {"name": target, **fields.pop("target_kw", {})},
        "arguments": arguments or {},
        "actor": {"subject": "agent-1"},
        "environment": {"env": "prod"},
    }
    if attributes is not None:
        data["attributes"] = attributes
    if sources is not None:
        data["attribute_sources"] = sources
    data.update(fields)
    return Action(data)


def make_signal(
    env: Action,
    code: str,
    *,
    source: str = "scanner",
    severity: str = "high",
    confidence: float = 1.0,
    facts: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    suggested: dict[str, Any] | None = None,
) -> Signal:
    _counter["n"] += 1
    return Signal(
        code=code,
        source=source,
        severity=severity,
        confidence=confidence,
        facts=facts,
        evidence=evidence,
        suggested_modification=suggested,
        id=f"sig-{_counter['n']:04d}",
    )


class Project:
    """A temp directory with helpers to write files and load a policy set from them."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), "utf-8", newline="\n")
        return path

    def policy(self, text: str, *, decls: str | None = None, name: str = "p.policy.yaml", **kw: Any) -> CompiledPolicy:
        paths = [self.write(name, text)]
        if decls is not None:
            self.write("d.decl.yaml", decls)
            kw.setdefault("decl_paths", [self.root / "d.decl.yaml"])
        kw.setdefault("roots", [self.root])
        return load_policy(paths, **kw)

    def evaluator(self, text: str, **kw: Any) -> RuleEvaluator:
        ev_kw = {k: kw.pop(k) for k in ("rate_limiter", "live", "posture", "profile") if k in kw}
        return RuleEvaluator(self.policy(text, **kw), **ev_kw)


@pytest.fixture
def project(tmp_path: Path) -> Project:
    return Project(tmp_path)


def outcome_of(v: Verdict) -> tuple[str, list[str]]:
    return v.outcome, v.reason_codes


def at(env: Action, timestamp: str) -> Action:
    """The same action at another time."""
    return Action({**env.data, "timestamp": timestamp})


BARE_HEAD = 'cpl: "1.0"\nid: p\nversion: 1\n'
DENY_DEFAULT = BARE_HEAD + "default: deny\nrules:\n"
ALLOW_DEFAULT = BARE_HEAD + "default: allow\nrules:\n"


def authoring_code(fn: Any) -> str:
    """The code of the AuthoringError that `fn` raises."""
    with pytest.raises(AuthoringError) as info:
        fn()
    return str(info.value.code)


def policy_error(project: Project, text: str, **kw: Any) -> str:
    """The code of the AuthoringError raised when `text` is loaded as a policy."""
    return authoring_code(lambda: project.policy(text, **kw))
