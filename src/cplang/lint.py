"""Static checks that point out likely mistakes in a compiled policy without changing what it means."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from cplang.compile import Compiled
from cplang.expr import Node
from cplang.inputs import CONDITION_ROOTS, ROOTS
from cplang.policy import CompiledPolicy, CRule


@dataclass(frozen=True)
class Finding:
    """One lint result: a code, a severity, the rule it concerns (if any) and a message."""

    code: str
    severity: str
    rule: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        """The finding as a dictionary."""
        return {"code": self.code, "severity": self.severity, "rule": self.rule, "message": self.message}


def lint(policy: CompiledPolicy) -> list[Finding]:
    """Findings for `policy`, in rule order, then declaration order."""
    findings: list[Finding] = []
    findings += _unused_variables(policy)
    findings += _unreachable_rules(policy)
    findings += _duplicate_rules(policy)
    findings += [
        Finding("disabled-rule", "info", r.id, "the rule is disabled and never evaluated")
        for r in policy.rules
        if not r.enabled
    ]
    findings += _undeclared_inputs(policy)
    findings += _unused_declarations(policy)
    return findings


def _walk(node: Node | None) -> Iterator[Node]:
    if node is None:
        return
    yield node
    for arg in node.args:
        if isinstance(arg, Node):
            yield from _walk(arg)


def _nodes(compiled: Compiled | None) -> Iterator[Node]:
    if compiled is not None:
        yield from _walk(compiled.node)


def _rule_nodes(rule: CRule) -> Iterator[Node]:
    yield from _nodes(rule.match)
    yield from _nodes(rule.gate)
    adm = rule.admission
    yield from _nodes(adm.deny)
    for threshold in adm.thresholds:
        for part in (threshold.cond, threshold.path, threshold.value):
            yield from _nodes(part)
    if rule.explain is not None:
        for piece in rule.explain.parts:
            if not isinstance(piece, str) and piece[0] == "path":
                yield from _nodes(piece[1])
    for _, compiled in rule.lets:
        yield from _nodes(compiled)


def _references(nodes: Iterator[Node], namespace: str) -> set[str]:
    names: set[str] = set()
    for node in nodes:
        if node.k == "path" and node.op == namespace:
            parts = [str(a) for a in node.args if isinstance(a, str)]
            names.update(parts)
            names.add(".".join(parts))
    return names


def _unused_variables(policy: CompiledPolicy) -> Iterator[Finding]:
    for rule in policy.rules:
        used = _references(_rule_nodes(rule), "var")
        for name, _ in rule.lets:
            if name not in used:
                yield Finding("unused-variable", "warning", rule.id, f"`let` variable {name!r} is never used")


def _trivial(compiled: Compiled | None) -> bool:
    node = compiled.node if compiled is not None else None
    return node is None or (node.k == "lit" and node.val is True)


def _unreachable_rules(policy: CompiledPolicy) -> Iterator[Finding]:
    """Under first_match and priority an earlier enforced rule stops evaluation; monitor rules only observe."""
    if policy.strategy == "deny_overrides":
        return
    order = sorted(policy.rules, key=lambda r: -r.priority) if policy.strategy == "priority" else list(policy.rules)
    catch_all: str | None = None
    earlier: dict[str, str] = {}
    match_only: dict[str, str] = {}  # match signature -> an earlier rule that decides every action that match selects
    for rule in (r for r in order if r.enabled):
        if catch_all is not None:
            yield Finding("unreachable-rule", "warning", rule.id, f"rule {catch_all!r} matches every action first")
            continue
        if rule.mode == "monitor":
            continue
        signature, match = _signature(rule), _match_signature(rule)
        if signature in earlier:
            yield Finding(
                "unreachable-rule",
                "warning",
                rule.id,
                f"rule {earlier[signature]!r} has the same conditions and is first",
            )
            continue
        if match in match_only:
            yield Finding(
                "unreachable-rule",
                "warning",
                rule.id,
                f"rule {match_only[match]!r} has the same match, no further conditions and is first",
            )
            continue
        earlier[signature] = rule.id
        if _trivial(rule.gate):
            match_only.setdefault(match, rule.id)
            if _trivial(rule.match):
                catch_all = rule.id


def _match_signature(rule: CRule) -> str:
    return json.dumps(rule.canon["match"], sort_keys=True, default=str)


def _signature(rule: CRule) -> str:
    keys = ("match", "let", "when", "admission")
    return json.dumps({k: rule.canon[k] for k in keys}, sort_keys=True, default=str)


def _duplicate_rules(policy: CompiledPolicy) -> Iterator[Finding]:
    seen: dict[str, CRule] = {}
    for rule in (r for r in policy.rules if r.enabled):
        first = seen.setdefault(_signature(rule), rule)
        if first is rule:
            continue
        if first.outcome == rule.outcome:
            yield Finding("duplicate-rule", "warning", rule.id, f"same conditions and outcome as rule {first.id!r}")
        else:
            yield Finding(
                "conflicting-rules",
                "warning",
                rule.id,
                f"same conditions as rule {first.id!r} with outcome {first.outcome}",
            )


def _unused_declarations(policy: CompiledPolicy) -> Iterator[Finding]:
    decls = policy.decls
    nodes = [n for rule in policy.rules for n in _rule_nodes(rule)]
    nodes += [n for _, tier in policy.risk_tiers for n in _nodes(tier)]
    free_text = " ".join(
        repr(spec) for group in (decls._funcs, decls._computed, decls.conditions) for spec in group.values()
    )
    declared = (
        ("param", decls.parameters),
        ("const", decls._consts_raw),
        ("table", decls.tables),
    )
    for namespace, names in declared:
        used = _references(iter(nodes), namespace)
        for name in sorted(names):
            if name not in used and name.split(".")[-1] not in used and name not in free_text:
                yield Finding("unused-declaration", "info", None, f"{namespace} {name!r} is declared but never used")


def _undeclared_inputs(policy: CompiledPolicy) -> Iterator[Finding]:
    """Top-level names that are neither standard, declared under `inputs:`, supplied by the host nor local."""
    decls = policy.decls
    known = {*ROOTS, *CONDITION_ROOTS, *decls.inputs, *policy.profile.roots, *decls.types}
    for rule in policy.rules:
        nodes = list(_rule_nodes(rule))
        local = {str(n.val) for n in nodes if n.k == "macro"}
        local.update(name for n in nodes if n.op == "with_locals" for name in n.opts["names"])
        reported: set[str] = set()
        for node in nodes:
            root = node.op
            if node.k == "path" and root and root not in known and root not in local and root not in reported:
                reported.add(root)
                yield Finding(
                    "undeclared-input",
                    "warning",
                    rule.id,
                    f"`{root}` is not a declared input; add it under `inputs:` in a declaration file",
                )
