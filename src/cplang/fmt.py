"""Canonical formatting of policy and declaration files: stable key order, comments preserved."""

from __future__ import annotations

import io
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from cplang.conditions import ADMISSION_KEYS
from cplang.declarations import OPEN_SECTIONS
from cplang.errors import AuthoringError

POLICY_ORDER = (
    "cpl",
    "id",
    "version",
    "fragment",
    "description",
    "imports",
    "vocabulary",
    "params",
    "mode",
    "default",
    "strategy",
    "risk_tiers",
    "default_risk_tier",
    "conditions",
    "rules",
    "ext",
)
RULE_ORDER = (
    "id",
    "description",
    "priority",
    "enabled",
    "mode",
    "match",
    "let",
    "when",
    "outcome",
    "modify",
    "reason",
    "explain",
    "hint",
    "obligations",
    "ext",
)
DECL_ORDER = (
    "schema",
    "namespace",
    "version",
    "description",
    "imports",
    "types",
    "attributes",
    "constants",
    "parameters",
    "tables",
    "functions",
    "conditions",
    "computed",
    *OPEN_SECTIONS,
    "ext",
)


def _reorder(node: Any, order: tuple[str, ...]) -> None:
    if isinstance(node, CommentedMap):
        for key in reversed(order):
            if key in node:
                node.move_to_end(key, last=False)


def _reorder_when(when: Any) -> None:
    """Conditions keep their order; requirement keys (deny, thresholds, approval, ...) follow in a fixed order."""
    if isinstance(when, CommentedMap):
        for key in ADMISSION_KEYS:
            if key in when:
                when.move_to_end(key, last=True)


def _has_comments(node: Any) -> bool:
    """Whether a loaded document carries any comment."""
    stack = [node]
    while stack:
        cur = stack.pop()
        ca = getattr(cur, "ca", None)
        if ca is not None and (ca.comment or ca.items or ca.end):
            return True
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


def format_text(text: str, kind: str) -> str:
    """Return `text` in canonical form. `kind` is `policy` or `decl`. Idempotent."""
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 120
    yaml.preserve_quotes = True
    try:
        doc = yaml.load(text)
    except Exception as exc:
        raise AuthoringError("SCHEMA_INVALID", f"document is not valid YAML: {type(exc).__name__}") from exc
    if not isinstance(doc, CommentedMap):
        raise AuthoringError("SCHEMA_INVALID", "a document is a mapping")
    if not _has_comments(doc):  # moving a key would carry the comment of its neighbour with it
        _reorder(doc, POLICY_ORDER if kind == "policy" else DECL_ORDER)
        if kind == "policy":
            for rule in doc.get("rules") or []:
                _reorder(rule, RULE_ORDER)
                _reorder_when(rule.get("when") if isinstance(rule, CommentedMap) else None)
    out = io.StringIO()
    yaml.dump(doc, out)
    return out.getvalue()
