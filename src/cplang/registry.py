"""The values the language itself defines: outcomes, their order, and the generic reason codes."""

from __future__ import annotations

import re
from typing import TypeGuard

from cplang.model import Outcome

REASON_CODES = frozenset(
    {
        "NO_MATCHING_RULE",
        "RULE_DENY",
        "RULE_ASK",
        "POLICY_SATISFIED",
        "POLICY_ADVISORY",
        "EVALUATION_ERROR",
        "MONITOR_WOULD_BLOCK",
        "ACTION_FORBIDDEN",
        "RATE_LIMIT_EXCEEDED",
        "THRESHOLD_EXCEEDED",
        "PARAM_IMMUTABLE_VIOLATION",
        "PARAM_OUT_OF_BOUNDS",
    }
)
REASON_TEXT = {
    "NO_MATCHING_RULE": "No rule matched, so the policy default applies.",
    "RULE_DENY": "A policy rule denies this action.",
    "RULE_ASK": "A policy rule requires approval for this action.",
    "POLICY_SATISFIED": "The policy allows this action.",
    "POLICY_ADVISORY": "The action is allowed with a flag.",
    "EVALUATION_ERROR": "The policy could not be evaluated, so the action is refused.",
    "MONITOR_WOULD_BLOCK": "Monitor mode: this action would have been blocked.",
    "ACTION_FORBIDDEN": "This action is forbidden.",
    "RATE_LIMIT_EXCEEDED": "The rate limit is exceeded.",
    "THRESHOLD_EXCEEDED": "A limit is exceeded.",
    "PARAM_IMMUTABLE_VIOLATION": "A fixed parameter was changed.",
    "PARAM_OUT_OF_BOUNDS": "A parameter is out of bounds.",
}
CUSTOM_REASON = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}/[A-Z][A-Z0-9_]*$")
CUSTOM_NAMESPACED = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}/[A-Za-z][A-Za-z0-9_.]*$")

RESERVED_NAMESPACES = frozenset({"cpl", "core", "std"})

OUTCOMES: tuple[Outcome, ...] = ("allow", "deny", "ask", "modify", "watch")
RULE_OUTCOMES: frozenset[str] = frozenset(OUTCOMES)


def is_outcome(value: object) -> TypeGuard[Outcome]:
    """True when `value` is one of the outcomes."""
    return isinstance(value, str) and value in RULE_OUTCOMES


# When rules disagree the highest rank wins.
PERMITTED: frozenset[Outcome] = frozenset({"allow", "watch", "modify"})  # outcomes that let the action proceed
RANK: dict[Outcome, int] = {"allow": 0, "watch": 1, "modify": 2, "ask": 3, "deny": 4}
STANDARD_OUTCOME_REASON: dict[Outcome, str] = {
    "deny": "RULE_DENY",
    "ask": "RULE_ASK",
    "allow": "POLICY_SATISFIED",
    "watch": "POLICY_ADVISORY",
    "modify": "POLICY_ADVISORY",
}
