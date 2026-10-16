"""The three data types of the language: the input (`Action`), the findings a host supplies (`Signal`) and the result
(`Verdict`). They are plain data and convert to JSON-compatible dictionaries with `to_wire()`."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, NotRequired, TypedDict, cast

from cplang.canonical import digest_object
from cplang.jsontypes import JsonValue as JsonValue

type Outcome = Literal["allow", "watch", "modify", "ask", "deny"]
"""The decision a verdict carries."""

type Severity = Literal["info", "low", "medium", "high", "critical"]
"""How serious a signal is, from least to most."""

type Mode = Literal["enforce", "monitor"]
"""Whether a policy blocks (`enforce`) or only reports what it would have blocked (`monitor`)."""

type Strategy = Literal["first_match", "deny_overrides", "priority"]
"""How the matching rules of a policy combine into one outcome."""

type Posture = Literal["deny", "allow_and_flag"]
"""What the evaluator returns when evaluation itself fails: a `deny`, or a `watch` that flags the action."""

SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


class Reason(TypedDict):
    """Why a verdict came out the way it did: a reason code and where it came from."""

    code: str
    source: str
    message: NotRequired[str]


class Obligation(TypedDict):
    """A follow-up duty attached to a verdict, such as `human_approval` or `notify`."""

    type: str
    params: dict[str, JsonValue]


class Edit(TypedDict):
    """One change a `modify` verdict asks the caller to apply to the action."""

    op: Literal["redact", "replace", "drop_field", "set"]
    json_pointer: str
    value: NotRequired[JsonValue]
    placeholder: NotRequired[str]


class Modifications(TypedDict, total=False):
    """The changes a `modify` verdict asks for: a full replacement or a list of edits."""

    replace: dict[str, JsonValue]
    edits: list[Edit]


class PolicyRef(TypedDict):
    """Identifies the policy that produced a verdict."""

    id: str
    version: int | str
    fingerprint: str


@dataclass(frozen=True)
class Action:
    """One thing about to happen, as a JSON-like document.

    `timestamp` (an RFC 3339 string) is the only required key. It is the `time.now` that expressions see, so the same
    action always gets the same verdict.
    """

    data: Mapping[str, JsonValue]

    @property
    def id(self) -> str:
        """The action's `id`, or an empty string."""
        value = self.data.get("id", "")
        return value if isinstance(value, str) else ""

    @property
    def timestamp(self) -> str:
        """The action's RFC 3339 timestamp."""
        value = self.data.get("timestamp")
        if not isinstance(value, str):
            raise ValueError("an action needs a `timestamp` (RFC 3339 string)")
        return value

    def to_wire(self) -> dict[str, JsonValue]:
        """A deep copy of the action as JSON data."""
        return copy.deepcopy(dict(self.data))

    def digest(self) -> str:
        """The `sha256:` digest of the canonical JSON of the action."""
        return digest_object(self.to_wire())


@dataclass(frozen=True)
class Signal:
    """A named fact about an action, reported by something outside the language such as a checker or a scanner."""

    code: str
    source: str = "host"
    severity: Severity = "high"
    confidence: float = 1.0
    facts: Mapping[str, JsonValue] | None = None
    evidence: Mapping[str, JsonValue] | None = None
    suggested_modification: Mapping[str, JsonValue] | None = None
    id: str = ""

    def to_wire(self) -> dict[str, JsonValue]:
        """The signal as JSON data."""
        out: dict[str, JsonValue] = {
            "code": self.code,
            "source": self.source,
            "severity": self.severity,
            "confidence": self.confidence,
            "id": self.id,
        }
        if self.facts is not None:
            out["facts"] = copy.deepcopy(dict(self.facts))
        if self.evidence is not None:
            out["evidence"] = copy.deepcopy(dict(self.evidence))
        if self.suggested_modification is not None:
            out["suggested_modification"] = copy.deepcopy(dict(self.suggested_modification))
        return out


@dataclass
class Verdict:
    """The decision for one action."""

    outcome: Outcome
    action_id: str = ""
    verdict_id: str = ""
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    explanation: str | None = None
    hint: dict[str, JsonValue] | None = None
    obligations: list[Obligation] = field(default_factory=list)
    modifications: Modifications | None = None
    risk_tier: str | None = None
    policy: PolicyRef | None = None
    input_digest: str = ""
    would_block: bool = False
    would_have_been: Outcome | None = None

    def to_wire(self) -> dict[str, JsonValue]:
        """The verdict as JSON-compatible data (described by `schemas/verdict.schema.json`)."""
        wire = copy.deepcopy(
            {
                "outcome": self.outcome,
                "action_id": self.action_id,
                "verdict_id": self.verdict_id,
                "matched_rules": list(self.matched_rules),
                "reasons": list(self.reasons),
                "reason_codes": list(self.reason_codes),
                "explanation": self.explanation,
                "hint": self.hint,
                "obligations": list(self.obligations),
                "modifications": self.modifications,
                "risk_tier": self.risk_tier,
                "policy": self.policy or {},
                "input_digest": self.input_digest,
                "would_block": self.would_block,
                "would_have_been": self.would_have_been,
            }
        )
        return cast("dict[str, JsonValue]", wire)
