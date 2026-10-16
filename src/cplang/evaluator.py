"""RuleEvaluator: `(Action, Signal[]) -> Verdict`, pure and deterministic."""

from __future__ import annotations

import contextlib
import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, cast

from cplang.canonical import digest_sha256
from cplang.compile import Compiled
from cplang.ids import IdGenerator, default_ids
from cplang.model import (
    Action,
    Edit,
    JsonValue,
    Modifications,
    Obligation,
    Outcome,
    Posture,
    Reason,
    Signal,
    Verdict,
)
from cplang.policy import CompiledPolicy, CRule
from cplang.profile import Profile
from cplang.ratelimit import InMemoryRateLimiter, RateLimiter
from cplang.registry import RANK, REASON_TEXT, STANDARD_OUTCOME_REASON
from cplang.runtime import Ctx, InputView
from cplang.values import (
    ABSENT,
    EvalError,
    V,
    from_json,
    is_num,
    render,
    render_number,
    to_wire,
)

BLOCKING: frozenset[Outcome] = frozenset({"deny", "ask"})


@dataclass
class Contribution:
    """What one rule, or one signal effect, contributes to the final verdict."""

    rule_id: str | None
    outcome: Outcome
    reasons: list[Reason]
    obligations: list[Obligation] = field(default_factory=list)
    edits: list[Edit] | None = None
    replace: dict[str, JsonValue] | None = None
    step: int = 13
    tindex: int = 0
    monitor: bool = False
    hard: bool = False
    rule: CRule | None = None
    hits: list[Signal] = field(default_factory=list)
    vars: dict[str, V] = field(default_factory=dict)


def _reason(code: str, source: str, rule: CRule | None = None) -> Reason:
    return {"code": code, "source": source}


def _trips(guard: Compiled, before: Compiled | None, ctx: Ctx, *, before_result: bool) -> bool:
    """A `deny:` or threshold guard trips unless it is definitely false, so a value it needs but the action lacks
    fails closed. To let an absent value pass, test for it: `all: [{x: {exists: true}}, {x: {gt: 30}}]`.
    Before the call has run, the parts of a guard that read the tool's response wait for the response (`before`)."""
    chosen = before if before_result and before is not None else guard
    return chosen.fn(ctx).v is not False


def _tagged(x: Any) -> Any:
    """A value with its kind attached, so the number 1.5 and the text "1.5" never compare equal."""
    if isinstance(x, dict):
        return {k: _tagged(v) for k, v in x.items()}
    if isinstance(x, list | tuple):
        return [_tagged(v) for v in x]
    if type(x) is bool:
        return ["b", x]
    if is_num(x):
        return ["n", render_number(x)]
    if isinstance(x, str):
        return ["s", x]
    return ["o", _canon(to_wire(x))]


def _canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), default=str)


def pointer_overlap(a: str, b: str) -> bool:
    return a == b or a.startswith(b + "/") or b.startswith(a + "/") or a == "" or b == ""


class RuleEvaluator:
    """Evaluates one compiled policy set. Thread-safe: all state is per call."""

    def __init__(
        self,
        policy: CompiledPolicy,
        *,
        ids: IdGenerator | None = None,
        rate_limiter: RateLimiter | None = None,
        live: bool = True,
        posture: Posture = "deny",
        on_suppressed: Callable[[Action, list[tuple[str, str]]], None] | None = None,
        profile: Profile | None = None,
    ) -> None:
        self.policy = policy
        self._on_suppressed = on_suppressed
        self._ids = ids or default_ids
        self._limiter: RateLimiter = rate_limiter or InMemoryRateLimiter()
        self._profile = profile or policy.profile
        self._texts = {**REASON_TEXT, **self._profile.reason_text}
        self._live = live
        self._posture = posture
        order = list(policy.rules)
        if policy.strategy == "priority":
            order = sorted(order, key=lambda r: -r.priority)  # stable: ties keep declared order
        self._order = order

    def evaluate(self, action: Action, signals: list[Signal]) -> Verdict:
        """The Verdict for one Action. A run-time failure yields `deny` (`watch` with posture `allow_and_flag`)."""
        try:
            return self._evaluate(action, signals, trace=None, live=self._live)
        except Exception as exc:  # any failure is a refusal, never an exception for the host to mishandle
            return self._error_verdict(action, _cause(exc))

    def evaluate_result(self, action: Action, signals: list[Signal]) -> Verdict:
        """Evaluate after the action has run: only rules that read signals or the response are considered, and no
        match means allow. Signals that force a deny still apply."""
        try:
            return self._evaluate(action, signals, trace=None, live=self._live, result=True)
        except Exception as exc:  # any failure is a refusal, never an exception for the host to mishandle
            return self._error_verdict(action, _cause(exc))

    def trace(self, action: Action, signals: list[Signal]) -> tuple[Verdict, list[dict[str, Any]]]:
        """Evaluate with a full trace. Same code path; read-only; rate limits are only peeked."""
        events: list[dict[str, Any]] = []
        try:
            return self._evaluate(action, signals, trace=events, live=False), events
        except Exception as exc:
            return self._error_verdict(action, _cause(exc)), events

    def _evaluate(
        self,
        action: Action,
        signals: list[Signal],
        trace: list[dict[str, Any]] | None,
        live: bool,
        result: bool = False,
    ) -> Verdict:
        p = self.policy
        view = InputView(action, signals, p.decls)
        view.validate_inputs()
        ctx = Ctx(view, p.limits, trace=trace)
        contributions: list[Contribution] = self._step_zero(view, p.mode == "monitor")
        matched: list[str] = []
        for rule in self._order:
            if not rule.enabled or (result and not rule.result_aware):
                continue
            contribution = self._run_rule(rule, ctx, trace, live and not result, before_result=not result)
            if contribution is None:
                continue
            matched.append(rule.id)
            contributions.append(contribution)
            if p.strategy in ("first_match", "priority") and not contribution.monitor:  # monitor rules only observe
                break
        return self._resolve(action, ctx, contributions, matched, result)

    def _step_zero(self, view: InputView, monitor_doc: bool) -> list[Contribution]:
        """What the host's signal effects do by themselves, before any rule runs."""
        out: list[Contribution] = []
        effect_of = self._profile.signal_effect
        if effect_of is None:
            return out
        for s in view.signals:
            effect = effect_of(s)
            if effect is None:
                continue
            out.append(
                Contribution(
                    None,
                    effect.outcome,
                    [_reason(effect.reason, f"signal:{s.source}")],
                    list(effect.obligations),
                    edits=list(effect.edits) if effect.edits else None,
                    step=effect.step,
                    hard=effect.hard,
                    monitor=monitor_doc and effect.monitor_aware,
                )
            )
        return out

    def _run_rule(
        self, rule: CRule, ctx: Ctx, trace: list[dict[str, Any]] | None, live: bool, *, before_result: bool
    ) -> Contribution | None:
        ctx.vars, ctx.signal_hits = {}, []
        step_log: dict[str, Any] | None = {"rule": rule.id} if trace is not None else None
        if rule.match is not None:
            m = rule.match.fn(ctx)
            if step_log is not None:
                step_log["match"] = _tri(m)
            if m.v is not True:
                self._log(trace, step_log)
                return None
        for name, compiled in rule.lets:
            ctx.vars[name] = compiled.fn(ctx)
            if step_log is not None:
                step_log.setdefault("let", {})[name] = render(ctx.vars[name].v)
        g = rule.gate.fn(ctx) if rule.gate is not None else V(True)
        if step_log is not None:
            step_log["when"] = _tri(g)
        if g.v is not True:
            self._log(trace, step_log)
            return None
        contribution = self._admission(rule, ctx, live, before_result)
        contribution.rule, contribution.hits, contribution.vars = rule, list(ctx.signal_hits), dict(ctx.vars)
        contribution.monitor = rule.mode == "monitor"
        if step_log is not None:
            step_log.update(
                {
                    "decided_at_step": contribution.step,
                    "outcome": contribution.outcome,
                    "reasons": [r["code"] for r in contribution.reasons],
                }
            )
        self._log(trace, step_log)
        return contribution

    @staticmethod
    def _log(trace: list[dict[str, Any]] | None, entry: dict[str, Any] | None) -> None:
        if trace is not None and entry is not None:
            trace.append(entry)

    def _admission(self, rule: CRule, ctx: Ctx, live: bool, before_result: bool) -> Contribution:
        a, view, src = rule.admission, ctx.view, f"rule:{rule.id}"

        def fail(
            outcome: Outcome, code: str, step: int, obligations: list[Obligation] | None = None, tindex: int = 0
        ) -> Contribution:
            return Contribution(rule.id, outcome, [_reason(code, src)], obligations or [], step=step, tindex=tindex)

        if a.deny is not None and _trips(a.deny, a.deny_before, ctx, before_result=before_result):
            return fail("deny", rule.reason or "ACTION_FORBIDDEN", 2)
        for key, value in a.host.items():
            failure = self._profile.rule_keys[key].check(rule.id, value, view)
            if failure is not None:
                return fail(failure.outcome, failure.reason, failure.step, list(failure.obligations))
        if a.immutable or a.bounded:
            code = self._params(a, view.wire.get("arguments", {}))
            if code is not None:
                return fail("deny", code, 7)
        if a.max_calls is not None and not self._rate_ok(rule, a.max_calls, ctx, live):
            return fail("deny", "RATE_LIMIT_EXCEEDED", 9)
        if a.thresholds:
            th = self._thresholds(rule, a, ctx, before_result)
            if th is not None and RANK[th.outcome] > RANK[rule.outcome]:  # a threshold only ever tightens a rule
                return th
        return self._rule_outcome(rule, a)

    def _rule_outcome(self, rule: CRule, a: Any) -> Contribution:
        code = rule.reason or STANDARD_OUTCOME_REASON[rule.outcome]
        obligations = list(rule.obligations)
        if rule.outcome == "ask" and a.approval is not None:
            obligations.append({"type": "human_approval", "params": {"approval": dict(a.approval)}})
        c = Contribution(rule.id, rule.outcome, [_reason(code, f"rule:{rule.id}")], obligations, step=13)
        if rule.outcome == "modify" and rule.modify is not None:
            if "replace" in rule.modify:
                c.replace = dict(rule.modify["replace"])
            elif "edits" in rule.modify:
                c.edits = list(rule.modify["edits"])
        return c

    @staticmethod
    def _params(a: Any, arguments: Any) -> str | None:
        def lookup(name: str) -> Any:
            node: Any = arguments
            parts = name.split("/")[1:] if name.startswith("/") else [name]
            for part in parts:
                part = part.replace("~1", "/").replace("~0", "~")
                node = node.get(part, ABSENT) if isinstance(node, dict) else ABSENT
            return node

        for name, fixed in (a.immutable or {}).items():
            actual = lookup(name)
            if actual is ABSENT or _tagged(actual) != _tagged(from_json(fixed)):
                return "PARAM_IMMUTABLE_VIOLATION"
        for name, bound in (a.bounded or {}).items():
            actual = lookup(name)
            if type(actual) is bool or not isinstance(actual, int | Decimal):
                return "PARAM_OUT_OF_BOUNDS"
            if ("min" in bound and Decimal(actual) < Decimal(bound["min"])) or (
                "max" in bound and Decimal(actual) > Decimal(bound["max"])
            ):
                return "PARAM_OUT_OF_BOUNDS"
        return None

    def _rate_ok(self, rule: CRule, spec: dict[str, int], ctx: Ctx, live: bool) -> bool:
        actor = ctx.view.wire.get("actor")
        subject = actor.get("subject") if isinstance(actor, dict) else actor
        key = f"{self.policy.id}/{rule.id}/{subject}"
        now_us = ctx.view.now.us
        try:
            counted = live and rule.mode != "monitor"
            fn = self._limiter.check if counted else self._limiter.peek
            return bool(fn(key, spec["limit"], spec["window_seconds"], now_us=now_us))
        except Exception as exc:
            raise EvalError(type(exc).__name__) from exc

    def _thresholds(self, rule: CRule, a: Any, ctx: Ctx, before_result: bool) -> Contribution | None:
        triggered = [t for t in a.thresholds if _trips(t.cond, t.cond_before, ctx, before_result=before_result)]
        if not triggered:
            return None
        rank = {"deny": 0, "ask": 2, "watch": 3}
        best = min(triggered, key=lambda t: (rank[t.outcome], t.index))
        code = best.reason or "THRESHOLD_EXCEEDED"
        obligations: list[Obligation] = []
        if best.outcome == "ask":
            params: dict[str, Any] = {"approval": dict(a.approval or {})}
            if best.expr is not None:
                params["expr"] = best.expr
            else:
                if best.path_text is not None:
                    params["path"] = best.path_text
                if best.path is not None:
                    params["value"] = to_wire(best.path.fn(ctx).v)
                if best.value is not None:
                    params["threshold"] = to_wire(best.value.fn(ctx).v)
            obligations.append({"type": "human_approval", "params": params})
        return Contribution(
            rule.id, best.outcome, [_reason(code, f"rule:{rule.id}")], obligations, step=12, tindex=best.index
        )

    def _resolve(
        self, env: Action, ctx: Ctx, contributions: list[Contribution], matched: list[str], result: bool = False
    ) -> Verdict:
        p = self.policy
        suppressed: list[Outcome] = []
        shadow: list[tuple[str, str]] = []  # (rule id, outcome) for the would-block report
        for c in contributions:  # monitor downgrade, before ranking
            if c.monitor and not (c.hard and c.step == 1):
                if c.outcome in BLOCKING:
                    suppressed.append(c.outcome)
                    if c.rule_id is not None:
                        shadow.append((c.rule_id, c.outcome))
                    c.outcome = "watch"
                elif c.outcome == "modify":
                    c.outcome, c.edits, c.replace = "watch", None, None
        no_match = not contributions
        if no_match:
            outcome: Outcome = "allow" if result else p.default
            code = "POLICY_SATISFIED" if result else "NO_MATCHING_RULE"
            contributions = [Contribution(None, outcome, [_reason(code, "core")], hard=False)]
            if p.mode == "monitor" and outcome == "deny":
                suppressed.append("deny")
                contributions[0].outcome = "watch"
        ordered = sorted(contributions, key=lambda c: (-RANK[c.outcome], c.rule_id or "", c.step, c.tindex))
        final = ordered[0].outcome
        reasons: list[Reason] = []
        seen: set[tuple[str, str]] = set()
        for c in ordered:
            for r in c.reasons:
                key = (r["code"], r["source"])
                if key not in seen:
                    seen.add(key)
                    reasons.append(r.copy())
        edits, replace, overlap = self._modifications(ordered)
        empty = final == "modify" and not edits and replace is None  # nothing to apply: refuse rather than pretend
        if overlap or empty:
            final = "deny"
            cause = "modification_overlap" if overlap else "modification_empty"
            reasons = [{"code": "EVALUATION_ERROR", "source": "core", "message": cause}, *reasons]
            edits, replace = None, None
        would_block = final == "watch" and bool(suppressed)
        would_have: Outcome | None = None
        if would_block:
            strongest: Outcome = max(suppressed, key=RANK.__getitem__)
            would_have = strongest
        if would_block:
            reasons = [{"code": "MONITOR_WOULD_BLOCK", "source": "core"}, *reasons]
        obligations = self._obligations(ordered, final)
        for r in reasons:
            r.setdefault("message", self._texts.get(r["code"], r["code"]))
        explanation, hint = self._explain(ctx, ordered, final, reasons, obligations)
        mods: Modifications | None = None
        if final == "modify":
            mods = {"replace": replace} if replace is not None else ({"edits": edits} if edits else None)
        if shadow and self._on_suppressed is not None:
            with contextlib.suppress(Exception):  # a report failure never changes a decision
                self._on_suppressed(env, shadow)
        return Verdict(
            verdict_id=self._ids.new_id("ver"),
            action_id=env.id,
            outcome=final,
            would_block=would_block,
            matched_rules=sorted(matched),
            reasons=reasons,
            reason_codes=[r["code"] for r in reasons],
            explanation=explanation,
            hint=copy.deepcopy(hint),  # a verdict owns its data; editing it never reaches the compiled policy
            obligations=copy.deepcopy(obligations),
            modifications=copy.deepcopy(mods),
            risk_tier=self._risk_tier(ctx),
            policy={"id": p.id, "version": p.version, "fingerprint": p.fingerprint},
            input_digest=_safe_digest(env),
            **({"would_have_been": would_have} if would_have else {}),
        )

    @staticmethod
    def _modifications(ordered: list[Contribution]) -> tuple[list[Edit] | None, dict[str, JsonValue] | None, bool]:
        mods = [c for c in ordered if c.outcome == "modify"]
        if not mods:
            return None, None, False
        edits: list[Edit] = []
        for c in mods:
            if c.rule and c.rule.modify and "apply_suggested" in c.rule.modify:
                edits.extend(cast("Edit", dict(s.suggested_modification)) for s in c.hits if s.suggested_modification)
            edits += c.edits or []
        unique: dict[str, Edit] = {_canon(e): e for e in edits}
        items = sorted(unique.values(), key=lambda e: (str(e.get("json_pointer", "")), _canon(e)))
        replaces = {_canon(c.replace): c.replace for c in mods if c.replace is not None}
        if replaces:  # a wholesale replacement overlaps every other edit; identical ones merge
            if len(replaces) == 1 and not items:
                return None, next(iter(replaces.values())), False
            return None, None, True
        for i, a in enumerate(items):
            for b in items[i + 1 :]:
                if pointer_overlap(str(a.get("json_pointer", "")), str(b.get("json_pointer", ""))):
                    return None, None, True
        return items, None, False

    @staticmethod
    def _obligations(ordered: list[Contribution], final: Outcome) -> list[Obligation]:
        out: dict[str, Obligation] = {}
        for c in ordered:
            for o in c.obligations:
                if o["type"] == "human_approval" and final != "ask":
                    continue
                out.setdefault(_canon(o), o)
        return list(out.values())

    def _explain(
        self,
        ctx: Ctx,
        ordered: list[Contribution],
        final: Outcome,
        reasons: list[Reason],
        obligations: list[Obligation],
    ) -> tuple[str | None, dict[str, JsonValue] | None]:
        first_code = reasons[0]["code"] if reasons else None
        text: str | None = None
        agent: str | None = None
        for c in ordered:
            if c.rule is not None and c.rule.explain is not None and RANK[c.outcome] == RANK[final]:
                ctx.vars, ctx.signal_hits = c.vars, c.hits
                text = c.rule.explain.render(ctx, agent=False)
                agent = c.rule.explain.render(ctx, agent=True)
                break
        if text is None and final != "allow":
            text = (reasons[0].get("message") if reasons else None) or self._texts.get(first_code or "", "Refused.")
        if final == "allow" and text is None:
            text = None
        hint: dict[str, JsonValue] | None = None
        if final != "allow" and final != "watch" and first_code is not None:
            steps: list[JsonValue] = []
            if final == "ask":
                steps.append({"kind": "request_approval"})
            rule_hint = next(
                (c.rule.hint for c in ordered if c.rule is not None and c.rule.hint and RANK[c.outcome] == RANK[final]),
                None,
            )
            hint = {"code": first_code, "next_steps": steps}
            if isinstance(rule_hint, dict):
                hint.update({k: v for k, v in rule_hint.items() if k in ("code", "next_steps")})
            hint["message"] = (agent or self._texts.get(first_code, "Refused."))[:512]
        return text, hint

    def _risk_tier(self, ctx: Ctx) -> str | None:
        ctx.vars, ctx.signal_hits = {}, []
        for tier_id, cond in self.policy.risk_tiers:
            if cond.fn(ctx).v is True:
                return tier_id
        return self.policy.default_risk_tier or "standard"

    def _error_verdict(self, env: Action, cause: str) -> Verdict:
        p = self.policy
        flag = self._posture == "allow_and_flag"
        outcome: Outcome = "watch" if flag else "deny"
        return Verdict(
            verdict_id=self._ids.new_id("ver"),
            action_id=env.id,
            outcome=outcome,
            reasons=[{"code": "EVALUATION_ERROR", "source": "core", "message": cause}],
            reason_codes=["EVALUATION_ERROR"],
            explanation=self._texts["EVALUATION_ERROR"],
            policy={"id": p.id, "version": p.version, "fingerprint": p.fingerprint},
            input_digest=_safe_digest(env),
        )


def _cause(exc: Exception) -> str:
    return str(exc) if isinstance(exc, EvalError) else type(exc).__name__


def _safe_digest(env: Action) -> str:
    """The action's digest; for data with no canonical JSON form (decimals, sets) a digest of its tagged content, so a
    refusal record still tells different inputs apart."""
    try:
        return env.digest()
    except Exception:
        return _content_digest(env)


def _content_digest(env: Action) -> str:
    try:
        return digest_sha256(json.dumps(_tagged_content(env.data), sort_keys=True, separators=(",", ":")).encode())
    except Exception:  # nesting too deep to walk
        return digest_sha256(b"cpl:input-has-no-canonical-form")


def _tagged_content(x: Any) -> Any:
    if isinstance(x, dict):
        return {"map": sorted([repr(k), _tagged_content(v)] for k, v in x.items())}
    if isinstance(x, list | tuple):
        return {"seq": [_tagged_content(v) for v in x]}
    if isinstance(x, set | frozenset):
        return {"set": sorted((_tagged_content(v) for v in x), key=lambda c: json.dumps(c, sort_keys=True))}
    return {type(x).__name__: repr(x)}


def _tri(v: V) -> str:
    return "absent" if v.v is ABSENT else str(v.v is True).lower()
