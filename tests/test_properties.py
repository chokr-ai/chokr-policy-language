"""Property tests of the evaluator: determinism, order independence, absent logic."""

from __future__ import annotations

import itertools
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from tests.conftest import IDS, make_env, make_signal

from cplang import RuleEvaluator, load_policy
from cplang.compile import Scope, compile_expression
from cplang.declarations import DeclarationSet
from cplang.runtime import Ctx, InputView
from cplang.values import ABSENT, EvalError

pytestmark = pytest.mark.property
SETTINGS = settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
_DIR = Path(tempfile.mkdtemp(prefix="cplang-prop-"))
OUTCOMES = ["allow", "watch", "modify", "ask", "deny"]
CODES = ["loop.a", "loop.b", "loop.c"]


def rule_text(index: int, outcome: str, action: str, code: str | None) -> str:
    when = f", when: {{signal: {{code: {code}}}}}" if code else ""
    ask = ", when: {approval: {timeout_seconds: 5}}" if outcome == "ask" and not code else ""
    if outcome == "ask" and code:
        when = f", when: {{signal: {{code: {code}}}, approval: {{timeout_seconds: 5}}}}"
    mod = f", modify: {{edits: [{{op: redact, json_pointer: /x{index}}}]}}" if outcome == "modify" else ""
    return f'  - {{id: r{index}, outcome: {outcome}, match: {{action_uri: ["{action}"]}}{when}{ask}{mod}}}\n'


def load_text(text: str, tag: str) -> RuleEvaluator:
    path = _DIR / f"{tag}.policy.yaml"
    path.write_text('cpl: "1.0"\nid: prop\nversion: 1\ndefault: deny\nrules:\n' + text, "utf-8", newline="\n")
    return RuleEvaluator(load_policy([path], roots=[_DIR]), ids=IDS)


def verdict_bytes(v: Any) -> str:
    wire = v.to_wire()
    for volatile in ("verdict_id", "latency_ms"):
        wire.pop(volatile, None)
    wire["policy"].pop("fingerprint", None)
    return repr(sorted(wire.items()))


rule_sets = st.lists(
    st.tuples(
        st.sampled_from(OUTCOMES), st.sampled_from(["app:a", "app:b"]), st.one_of(st.none(), st.sampled_from(CODES))
    ),
    min_size=1,
    max_size=5,
)


@SETTINGS
@given(spec=rule_sets, data=st.data())
def test_reordering_rules_never_changes_the_verdict(spec: list[tuple[str, str, str | None]], data: Any) -> None:
    """deny_overrides is independent of rule order and of Signal arrival order."""
    rules = [rule_text(i, *s) for i, s in enumerate(spec)]
    perm = data.draw(st.permutations(rules))
    env = make_env(action_uri=data.draw(st.sampled_from(["app:a", "app:b", "app:c"])))
    codes = data.draw(st.lists(st.sampled_from(CODES), max_size=3))
    signals = [make_signal(env, c, source=f"g{i}") for i, c in enumerate(codes)]
    shuffled = data.draw(st.permutations(signals))
    a = load_text("".join(rules), "a").evaluate(env, signals)
    b = load_text("".join(perm), "b").evaluate(env, list(shuffled))
    assert verdict_bytes(a) == verdict_bytes(b)


@SETTINGS
@given(spec=rule_sets, action=st.sampled_from(["app:a", "app:b", "app:c"]))
def test_the_verdict_is_deterministic_and_never_less_strict_than_any_matched_rule(
    spec: list[tuple[str, str, str | None]], action: str
) -> None:
    ev = load_text("".join(rule_text(i, *s) for i, s in enumerate(spec)), "d")
    env = make_env(action_uri=action)
    first, second = ev.evaluate(env, []), ev.evaluate(env, [])
    assert verdict_bytes(first) == verdict_bytes(second)
    rank = {"allow": 0, "watch": 1, "modify": 2, "ask": 3, "deny": 4}
    for outcome, act, code in spec:
        if act == action and code is None:  # rules that match with no signal condition
            assert rank[first.outcome] >= rank[outcome] or first.outcome == "deny"


TRI = st.sampled_from(["true", "false", "arguments.missing == 1"])


@SETTINGS
@given(a=TRI, b=TRI, c=TRI)
def test_three_valued_logic_tables(a: str, b: str, c: str) -> None:
    """Every combinator over {true, false, absent}, checked against the truth tables."""
    decls = DeclarationSet()
    env = make_env({})

    def value(src: str) -> Any:
        return compile_expression(src, Scope(decls)).fn(Ctx(InputView(env, [], decls), Scope(decls).limits)).v

    def tri(src: str) -> Any:
        return value(src)

    va, vb, vc = tri(a), tri(b), tri(c)
    assert value(f"({a}) && ({b})") is _and(va, vb)
    assert value(f"({a}) || ({b})") is _or(va, vb)
    assert value(f"!({a})") is (ABSENT if va is ABSENT else (not va))
    assert value(f"({a}) ? ({b}) : ({c})") is (ABSENT if va is ABSENT else (vb if va else vc))
    assert value(f"!({a})") is not True or va is False  # `!absent` is never true


def _and(x: Any, y: Any) -> Any:
    if x is False or y is False:
        return False
    return ABSENT if (x is ABSENT or y is ABSENT) else True


def _or(x: Any, y: Any) -> Any:
    if x is True or y is True:
        return True
    return ABSENT if (x is ABSENT or y is ABSENT) else False


@SETTINGS
@given(n=st.integers(-(2**40), 2**40), m=st.integers(-(2**40), 2**40))
def test_integer_arithmetic_matches_python_and_never_overflows_silently(n: int, m: int) -> None:
    decls = DeclarationSet()
    env = make_env({"n": n, "m": m})
    view = InputView(env, [], decls)

    def run(src: str) -> Any:
        c = compile_expression(src, Scope(decls))
        return c.fn(Ctx(view, Scope(decls).limits)).v

    def checked(src: str, expected: int) -> None:
        if -(2**63) <= expected <= 2**63 - 1:
            assert run(src) == expected
        else:
            with pytest.raises(EvalError, match="overflow"):
                run(src)

    checked("arguments.n + arguments.m", n + m)
    checked("arguments.n * arguments.m", n * m)
    checked("arguments.n - arguments.m", n - m)
    assert run("arguments.n < arguments.m") is (n < m)


@pytest.mark.parametrize("order", list(itertools.permutations(range(3))))
def test_admission_order_is_independent_of_yaml_key_order(order: tuple[int, ...]) -> None:
    keys = ["deny: {expr: 'arguments.n > 100'}", "immutable_params: {m: 1}", "bounded_params: {n: {max: 1}}"]
    when = ", ".join(keys[i] for i in order)
    ev = load_text(f"  - {{id: r, outcome: allow, when: {{{when}}}}}\n", f"o{''.join(map(str, order))}")
    assert ev.evaluate(make_env({"n": 5}), []).reason_codes == ["PARAM_IMMUTABLE_VIOLATION"]
