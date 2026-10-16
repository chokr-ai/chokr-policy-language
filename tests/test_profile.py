"""Host profiles: a program that embeds the language adds vocabulary, signal effects, input names and rule keys."""

from __future__ import annotations

from typing import Any

import pytest
from tests.conftest import Project, make_env, make_signal

from cplang import AuthoringError, RuleEvaluator
from cplang.profile import Failure, Profile, RuleKey, SignalEffect

HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: allow\n'


def _need_even(value: Any) -> int:
    if not isinstance(value, int) or value % 2:
        raise ValueError("must be an even integer")
    return value


def _check_even_args(_rule: str, value: Any, view: Any) -> Failure | None:
    n = view.wire.get("arguments", {}).get("n", 0)
    return None if n <= value else Failure("deny", "THRESHOLD_EXCEEDED")


def _effect(signal: Any) -> SignalEffect | None:
    if signal.code == "scan.secret":
        return SignalEffect("deny", "ACTION_FORBIDDEN", hard=True)
    return None


def _ev(project: Project, text: str) -> RuleEvaluator:
    return RuleEvaluator(project.policy(text, profile=PROFILE), profile=PROFILE)


PROFILE = Profile(
    signal_families=frozenset({"scan"}),
    signal_effect=_effect,
    hard_signal_codes=frozenset({"scan.secret"}),
    roots={"tenant": None},
    rule_keys={"max_n": RuleKey(_need_even, _check_even_args)},
)


def test_the_neutral_profile_rejects_host_keys_and_roots(project: Project) -> None:
    with pytest.raises(AuthoringError):
        project.policy(HEAD + "rules:\n  - {id: r, outcome: allow, when: {max_n: 4}}\n", strict_inputs=True)


def test_a_host_rule_key_is_parsed_and_checked(project: Project) -> None:
    ev = _ev(project, HEAD + "rules:\n  - {id: r, outcome: allow, when: {max_n: 4}}\n")
    assert ev.evaluate(make_env({"n": 2}), []).outcome == "allow"
    assert ev.evaluate(make_env({"n": 9}), []).outcome == "deny"


def test_a_host_rule_key_validates_its_value(project: Project) -> None:
    with pytest.raises(AuthoringError):
        project.policy(HEAD + "rules:\n  - {id: r, outcome: allow, when: {max_n: 3}}\n", profile=PROFILE)


def test_a_host_signal_effect_denies_without_any_rule(project: Project) -> None:
    ev = _ev(project, HEAD + "rules:\n  - {id: r, outcome: allow}\n")
    env = make_env()
    assert ev.evaluate(env, [make_signal(env, "scan.secret")]).outcome == "deny"
    assert ev.evaluate(env, [make_signal(env, "scan.other")]).outcome == "allow"


def test_a_host_root_is_readable_in_expressions(project: Project) -> None:
    text = HEAD + "rules:\n  - {id: r, outcome: deny, when: {expr: \"tenant == 'acme'\"}}\n"
    ev = _ev(project, text)
    assert ev.evaluate(make_env(tenant="acme"), []).outcome == "deny"
    assert ev.evaluate(make_env(tenant="other"), []).outcome == "allow"


def test_the_profile_is_part_of_the_evaluator_not_the_language(project: Project) -> None:
    policy = project.policy(HEAD + "rules:\n  - {id: r, outcome: allow}\n")
    assert RuleEvaluator(policy, profile=PROFILE).evaluate(make_env(), []).outcome == "allow"
