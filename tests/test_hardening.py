"""Hardening: rate limiter memory, vector file confinement, and the result path of the evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import Project, make_env

from cplang.conformance import default_vectors, run
from cplang.ratelimit import InMemoryRateLimiter

SECOND = 1_000_000


def test_rate_limiter_admits_up_to_the_limit_then_recovers() -> None:
    rl = InMemoryRateLimiter()
    assert rl.check("k", 2, 10, now_us=0) and rl.check("k", 2, 10, now_us=1)
    assert not rl.check("k", 2, 10, now_us=2) and not rl.peek("k", 2, 10, now_us=2)
    assert rl.peek("k", 2, 10, now_us=11 * SECOND) and rl.check("k", 2, 10, now_us=11 * SECOND)


def test_rate_limiter_forgets_idle_keys() -> None:
    rl = InMemoryRateLimiter()
    for i in range(1000):
        assert rl.check(f"key-{i}", 1, 1, now_us=0)
    assert rl.peek("probe", 1, 1, now_us=10 * SECOND)
    for i in range(1000):
        rl.peek(f"key-{i}", 1, 1, now_us=10 * SECOND)
    assert rl._calls == {}


def _vector(tmp_path: Path, files: dict[str, str]) -> Path:
    area = tmp_path / "declarations"
    area.mkdir()
    (area / "escape.json").write_text(
        json.dumps(
            {
                "id": "declarations/escape",
                "level": "core",
                "expected": {"ok": True},
                "input": {"files": files, "entries": ["a.decl.yaml"]},
            }
        ),
        "utf-8",
    )
    return tmp_path


@pytest.mark.parametrize("name", ["../escaped.txt", "sub/../../escaped.txt", "ABSOLUTE"])
def test_a_vector_cannot_write_outside_its_directory(tmp_path: Path, name: str) -> None:
    name = (tmp_path / "escaped.txt").as_posix() if name == "ABSOLUTE" else name
    vectors = tmp_path / "vectors"
    vectors.mkdir()
    report = run(_vector(vectors, {name: "x", "a.decl.yaml": "schema: cpl.declarations/1.0\n"}))
    assert report.failed == 1
    assert not (tmp_path / "escaped.txt").exists()


def test_the_default_vectors_are_the_checkout_vectors() -> None:
    assert default_vectors().is_dir() and run(default_vectors()).ok


def test_the_result_path_defaults_to_allow(project: Project) -> None:
    text = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\nrules:\n  - {id: r, outcome: deny, when: {signal: {code: scan.x}}}\n'
    ev = project.evaluator(text)
    assert ev.evaluate_result(make_env(), []).outcome == "allow"


HEAD = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\n'


def test_limits_are_configurable(project: Project) -> None:
    from cplang import AuthoringError, CplLimits, RuleEvaluator

    rules = "".join(f"  - {{id: r{i}, outcome: allow}}\n" for i in range(3))
    with pytest.raises(AuthoringError):
        project.policy(HEAD + "rules:\n" + rules, limits=CplLimits(max_rules=2))
    project.policy(HEAD + "rules:\n" + rules, limits=CplLimits(max_rules=3))

    rows = ", ".join("{outcome: watch, path: arguments.n, gt: 1}" for _ in range(3))
    text = HEAD + f"rules:\n  - {{id: r, outcome: allow, when: {{thresholds: [{rows}]}}}}\n"
    with pytest.raises(AuthoringError):
        project.policy(text, limits=CplLimits(max_threshold_entries=2))

    with pytest.raises(AuthoringError):
        project.policy(HEAD + "rules: []\n", limits=CplLimits(max_document_bytes=10))

    explained = HEAD + "rules:\n  - {id: r, outcome: deny, explain: 'a long explanation of the decision'}\n"
    verdict = RuleEvaluator(project.policy(explained, limits=CplLimits(max_explain_chars=6))).evaluate(make_env(), [])
    assert verdict.explanation == "a long"


def test_table_files_have_a_size_limit(project: Project) -> None:
    from cplang import AuthoringError, CplLimits

    project.write("t.csv", "key,value\n" + "a,1\n" * 100)
    decl = "schema: cpl.declarations/1.0\ntables:\n  t: {key: string, value: integer, source: ./t.csv}\n"
    with pytest.raises(AuthoringError) as e:
        project.policy(HEAD + "rules: []\n", decls=decl, limits=CplLimits(max_table_bytes=50))
    assert e.value.code == "TABLE_INVALID"
