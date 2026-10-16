"""The repository's data: conformance vectors, schemas, the registry export, and the independence rule."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from tests.conftest import Project, make_env, make_signal

from cplang import Signal
from cplang.conformance import COMPUTE, run

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance"
SCHEMAS = ROOT / "schemas"
pytestmark = pytest.mark.skipif(not VECTORS.is_dir(), reason="the repository checkout is not available")


def _vector_files() -> list[Path]:
    return sorted(VECTORS.rglob("*.json"))


def test_every_vector_passes() -> None:
    report = run(VECTORS)
    failures = [f"{r.id}: {r.detail}" for r in report.results if r.status != "pass"]
    assert not failures, failures
    assert report.passed >= 90


@pytest.mark.parametrize("path", _vector_files(), ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_vector_shape(path: Path) -> None:
    vector = json.loads(path.read_text("utf-8"))
    assert set(vector) == {"id", "level", "input", "expected"}
    assert vector["id"] == f"{path.parent.name}/{path.stem}"
    assert vector["level"] == "core"
    assert path.parent.name in COMPUTE
    assert path.read_text("utf-8") == json.dumps(vector, indent=2, sort_keys=True) + "\n"


def test_the_vectors_use_the_standard_names_only() -> None:
    forbidden = re.compile(r"chokr|schema_version|\"envelope\"|\"guard\"", re.IGNORECASE)
    assert [p.name for p in _vector_files() if forbidden.search(p.read_text("utf-8"))] == []


def test_the_runner_fails_an_empty_directory(tmp_path: Path) -> None:
    assert not run(tmp_path).ok
    (tmp_path / "decision").mkdir()
    assert not run(tmp_path).ok


def test_the_runner_detects_a_wrong_expectation(tmp_path: Path) -> None:
    source = json.loads((VECTORS / "decision" / "default_deny.json").read_text("utf-8"))
    source["expected"]["outcome"] = "allow"
    (tmp_path / "decision").mkdir()
    (tmp_path / "decision" / "default_deny.json").write_text(json.dumps(source), "utf-8")
    assert run(tmp_path).failed == 1


def _validator(name: str) -> Draft202012Validator:
    document = json.loads((SCHEMAS / f"{name}.schema.json").read_text("utf-8"))
    Draft202012Validator.check_schema(document)
    return Draft202012Validator(document, format_checker=Draft202012Validator.FORMAT_CHECKER)


def test_the_wire_shapes_match_the_schemas(project: Project) -> None:
    action = make_env({"n": 1})
    assert _validator("action").is_valid(action.to_wire())
    assert not _validator("action").is_valid({"kind": "x"})
    signal: Signal = make_signal(action, "scan.thing")
    assert _validator("signal").is_valid(signal.to_wire())
    policy_text = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\nrules:\n  - {id: r, outcome: allow}\n'
    verdict = project.evaluator(policy_text).evaluate(action, [signal])
    assert _validator("verdict").is_valid(verdict.to_wire()), verdict.to_wire()


def test_the_fixture_schema_accepts_the_documented_shape() -> None:
    doc: dict[str, Any] = {
        "schema": "cpl.fixtures/1.0",
        "cases": [{"name": "a", "action": {}, "expect": {"outcome": "allow"}}],
    }
    assert _validator("fixtures").is_valid(doc)
    assert not _validator("fixtures").is_valid({"schema": "cpl.fixtures/1.0", "cases": []})


def test_the_registry_export_is_current() -> None:
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "export_registry.py"), "--check"], check=False)  # noqa: S603 - fixed arguments
    assert result.returncode == 0


def test_no_product_name_in_the_language_code() -> None:
    """The package refers to no host product by name."""
    pattern = re.compile(r"chokr[._]|CHK-", re.IGNORECASE)
    hits = [
        f"{p.name}:{i}"
        for p in (ROOT / "src" / "cplang").glob("*.py")
        for i, line in enumerate(p.read_text("utf-8").splitlines(), 1)
        if pattern.search(line)
    ]
    assert hits == []


def test_the_signal_helper_is_importable() -> None:
    assert make_signal and make_env


def test_every_accepted_rule_form_matches_the_policy_schema() -> None:
    from tests.test_authoring import VALID_RULES, doc

    from cplang.source import parse_source

    validator = _validator("policy")
    for rule in VALID_RULES:
        document = parse_source(doc(rule).encode(), "<doc>").data
        assert validator.is_valid(document), rule
    assert not validator.is_valid({"cpl": "2.0"})
    assert not validator.is_valid(parse_source(doc("{id: r, outcome: nope}").encode(), "<doc>").data)
    assert not validator.is_valid(parse_source(doc("{id: r, outcome: allow, bogus: 1}").encode(), "<doc>").data)
