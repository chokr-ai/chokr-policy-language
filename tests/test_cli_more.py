"""The command line: error paths, JSON output and the rarely used commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import BARE_HEAD
from typer.testing import CliRunner

from cplang import AuthoringError, FunctionRegistry
from cplang.canonical import canonicalize
from cplang.cli import app, main
from cplang.errors import CanonicalizationError

runner = CliRunner()
POLICY = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\nrules:\n  - {id: r, outcome: allow, match: {action_uri: ["app:read"]}}\n'
FIXTURES = (
    'schema: cpl.fixtures/1.0\ncases:\n  - name: reads\n    action: {action_uri: "app:read", timestamp: "2026-01-01T00:00:00Z"}\n'
    "    expect: {outcome: allow}\n"
)
DECL = "schema: cpl.declarations/1.0\nparameters:\n  cap: {type: integer, default: 1}\nconstants:\n  k: {type: integer, value: 2}\n"


def write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, "utf-8", newline="\n")
    return p


def test_fingerprint_types_and_directories(tmp_path: Path) -> None:
    write(tmp_path, "a.policy.yaml", POLICY)
    write(tmp_path, "d.decl.yaml", DECL)
    out = runner.invoke(app, ["policy", "fingerprint", str(tmp_path), "--json"])
    assert out.exit_code == 0 and json.loads(out.output)["fingerprint"].startswith("sha256:")
    assert runner.invoke(app, ["policy", "fingerprint", str(tmp_path)]).output.startswith("sha256:")
    assert runner.invoke(app, ["policy", "types", str(tmp_path)]).exit_code == 0
    assert json.loads(runner.invoke(app, ["policy", "types", str(tmp_path), "--json"]).output) == []


def test_failures_exit_one(tmp_path: Path) -> None:
    bad = write(tmp_path, "bad.policy.yaml", POLICY.replace("allow", "nope"))
    for args in (
        ["policy", "fingerprint", str(bad)],
        ["policy", "types", str(bad)],
        ["policy", "fingerprint", str(bad), "--json"],
    ):
        assert runner.invoke(app, args).exit_code == 1


def test_param_binding_errors() -> None:
    assert runner.invoke(app, ["policy", "validate", ".", "--param", "novalue"]).exit_code == 2


def test_fmt_json_and_missing_file(tmp_path: Path) -> None:
    messy = write(tmp_path, "m.policy.yaml", 'rules: []\nid: p\nversion: 1\ncpl: "1.0"\ndefault: deny\n')
    r = runner.invoke(app, ["policy", "fmt", str(messy), "--check", "--json"])
    assert r.exit_code == 1 and json.loads(r.output)["changed"] == [str(messy)]
    assert runner.invoke(app, ["policy", "fmt", str(tmp_path / "missing.yaml")]).exit_code == 2
    decl = write(tmp_path, "x.decl.yaml", "parameters: {}\nschema: cpl.declarations/1.0\n")
    assert runner.invoke(app, ["decl", "fmt", str(decl)]).exit_code == 0
    assert runner.invoke(app, ["decl", "fmt", str(tmp_path), "--check"]).exit_code in (0, 1)


def test_explain_errors_and_case_selection(tmp_path: Path) -> None:
    p = write(tmp_path, "p.policy.yaml", POLICY)
    f = write(tmp_path, "p.fixtures.yaml", FIXTURES)
    assert (
        runner.invoke(app, ["policy", "explain", "--policy", str(p), "--fixtures", str(f), "--case", "reads"]).exit_code
        == 0
    )
    assert (
        runner.invoke(app, ["policy", "explain", "--policy", str(p), "--fixtures", str(f), "--case", "nope"]).exit_code
        == 1
    )


def test_decl_commands(tmp_path: Path) -> None:
    d = write(tmp_path, "d.decl.yaml", DECL)
    p = write(tmp_path, "p.policy.yaml", POLICY)
    assert json.loads(runner.invoke(app, ["decl", "check", str(d), "--json"]).output)["result"] == "OK"
    assert runner.invoke(app, ["decl", "check", str(d), "--policy", str(p), "--set", "cap=3"]).exit_code == 0
    assert runner.invoke(app, ["decl", "check", str(d), "--set", "cap=x"]).exit_code == 1
    shown = runner.invoke(app, ["decl", "show", str(d)])
    assert shown.exit_code == 0 and "cap" in shown.output
    assert json.loads(runner.invoke(app, ["decl", "show", str(d), "--json"]).output)
    assert runner.invoke(app, ["decl", "show", str(tmp_path / "none.decl.yaml")]).exit_code == 1
    lock = tmp_path / "x.lock"
    assert (
        json.loads(runner.invoke(app, ["decl", "lock", str(d), "--out", str(lock), "--json"]).output)["result"] == "OK"
    )
    assert runner.invoke(app, ["decl", "lock", str(tmp_path / "none.decl.yaml")]).exit_code == 1


def test_expr_eval_variants(tmp_path: Path) -> None:
    f = write(tmp_path, "p.fixtures.yaml", FIXTURES.replace("action_uri:", "arguments: {n: 4}, action_uri:"))
    r = runner.invoke(app, ["expr", "eval", "arguments.n + 1", "--fixtures", str(f)])
    assert r.exit_code == 0 and "5" in r.output
    d = write(tmp_path, "d.decl.yaml", DECL)
    assert json.loads(runner.invoke(app, ["expr", "eval", "const.k", "--decl", str(d), "--json"]).output)["value"] == 2
    assert runner.invoke(app, ["expr", "eval", "arguments.n / 0", "--json"]).exit_code in (0, 1)
    assert runner.invoke(app, ["expr", "eval", "1 +", "--decl", str(d)]).exit_code == 1


def test_test_command_requires_inputs(tmp_path: Path) -> None:
    p = write(tmp_path, "p.policy.yaml", POLICY)
    f = write(tmp_path, "p.fixtures.yaml", FIXTURES)
    assert runner.invoke(app, ["test", "--fixtures", str(f)]).exit_code == 2  # names no `policy:` either
    assert runner.invoke(app, ["test", "--policy", str(p)]).exit_code == 2
    named = write(tmp_path, "named.fixtures.yaml", FIXTURES.replace("cases:", "policy: p.policy.yaml\ncases:", 1))
    assert json.loads(runner.invoke(app, ["test", "--fixtures", str(named), "--json"]).output)["passed"] == 1
    r = runner.invoke(app, ["test", "--policy", str(p), "--fixtures", str(f), "--json"])
    assert json.loads(r.output)["passed"] == 1
    assert (
        runner.invoke(app, ["test", "--policy", str(p), "--fixtures", str(tmp_path / "none.fixtures.yaml")]).exit_code
        == 2
    )


def test_conformance_command(tmp_path: Path) -> None:
    assert runner.invoke(app, ["conformance", str(tmp_path / "missing")]).exit_code == 2
    assert runner.invoke(app, ["conformance", str(tmp_path)]).exit_code == 1
    vectors = Path(__file__).resolve().parents[1] / "conformance"
    report = tmp_path / "report.json"
    r = runner.invoke(app, ["conformance", str(vectors), "--report", str(report), "--json"])
    assert r.exit_code == 0 and json.loads(report.read_text("utf-8"))["failed"] == 0


def test_prove_without_arguments_and_emit(tmp_path: Path) -> None:
    pytest.importorskip("z3")
    p = write(tmp_path, "p.policy.yaml", POLICY)
    assert runner.invoke(app, ["policy", "prove", "--no-bypass", str(p)]).exit_code == 3
    assert (
        runner.invoke(
            app, ["policy", "prove", "--candidate", str(tmp_path / "none.yaml"), "--boundary", str(p)]
        ).exit_code
        == 2
    )


def test_main_maps_unexpected_errors_to_exit_three(monkeypatch: pytest.MonkeyPatch) -> None:
    import cplang.cli as cli

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("secret detail")

    monkeypatch.setattr(cli, "app", boom)
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 3


def test_functions_registry() -> None:
    reg = FunctionRegistry()
    reg.register("acme/double", lambda _a, x: x * 2, version="2")
    assert reg.has("acme/double") and reg.resolve("acme/double")(None, 2) == 4
    assert reg.versions({"acme/double", "acme/none"}) == [{"name": "acme/double", "version": "2"}]
    for name in ("bad", "Acme/x"):
        with pytest.raises(Exception):
            reg.register(name, len)
    with pytest.raises(AuthoringError):
        reg.register("acme/double", len)
    with pytest.raises(AuthoringError):
        reg.resolve("acme/none")


def test_canonicalization_limits() -> None:
    assert canonicalize({"b": 1, "a": [1, 2.5, "x", None, True]}) == b'{"a":[1,2.5,"x",null,true],"b":1}'
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "non-string key"})
    with pytest.raises(CanonicalizationError):
        canonicalize(object())
    deep: object = []
    for _ in range(200):
        deep = [deep]
    with pytest.raises(CanonicalizationError):
        canonicalize(deep)


class TestCommandLine:
    def test_formatting_a_directory_leaves_declaration_files_alone(self, tmp_path: Any) -> None:
        from typer.testing import CliRunner

        from cplang.cli import app

        (tmp_path / "p.policy.yaml").write_text('cpl: "1.0"\nid: p\nversion: 1\nrules: []\n', "utf-8")
        (tmp_path / "x.decl.yaml").write_text("types: {}\nschema: cpl.declarations/1.0\n", "utf-8")
        result = CliRunner().invoke(app, ["policy", "fmt", str(tmp_path), "--check"])
        assert "x.decl.yaml" not in result.output

    def test_output_survives_a_terminal_that_cannot_show_the_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import io
        import sys

        from cplang.cli import _safe_streams

        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        monkeypatch.setattr(sys, "stdout", stream)
        _safe_streams()
        sys.stdout.write("caf\u00e9\n")
        stream.flush()

    def test_a_file_that_cannot_be_written_is_an_input_error(self, tmp_path: Any) -> None:
        from typer.testing import CliRunner

        from cplang.cli import app

        blocker = tmp_path / "file"
        blocker.write_text("x", "utf-8")
        result = CliRunner().invoke(app, ["conformance", "--report", str(blocker / "report.json")])
        assert result.exit_code == 2

    def test_no_bypass_can_be_asked_with_a_hard_signal(self, tmp_path: Any) -> None:
        pytest.importorskip("z3")
        from typer.testing import CliRunner

        from cplang.cli import app

        policy = tmp_path / "p.policy.yaml"
        policy.write_text(
            BARE_HEAD + "default: allow\nrules:\n  - {id: hard, outcome: deny, when: {signal: {code: scan.hard}}}\n",
            "utf-8",
        )
        result = CliRunner().invoke(app, ["policy", "prove", "--no-bypass", str(policy), "--hard-signal", "scan.hard"])
        assert result.exit_code == 0, result.output
