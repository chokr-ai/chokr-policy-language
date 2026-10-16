"""The `cplang` command: exit codes and machine-readable output."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cplang import __version__
from cplang.cli import app

runner = CliRunner()
POLICY = 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\nrules:\n  - {id: r, outcome: allow, match: {action_uri: ["app:read"]}}\n'
FIXTURES = (
    'schema: cpl.fixtures/1.0\ncases:\n  - name: reads\n    action: {action_uri: "app:read", kind: tool_call, '
    'timestamp: "2026-01-01T00:00:00Z"}\n    expect: {outcome: allow}\n'
    '  - name: writes\n    action: {action_uri: "app:write", kind: tool_call, timestamp: "2026-01-01T00:00:00Z"}\n'
    "    expect: {outcome: deny}\n"
)


def write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, "utf-8", newline="\n")
    return p


def test_version() -> None:
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and __version__ in r.output


def test_validate_and_pin(tmp_path: Path) -> None:
    p = write(tmp_path, "p.policy.yaml", POLICY)
    ok = runner.invoke(app, ["policy", "validate", str(p), "--json"])
    body = json.loads(ok.output)
    assert ok.exit_code == 0 and body["result"] == "OK" and body["fingerprint"].startswith("sha256:")
    assert runner.invoke(app, ["policy", "validate", str(p), "--pin", body["fingerprint"]]).exit_code == 0
    assert runner.invoke(app, ["policy", "validate", str(p), "--pin", "sha256:0"]).exit_code == 2


def test_validate_reports_errors_with_exit_one(tmp_path: Path) -> None:
    bad = write(tmp_path, "bad.policy.yaml", POLICY.replace("allow", "nope"))
    r = runner.invoke(app, ["policy", "validate", str(bad), "--json"])
    assert r.exit_code == 1 and json.loads(r.output)["errors"][0]["code"] == "SCHEMA_INVALID"


def test_fmt_check_and_rewrite(tmp_path: Path) -> None:
    messy = write(
        tmp_path, "m.policy.yaml", 'rules:\n  - {outcome: allow, id: r}\nid: p\nversion: 1\ncpl: "1.0"\ndefault: deny\n'
    )
    assert runner.invoke(app, ["policy", "fmt", str(messy), "--check"]).exit_code == 1
    assert runner.invoke(app, ["policy", "fmt", str(messy)]).exit_code == 0
    assert runner.invoke(app, ["policy", "fmt", str(messy), "--check"]).exit_code == 0


def test_test_command_runs_fixtures(tmp_path: Path) -> None:
    p = write(tmp_path, "p.policy.yaml", POLICY)
    f = write(tmp_path, "p.fixtures.yaml", FIXTURES)
    r = runner.invoke(app, ["test", "--policy", str(p), "--fixtures", str(f)])
    assert r.exit_code == 0 and "2 passed, 0 failed" in r.output
    wrong = write(tmp_path, "w.fixtures.yaml", FIXTURES.replace("outcome: deny", "outcome: allow"))
    assert runner.invoke(app, ["test", "--policy", str(p), "--fixtures", str(wrong)]).exit_code == 1


def test_explain_traces_every_rule(tmp_path: Path) -> None:
    p = write(tmp_path, "p.policy.yaml", POLICY)
    f = write(tmp_path, "p.fixtures.yaml", FIXTURES)
    r = runner.invoke(app, ["policy", "explain", "--policy", str(p), "--fixtures", str(f), "--json"])
    body = json.loads(r.output)
    assert r.exit_code == 0 and body["verdict"]["outcome"] == "allow" and body["trace"][0]["rule"] == "r"


def test_expr_eval() -> None:
    r = runner.invoke(app, ["expr", "eval", "1 + 2", "--json"])
    assert r.exit_code == 0 and json.loads(r.output)["value"] == 3
    assert runner.invoke(app, ["expr", "eval", "1 +", "--json"]).exit_code == 1


def test_decl_lock_and_check(tmp_path: Path) -> None:
    d = write(
        tmp_path, "d.decl.yaml", "schema: cpl.declarations/1.0\nparameters:\n  cap: {type: integer, default: 1}\n"
    )
    assert runner.invoke(app, ["decl", "check", str(d)]).exit_code == 0
    lock = tmp_path / "cpl.decl.lock"
    assert runner.invoke(app, ["decl", "lock", str(d), "--out", str(lock)]).exit_code == 0 and lock.exists()
