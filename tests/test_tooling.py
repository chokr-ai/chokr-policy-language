"""The tools a language needs to be usable on its own: examples, `cplang eval`, `cplang schema`, `python -m cplang`."""

from __future__ import annotations

import json
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cplang.cli import app
from cplang.data import SCHEMAS, schema_path
from cplang.errors import AuthoringError
from cplang.fixtures import load_action, load_signals

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "access"
FIXTURES = EXAMPLE / "access.fixtures.yaml"


def write(tmp: Path, name: str, text: str) -> Path:
    path = tmp / name
    path.write_text(text, "utf-8", newline="\n")
    return path


def test_the_example_fixtures_pass() -> None:
    result = runner.invoke(app, ["test", "--policy", str(EXAMPLE), "--fixtures", str(FIXTURES)])
    assert result.exit_code == 0, result.output


def test_the_agent_example_passes_its_fixtures_and_checks_clean() -> None:
    agent = ROOT / "examples" / "agent_tool_call"
    tested = runner.invoke(app, ["test", "--policy", str(agent), "--fixtures", str(agent / "agent.fixtures.yaml")])
    assert tested.exit_code == 0, tested.output
    assert runner.invoke(app, ["policy", "check", str(agent)]).exit_code == 0


def test_the_example_validates_and_is_proved_bounded() -> None:
    assert runner.invoke(app, ["policy", "validate", str(EXAMPLE), "--json"]).exit_code == 0
    assert runner.invoke(app, ["policy", "types", str(EXAMPLE)]).exit_code == 0


def test_eval_decides_one_action(tmp_path: Path) -> None:
    action = write(tmp_path, "a.json", '{"kind": "read", "resource": {"type": "public"}}')
    result = runner.invoke(
        app, ["eval", "--policy", str(EXAMPLE), "--action", str(action), "--now", "2026-01-05T10:00:00Z", "--json"]
    )
    verdict = json.loads(result.output)
    assert result.exit_code == 0 and verdict["outcome"] == "allow" and verdict["matched_rules"] == ["read-public"]


def test_eval_exit_codes_and_signals(tmp_path: Path) -> None:
    action = write(tmp_path, "a.yaml", 'kind: read\nresource: {type: public}\ntimestamp: "2026-01-05T10:00:00Z"\n')
    signals = write(tmp_path, "s.yaml", "- {code: scan.malware, severity: high}\n")
    denied = runner.invoke(app, ["eval", "--policy", str(EXAMPLE), "--action", str(action), "--signals", str(signals)])
    assert denied.exit_code == 1 and denied.output.startswith("deny")
    asked = write(
        tmp_path,
        "w.yaml",
        'kind: write\nactor: {type: staff}\narguments: {size_kb: 900}\ntimestamp: "2026-01-05T10:00:00Z"\n',
    )
    assert runner.invoke(app, ["eval", "--policy", str(EXAMPLE), "--action", str(asked)]).exit_code == 1
    bound = runner.invoke(
        app, ["eval", "--policy", str(EXAMPLE), "--action", str(asked), "--param", "max_upload_kb=1000"]
    )
    assert bound.exit_code == 0 and bound.output.startswith("allow")


def test_eval_rejects_bad_input(tmp_path: Path) -> None:
    no_time = write(tmp_path, "a.yaml", "kind: read\n")
    assert runner.invoke(app, ["eval", "--policy", str(EXAMPLE), "--action", str(no_time)]).exit_code == 2
    missing = tmp_path / "missing.yaml"
    assert runner.invoke(app, ["eval", "--policy", str(EXAMPLE), "--action", str(missing), "--json"]).exit_code == 2


def test_loaders_report_malformed_documents(tmp_path: Path) -> None:
    with pytest.raises(AuthoringError):
        load_action(write(tmp_path, "a.yaml", "- 1\n"))
    with pytest.raises(AuthoringError):
        load_signals(write(tmp_path, "s.yaml", "code: x\n"))
    with pytest.raises(AuthoringError):
        load_signals(write(tmp_path, "s2.yaml", "- {nope: 1}\n"))
    action = load_action(write(tmp_path, "b.yaml", "kind: read\nscore: 1.5\n"), now="2026-01-01T00:00:00Z")
    assert action.timestamp == "2026-01-01T00:00:00Z"


def test_schema_command() -> None:
    listing = runner.invoke(app, ["schema"])
    assert listing.output.split() == list(SCHEMAS)
    for name in SCHEMAS:
        shown = runner.invoke(app, ["schema", name])
        assert shown.exit_code == 0 and json.loads(shown.output)["$id"].startswith("cpl.")
        assert schema_path(name).is_file()
    assert runner.invoke(app, ["schema", "nope"]).exit_code == 2
    with pytest.raises(KeyError):
        schema_path("nope")


def test_python_dash_m_cpl() -> None:
    result = subprocess.run([sys.executable, "-m", "cplang", "--version"], capture_output=True, text=True, check=False)
    assert result.returncode == 0 and result.stdout.startswith("cplang ")


class TestSchemas:
    def test_imports_with_every_option_are_valid(self) -> None:
        import json

        import jsonschema

        from cplang.data import schema_path

        schema = json.loads(schema_path("policy").read_text("utf-8"))
        doc = {
            "cpl": "1.0",
            "id": "p",
            "imports": [
                {"from": "a.decl.yaml", "only": ["x"], "rename": {"x": "y"}, "with": {"n": 1}, "digest": "sha256:0"}
            ],
        }
        jsonschema.validate(doc, schema)

    def test_fixture_signal_providers_are_a_list(self) -> None:
        import json

        import jsonschema

        from cplang.data import schema_path

        schema = json.loads(schema_path("fixtures").read_text("utf-8"))
        doc = {
            "schema": "cpl.fixtures/1.0",
            "cases": [{"name": "n", "signals_from": ["scanner"], "expect": {"outcome": "allow"}}],
        }
        jsonschema.validate(doc, schema)


class TestFixtureNumbers:
    """Fixture numbers keep every digit they were written with."""

    def test_fixture_numbers_keep_every_digit(self) -> None:
        from cplang.fixtures import _plain

        assert _plain(Decimal("1.5")) == 1.5
        assert _plain(Decimal("100.00000000000000001")) == Decimal("100.00000000000000001")


def test_fixture_files_are_validated_and_errors_never_pass_silently(tmp_path: Path) -> None:
    from cplang.fixtures import load_suite

    head = "schema: cpl.fixtures/1.0\n"
    case = "cases:\n  - {name: c, action: {kind: read}, expect: {outcome: deny}}\n"
    for name, text in {
        "bad_now": head + 'now: "not-a-time"\n' + case,
        "no_cases": head + "cases: []\n",
        "missing_policy": head + "policy: nope.policy.yaml\n" + case,
    }.items():
        with pytest.raises(AuthoringError):
            load_suite(write(tmp_path, f"{name}.fixtures.yaml", text))
    policy = write(tmp_path, "p.policy.yaml", 'cpl: "1.0"\nid: p\nversion: 1\ndefault: deny\nrules: []\n')
    erroring = write(  # the action has no valid time, so the deny is an evaluation error, not the policy's default
        tmp_path, "err.fixtures.yaml", head + case.replace("kind: read}", 'kind: read, timestamp: "noon"}')
    )
    result = runner.invoke(app, ["test", "--policy", str(policy), "--fixtures", str(erroring)])
    assert result.exit_code == 1 and "evaluation error" in result.output
    explicit = write(
        tmp_path, "explicit.fixtures.yaml", (head + case).replace("deny}", "deny, reason_codes: [EVALUATION_ERROR]}")
    )
    explicit.write_text(explicit.read_text("utf-8").replace("kind: read}", 'kind: read, timestamp: "noon"}'), "utf-8")
    assert runner.invoke(app, ["test", "--policy", str(policy), "--fixtures", str(explicit)]).exit_code == 0
