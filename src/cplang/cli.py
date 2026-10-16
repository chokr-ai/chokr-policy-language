"""The `cplang` command: validate, format, explain, fingerprint, test, evaluate and prove policies and declarations.

Exit codes: 0 ok, 1 the check failed (invalid policy, failing fixture, exceeded boundary), 2 usage or input error,
3 internal error (the exception type only, never its message)."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

import typer

from cplang import __version__
from cplang.compile import Scope, compile_expression
from cplang.data import SCHEMAS, schema_path
from cplang.declarations import DeclarationSet, _Loader, load_declarations, write_lock
from cplang.errors import AuthoringError
from cplang.evaluator import RuleEvaluator
from cplang.fixtures import CaseResult, load_action, load_signals, load_suites, run_suite
from cplang.fmt import format_text
from cplang.lint import lint
from cplang.model import Action
from cplang.policy import CompiledPolicy, load_policy
from cplang.profile import Profile
from cplang.registry import PERMITTED
from cplang.runtime import CplLimits, Ctx, InputView
from cplang.source import parse_source
from cplang.values import V, render, to_wire, type_label

app = typer.Typer(no_args_is_help=True, add_completion=False, help="The CHOKR Policy Language command")
policy_app = typer.Typer(no_args_is_help=True, help="Validate, format, explain, fingerprint and prove policies")
decl_app = typer.Typer(no_args_is_help=True, help="Check, lock, show and format declaration files")
expr_app = typer.Typer(no_args_is_help=True, help="Evaluate policy expressions")
app.add_typer(policy_app, name="policy")
app.add_typer(decl_app, name="decl")
app.add_typer(expr_app, name="expr")

Paths = Annotated[list[Path], typer.Argument(help="Policy files or directories")]
JsonFlag = Annotated[bool, typer.Option("--json", help="Machine-readable output (one JSON document)")]
_ENCODING = (getattr(sys.stdout, "encoding", None) or "ascii").lower()
_MARKS = ("\u2713", "\u2717") if "utf" in _ENCODING else ("PASS", "FAIL")


def _out(payload: Any, *, as_json: bool, text: str, code: int = 0) -> None:
    typer.echo(json.dumps(payload, default=str, sort_keys=True) if as_json else text)
    raise typer.Exit(code)


def _error_payload(exc: AuthoringError) -> dict[str, Any]:
    return {"result": "FAILED", "errors": [exc.to_dict()], "warnings": []}


def _expand(paths: Sequence[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        files += (
            sorted(
                q
                for q in p.rglob("*")
                if q.suffix in (".yaml", ".yml", ".json")
                and q.is_file()
                and ".decl." not in q.name
                and ".fixtures." not in q.name
            )
            if p.is_dir()
            else [p]
        )
    return files


def _params(values: list[str] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in values or []:
        name, sep, raw = item.partition("=")
        if not sep or not name:
            raise typer.BadParameter(f"{item!r}: use name=value")
        out[name] = parse_source(f"v: {raw}\n".encode(), "<param>").data["v"]
    return out


def _load(
    paths: Sequence[Path],
    decl: Sequence[Path],
    roots: Sequence[Path],
    params: dict[str, Any],
    strict: bool,
    *,
    strict_inputs: bool = False,
    profile: Profile | None = None,
) -> CompiledPolicy:
    extra: dict[str, Any] = {} if profile is None else {"profile": profile}
    return load_policy(
        _expand(paths),
        decl_paths=list(decl),
        roots=list(roots) or None,
        config_params=[params],
        strict=strict,
        strict_inputs=strict_inputs,
        **extra,
    )


def _version(show: bool) -> None:
    if show:
        typer.echo(f"cplang {__version__}")
        raise typer.Exit(0)


def _safe_streams() -> None:
    """Never fail on text the terminal cannot show: unencodable characters are written as escapes."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _write(path: Path, text: str) -> None:
    """Write a file for the user; a path that cannot be written is an input error, not an internal one."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, "utf-8", newline="\n")
    except OSError as exc:
        typer.echo(f"{path}: cannot write the file ({type(exc).__name__})", err=True)
        raise typer.Exit(2) from exc


@app.callback()
def _main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Print the version")
    ] = False,
) -> None:
    _safe_streams()


@policy_app.command("validate")
def policy_validate(
    paths: Paths,
    decl: Annotated[list[Path] | None, typer.Option(help="Declaration file (repeatable)")] = None,
    root: Annotated[list[Path] | None, typer.Option(help="Import root (repeatable)")] = None,
    param: Annotated[list[str] | None, typer.Option(help="Parameter binding name=value (repeatable)")] = None,
    strict: Annotated[bool, typer.Option(help="Undeclared custom codes are errors")] = False,
    strict_inputs: Annotated[
        bool,
        typer.Option("--strict-inputs", help="Reject names that are neither standard nor declared under `inputs:`"),
    ] = False,
    pin: Annotated[str | None, typer.Option(help="Fail (exit 2) if the fingerprint differs")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Parse, type-check, compile and fingerprint a policy set. Exit 0 valid, 1 invalid, 2 pin mismatch."""
    try:
        policy = _load(paths, decl or [], root or [], _params(param), strict, strict_inputs=strict_inputs)
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    payload = {"result": "OK", "fingerprint": policy.fingerprint, "errors": [], "warnings": policy.warnings}
    if pin is not None and pin != policy.fingerprint:
        payload.update(result="FAILED", errors=[{"code": "FINGERPRINT_MISMATCH", "message": "fingerprint differs"}])
        _out(payload, as_json=as_json, text=f"FAILED: fingerprint {policy.fingerprint} != pinned {pin}", code=2)
    lines = [
        f"OK fingerprint={policy.fingerprint}",
        *(f"warning: {w['message']} ({w['file']}:{w['line']})" for w in policy.warnings),
    ]
    _out(payload, as_json=as_json, text="\n".join(lines))


@policy_app.command("fingerprint")
def policy_fingerprint(
    paths: Paths,
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    root: Annotated[list[Path] | None, typer.Option()] = None,
    param: Annotated[list[str] | None, typer.Option()] = None,
    as_json: JsonFlag = False,
) -> None:
    """Print the fingerprint of the compiled policy set."""
    try:
        value = _load(paths, decl or [], root or [], _params(param), False).fingerprint
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    _out({"result": "OK", "fingerprint": value}, as_json=as_json, text=value)


@policy_app.command("types")
def policy_types(
    paths: Paths,
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    root: Annotated[list[Path] | None, typer.Option()] = None,
    as_json: JsonFlag = False,
) -> None:
    """Inferred type of every `let` and `computed` value."""
    try:
        policy = _load(paths, decl or [], root or [], {}, False)
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    rows: list[dict[str, str]] = [
        {"name": f"{r.id}: var.{n}", "type": str(c.t or "unknown")} for r in policy.rules for n, c in r.lets
    ]
    rows += [
        {"name": f"computed.{n}", "type": str(policy.decls.computed(n).type)}  # type: ignore[union-attr]
        for n in sorted(policy.decls._computed)
    ]
    _out(rows, as_json=as_json, text="\n".join(f"{r['name']:<40} {r['type']}" for r in rows) or "no variables")


def _format_targets(directory: Path, kind: str) -> list[Path]:
    """The files of a directory that are written in the given kind: declarations and fixtures are not policies."""
    files = sorted(directory.rglob("*.y*ml"))
    if kind == "decl":
        return [f for f in files if ".decl." in f.name]
    return [f for f in files if ".decl." not in f.name and ".fixtures." not in f.name]


def _format(paths: Sequence[Path], kind: str, check: bool, as_json: bool) -> None:
    changed: list[str] = []
    for path in [q for p in paths for q in (_format_targets(p, kind) if p.is_dir() else [p])]:
        try:
            original = path.read_text("utf-8")
            formatted = format_text(original, kind)
        except (AuthoringError, OSError, UnicodeDecodeError) as exc:
            typer.echo(f"{path}: {exc}", err=True)
            raise typer.Exit(2) from exc
        if formatted != original:
            changed.append(str(path))
            if not check:
                _write(path, formatted)
    verb = "would reformat" if check else "reformatted"
    _out(
        {"result": "FAILED" if check and changed else "OK", "changed": changed},
        as_json=as_json,
        text="\n".join(f"{verb} {c}" for c in changed),
        code=1 if check and changed else 0,
    )


@policy_app.command("lint")
def policy_lint(
    paths: Paths,
    decl: Annotated[list[Path] | None, typer.Option(help="Declaration file (repeatable)")] = None,
    root: Annotated[list[Path] | None, typer.Option(help="Import root (repeatable)")] = None,
    param: Annotated[list[str] | None, typer.Option(help="Parameter binding name=value (repeatable)")] = None,
    strict: Annotated[bool, typer.Option(help="Exit 1 when there is a warning")] = False,
    strict_inputs: Annotated[
        bool,
        typer.Option("--strict-inputs", help="Reject names that are neither standard nor declared under `inputs:`"),
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Report likely mistakes in a policy set: unused variables, unreachable or duplicate rules, unused declarations."""
    try:
        findings = lint(_load(paths, decl or [], root or [], _params(param), False, strict_inputs=strict_inputs))
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    warned = any(f.severity == "warning" for f in findings)
    lines = [f"{f.severity:<7} {f.code:<19} {f.rule or '-':<24} {f.message}" for f in findings]
    _out(
        {"result": "WARNINGS" if warned else "OK", "findings": [f.to_dict() for f in findings]},
        as_json=as_json,
        text="\n".join(lines) or "no findings",
        code=1 if strict and warned else 0,
    )


@policy_app.command("check")
def policy_check(
    paths: Paths,
    decl: Annotated[list[Path] | None, typer.Option(help="Declaration file (repeatable)")] = None,
    root: Annotated[list[Path] | None, typer.Option(help="Import root (repeatable)")] = None,
    param: Annotated[list[str] | None, typer.Option(help="Parameter binding name=value (repeatable)")] = None,
    open_inputs: Annotated[
        bool, typer.Option("--open-inputs", help="Accept names that are not standard or declared under `inputs:`")
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Validate and lint in one step, the check to run in CI: undeclared inputs are errors and any warning fails."""
    try:
        policy = _load(paths, decl or [], root or [], _params(param), True, strict_inputs=not open_inputs)
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    findings = lint(policy)
    warned = any(f.severity == "warning" for f in findings)
    lines = [f"{f.severity:<7} {f.code:<19} {f.rule or '-':<24} {f.message}" for f in findings]
    _out(
        {
            "result": "FAILED" if warned else "OK",
            "fingerprint": policy.fingerprint,
            "findings": [f.to_dict() for f in findings],
        },
        as_json=as_json,
        text="\n".join(lines) or f"OK fingerprint={policy.fingerprint}",
        code=1 if warned else 0,
    )


@policy_app.command("fmt")
def policy_fmt(
    paths: Paths,
    check: Annotated[bool, typer.Option(help="Exit 1 if a file would change")] = False,
    as_json: JsonFlag = False,
) -> None:
    """Rewrite policy files in canonical form."""
    _format(paths, "policy", check, as_json)


@decl_app.command("fmt")
def decl_fmt(
    paths: Paths,
    check: Annotated[bool, typer.Option(help="Exit 1 if a file would change")] = False,
    as_json: JsonFlag = False,
) -> None:
    """Rewrite declaration files in canonical form."""
    _format(paths, "decl", check, as_json)


@policy_app.command("explain")
def policy_explain(
    fixtures: Annotated[Path, typer.Option("--fixtures", help="Fixture file; the first case is explained")],
    policy_path: Annotated[list[Path], typer.Option("--policy", help="Policy file or directory")],
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    root: Annotated[list[Path] | None, typer.Option()] = None,
    case: Annotated[str | None, typer.Option(help="Case name (default: the first)")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Evaluate one fixture case with a full trace: every rule, condition result, `let` value and deciding step."""
    try:
        suite = load_suites([fixtures])[0]
        pol = _load(policy_path, decl or [], root or [], suite.params, False)
        chosen = next((c for c in suite.cases if case in (None, c.name)), None)
        if chosen is None:
            raise AuthoringError("SCHEMA_INVALID", f"case {case!r} not found")
        verdict, events = RuleEvaluator(pol, live=False).trace(chosen.action, chosen.signals)
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    lines = [
        f"rule {e['rule']}: match={e.get('match', '-')} when={e.get('when', '-')} -> "
        f"{e.get('outcome', 'no match')} {e.get('reasons', '')}"
        for e in events
    ]
    lines.append(f"verdict: {verdict.outcome} {verdict.reason_codes}  rules={verdict.matched_rules}")
    _out({"verdict": verdict.to_wire(), "trace": events}, as_json=as_json, text="\n".join(lines))


def _load_decls(paths: Sequence[Path], params: dict[str, Any], roots: Sequence[Path] | None = None) -> DeclarationSet:
    return load_declarations(list(paths), roots=list(roots) if roots else None, bindings=[params])


@decl_app.command("check")
def decl_check(
    paths: Annotated[list[Path], typer.Argument()],
    set_: Annotated[list[str] | None, typer.Option("--set", help="name=value")] = None,
    policy: Annotated[list[Path] | None, typer.Option(help="Also check these policies")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Validate declaration files (and optionally policies against them)."""
    try:
        params = _params(set_)
        decls = _load_decls(paths, params)
        if policy:
            _load(policy, paths, [], params, False)
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    _out({"result": "OK", "files": len(decls.files)}, as_json=as_json, text=f"OK ({len(decls.files)} file(s))")


@decl_app.command("show")
def decl_show(
    paths: Annotated[list[Path], typer.Argument()],
    set_: Annotated[list[str] | None, typer.Option("--set")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Show the merged declaration set."""
    try:
        shown = _load_decls(paths, _params(set_)).to_dict()
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    _out(shown, as_json=as_json, text=json.dumps(shown, indent=2, sort_keys=True))


@decl_app.command("lock")
def decl_lock(
    paths: Annotated[list[Path], typer.Argument()],
    out: Annotated[Path, typer.Option(help="Lock file to write")] = Path("cpl.decl.lock"),
    as_json: JsonFlag = False,
) -> None:
    """Write sha256 digests of every resolved import and table file (never content)."""
    try:
        decls = _load_decls(paths, {})
        loader = _Loader([p.resolve().parent for p in paths], CplLimits(), 16, None, None, False, None)
        for p in paths:
            loader.load(p)
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    write_lock(decls, loader.lock_rows, out)
    _out({"result": "OK", "file": str(out)}, as_json=as_json, text=f"wrote {out}")


@expr_app.command("eval")
def expr_eval(
    expression: Annotated[str, typer.Argument()],
    fixtures: Annotated[Path | None, typer.Option(help="Fixture file; the first case is the action")] = None,
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    as_json: JsonFlag = False,
) -> None:
    """Evaluate one expression: prints its value, its type and whether it derives from untrusted input."""
    try:
        decls = _load_decls(decl or [], {}) if decl else DeclarationSet()
        action = (
            load_suites([fixtures])[0].cases[0].action
            if fixtures
            else Action({"id": "cli", "timestamp": "2026-01-01T00:00:00Z"})
        )
        compiled = compile_expression(expression, Scope(decls))
        result: V = compiled.fn(Ctx(InputView(action, [], decls), CplLimits()))
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=1)
    except Exception as exc:
        _out({"result": "FAILED", "error": type(exc).__name__}, as_json=as_json, text=f"FAILED: {exc}", code=1)
    payload = {
        "value": to_wire(result.v) if render(result.v) != "n/a" else None,
        "type": type_label(result.v),
        "static_type": str(compiled.t or "unknown"),
        "trusted": result.trusted,
        "absent": render(result.v) == "n/a" and type_label(result.v) == "absent",
    }
    _out(
        payload,
        as_json=as_json,
        text=f"{render(result.v)}  ({payload['type']}, {'trusted' if result.trusted else 'untrusted'})",
    )


@app.command("test")
def run_test(
    fixtures: Annotated[list[Path], typer.Option("--fixtures", help="Fixture files or directories")] = [],  # noqa: B006
    policy: Annotated[list[Path], typer.Option("--policy", help="Policy files or directories")] = [],  # noqa: B006
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    root: Annotated[list[Path] | None, typer.Option()] = None,
    strict_inputs: Annotated[
        bool,
        typer.Option("--strict-inputs", help="Reject names that are neither standard nor declared under `inputs:`"),
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Run fixture actions through the evaluator offline. Exit 1 on any mismatch, 2 for an unreadable fixture or policy.
    `--policy` defaults to the policy a fixture file names under `policy:`."""
    if not fixtures:
        raise typer.BadParameter("--fixtures is required")
    results: list[CaseResult] = []
    try:
        for suite in load_suites(fixtures):
            paths = policy or ([Path(suite.policy)] if suite.policy else [])
            if not paths:
                raise typer.BadParameter(f"--policy is required: {suite.file} does not name its `policy`")
            pol = _load(paths, decl or [], root or [], suite.params, False, strict_inputs=strict_inputs)
            results += run_suite(suite, RuleEvaluator(pol, live=False))
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=2)  # bad input, not a failed case
    failed = [r for r in results if not r.passed]
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "passed": len(results) - len(failed),
                    "failed": len(failed),
                    "cases": [
                        {
                            "name": r.case.name,
                            "outcome": r.verdict.outcome,
                            "reason_codes": r.verdict.reason_codes,
                            "failures": r.failures,
                        }
                        for r in results
                    ],
                }
            )
        )
    else:
        for r in results:
            typer.echo(f"{_MARKS[0 if r.passed else 1]} {r.case.name:<48} {r.verdict.outcome}")
            for f in r.failures:
                typer.echo(f"  {f}")
        typer.echo(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    raise typer.Exit(1 if failed else 0)


@app.command("eval")
def run_eval(
    action: Annotated[Path, typer.Option("--action", help="Action file (YAML or JSON)")],
    policy: Annotated[list[Path], typer.Option("--policy", help="Policy files or directories")],
    signals: Annotated[
        Path | None, typer.Option(help="Signals file: a list of {code, source?, severity?, ...}")
    ] = None,
    now: Annotated[str | None, typer.Option(help="RFC 3339 timestamp for an action that has none")] = None,
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    root: Annotated[list[Path] | None, typer.Option()] = None,
    param: Annotated[list[str] | None, typer.Option(help="Parameter binding name=value (repeatable)")] = None,
    strict_inputs: Annotated[
        bool,
        typer.Option("--strict-inputs", help="Reject names that are neither standard nor declared under `inputs:`"),
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Decide one action. Exit 0 when the outcome is allow, watch or modify; 1 for deny or ask."""
    try:
        pol = _load(policy, decl or [], root or [], _params(param), False, strict_inputs=strict_inputs)
        verdict = RuleEvaluator(pol, live=False).evaluate(
            load_action(action, now=now), load_signals(signals) if signals else []
        )
    except AuthoringError as exc:
        _out(_error_payload(exc), as_json=as_json, text=f"FAILED: {exc}", code=2)  # bad input, not a deny
    text = f"{verdict.outcome} {' '.join(verdict.reason_codes)}  rules={verdict.matched_rules}"
    _out(verdict.to_wire(), as_json=as_json, text=text, code=0 if verdict.outcome in PERMITTED else 1)


@app.command("schema")
def run_schema(name: Annotated[str | None, typer.Argument(help="Schema to print; omit to list them")] = None) -> None:
    """Print one of the JSON Schemas of the language's documents (policy, action, signal, verdict, fixtures)."""
    if name is None:
        typer.echo("\n".join(SCHEMAS))
        raise typer.Exit(0)
    if name not in SCHEMAS:
        typer.echo(f"unknown schema {name!r}; one of {', '.join(SCHEMAS)}", err=True)
        raise typer.Exit(2)
    typer.echo(schema_path(name).read_text("utf-8"), nl=False)


def _fixture_from(result: Any) -> dict[str, Any]:
    """A proof counterexample as a fixture file, so a failing proof becomes a regression test."""
    raw = dict(result.counterexample["action"])
    state = dict(raw.pop("state", {}))
    run = state.pop("run", {})
    action: dict[str, Any] = dict(raw)
    if state:
        action["context"] = state
    if "depth" in run:
        action["depth"] = run["depth"]
    case: dict[str, Any] = {
        "name": "counterexample",
        "action": action,
        "expect": {"outcome": result.counterexample["outcome_candidate"]},
    }
    if result.counterexample.get("signals"):
        case["signals"] = [
            {"code": c, "source": "prover", "severity": "high"} for c in result.counterexample["signals"]
        ]
    return {"schema": "cpl.fixtures/1.0", "cases": [case]}


@policy_app.command("prove")
def policy_prove(
    candidate: Annotated[Path | None, typer.Option(help="Policy to check")] = None,
    boundary: Annotated[Path | None, typer.Option(help="Policy that bounds the candidate")] = None,
    diff: Annotated[tuple[Path, Path] | None, typer.Option(help="OLD NEW: what the change newly permits")] = None,
    no_bypass: Annotated[Path | None, typer.Option(help="Prove no hard-deny signal is bypassed")] = None,
    hard_signal: Annotated[
        list[str] | None, typer.Option(help="Signal code that must always deny, for --no-bypass (repeatable)")
    ] = None,
    timeout_ms: Annotated[int, typer.Option(help="Solver timeout")] = 10_000,
    emit_fixture: Annotated[Path | None, typer.Option(help="Write counterexamples as fixtures here")] = None,
    decl: Annotated[list[Path] | None, typer.Option()] = None,
    root: Annotated[list[Path] | None, typer.Option()] = None,
    as_json: JsonFlag = False,
) -> None:
    """Prove a policy stays within a boundary. Exit 0 within_boundary, 1 exceeds_boundary, 2 error, 3 unsupported or
    inconclusive."""
    from cplang.prove import prove

    profile = Profile(hard_signal_codes=frozenset(hard_signal)) if hard_signal else None

    def pol(path: Path) -> CompiledPolicy:
        return _load([path], decl or [], root or [], {}, False, profile=profile)

    try:
        if diff is not None:
            result = prove(pol(diff[1]), pol(diff[0]), mode="diff", timeout_ms=timeout_ms)
        elif no_bypass is not None:
            loaded = pol(no_bypass)
            result = prove(loaded, loaded, mode="no_bypass", timeout_ms=timeout_ms)
        elif candidate is not None and boundary is not None:
            result = prove(pol(candidate), pol(boundary), timeout_ms=timeout_ms)
        else:
            typer.echo("give --candidate and --boundary, or --diff or --no-bypass", err=True)
            raise typer.Exit(2)
    except AuthoringError as exc:
        _out(
            {"result": "error", "reason_code": exc.code, "detail": exc.message},
            as_json=as_json,
            text=f"error: {exc}",
            code=2,
        )
    if (
        emit_fixture is not None
        and result.counterexample is not None
        and "outcome_candidate" in (result.counterexample)
    ):
        _write(
            emit_fixture / "counterexample.fixtures.json",
            json.dumps(_fixture_from(result), indent=2, sort_keys=True) + "\n",
        )
    text = f"{result.result}" + (f" ({result.reason_code})" if result.reason_code else "")
    if result.detail:
        text += f": {result.detail}"
    if result.counterexample is not None:
        text += "\ncounterexample: " + json.dumps(result.counterexample, sort_keys=True, default=str)
    _out(result.to_dict(), as_json=as_json, text=text, code=result.exit_code)


@app.command("conformance")
def run_conformance(
    vectors: Annotated[Path | None, typer.Argument(help="Vector directory (default: the bundled vectors)")] = None,
    report: Annotated[Path | None, typer.Option(help="Write the JSON report here")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Run the conformance vectors against this implementation. Exit 0 only when every vector passes."""
    from cplang.conformance import default_vectors, run

    vectors = vectors or default_vectors()
    if not vectors.is_dir():
        typer.echo("FAILED: the vector directory does not exist", err=True)
        raise typer.Exit(2)
    result = run(vectors)
    document = result.to_dict()
    if report is not None:
        _write(report, json.dumps(document, indent=2, sort_keys=True) + "\n")
    lines = [
        f"{r.status.upper():<5} {r.id}" + (f": {r.detail}" if r.detail else "")
        for r in result.results
        if r.status != "pass"
    ]
    lines.append(f"{result.passed} passed, {result.failed} failed")
    _out(document, as_json=as_json, text="\n".join(lines), code=0 if result.ok else 1)


def main() -> None:
    """Entry point of the `cplang` command."""
    try:
        app(standalone_mode=True)
    except SystemExit:
        raise
    except Exception as exc:
        typer.echo(f"internal error ({type(exc).__name__})", err=True)
        raise SystemExit(3) from exc


if __name__ == "__main__":
    main()
