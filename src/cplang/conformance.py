"""The conformance runner: executes the vectors of a vector directory against this implementation and reports.

A vector is a JSON file `{id, level, input, expected}` under `<vectors>/<area>/`. `COMPUTE[area]` returns the actual
result in the shape of `expected`; the runner checks that `expected` is a subset of it. Another implementation
self-certifies by producing the same report (`{id, status: pass|fail}` per vector). An empty area counts as a
failure."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cplang import __version__
from cplang.data import data_dir
from cplang.errors import AuthoringError

REPORT_SCHEMA = "1.0"


@dataclass
class Result:
    """The outcome of one conformance vector."""

    id: str
    status: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "status": self.status}
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Report:
    """The outcome of a conformance run."""

    results: list[Result] = field(default_factory=list)
    implementation: str = "cplang-reference"
    version: str = __version__

    @property
    def passed(self) -> int:
        return sum(r.status == "pass" for r in self.results)

    @property
    def failed(self) -> int:
        return sum(r.status == "fail" for r in self.results)

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.passed > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": REPORT_SCHEMA,
            "implementation": self.implementation,
            "version": self.version,
            "results": [r.to_dict() for r in self.results],
            "passed": self.passed,
            "failed": self.failed,
        }


def _code(exc: BaseException) -> str:
    return str(getattr(exc, "code", None) or type(exc).__name__)


def default_vectors() -> Path:
    """The vectors bundled in the wheel, or the checkout's `conformance/` directory when run from source."""
    return data_dir() / "conformance"


def _write(root: Path, files: Mapping[str, str]) -> None:
    """Write a vector's files under `root`; a name that resolves outside it is a malformed vector."""
    base = root.resolve()
    for name, text in files.items():
        target = (base / name).resolve()
        if not target.is_relative_to(base):
            raise ValueError("a vector file escapes its directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")


def decision(v: dict[str, Any]) -> dict[str, Any]:
    """A policy set (`files`, the `policies` among them, optional `params`) applied to one action with signals."""
    from cplang.evaluator import RuleEvaluator
    from cplang.fixtures import load_suite
    from cplang.policy import load_policy

    spec = v["input"]
    with tempfile.TemporaryDirectory(prefix="cplang-vector-") as tmp:
        root = Path(tmp)
        _write(root, spec["files"])
        _write(
            root,
            {
                "case.fixtures.json": json.dumps(
                    {
                        "schema": "cpl.fixtures/1.0",
                        "cases": [
                            {
                                "name": "v",
                                "action": spec["action"],
                                "signals": spec.get("signals", []),
                                "expect": {"outcome": "allow"},
                            }
                        ],
                    }
                )
            },
        )
        try:
            policy = load_policy(
                [root / p for p in spec["policies"]],
                roots=[root],
                config_params=[spec.get("params", {})],
                rules_mode=spec.get("mode"),
                strict_inputs=bool(spec.get("strict_inputs", False)),
            )
            case = load_suite(root / "case.fixtures.json").cases[0]
            verdict, _ = RuleEvaluator(policy, live=False).trace(case.action, case.signals)
        except AuthoringError as exc:
            return {"error": _code(exc)}
    return {"outcome": verdict.outcome, "reason_codes": verdict.reason_codes, "matched_rules": verdict.matched_rules}


def declarations(v: dict[str, Any]) -> dict[str, Any]:
    """Load declaration files (`files`, the `entries` among them): which sections end up populated, or the error."""
    from cplang.declarations import SECTIONS, load_declarations

    spec = v["input"]
    with tempfile.TemporaryDirectory(prefix="cplang-vector-") as tmp:
        root = Path(tmp)
        _write(root, spec["files"])
        try:
            loaded = load_declarations(
                [root / e for e in spec["entries"]], roots=[root], bindings=[spec.get("params", {})]
            )
        except AuthoringError as exc:
            return {"error": _code(exc)}
        shown = loaded.to_dict()
    return {"ok": True, "sections": sorted(s for s in SECTIONS if shown.get(s))}


def expression(v: dict[str, Any]) -> dict[str, Any]:
    """Evaluate an expression vector: the expression runs against the vector's `arguments`."""
    from cplang.compile import Scope, compile_expression
    from cplang.declarations import DeclarationSet
    from cplang.model import Action
    from cplang.runtime import CplLimits, Ctx, InputView
    from cplang.values import EvalError, render, to_wire, type_label

    action = Action(
        {"timestamp": "2026-01-01T00:00:00Z", "action_uri": "app:act", "arguments": v["input"].get("arguments", {})}
    )
    decls = DeclarationSet()
    try:
        compiled = compile_expression(v["input"]["expression"], Scope(decls))
        result = compiled.fn(Ctx(InputView(action, [], decls), CplLimits()))
    except AuthoringError as exc:
        return {"error": _code(exc)}
    except EvalError:
        return {"error": "EVALUATION_ERROR"}
    absent = render(result.v) == "n/a" and type_label(result.v) == "absent"
    return {
        "value": None if absent else to_wire(result.v),
        "type": type_label(result.v),
        "absent": absent,
        "static_type": str(compiled.t or "unknown"),
    }


def types(v: dict[str, Any]) -> dict[str, Any]:
    """Parse the type expression of a type vector."""
    from cplang.types import parse_type_expr

    try:
        return {"canonical": str(parse_type_expr(v["input"]["type"], {}))}
    except (AuthoringError, ValueError) as exc:
        return {"error": _code(exc)}


COMPUTE: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "decision": decision,
    "parameters": decision,
    "declarations": declarations,
    "imports": declarations,
    "expressions": expression,
    "types": types,
}


def _subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _subset(v, actual[k]) for k, v in expected.items())
    return bool(expected == actual)


def _execute(path: Path, area: str) -> Result:
    vector_id = f"{area}/{path.stem}"
    try:
        vector = json.loads(path.read_text("utf-8"))
        vector_id = str(vector.get("id") or vector_id)
        compute = COMPUTE.get(area)
        if compute is None:
            return Result(vector_id, "fail", f"no executor for the area {area!r}")
        actual = compute(vector)
        if _subset(vector["expected"], actual):
            return Result(vector_id, "pass")
        return Result(
            vector_id,
            "fail",
            f"expected {json.dumps(vector['expected'], sort_keys=True)[:300]}, "
            f"got {json.dumps(actual, sort_keys=True, default=str)[:300]}",
        )
    except Exception as exc:  # a vector that cannot run is a failure
        return Result(vector_id, "fail", type(exc).__name__)


def run(vectors: Path) -> Report:
    """Run every vector under `vectors` and report the results."""
    report = Report()
    areas = sorted(p for p in vectors.glob("*") if p.is_dir()) if vectors.is_dir() else []
    if not areas:
        report.results.append(Result("vectors", "fail", f"no vector areas under {vectors}"))
    for area_dir in areas:
        files = sorted(area_dir.glob("*.json"))
        if not files:
            report.results.append(Result(area_dir.name, "fail", "no vectors in this area"))
        report.results += [_execute(path, area_dir.name) for path in files]
    return report
