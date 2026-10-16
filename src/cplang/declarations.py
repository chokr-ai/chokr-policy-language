"""Declaration files: types, attributes, constants, parameters, tables, functions, computed values and imports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from cplang.compile import Compiled, Scope, compile_expression
from cplang.errors import AuthoringError
from cplang.functions import FunctionRegistry
from cplang.profile import NEUTRAL, Profile
from cplang.runtime import CplLimits, Ctx
from cplang.source import Source, parse_source
from cplang.types import (
    Type,
    check_value,
    define_type,
    parse_type_expr,
)
from cplang.values import (
    ABSENT,
    EnumVal,
    EvalError,
    V,
    from_json,
    render_number,
    to_wire,
)

SCHEMAS = ("cpl.declarations/1.0",)
OPEN_SECTIONS = (
    "kinds",
    "reason_codes",
    "signal_codes",
    "obligation_types",
    "risk_tiers",
    "environments",
    "resource_types",
)
SECTIONS = (
    "types",
    "attributes",
    "constants",
    "parameters",
    "tables",
    "functions",
    "conditions",
    "computed",
    "inputs",
    "shortcuts",
    *OPEN_SECTIONS,
)
_HEADER = {"schema", "namespace", "version", "imports", "description", "ext", *SECTIONS}
_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_NS = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}$")
_RESERVED = frozenset(
    {
        "true",
        "false",
        "in",
        "ref",
        "expr",
        "use",
        "let",
        "param",
        "const",
        "table",
        "computed",
        "fn",
        "var",
        "attributes",
        "arguments",
        "state",
        "time",
        "ext",
    }
)


def _condition_names() -> frozenset[str]:
    """Names a condition already gives a meaning to: standard roots, sugar keys, admission keys and combinators."""
    from cplang.conditions import ADMISSION_KEYS, SUGAR_KEYS
    from cplang.inputs import CONDITION_ROOTS, ROOTS

    return frozenset({*ROOTS, *CONDITION_ROOTS, *ADMISSION_KEYS, *SUGAR_KEYS, "any", "all", "not", "signal", "with"})


_ENTRY_KEYS: dict[str, frozenset[str]] = {
    "attributes": frozenset({"type", "source", "required", "default", "unit", "sensitivity"}),
    "parameters": frozenset({"type", "default", "required"}),
    "constants": frozenset({"type", "value", "expr"}),
    "tables": frozenset({"key", "value", "rows", "source", "format", "digest"}),
    "functions": frozenset({"params", "returns", "body"}),
    "conditions": frozenset({"params", "when"}),
    "computed": frozenset({"type", "expr", "requires"}),
    "inputs": frozenset({"type"}),
}
_COMMON_KEYS = frozenset({"description", "private", "deprecated", "ext"})
_IMPORT_KEYS = frozenset({"from", "only", "rename", "as", "digest", "with"})
LOCK_NAME = "cpl.decl.lock"
PackResolver = Callable[[str], "Path | None"]


def sha256_file(data: bytes) -> str:
    """Digest of a text file with line endings normalized, so a checkout with CRLF hashes like one with LF."""
    return "sha256:" + hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


@dataclass
class AttrDef:
    """A declared attribute: its type, where its value comes from and whether it is required."""

    type: Type
    source: str = "either"
    required: bool = False
    default: Any = ABSENT
    unit: str | None = None
    sensitivity: str | None = None


@dataclass
class ParamDef:
    """A declared parameter with its type and default."""

    type: Type
    default: Any = ABSENT
    required: bool = False
    description: str | None = None


@dataclass
class TableDef:
    """A declared lookup table from string keys to typed values."""

    key_type: Type
    value_type: Type
    rows: dict[str, Any]
    digest: str | None = None

    @staticmethod
    def norm(key: Any) -> str:
        """The string form of a table key."""
        if isinstance(key, EnumVal):
            return key.name
        if type(key) is bool:
            return "true" if key else "false"
        if isinstance(key, int | Decimal):
            return render_number(key)
        return str(key)

    def lookup(self, key: Any) -> Any:
        """The value stored for `key`, or `absent`."""
        return self.rows.get(self.norm(key), ABSENT)

    def as_value(self) -> dict[str, Any]:
        """A copy of all rows."""
        return dict(self.rows)


@dataclass
class FuncDef:
    """A declared function: parameters, return type and body expression."""

    spec: dict[str, Any]
    params: dict[str, Type]
    returns: Type
    body: Compiled | None = None


@dataclass
class CondDef:
    """A declared named condition with its parameters."""

    params: dict[str, Type]
    when: Any
    file: str | None = None
    src: Source | None = None
    in_policy: bool = False  # defined in a policy file, so its body may only name public declarations


@dataclass
class ComputedDef:
    """A declared computed value."""

    type: Type
    spec: dict[str, Any]
    requires: tuple[str, ...]
    compiled: Compiled | None = None

    def evaluate(self, ctx: Ctx) -> V:
        """Evaluate the computed value in the current context."""
        for name in self.requires:
            if ctx.view.attribute(name).v is ABSENT:
                return V(ABSENT, True)
        if self.compiled is None:
            raise EvalError("computed value is not compiled")
        out = self.compiled.fn(ctx)
        return V(out.v if out.v is ABSENT else check_value_loose(self.type, out.v), out.trusted)


def check_value_loose(t: Type, value: Any) -> Any:
    """A computed value is already a language value; only integer/number widening is enforced."""
    if t.kind == "number" and type(value) is int:
        return value
    return value


class _NoView:
    """The input view used when a declaration is evaluated outside any action."""

    action = None

    def attribute(self, name: str) -> V:
        raise EvalError("the action is not available in a declaration")

    def root(self, name: str) -> V:
        raise EvalError("the action is not available in a declaration")


@dataclass
class _Edge:
    spec: dict[str, Any]
    resolved: Path


@dataclass
class _File:
    path: Path
    src: Source
    digest: str
    namespace: str | None
    version: Any
    edges: list[_Edge] = field(default_factory=list)
    include: set[str] | None = None  # names imported via `only` (None = everything)
    import_all: bool = False
    renames: dict[str, str] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)

    def sections(self) -> dict[str, dict[str, Any]]:
        return {s: self.src.data.get(s) or {} for s in SECTIONS}


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


class DeclarationSet:
    """Resolved, merged and type-checked declarations. Immutable after `load`."""

    def __init__(self, limits: CplLimits | None = None) -> None:
        self.limits = limits or CplLimits()
        self.types: dict[str, Type] = {}
        self.attributes: dict[str, AttrDef] = {}
        self._consts_raw: dict[str, dict[str, Any]] = {}
        self._consts: dict[str, tuple[Type, Any]] = {}
        self.parameters: dict[str, ParamDef] = {}
        self.resolved_params: dict[str, Any] = {}
        self.tables: dict[str, TableDef] = {}
        self._funcs: dict[str, FuncDef] = {}
        self.conditions: dict[str, CondDef] = {}
        self.inputs: dict[str, Type] = {}
        self.shortcuts: dict[str, dict[str, Any]] = {}
        self.strict_inputs = False
        self._computed: dict[str, ComputedDef] = {}
        self.open_values: dict[str, dict[str, dict[str, Any]]] = {s: {} for s in OPEN_SECTIONS}
        self.files: dict[str, str] = {}  # location-independent file name -> digest
        self.table_files: dict[str, str] = {}  # table name -> digest of its source file
        self.private: set[tuple[str, str]] = set()
        self.version: Any = None
        self.plugins: FunctionRegistry | None = None
        self.profile: Profile = NEUTRAL
        self._compiling: set[str] = set()

    def attribute_type(self, name: str) -> Type | None:
        """The declared type of attribute `name`, or None."""
        a = self.attributes.get(name)
        return a.type if a else None

    def const(self, name: str) -> tuple[Type, Any] | None:
        """The type and value of constant `name`, or None."""
        if name in self._consts:
            return self._consts[name]
        raw = self._consts_raw.get(name)
        if raw is None:
            return None
        if name in self._compiling:
            raise AuthoringError("DECLARATION_INVALID", f"constant {name} depends on itself")
        self._compiling.add(name)
        try:
            self._consts[name] = self._eval_const(name, raw)
        finally:
            self._compiling.discard(name)
        return self._consts[name]

    def param(self, name: str) -> tuple[Type, Any] | None:
        """The type and bound value of parameter `name`, or None."""
        p = self.parameters.get(name)
        return (p.type, self.resolved_params[name]) if p and name in self.resolved_params else None

    def table(self, name: str) -> TableDef | None:
        """The table called `name`, or None."""
        return self.tables.get(name)

    def function(self, name: str) -> FuncDef | None:
        """The declared function called `name`, or None."""
        f = self._funcs.get(name)
        if f is None:
            return None
        if f.body is None:
            key = f"fn.{name}"
            if key in self._compiling:
                raise AuthoringError("TYPE_ERROR", f"function {name} is recursive")
            self._compiling.add(key)
            try:
                scope = Scope(self, dict(f.params), {}, self.plugins, self.limits, env_ok=False)
                body = compile_expression(str(f.spec["body"]), scope)
                if body.t is not None and not _assignable(body.t, f.returns):
                    raise AuthoringError("TYPE_ERROR", f"function {name} returns {body.t}, declared {f.returns}")
                f.body = body
            finally:
                self._compiling.discard(key)
        return f

    def computed(self, name: str) -> ComputedDef | None:
        """The computed value called `name`, or None."""
        c = self._computed.get(name)
        if c is None:
            return None
        if c.compiled is None:
            key = f"computed.{name}"
            if key in self._compiling:
                raise AuthoringError("TYPE_ERROR", f"computed value {name} depends on itself")
            self._compiling.add(key)
            try:
                scope = Scope(self, {}, {}, self.plugins, self.limits)
                compiled = compile_expression(str(c.spec["expr"]), scope)
                if compiled.t is not None and not _assignable(compiled.t, c.type):
                    raise AuthoringError("TYPE_ERROR", f"computed {name} is {compiled.t}, declared {c.type}")
                c.compiled = compiled
            finally:
                self._compiling.discard(key)
        return c

    def input_type(self, parts: Sequence[str]) -> Type | None:
        """The declared type of an input path such as `customer.tier`, or None when it is not declared."""
        found = self.inputs.get(parts[0]) if parts else None
        for part in parts[1:]:
            if found is None:
                return None
            kind = found.args[0] if found.kind == "optional" else found
            if kind.kind == "object":
                field = kind.fields.get(part)
                found = field.type if field is not None else None
            elif kind.kind == "map":
                found = kind.args[0]
            else:
                return None
        return found

    def enum_order(self, etype: str) -> tuple[str, ...] | None:
        """The ordered member names of enum `etype`, or None when the enum is unordered."""
        t = self.types.get(etype)
        return t.c["values"] if t is not None and t.kind == "enum" and t.c.get("ordered") else None

    def conversions(self, qtype: str | None) -> dict[str, Any]:
        """The unit conversions of quantity type `qtype`."""
        t = self.types.get(qtype or "")
        return dict(t.c.get("conversions", {})) if t is not None and t.kind == "quantity" else {}

    def typed_attribute(self, name: str, raw: Any) -> Any:
        """Validate an attribute value against its declared type and return the typed value."""
        a = self.attributes.get(name)
        if a is None:
            raise EvalError("undeclared attribute")
        if a.unit and a.type.kind == "quantity" and not isinstance(raw, dict):
            raw = {"value": raw, "unit": a.unit}
        return check_value(a.type, raw)

    def validate_attributes(self, attributes: Mapping[str, Any] | None, *, strict: bool = False) -> list[str]:
        """Names of attributes that are invalid: wrong type, undeclared (strict) or missing required.
        Only names are returned."""
        attributes = attributes or {}
        bad: list[str] = []
        for name, raw in attributes.items():
            if name not in self.attributes:
                if strict:
                    bad.append(name)
                continue
            try:
                self.typed_attribute(name, raw)
            except EvalError:
                bad.append(name)
        bad += [n for n, a in self.attributes.items() if a.required and n not in attributes and a.default is ABSENT]
        return sorted(set(bad))

    def _eval_const(self, name: str, raw: dict[str, Any]) -> tuple[Type, Any]:
        t = parse_type_expr(str(raw.get("type", "any")), self.types, self.limits.max_type_depth)
        if "expr" in raw:
            scope = Scope(self, {}, {}, self.plugins, self.limits, env_ok=False)
            compiled = compile_expression(str(raw["expr"]), scope)
            try:
                value = compiled.fn(Ctx(_NoView(), self.limits)).v  # type: ignore[arg-type]
            except EvalError as exc:
                raise AuthoringError("DECLARATION_INVALID", f"constant {name} cannot be evaluated: {exc}") from exc
        else:
            try:
                value = check_value(t, raw.get("value", ABSENT))
            except EvalError as exc:
                raise AuthoringError("DECLARATION_INVALID", f"constant {name}: {exc}") from exc
        if t.kind == "any":
            raise AuthoringError("TYPE_ERROR", f"constant {name} cannot have type any")
        return t, value

    def to_dict(self) -> dict[str, Any]:
        """A JSON-compatible summary of the declarations."""
        return {
            "version": self.version,
            "files": dict(sorted(self.files.items())),
            "types": {n: str(t) for n, t in sorted(self.types.items())},
            "attributes": {
                n: {"type": str(a.type), "source": a.source, "required": a.required}
                for n, a in sorted(self.attributes.items())
            },
            "parameters": {
                n: {"type": str(p.type), "value": to_wire(self.resolved_params.get(n, ABSENT))}
                for n, p in sorted(self.parameters.items())
            },
            "constants": {n: {"type": str(t), "value": to_wire(v)} for n, (t, v) in sorted(self._consts.items())},
            "tables": {
                n: {"key": str(t.key_type), "value": str(t.value_type), "rows": len(t.rows), "digest": t.digest}
                for n, t in sorted(self.tables.items())
            },
            "functions": sorted(self._funcs),
            "conditions": sorted(self.conditions),
            "computed": sorted(self._computed),
            "inputs": {n: str(t) for n, t in sorted(self.inputs.items())},
            "shortcuts": {n: dict(s) for n, s in sorted(self.shortcuts.items())},
            "open_values": {s: sorted(v) for s, v in self.open_values.items() if v},
        }

    def fingerprint_parts(self) -> dict[str, Any]:
        """Everything the fingerprint covers besides rules: declaration digests, tables, parameters."""
        parts: dict[str, Any] = {
            "declarations": dict(sorted(self.files.items())),
            "tables": dict(sorted(self.table_files.items())),
            "params": {n: _canon_value(v) for n, v in sorted(self.resolved_params.items())},
        }
        if self.inputs:
            parts["inputs"] = {n: str(t) for n, t in sorted(self.inputs.items())}
        if self.shortcuts:
            parts["shortcuts"] = {n: dict(sorted(s.items())) for n, s in sorted(self.shortcuts.items())}
        return parts


def _canon_value(v: Any) -> Any:
    wire = to_wire(v)
    return wire


def _assignable(actual: Type, declared: Type) -> bool:
    from cplang.types import is_subtype

    return (
        is_subtype(actual, declared)
        or declared.kind == "any"
        or (declared.kind == "number" and actual.kind in ("integer", "number"))
    )


class _Loader:
    def __init__(
        self,
        roots: Sequence[Path],
        limits: CplLimits,
        max_depth: int,
        pack_resolver: PackResolver | None,
        lock: Mapping[str, Any] | None,
        require_lock: bool,
        plugins: FunctionRegistry | None,
    ) -> None:
        self.roots = [r.resolve() for r in roots]
        self.limits, self.max_depth = limits, max_depth
        self.pack_resolver, self.lock, self.require_lock, self.plugins = pack_resolver, lock, require_lock, plugins
        self.loaded: dict[Path, _File] = {}
        self.order: list[_File] = []
        self.import_with: dict[str, Any] = {}
        self.lock_rows: list[dict[str, str]] = []

    def load(self, path: Path, chain: tuple[Path, ...] = ()) -> _File:
        resolved = path.resolve()
        if resolved in chain:
            raise AuthoringError(
                "IMPORT_CYCLE",
                "imports form a cycle: " + " -> ".join(p.name for p in (*chain, resolved)),
                file=str(path),
            )
        if resolved in self.loaded:
            return self.loaded[resolved]
        if len(chain) >= self.max_depth:
            raise AuthoringError(
                "IMPORT_FORBIDDEN", "import depth exceeds declarations.max_import_depth", file=str(path)
            )
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise AuthoringError("IMPORT_NOT_FOUND", "declaration file cannot be read", file=str(path)) from exc
        src = parse_source(data, str(path), error_code="DECLARATION_INVALID", limits=self.limits)
        file = self._check_header(path, src, data)
        self.loaded[resolved] = file
        for spec in src.data.get("imports") or []:
            target = self._resolve_import(path, spec, src)
            sub = self.load(target, (*chain, resolved))
            file.edges.append(_Edge(spec, target))
            self._apply_edge(file, sub, spec)
            self.lock_rows.append({"from": str(spec["from"]), "resolved": self.ref(target), "digest": sub.digest})
        self.order.append(file)
        return file

    def ref(self, path: Path) -> str:
        """A location-independent name for a file: its POSIX path below the first import root that holds it."""
        if str(path).startswith("<inline:"):
            return str(path)
        resolved = path.resolve()
        for root in self.roots:
            if _inside(root, resolved):
                return resolved.relative_to(root).as_posix()
        return resolved.as_posix()

    def _check_header(self, path: Path, src: Source, data: bytes) -> _File:
        doc = src.data
        if not isinstance(doc, dict):
            raise src.error("DECLARATION_INVALID", "a declaration file is a mapping")
        if doc.get("schema") not in SCHEMAS:
            raise src.error("DECLARATION_INVALID", f"schema must be one of {', '.join(SCHEMAS)}", "schema")
        for key in doc:
            if key not in _HEADER:
                raise src.error("DECLARATION_INVALID", f"unknown key {key!r}", key)
        ns = doc.get("namespace")
        if ns is not None and not (isinstance(ns, str) and _NS.fullmatch(ns)):
            raise src.error("DECLARATION_INVALID", "namespace is not valid", "namespace")
        return _File(path, src, sha256_file(data), ns, doc.get("version"))

    def _resolve_import(self, importer: Path, spec: Any, src: Source, idx: int | None = None) -> Path:
        if idx is None:
            idx = (src.data.get("imports") or []).index(spec)
        if not isinstance(spec, dict) or not isinstance(spec.get("from"), str):
            raise src.error("DECLARATION_INVALID", "an import needs `from`", "imports", idx)
        _check_import_spec(spec, src, idx)
        ref: str = spec["from"]
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", ref):
            raise src.error("IMPORT_FORBIDDEN", "imports are never fetched from the network", "imports", idx, "from")
        if ref.startswith("workspace:"):
            raise src.error("IMPORT_FORBIDDEN", "workspace imports need a connected Engine (Phase 2)", "imports", idx)
        if ref.startswith("pack:"):
            found = self.pack_resolver(ref) if self.pack_resolver else None
            if found is None:
                raise src.error("IMPORT_NOT_FOUND", f"pack {ref} is not installed", "imports", idx, "from")
            return found
        if Path(ref).is_absolute() or re.match(r"^[A-Za-z]:", ref):
            raise src.error("IMPORT_FORBIDDEN", "absolute import paths are not allowed", "imports", idx, "from")
        target = importer.parent / ref
        if not any(_inside(r, target) for r in self.roots):
            raise src.error("IMPORT_FORBIDDEN", "the import leaves every import root", "imports", idx, "from")
        if not target.is_file():
            raise src.error("IMPORT_NOT_FOUND", f"{ref} does not exist", "imports", idx, "from")
        return target

    def _apply_edge(self, importer: _File, sub: _File, spec: dict[str, Any]) -> None:
        digest = spec.get("digest")
        if digest is not None and digest != sub.digest:
            raise importer.src.error(
                "IMPORT_DIGEST_MISMATCH", "the imported file differs from its pinned digest", "imports"
            )
        only = spec.get("only")
        if only is not None:
            sub.include = (sub.include or set()) | set(only)
        else:
            sub.import_all = True
        if spec.get("rename"):
            sub.renames.update(spec["rename"])
        if spec.get("as"):
            sub.aliases.append(spec["as"])
        for name, value in (spec.get("with") or {}).items():
            self.import_with[name] = from_json(value)


def _check_import_spec(spec: dict[str, Any], src: Source, idx: int) -> None:
    """The keys of an import and their shapes: `only` is a list of names, `rename` maps names to names."""
    unknown = sorted(str(k) for k in set(spec) - _IMPORT_KEYS)
    if unknown:
        raise src.error("DECLARATION_INVALID", f"an import has no key {unknown[0]!r}", "imports", idx, unknown[0])
    only, rename = spec.get("only"), spec.get("rename")
    checks = (
        ("only", only is None or (isinstance(only, list) and all(isinstance(n, str) for n in only))),
        ("rename", rename is None or (isinstance(rename, dict) and all(isinstance(v, str) for v in rename.values()))),
        ("as", spec.get("as") is None or isinstance(spec["as"], str)),
        ("digest", spec.get("digest") is None or isinstance(spec["digest"], str)),
        ("with", spec.get("with") is None or isinstance(spec["with"], dict)),
    )
    for key, ok in checks:
        if not ok:
            raise src.error("DECLARATION_INVALID", f"import {key} has the wrong shape", "imports", idx, key)


def load_declarations(
    paths: Sequence[Path] = (),
    *,
    roots: Sequence[Path] | None = None,
    bindings: Sequence[Mapping[str, object]] = (),
    limits: CplLimits | None = None,
    max_import_depth: int = 16,
    pack_resolver: PackResolver | None = None,
    lock: Mapping[str, Any] | None = None,
    require_lock: bool = False,
    plugins: FunctionRegistry | None = None,
    inline: Sequence[tuple[Mapping[str, Any], str | None]] = (),
    import_specs: Sequence[tuple[Path, Source, Sequence[tuple[int, dict[str, Any]]]]] = (),
) -> DeclarationSet:
    """Load declaration files (and everything they import) into one DeclarationSet.

    `bindings` are parameter layers, lowest precedence first: policy `params`, config `params`, profile `params`.
    Import `with:` values sit below them.
    """
    limits = limits or CplLimits()
    base_roots = list(roots) if roots else [Path(p).resolve().parent for p in paths] or [Path.cwd()]
    loader = _Loader(base_roots, limits, max_import_depth, pack_resolver, lock, require_lock, plugins)
    for path in paths:
        loader.load(Path(path))
    for importer, psrc, specs in import_specs:
        for idx, spec in specs:
            target = loader._resolve_import(importer, spec, psrc, idx)
            sub = loader.load(target)
            loader._apply_edge(_File(importer, psrc, "", None, None), sub, spec)
    for index, (doc, ns) in enumerate(inline):
        data = json.dumps(dict(doc), default=str).encode()
        src = parse_source(data, f"<inline:{index}>", error_code="DECLARATION_INVALID", limits=limits)
        src.data.setdefault("schema", SCHEMAS[0])
        if ns:
            src.data["namespace"] = ns
        loader.order.append(
            _File(Path(f"<inline:{index}>"), src, sha256_file(data), ns or "local", src.data.get("version"))
        )
    if require_lock:
        _check_lock(loader, lock)
    decls = DeclarationSet(limits)
    decls.plugins = plugins
    _build(decls, loader, list(bindings))
    return decls


def _check_lock(loader: _Loader, lock: Mapping[str, Any] | None) -> None:
    locked = {row["resolved"]: row["digest"] for row in (lock or {}).get("imports", [])}
    for row in loader.lock_rows:
        if locked.get(row["resolved"]) != row["digest"]:
            raise AuthoringError("IMPORT_DIGEST_MISMATCH", f"{row['from']} is not in {LOCK_NAME} or has changed")


def _build(decls: DeclarationSet, loader: _Loader, layers: list[Mapping[str, Any]]) -> None:
    raw_types: dict[str, dict[str, Any]] = {}
    raw_attrs: dict[str, tuple[dict[str, Any], _File]] = {}
    raw_params: dict[str, tuple[dict[str, Any], _File]] = {}
    raw_tables: dict[str, tuple[dict[str, Any], _File]] = {}
    seen: dict[tuple[str, str], tuple[Any, _File]] = {}
    deferred: list[tuple[str, str, dict[str, Any], _File]] = []
    for file in loader.order:
        decls.files[loader.ref(file.path)] = file.digest
        decls.version = file.version if file.version is not None else decls.version
        secs = file.sections()
        for kind, sec in secs.items():
            if not isinstance(sec, dict):
                raise file.src.error("DECLARATION_INVALID", f"{kind} must be a mapping", kind)
            for name, spec in sec.items():
                if kind in OPEN_SECTIONS:
                    full = f"{file.namespace}/{name}" if file.namespace else name
                    decls.open_values[kind][full] = spec if isinstance(spec, dict) else {}
                    continue
                if not isinstance(spec, dict):
                    raise file.src.error("DECLARATION_INVALID", f"{kind[:-1]} {name!r} must be a mapping", kind, name)
                _check_entry_keys(file, kind, name, spec)
                if kind != "types" and (not _NAME.fullmatch(name) or name in _RESERVED):
                    raise file.src.error(
                        "DECLARATION_INVALID", f"{name!r} is not a valid or is a reserved name", kind, name
                    )
                if kind in ("inputs", "shortcuts") and name in _condition_names():
                    raise file.src.error(
                        "DECLARATION_INVALID", f"{name!r} is a standard name and cannot be redefined", kind, name
                    )
                names = [name]
                if kind == "attributes" and name in file.renames:
                    names = [file.renames[name]]
                for alias in file.aliases:
                    if kind in ("parameters", "constants", "tables", "functions", "conditions", "computed"):
                        names.append(f"{alias}.{name}")
                # private (or left out of every import's `only:`): a dependency of the file, never named by a policy
                if spec.get("private") or (
                    file.include is not None and not file.import_all and name not in file.include
                ):
                    decls.private.update((kind, target) for target in names)
                for target in names:
                    previous = seen.get((kind, target))
                    if previous is not None:
                        if previous[0] == spec:
                            continue  # an identical re-declaration is accepted
                        where_file, line, col = file.src.where(kind, name)
                        raise AuthoringError(
                            "DECLARATION_CONFLICT",
                            f"{kind} entry {target!r} is declared differently in {previous[1].path}",
                            file=where_file,
                            line=line,
                            column=col,
                        )
                    seen[(kind, target)] = (spec, file)
                    deferred.append((kind, target, spec, file))
    raw_types.update({target: spec for kind, target, spec, _ in deferred if kind == "types"})
    _build_types(decls, raw_types)
    for kind, target, spec, file in deferred:
        if kind != "types":
            _put(kind, target, spec, file, raw_types, raw_attrs, raw_params, raw_tables, decls)
    for name, (spec, file) in raw_attrs.items():
        decls.attributes[name] = _attr(decls, name, spec, file)
    for name, (spec, file) in raw_tables.items():
        decls.tables[name] = _table(decls, name, spec, file, loader.roots)
        if decls.tables[name].digest:
            decls.table_files[name] = decls.tables[name].digest  # type: ignore[assignment]
    for name, (spec, file) in raw_params.items():
        decls.parameters[name] = _param(decls, name, spec, file)
    _bind_params(decls, loader.import_with, layers)
    for name in list(decls._consts_raw):
        decls.const(name)
    for name in list(decls._funcs):
        decls.function(name)
    for name in list(decls._computed):
        decls.computed(name)


def _put(
    kind: str,
    name: str,
    spec: dict[str, Any],
    file: _File,
    raw_types: dict[str, Any],
    raw_attrs: dict[str, Any],
    raw_params: dict[str, Any],
    raw_tables: dict[str, Any],
    decls: DeclarationSet,
) -> None:
    if kind == "types":
        raw_types[name] = spec
    elif kind == "attributes":
        raw_attrs[name] = (spec, file)
    elif kind == "parameters":
        raw_params[name] = (spec, file)
    elif kind == "tables":
        raw_tables[name] = (spec, file)
    elif kind == "constants":
        decls._consts_raw[name] = spec
    elif kind == "functions":
        params = {
            p: parse_type_expr(str(t), decls.types, decls.limits.max_type_depth)
            for p, t in (spec.get("params") or {}).items()
        }
        if "body" not in spec or "returns" not in spec:
            raise file.src.error("DECLARATION_INVALID", f"function {name} needs `body` and `returns`", kind, name)
        decls._funcs[name] = FuncDef(
            spec, params, parse_type_expr(str(spec["returns"]), decls.types, decls.limits.max_type_depth)
        )
    elif kind == "conditions":
        params = {
            p: parse_type_expr(str(t), decls.types, decls.limits.max_type_depth)
            for p, t in (spec.get("params") or {}).items()
        }
        decls.conditions[name] = CondDef(params, spec.get("when"), str(file.path), file.src)
    elif kind == "inputs":
        if "type" not in spec:
            raise file.src.error("DECLARATION_INVALID", f"input {name} needs a `type`", kind, name)
        if name in decls.types:
            raise file.src.error("DECLARATION_CONFLICT", f"{name!r} is both an input and a type", kind, name)
        decls.inputs[name] = parse_type_expr(str(spec["type"]), decls.types, decls.limits.max_type_depth)
    elif kind == "shortcuts":
        if not isinstance(spec.get("path"), str) or set(spec) - {"path", "glob"} - _COMMON_KEYS:
            raise file.src.error("DECLARATION_INVALID", f"shortcut {name} is {{path, glob?}}", kind, name)
        glob = spec.get("glob") or {}
        if not isinstance(glob, dict) or set(glob) - {"sep", "normalize", "case_insensitive"}:
            raise file.src.error(
                "DECLARATION_INVALID", f"shortcut {name}: glob takes sep, normalize, case_insensitive", kind, name
            )
        decls.shortcuts[name] = {"path": spec["path"], "glob": dict(glob)}
    elif kind == "computed":
        if "type" not in spec or "expr" not in spec:
            raise file.src.error("DECLARATION_INVALID", f"computed {name} needs `type` and `expr`", kind, name)
        decls._computed[name] = ComputedDef(
            parse_type_expr(str(spec["type"]), decls.types, decls.limits.max_type_depth),
            spec,
            tuple(spec.get("requires") or ()),
        )


def _build_types(decls: DeclarationSet, raw: dict[str, dict[str, Any]]) -> None:
    """Define named types in dependency order; a type that cannot be resolved is a TYPE_ERROR."""
    pending = dict(raw)
    while pending:
        progressed = False
        for name in list(pending):
            try:
                decls.types[name] = define_type(name, pending[name], decls.types, decls.limits.max_type_depth)
            except AuthoringError as exc:
                if "unknown type" in exc.message:
                    continue
                raise
            del pending[name]
            progressed = True
        if not progressed:
            name = sorted(pending)[0]
            raise AuthoringError("TYPE_ERROR", f"type {name} refers to an unknown or recursive type")


def _check_entry_keys(file: _File, kind: str, name: str, spec: dict[str, Any]) -> None:
    """A declaration entry has only the keys its section defines, and its flags are real booleans."""
    allowed = _ENTRY_KEYS.get(kind)
    if allowed is None:
        return
    extra = sorted(str(k) for k in set(spec) - allowed - _COMMON_KEYS)
    if extra:
        raise file.src.error("DECLARATION_INVALID", f"{kind[:-1]} {name!r} has unknown key {extra[0]!r}", kind, name)
    for flag in ("required", "private", "deprecated"):
        if flag in spec and type(spec[flag]) is not bool:
            raise file.src.error("DECLARATION_INVALID", f"{flag} is true or false", kind, name, flag)


def _attr(decls: DeclarationSet, name: str, spec: dict[str, Any], file: _File) -> AttrDef:
    try:
        t = parse_type_expr(str(spec.get("type", "")), decls.types, decls.limits.max_type_depth)
    except AuthoringError as exc:
        raise exc.located(*file.src.where("attributes", name)) from exc
    if t.kind == "any":
        raise file.src.error("TYPE_ERROR", f"attribute {name} cannot have type any", "attributes", name)
    source = spec.get("source", "either")
    if source not in ("asserted", "derived", "either"):
        raise file.src.error("DECLARATION_INVALID", "source is asserted, derived or either", "attributes", name)
    default = ABSENT
    if "default" in spec:
        if source == "derived":
            raise file.src.error("DECLARATION_INVALID", "only asserted attributes have a default", "attributes", name)
        default = check_value(t, spec["default"])
    return AttrDef(t, source, bool(spec.get("required", False)), default, spec.get("unit"), spec.get("sensitivity"))


def _param(decls: DeclarationSet, name: str, spec: dict[str, Any], file: _File) -> ParamDef:
    t = parse_type_expr(str(spec.get("type", "")), decls.types, decls.limits.max_type_depth)
    default = ABSENT
    if "default" in spec:
        try:
            default = check_value(t, spec["default"])
        except EvalError as exc:
            raise file.src.error("PARAM_INVALID", f"default of {name}: {exc}", "parameters", name) from exc
    return ParamDef(t, default, bool(spec.get("required", False)) or "default" not in spec, spec.get("description"))


def _bind_params(decls: DeclarationSet, import_with: Mapping[str, Any], layers: Sequence[Mapping[str, Any]]) -> None:
    for name, p in decls.parameters.items():
        if p.default is not ABSENT:
            decls.resolved_params[name] = p.default
    for layer in (import_with, *layers):
        for name, raw in layer.items():
            pdef = decls.parameters.get(name)
            if pdef is None:
                raise AuthoringError("DECLARATION_UNKNOWN_NAME", f"parameter {name!r} is not declared")
            try:
                decls.resolved_params[name] = check_value(pdef.type, raw)
            except EvalError as exc:
                raise AuthoringError("PARAM_INVALID", f"parameter {name}: {exc}") from exc
    for name in decls.parameters:
        if name not in decls.resolved_params:
            raise AuthoringError("PARAM_UNBOUND", f"parameter {name!r} has no default and no binding")


def _table(decls: DeclarationSet, name: str, spec: dict[str, Any], file: _File, roots: Sequence[Path]) -> TableDef:
    lim = decls.limits
    kt = parse_type_expr(str(spec.get("key", "string")), decls.types, lim.max_type_depth)
    vt = parse_type_expr(str(spec.get("value", "")), decls.types, lim.max_type_depth)
    if kt.kind not in ("string", "integer", "number", "boolean", "enum"):
        raise file.src.error("TABLE_INVALID", f"table {name} key must be a scalar type", "tables", name)
    digest: str | None = None
    if "rows" in spec:
        rows_raw: Any = spec["rows"]
    elif "source" in spec:
        rows_raw, digest = _read_table_file(decls, name, spec, file, roots, vt)
    else:
        raise file.src.error("TABLE_INVALID", f"table {name} needs `rows` or `source`", "tables", name)
    if not isinstance(rows_raw, dict):
        raise file.src.error("TABLE_INVALID", f"table {name} rows must be a mapping", "tables", name)
    if len(rows_raw) > lim.max_table_rows:
        raise file.src.error("TABLE_INVALID", f"table {name} exceeds cpl.max_table_rows", "tables", name)
    rows: dict[str, Any] = {}
    for key, raw in rows_raw.items():
        try:
            key_value = check_value(kt, _key_wire(kt, key))
            norm = TableDef.norm(key_value)
            if norm in rows:
                raise EvalError("duplicate table key")
            rows[norm] = check_value(vt, raw)
        except EvalError as exc:
            raise file.src.error("TABLE_INVALID", f"table {name} row {key!r}: {exc}", "tables", name) from exc
    return TableDef(kt, vt, rows, digest)


def _key_wire(kt: Type, key: Any) -> Any:
    try:
        if kt.kind == "integer":
            return int(key)
        if kt.kind == "number":
            return Decimal(str(key))
        if kt.kind == "boolean":
            return {"true": True, "false": False}[str(key).lower()]
    except (ValueError, InvalidOperation, KeyError) as exc:
        raise EvalError("invalid table key") from exc
    return key


def _read_table_file(
    decls: DeclarationSet, name: str, spec: dict[str, Any], file: _File, roots: Sequence[Path], vt: Type
) -> tuple[dict[str, Any], str]:
    ref = str(spec["source"])
    path = file.path.parent / ref
    if (
        re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", ref)
        or Path(ref).is_absolute()
        or not any(_inside(r, path) for r in roots)
    ):
        raise file.src.error("IMPORT_FORBIDDEN", "table files must be inside an import root", "tables", name)
    try:
        if path.stat().st_size > decls.limits.max_table_bytes:
            raise file.src.error(
                "TABLE_INVALID", f"table file {ref} exceeds {decls.limits.max_table_bytes} bytes", "tables", name
            )
        data = path.read_bytes()
    except OSError as exc:
        raise file.src.error("IMPORT_NOT_FOUND", f"table file {ref} cannot be read", "tables", name) from exc
    data = data.replace(b"\r\n", b"\n")  # parse what is hashed: a CRLF checkout yields the same rows and digest
    digest = sha256_file(data)
    if spec.get("digest") not in (None, digest):
        raise file.src.error(
            "IMPORT_DIGEST_MISMATCH", f"table file {ref} differs from its pinned digest", "tables", name
        )
    fmt = spec.get("format") or path.suffix.lstrip(".")
    try:
        if fmt == "csv":
            return _csv_rows(data.decode("utf-8"), vt), digest
        parsed = parse_source(data, str(path), error_code="TABLE_INVALID", limits=decls.limits).data
    except (UnicodeDecodeError, csv.Error) as exc:
        raise file.src.error("TABLE_INVALID", f"table file {ref} is not valid {fmt}", "tables", name) from exc
    return parsed, digest


def _csv_rows(text: str, vt: Type) -> dict[str, Any]:
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames or "key" not in reader.fieldnames:
        raise EvalError("csv needs a `key` column")
    rows: dict[str, Any] = {}
    for record in reader:
        key = record.pop("key")
        if key in rows:
            raise EvalError("duplicate table key")
        if vt.kind == "object":
            rows[key] = {col: _csv_cell(vt.fields[col].type, cell) for col, cell in record.items() if col in vt.fields}
        else:
            rows[key] = _csv_cell(vt, record.get("value", ""))
    return rows


def _csv_cell(t: Type, cell: str) -> Any:
    try:
        if t.kind == "integer":
            return int(cell)
        if t.kind == "number":
            return Decimal(cell)
        if t.kind == "boolean":
            return {"true": True, "false": False}[cell.strip().lower()]
    except (ValueError, InvalidOperation, KeyError) as exc:
        raise EvalError("invalid csv cell") from exc
    return cell


def write_lock(decls: DeclarationSet, loader_rows: Sequence[Mapping[str, str]], path: Path) -> None:
    """`cpl.decl.lock`: sha256 digests only, never content."""
    payload = {
        "imports": list(loader_rows),
        "tables": [{"name": n, "digest": d} for n, d in sorted(decls.table_files.items())],
        "packs": [],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", "utf-8", newline="\n")
