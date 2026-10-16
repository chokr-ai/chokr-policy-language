"""Structured conditions: turns YAML condition blocks such as `{arguments.n: {gt: 1}}` into the same parsed form
that text expressions produce."""

from __future__ import annotations

import re
from collections.abc import Callable, Collection
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from cplang.errors import AuthoringError
from cplang.expr import Node, lit, parse_expression
from cplang.inputs import CONDITION_ROOTS
from cplang.source import Source

if TYPE_CHECKING:
    from cplang.compile import DeclLike
    from cplang.declarations import DeclarationSet

OPERATORS = (
    "eq",
    "ne",
    "in",
    "nin",
    "gt",
    "gte",
    "lt",
    "lte",
    "between",
    "regex",
    "glob",
    "exists",
    "contains",
    "starts_with",
    "len_gt",
    "len_lt",
)
_MODIFIERS = ("negate", "sep", "case_insensitive", "normalize")
ADMISSION_KEYS = ("deny", "immutable_params", "bounded_params", "max_calls_per_window", "thresholds", "approval")
_WINDOWS = ("1m", "5m", "10m", "30m", "1h")

# shorthand key -> (path, glob options)
_GLOB_SUGAR: dict[str, tuple[str, dict[str, Any]]] = {
    "target": ("target.name", {}),
    "command_matches": ("arguments.command", {"normalize": "command"}),
    "path_matches": ("arguments.path", {"sep": "/", "normalize": "path"}),
    "domain_matches": ("target.destination_host", {"sep": "."}),
    "url_matches": ("arguments.url", {"sep": "/"}),
    "response_matches": ("arguments.response", {}),
}
_NEGATED_SUGAR: dict[str, str] = {
    "command_not_matches": "command_matches",
    "path_not_matches": "path_matches",
    "response_not_matches": "response_matches",
}
SUGAR_KEYS = (*_GLOB_SUGAR, *_NEGATED_SUGAR, "arguments_match", "domain_suffix", "default")


def _py_lit(value: Any, pos: int = 0) -> Node:
    if type(value) is bool:
        return lit(value, "boolean", pos)
    if type(value) is int:
        return lit(value, "integer", pos)
    if isinstance(value, Decimal):
        return lit(value, "number", pos)
    if isinstance(value, str):
        return lit(value, "string", pos)
    raise AuthoringError("SCHEMA_INVALID", "a literal is a string, number or boolean")


def pointer_parts(pointer: str) -> tuple[str, ...]:
    """Split a JSON pointer such as `/a/b` into its unescaped parts."""
    return tuple(p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:])


def path_node(text: str) -> Node:
    """A dotted path (`attributes.q.value`), an expression path (`table.t[attributes.k]`) or an arguments pointer."""
    if text.startswith("arguments./"):
        return Node("path", "arguments", pointer_parts(text[len("arguments") :]))
    node = parse_expression(text)
    if node.k != "path":
        raise AuthoringError("SCHEMA_INVALID", f"{text!r} is not a path")
    return node


_DECLARED_ROOTS = {"param": "parameters", "const": "constants", "table": "tables", "computed": "computed"}


def private_reference(node: Node, decls: DeclLike) -> str | None:
    """The first declaration `node` names that is private to its file (`private: true`, or left out of every import's
    `only:`), or None. Policies may not name these; declarations still use them as dependencies."""
    if not decls.private:
        return None
    first = node.args[0] if node.args and isinstance(node.args[0], str) else None
    if node.k == "path" and first is not None and node.op in _DECLARED_ROOTS:
        kind = _DECLARED_ROOTS[node.op]
        if (kind, first) in decls.private:
            return f"{node.op}.{first}"
        second = node.args[1] if len(node.args) > 1 and isinstance(node.args[1], str) else None
        aliased = second is not None and getattr(decls, node.op)(first) is None  # resolved as Compiler._pick does
        if aliased and (kind, f"{first}.{second}") in decls.private:
            return f"{node.op}.{first}.{second}"
    elif node.k == "path" and node.op == "attributes" and first is not None:
        if ("attributes", first) in decls.private:
            return f"attributes.{first}"
    elif node.k == "path" and node.op is not None and ("types", node.op) in decls.private:
        return f"type {node.op}"
    elif node.k == "call" and (node.op or "").startswith("fn.") and ("functions", (node.op or "")[3:]) in decls.private:
        return node.op
    for arg in node.args:
        if isinstance(arg, Node) and (found := private_reference(arg, decls)) is not None:
            return found
    return None


class ConditionBuilder:
    """Builds parsed expressions (`Node` objects) from condition mappings. `where` locates the block inside `src` for
    error messages."""

    def __init__(
        self,
        src: Source,
        decls: DeclarationSet,
        *,
        in_match: bool = False,
        check_signal_code: Callable[[str, tuple[str | int, ...]], None] | None = None,
        host_keys: Collection[str] = (),
        host_roots: Collection[str] = (),
        public_only: bool = False,
    ) -> None:
        self.src, self.decls, self.in_match = src, decls, in_match
        self.check_signal_code = check_signal_code
        self.host_keys, self.host_roots = frozenset(host_keys), frozenset(host_roots)
        self.public_only = public_only  # building a policy's text, which may not name private declarations
        self.use_stack: tuple[str, ...] = ()

    def fail(self, message: str, *where: str | int, code: str = "SCHEMA_INVALID") -> AuthoringError:
        return self.src.error(code, message, *where)

    def _public(self, node: Node, where: tuple[str | int, ...]) -> Node:
        name = private_reference(node, self.decls) if self.public_only else None
        if name is not None:
            raise self.fail(f"{name} is private to its declaration file", *where, code="DECLARATION_UNKNOWN_NAME")
        return node

    def _public_name(self, kind: str, name: str, where: tuple[str | int, ...]) -> None:
        if self.public_only and (kind, name) in self.decls.private:
            raise self.fail(
                f"{kind[:-1]} {name} is private to its declaration file", *where, code="DECLARATION_UNKNOWN_NAME"
            )

    def value(self, raw: Any, where: tuple[str | int, ...]) -> Node:
        """A literal, `{ref: name}`, `{expr: "..."}`, `{literal: ...}`, or a list of those."""
        if isinstance(raw, dict):
            if set(raw) == {"ref"} and isinstance(raw["ref"], str):
                return self._parse(raw["ref"], (*where, "ref"))
            if set(raw) == {"expr"} and isinstance(raw["expr"], str):
                return self._parse(raw["expr"], (*where, "expr"))
            if set(raw) == {"literal"}:
                return self._literal(raw["literal"], (*where, "literal"))
            raise self.fail("a value is a literal, {ref: ...}, {expr: ...} or {literal: ...}", *where)
        return self._literal(raw, where)

    def _literal(self, raw: Any, where: tuple[str | int, ...]) -> Node:
        if isinstance(raw, list):
            return Node("op", "list", tuple(self.value(v, (*where, i)) for i, v in enumerate(raw)))
        if isinstance(raw, dict):
            return Node(
                "op",
                "map",
                tuple(
                    Node("op", "entry", (lit(k, "string"), self.value(v, (*where, k)))) for k, v in sorted(raw.items())
                ),
            )
        try:
            return _py_lit(raw)
        except AuthoringError as exc:
            raise self.fail(exc.message, *where) from exc

    def _parse(self, text: str, where: tuple[str | int, ...]) -> Node:
        try:
            node = parse_expression(text)
        except AuthoringError as exc:
            raise exc.located(*self.src.where(*where)) from exc
        return self._public(node, where)

    def path(self, text: Any, where: tuple[str | int, ...]) -> Node:
        if not isinstance(text, str):
            raise self.fail("a condition key is a path", *where)
        try:
            node = path_node(text)
        except AuthoringError as exc:
            raise exc.located(*self.src.where(*where)) from exc
        return self._public(node, where)

    def block(self, cond: Any, where: tuple[str | int, ...], *, allow_admission: bool = False) -> Node:
        """AND of every entry of a condition mapping. An empty block is true."""
        if cond is None or cond == {}:
            return lit(True, "boolean")
        if not isinstance(cond, dict):
            raise self.fail("a condition is a mapping", *where)
        nodes: list[Node | None] = []
        if "use" in cond:
            nodes.append(self.use(cond["use"], cond.get("with") or {}, where))
        nodes += [self.entry(k, v, (*where, k), allow_admission) for k, v in cond.items() if k not in ("use", "with")]
        built = [n for n in nodes if n is not None]
        if not built:
            return lit(True, "boolean")
        return built[0] if len(built) == 1 else Node("op", "and", tuple(built))

    def entry(self, key: str, value: Any, where: tuple[str | int, ...], allow_admission: bool) -> Node | None:
        if key in ADMISSION_KEYS or key in self.host_keys:
            if not allow_admission:
                raise self.fail(f"{key} is an admission requirement and is not allowed here", *where)
            return None
        if key in ("any", "all"):
            if not isinstance(value, list) or not value:
                raise self.fail(f"{key} is a non-empty list of conditions", *where)
            return Node(
                "op", "or" if key == "any" else "and", tuple(self.block(v, (*where, i)) for i, v in enumerate(value))
            )
        if key == "not":
            return Node("op", "not", (self.block(value, where),))
        if key == "signal":
            return self.signal(value, where)
        if key == "expr":
            if not isinstance(value, str):
                raise self.fail("expr is a string", *where)
            return self._parse(value, where)
        if key == "use":
            raise self.fail("use needs a `with` sibling and is handled by the rule", *where)
        if key in ("time", "time.window"):
            return self.time_window(
                value["window"] if key == "time" and isinstance(value, dict) and "window" in value else value, where
            )
        if key == "default":
            if value is not True:
                raise self.fail("default is `true`", *where)
            return lit(True, "boolean")
        if key in SUGAR_KEYS:
            return self.sugar(key, value, where)
        shortcut = self.decls.shortcuts.get(key)
        if shortcut is not None:
            self._public_name("shortcuts", key, where)
            return self._glob_sugar(shortcut["path"], shortcut["glob"], value, where)
        head = key.split(".", 1)[0].split("[", 1)[0]
        known = head in CONDITION_ROOTS or head in self.host_roots or head in self.decls.inputs
        if known or "/" in key:
            return self.operators(self.path(key, where), value, where)
        if not self.decls.strict_inputs:
            try:
                target = self.path(key, where)
            except AuthoringError:
                pass
            else:
                return self.operators(target, value, where)
        raise self.fail(f"unknown condition key {key!r} (declare an input of that name to use it)", *where)

    def operators(self, target: Node, spec: Any, where: tuple[str | int, ...]) -> Node:
        if isinstance(spec, list):
            op = "glob_any" if self.in_match else "in"
            if op == "glob_any":
                return Node(
                    "op",
                    "or",
                    tuple(Node("op", "glob", (target, self.value(v, (*where, i)))) for i, v in enumerate(spec)),
                )
            return Node("op", "in", (target, self.value(spec, where)))
        if not isinstance(spec, dict) or (spec and set(spec) <= {"ref", "literal", "expr"}):
            return Node("op", "eq", (target, self.value(spec, where)))  # `<path>: value` means eq
        if not set(spec) - set(_MODIFIERS):
            raise self.fail("a condition needs at least one operator", *where)
        opts = {k: spec[k] for k in ("sep", "case_insensitive", "normalize") if k in spec}
        nodes: list[Node] = []
        for op, raw in spec.items():
            if op in _MODIFIERS:
                continue
            nodes.append(self._operator(op, target, raw, opts, (*where, op)))
        combined = nodes[0] if len(nodes) == 1 else Node("op", "and", tuple(nodes))
        return Node("op", "not", (combined,)) if spec.get("negate") is True else combined

    def _operator(self, op: str, target: Node, raw: Any, opts: dict[str, Any], where: tuple[str | int, ...]) -> Node:
        if "/" in op:  # a host-registered function used as an operator
            return Node("call", op, (target, self.value(raw, where)), opts={"as_op": True})
        if op not in OPERATORS:
            raise self.fail(f"operator {op!r} is outside the language's operator set", *where)
        if op == "exists":
            if type(raw) is not bool:
                raise self.fail("exists is true or false", *where)
            return Node("op", "exists", (target,), opts={"expect": raw})
        if op == "between":
            if not isinstance(raw, list) or len(raw) != 2:
                raise self.fail("between is [low, high]", *where)
            lo, hi = (self.value(v, (*where, i)) for i, v in enumerate(raw))
            if lo.k == "lit" and hi.k == "lit" and isinstance(lo.val, int | Decimal) and lo.val > hi.val:
                raise self.fail("between: low is greater than high", *where)
            return Node("op", "between", (target, lo, hi))
        if op == "glob":
            return Node("op", "glob", (target, self.value(raw, where)), opts=opts)
        return Node("op", op, (target, self.value(raw, where)))

    def use(self, name: Any, with_: Any, where: tuple[str | int, ...]) -> Node:
        """Expand a named condition: its body is built in its own file, parameters become locals."""
        cdef = self.decls.conditions.get(name) if isinstance(name, str) else None
        if cdef is None:
            raise self.fail(f"unknown condition {name!r}", *where, "use", code="DECLARATION_UNKNOWN_NAME")
        if not isinstance(with_, dict) or set(with_) != set(cdef.params):
            raise self.fail(
                f"condition {name} takes parameters: {', '.join(cdef.params) or 'none'}",
                *where,
                "with",
                code="TYPE_ERROR",
            )
        if name in self.use_stack:
            raise self.fail(f"condition {name} uses itself", *where, code="DECLARATION_INVALID")
        self._public_name("conditions", name, (*where, "use"))
        inner = ConditionBuilder(
            cdef.src or self.src,
            self.decls,
            in_match=self.in_match,
            check_signal_code=self.check_signal_code,
            host_keys=self.host_keys,
            host_roots=self.host_roots,
            public_only=self.public_only and cdef.in_policy,  # a declared condition's body may use its dependencies
        )
        inner.use_stack = (*self.use_stack, name)
        body = inner.block(cdef.when, ("conditions", name, "when"))
        values = tuple(self.value(with_[p], (*where, "with", p)) for p in cdef.params)
        return Node("op", "with_locals", (body, *values), opts={"names": list(cdef.params), "types": cdef.params})

    def signal(self, spec: Any, where: tuple[str | int, ...]) -> Node:
        allowed = {"code", "code_prefix", "source", "severity_gte", "confidence_gte", "count_gte", "facts"}
        if not isinstance(spec, dict) or not spec or set(spec) - allowed:
            raise self.fail(
                "signal takes code, code_prefix, source, severity_gte, confidence_gte, count_gte, facts", *where
            )
        facts = spec.get("facts")
        if "facts" in spec and (
            not isinstance(facts, dict)
            or not facts
            or not all(
                isinstance(k, str)
                and (
                    isinstance(v, str | bool | int)
                    or (isinstance(v, list) and v and all(isinstance(x, str | bool | int) for x in v))
                )
                for k, v in facts.items()
            )
        ):
            raise self.fail("facts maps a fact name to a string, boolean, integer or a list of them", *where, "facts")
        severities = ("info", "low", "medium", "high", "critical")
        if "severity_gte" in spec and spec["severity_gte"] not in severities:
            raise self.fail("severity_gte is info, low, medium, high or critical", *where, "severity_gte")
        if "count_gte" in spec and (type(spec["count_gte"]) is not int or spec["count_gte"] < 1):
            raise self.fail("count_gte is an integer >= 1", *where, "count_gte")
        if "confidence_gte" in spec and not (
            isinstance(spec["confidence_gte"], int | Decimal) and 0 <= spec["confidence_gte"] <= 1
        ):
            raise self.fail("confidence_gte is a number between 0 and 1", *where, "confidence_gte")
        if "code" in spec and self.check_signal_code is not None:
            self.check_signal_code(str(spec["code"]), (*where, "code"))
        return Node("op", "signal", (), opts=dict(spec))

    def time_window(self, spec: Any, where: tuple[str | int, ...]) -> Node:
        if not isinstance(spec, dict) or set(spec) - {"days", "from", "to", "tz"} or not {"from", "to"} <= set(spec):
            raise self.fail("time.window takes days, from, to, tz", *where)
        days = spec.get("days", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
        if not isinstance(days, list) or any(d not in ("mon", "tue", "wed", "thu", "fri", "sat", "sun") for d in days):
            raise self.fail("days are mon..sun", *where, "days")
        for edge in ("from", "to"):
            if not (isinstance(spec[edge], str) and re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", spec[edge])):
                raise self.fail(f"{edge} is HH:MM", *where, edge)
        tz = spec.get("tz", "UTC")
        if not (isinstance(tz, str) and re.fullmatch(r"UTC|[+-](0\d|1\d|2[0-3]):[0-5]\d", tz)):
            raise self.fail(
                "tz is UTC or a fixed offset +HH:MM (IANA names are not supported)", *where, "tz", code="TYPE_ERROR"
            )
        return Node(
            "op", "time_window", (), opts={"days": list(days), "from": spec["from"], "to": spec["to"], "tz": tz}
        )

    def sugar(self, key: str, value: Any, where: tuple[str | int, ...]) -> Node:
        if key in _GLOB_SUGAR:
            path, opts = _GLOB_SUGAR[key]
            return self._glob_sugar(path, opts, value, where)
        if key in _NEGATED_SUGAR:
            path, opts = _GLOB_SUGAR[_NEGATED_SUGAR[key]]
            return Node("op", "not", (self._glob_sugar(path, opts, value, where),))
        if key == "arguments_match":
            if not isinstance(value, dict) or not value:
                raise self.fail("arguments_match is {parameter: pattern}", *where)
            return Node(
                "op",
                "and",
                tuple(
                    Node(
                        "op",
                        "glob",
                        (Node("path", "arguments", (p,)), self.value(v, (*where, p))),
                        opts={"case_insensitive": True},
                    )
                    for p, v in sorted(value.items())
                ),
            )
        if key == "domain_suffix":
            if not isinstance(value, str) or not value:
                raise self.fail("domain_suffix is a non-empty string", *where)
            host = path_node("target.destination_host")
            return Node(
                "op",
                "or",
                (
                    Node("op", "eq", (host, lit(value, "string"))),
                    Node("op", "glob", (host, lit("*." + value, "string"))),
                ),
            )
        raise self.fail(f"unknown sugar key {key!r}", *where)

    def _glob_sugar(self, path: str, opts: dict[str, Any], value: Any, where: tuple[str | int, ...]) -> Node:
        target = path_node(path)
        patterns = value if isinstance(value, list) else [value]
        if not patterns:
            raise self.fail("a pattern list cannot be empty", *where)
        nodes = [
            Node("op", "glob", (target, self.value(v, (*where, i))), opts=dict(opts)) for i, v in enumerate(patterns)
        ]
        return nodes[0] if len(nodes) == 1 else Node("op", "or", tuple(nodes))
