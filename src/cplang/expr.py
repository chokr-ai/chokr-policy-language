"""Policy expressions: tokenizer, parser and the `Node` tree they produce, which structured conditions also use."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from decimal import Decimal, InvalidOperation
from typing import Any

from cplang.errors import AuthoringError

MACROS = ("all", "any", "filter", "map")
_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<func>[a-z0-9][a-z0-9.-]*/[a-z][a-z0-9_]*(?=\())
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||[<>+\-*/%!?:.,()\[\]{}])
""",
    re.VERBOSE | re.ASCII,
)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "/": "/"}


@dataclass(frozen=True)
class Node:
    """One node of a parsed expression: `k` is lit, path, op, call, macro (all, any, filter, map) or use.

    lit: `val` is the language value, `typ` its type label. path: `op` is the root name, `args` the parts (str or Node).
    op: `op` is the canonical operator, `args` operands, `opts` e.g. glob options. call: `op` is the function name.
    macro: `op` is the macro, `val` the element variable, `args` (collection, body).
    """

    k: str
    op: str | None = None
    args: tuple[Any, ...] = ()
    val: Any = None
    typ: str | None = None
    opts: dict[str, Any] = field(default_factory=dict)
    pos: int = 0

    def count(self) -> int:
        total = 1
        for a in self.args:
            if isinstance(a, Node):
                total += a.count()
        return total

    def canon(self) -> dict[str, Any]:
        """Canonical JSON of the node: no positions, operands never reordered."""
        from cplang.values import render, type_label

        if self.k == "lit":
            return {"k": "lit", "type": self.typ or type_label(self.val), "v": render(self.val)}
        out: dict[str, Any] = {"k": self.k}
        if self.op is not None:
            out["op"] = self.op
        if self.k == "macro":
            out["var"] = self.val
        if self.k == "use":
            out["with"] = {n: v.canon() for n, v in sorted(self.opts.items())}
        if self.args or self.k in ("op", "call", "path"):
            out["args"] = [a.canon() if isinstance(a, Node) else a for a in self.args]
        if self.opts and self.k == "op":
            out["opts"] = {k: _canon_option(self.opts[k]) for k in sorted(self.opts)}
        if self.k == "call" and self.opts.get("as_op"):  # `{f: x}` and `f(x)` read differently, so they differ here
            out["as_op"] = True
        return out


def reads_response(node: Node | None) -> bool:
    """Whether an expression reads `arguments.response`, the tool's reply, which exists only after the call."""
    if node is None:
        return False
    if node.k == "path" and node.op == "arguments" and node.args and node.args[0] == "response":
        return True
    return any(reads_response(a) for a in node.args if isinstance(a, Node))


def defer_response(node: Node, positive: bool = True) -> Node:
    """A guard as it reads before the call has run. A term that reads `arguments.response` cannot be checked yet, so it
    counts as not tripping (false, or true under a `not`); it is checked once the response exists. Every other term
    keeps its meaning."""
    if node.k == "op" and node.op in ("and", "or"):
        return replace(node, args=tuple(defer_response(a, positive) if isinstance(a, Node) else a for a in node.args))
    if node.k == "op" and node.op == "not":
        return replace(
            node, args=tuple(defer_response(a, not positive) if isinstance(a, Node) else a for a in node.args)
        )
    if reads_response(node):
        return lit(not positive, "boolean", node.pos)
    return node


def _canon_option(value: Any) -> Any:
    """An operator option in canonical form: types are written by name."""
    from cplang.types import Type

    if isinstance(value, Type):
        return str(value)
    if isinstance(value, dict):
        return {k: _canon_option(value[k]) for k in sorted(value)}
    if isinstance(value, list | tuple):
        return [_canon_option(v) for v in value]
    return value


def lit(value: Any, typ: str | None = None, pos: int = 0) -> Node:
    """A literal node."""
    return Node("lit", val=value, typ=typ, pos=pos)


class _Tok:
    __slots__ = ("kind", "pos", "text")

    def __init__(self, kind: str, text: str, pos: int) -> None:
        self.kind, self.text, self.pos = kind, text, pos


def _syntax(msg: str, src: str, pos: int) -> AuthoringError:
    err = AuthoringError("EXPRESSION_SYNTAX", msg).at_expression(pos + 1)
    err.path = src[:80]
    return err


def _lex(src: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i = 0
    while i < len(src):
        m = _TOKEN.match(src, i)
        if not m:
            raise _syntax(f"unexpected character {src[i]!r}", src, i)
        kind = m.lastgroup or ""
        if kind != "ws":
            toks.append(_Tok(kind, m.group(), i))
        i = m.end()
    toks.append(_Tok("eof", "", len(src)))
    return toks


def _unquote(text: str, src: str, pos: int) -> str:
    body, out, i = text[1:-1], [], 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "u":
            hexa = body[i + 2 : i + 6]
            if len(hexa) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", hexa):
                raise _syntax("invalid \\u escape", src, pos + i)
            out.append(chr(int(hexa, 16)))
            i += 6
        elif nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
        else:
            raise _syntax(f"invalid escape \\{nxt}", src, pos + i)
    return "".join(out)


_BINARY = {
    "||": (1, "or"),
    "&&": (2, "and"),
    "==": (3, "eq"),
    "!=": (3, "ne"),
    "<": (3, "lt"),
    "<=": (3, "lte"),
    ">": (3, "gt"),
    ">=": (3, "gte"),
    "in": (3, "in"),
    "+": (4, "add"),
    "-": (4, "sub"),
    "*": (5, "mul"),
    "/": (5, "div"),
    "%": (5, "mod"),
}
_MAX_DEPTH = 64


class _Parser:
    def __init__(self, src: str) -> None:
        self.src, self.toks, self.i, self.depth = src, _lex(src), 0, 0

    @property
    def tok(self) -> _Tok:
        return self.toks[self.i]

    def take(self) -> _Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def expect(self, text: str) -> _Tok:
        if self.tok.text != text or self.tok.kind in ("str",):
            raise _syntax(f"expected {text!r}", self.src, self.tok.pos)
        return self.take()

    def parse(self) -> Node:
        node = self.expr(0)
        if self.tok.kind != "eof":
            raise _syntax(f"unexpected {self.tok.text!r}", self.src, self.tok.pos)
        return node

    def expr(self, min_bp: int) -> Node:
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise AuthoringError("EXPRESSION_LIMIT", "expression is nested too deeply")
        left = self.unary()
        compared = False
        while True:
            tok = self.tok
            text = tok.text if tok.kind in ("op", "ident") else ""
            if text == "?" and min_bp == 0:
                self.take()
                yes = self.expr(0)
                self.expect(":")
                no = self.expr(0)
                left = Node("op", "tern", (left, yes, no), pos=tok.pos)
                break
            spec = _BINARY.get(text) if not (tok.kind == "ident" and text != "in") else None
            if spec is None or spec[0] < min_bp:
                break
            bp, name = spec
            if bp == 3:
                if compared:
                    raise _syntax("comparison operators do not chain", self.src, tok.pos)
                compared = True
            self.take()
            right = self.expr(bp + 1)
            left = Node("op", name, (left, right), pos=tok.pos)
        self.depth -= 1
        return left

    def unary(self) -> Node:
        tok = self.tok
        if tok.kind == "op" and tok.text in ("!", "-"):
            self.take()
            self.depth += 1
            if self.depth > _MAX_DEPTH:
                raise AuthoringError("EXPRESSION_LIMIT", "expression is nested too deeply")
            operand = self.unary()
            self.depth -= 1
            if tok.text == "-" and operand.k == "lit" and operand.typ in ("integer", "number"):
                return lit(-operand.val, operand.typ, tok.pos)
            return Node("op", "not" if tok.text == "!" else "neg", (operand,), pos=tok.pos)
        return self.postfix(self.primary())

    def postfix(self, node: Node) -> Node:
        while True:
            tok = self.tok
            if tok.kind == "op" and tok.text == "." and node.k in ("path",):
                self.take()
                name = self.take()
                if name.kind != "ident":
                    raise _syntax("expected a name after '.'", self.src, name.pos)
                node = Node("path", node.op, (*node.args, name.text), pos=node.pos)
            elif tok.kind == "op" and tok.text == ".":
                self.take()
                name = self.take()
                if name.kind != "ident":
                    raise _syntax("expected a name after '.'", self.src, name.pos)
                node = Node("op", "at", (node, lit(name.text, "string")), pos=tok.pos)
            elif tok.kind == "op" and tok.text == "[" and node.k == "path":
                self.take()
                idx = self.expr(0)
                self.expect("]")
                node = Node("path", node.op, (*node.args, idx), pos=node.pos)
            elif tok.kind == "op" and tok.text == "[":
                self.take()
                idx = self.expr(0)
                self.expect("]")
                node = Node("op", "at", (node, idx), pos=tok.pos)
            elif tok.kind == "op" and tok.text == "(" and node.k == "path":
                node = self.call(node)
            else:
                return node

    def args_of_call(self) -> list[Node]:
        self.expect("(")
        args: list[Node] = []
        while not (self.tok.kind == "op" and self.tok.text == ")"):
            if args:
                self.expect(",")
            args.append(self.expr(0))
        self.expect(")")
        return args

    def call(self, path: Node) -> Node:
        args = self.args_of_call()
        names = list(path.args)
        root = path.op or ""
        if root == "fn" and 1 <= len(names) <= 2 and all(isinstance(x, str) for x in names):
            return Node("call", "fn." + ".".join(names), tuple(args), pos=path.pos)
        if names:
            raise _syntax("only declared functions and built-ins can be called", self.src, path.pos)
        if root in MACROS:
            return self._macro(root, args, path.pos)
        return Node("call", root, tuple(args), pos=path.pos)

    def _macro(self, name: str, args: list[Node], pos: int) -> Node:
        if len(args) == 2:
            return Node("macro", name, (args[0], args[1]), val="it", pos=pos)
        if len(args) == 3 and args[1].k == "path" and not args[1].args:
            return Node("macro", name, (args[0], args[2]), val=args[1].op, pos=pos)
        raise _syntax(f"{name}(collection, predicate) or {name}(collection, name, predicate)", self.src, pos)

    def primary(self) -> Node:
        tok = self.take()
        if tok.kind == "num":
            if any(c in tok.text for c in ".eE"):
                try:
                    number = Decimal(tok.text)
                except InvalidOperation as exc:
                    raise _syntax("invalid number", self.src, tok.pos) from exc
                if abs(number.adjusted()) > 6000:
                    raise _syntax("number out of range", self.src, tok.pos)
                return lit(number, "number", tok.pos)
            whole = int(tok.text)
            if whole > 2**63 - 1:
                raise _syntax("integer outside signed 64-bit", self.src, tok.pos)
            return lit(whole, "integer", tok.pos)
        if tok.kind == "str":
            return lit(_unquote(tok.text, self.src, tok.pos), "string", tok.pos)
        if tok.kind == "func":
            return Node("call", tok.text, tuple(self.args_of_call()), pos=tok.pos)
        if tok.kind == "ident":
            if tok.text in ("true", "false"):
                return lit(tok.text == "true", "boolean", tok.pos)
            return Node("path", tok.text, (), pos=tok.pos)
        if tok.kind == "op" and tok.text == "(":
            inner = self.expr(0)
            self.expect(")")
            return inner
        if tok.kind == "op" and tok.text == "[":
            items: list[Node] = []
            while not (self.tok.kind == "op" and self.tok.text == "]"):
                if items:
                    self.expect(",")
                items.append(self.expr(0))
            self.expect("]")
            return Node("op", "list", tuple(items), pos=tok.pos)
        if tok.kind == "op" and tok.text == "{":
            pairs: list[Node] = []
            while not (self.tok.kind == "op" and self.tok.text == "}"):
                if pairs:
                    self.expect(",")
                key = self.take()
                if key.kind == "str":
                    kname = _unquote(key.text, self.src, key.pos)
                elif key.kind == "ident":
                    kname = key.text
                else:
                    raise _syntax("map keys are names or strings", self.src, key.pos)
                self.expect(":")
                pairs.append(Node("op", "entry", (lit(kname, "string"), self.expr(0)), pos=key.pos))
            self.expect("}")
            return Node("op", "map", tuple(pairs), pos=tok.pos)
        raise _syntax(f"unexpected {tok.text or 'end of expression'!r}", self.src, tok.pos)


def parse_expression(src: str) -> Node:
    """Parse `src`. Raises EXPRESSION_SYNTAX with a 1-based column. Never evaluates anything."""
    if not isinstance(src, str) or not src.strip():
        raise _syntax("empty expression", str(src), 0)
    return _Parser(src).parse()
