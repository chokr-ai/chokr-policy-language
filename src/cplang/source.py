"""Strict YAML/JSON loading with source positions and decimal numbers.

Numbers without a fraction or exponent are `int`; every other numeral is a `Decimal` parsed from its text.
Duplicate keys, anchors, aliases, merge keys, custom tags, `.inf`, `.nan`, a BOM and oversized documents are
reported as errors.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from cplang.errors import AuthoringError
from cplang.runtime import CplLimits

_CORE_TAG_PREFIX = "tag:yaml.org,2002:"
_ALLOWED_TAGS = {_CORE_TAG_PREFIX + t for t in ("str", "int", "float", "bool", "null", "map", "seq")}
Path_ = tuple[str | int, ...]


@dataclass
class Source:
    """A parsed document: plain data plus the (line, column), both 1-based, of every key and value."""

    file: str
    data: Any
    positions: dict[Path_, tuple[int, int]] = field(default_factory=dict)

    def where(self, *path: str | int) -> tuple[str, int | None, int | None]:
        """Position of `path`, falling back to the nearest parent that has one."""
        key = tuple(path)
        while key:
            if key in self.positions:
                pos = self.positions[key]
                return self.file, pos[0], pos[1]
            key = key[:-1]
        root = self.positions.get(())
        return (self.file, root[0], root[1]) if root else (self.file, None, None)

    def error(self, code: str, message: str, *path: str | int) -> AuthoringError:
        file, line, col = self.where(*path)
        return AuthoringError(code, message, file=file, line=line, column=col, path=".".join(str(p) for p in path))


def _check_nodes(root: Node, fail: Any) -> None:
    """Walk the node tree iteratively and reject anchors (and so aliases), merge keys and custom tags."""
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        if getattr(node, "anchor", None):
            raise fail("YAML anchors and aliases are not allowed", node.start_mark.line + 1, node.start_mark.column + 1)
        tag = node.tag or ""
        if tag not in _ALLOWED_TAGS:
            if tag.startswith(_CORE_TAG_PREFIX):  # dates, binary data and the like: text must be quoted
                raise fail(
                    "only strings, numbers, booleans, null, lists and mappings are allowed; quote dates and text",
                    node.start_mark.line + 1,
                    node.start_mark.column + 1,
                )
            raise fail("custom YAML tags are not allowed", node.start_mark.line + 1, node.start_mark.column + 1)
        if isinstance(node, MappingNode):
            for key, value in node.value:
                if isinstance(key, ScalarNode) and key.value == "<<" and (key.tag or "").endswith("merge"):
                    raise fail("YAML merge keys are not allowed", key.start_mark.line + 1, key.start_mark.column + 1)
                stack.extend((key, value))
        elif isinstance(node, SequenceNode):
            stack.extend(node.value)


def read_source(path: Path, limits: CplLimits | None = None) -> Source:
    """Read and parse a YAML or JSON file, keeping the position of every key and value."""
    try:
        if limits is not None and path.stat().st_size > limits.max_document_bytes:  # refuse before reading it all
            raise AuthoringError(
                "SCHEMA_INVALID", f"document exceeds {limits.max_document_bytes} bytes", file=str(path)
            )
        data = path.read_bytes()
    except OSError as exc:
        raise AuthoringError("IMPORT_NOT_FOUND", "file cannot be read", file=str(path)) from exc
    return parse_source(data, str(path), limits=limits)


def parse_source(
    data: bytes, file: str, *, error_code: str = "SCHEMA_INVALID", limits: CplLimits | None = None
) -> Source:
    """Parse YAML or JSON text, keeping positions; errors are reported with `error_code`."""
    limits = limits or CplLimits()

    def fail(message: str, line: int | None = None, col: int | None = None) -> AuthoringError:
        return AuthoringError(error_code, message, file=file, line=line, column=col)

    if len(data) > limits.max_document_bytes:
        raise fail(f"document exceeds {limits.max_document_bytes} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise fail("BOM is not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise fail("document is not valid UTF-8") from exc
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("%"):  # a `%YAML 1.1` directive would switch to looser scalar rules
            raise fail("YAML directives are not allowed")
        if stripped and not stripped.startswith("#"):
            break
    if file.endswith(".json"):
        try:
            json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise fail("document is not valid JSON") from exc
    yaml = YAML(typ="safe", pure=True)
    yaml.allow_duplicate_keys = False
    try:
        nodes = list(yaml.compose_all(io.StringIO(text)))
        if len(nodes) != 1:
            raise fail("exactly one YAML document is required")
        _check_nodes(nodes[0], fail)
        src = Source(file, None)
        src.data = _build(nodes[0], yaml, src, (), 0, fail, limits.max_document_depth)
    except AuthoringError:
        raise
    except YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = (mark.line + 1, mark.column + 1) if mark else (None, None)
        raise fail("document is not valid YAML", *where) from exc
    return src


def _build(node: Node, yaml: YAML, src: Source, path: Path_, depth: int, fail: Any, max_depth: int) -> Any:
    if depth > max_depth:
        raise fail("document is nested too deeply")
    src.positions[path] = (node.start_mark.line + 1, node.start_mark.column + 1)
    if isinstance(node, MappingNode):
        out: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode) or not isinstance(yaml.constructor.construct_object(key_node), str):
                raise fail("mapping keys must be strings", key_node.start_mark.line + 1, key_node.start_mark.column + 1)
            key = key_node.value
            if key in out:
                raise fail(f"duplicate key {key!r}", key_node.start_mark.line + 1, key_node.start_mark.column + 1)
            out[key] = _build(value_node, yaml, src, (*path, key), depth + 1, fail, max_depth)
            src.positions[(*path, key)] = (key_node.start_mark.line + 1, key_node.start_mark.column + 1)
        return out
    if isinstance(node, SequenceNode):
        return [_build(item, yaml, src, (*path, i), depth + 1, fail, max_depth) for i, item in enumerate(node.value)]
    if not isinstance(node, ScalarNode):
        raise fail("unsupported YAML node", node.start_mark.line + 1, node.start_mark.column + 1)
    if node.tag == "tag:yaml.org,2002:float":
        text = node.value.replace("_", "")
        try:
            number = Decimal(text)
        except InvalidOperation as exc:
            raise fail("invalid number", node.start_mark.line + 1, node.start_mark.column + 1) from exc
        if not number.is_finite():
            raise fail(".inf and .nan are not allowed", node.start_mark.line + 1, node.start_mark.column + 1)
        if abs(number.adjusted()) > 6000:
            raise fail("number out of range", node.start_mark.line + 1, node.start_mark.column + 1)
        return number
    value = yaml.constructor.construct_object(node, deep=True)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise fail("text contains a lone surrogate", node.start_mark.line + 1, node.start_mark.column + 1) from None
    return value
