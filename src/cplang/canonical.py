"""Canonical JSON (RFC 8785) for digests and fingerprints, with a nesting limit."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from cplang.errors import CanonicalizationError

MAX_DEPTH = 200  # deepest nesting accepted; callers may lower it


def _check_depth(obj: Any, max_depth: int) -> None:
    """Reject values nested deeper than `max_depth`; the root container is level 1."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, dict):
            children: Any = cur.values()
        elif isinstance(cur, (list, tuple)):
            children = cur
        else:
            continue
        if depth > max_depth:
            raise CanonicalizationError(f"nesting exceeds {max_depth} levels")
        stack.extend((c, depth + 1) for c in children)


def canonicalize(obj: Any, *, max_depth: int = MAX_DEPTH) -> bytes:
    """Serialize `obj` as canonical JSON bytes (RFC 8785); unsupported values raise `CanonicalizationError`."""
    if not 1 <= max_depth <= MAX_DEPTH:
        raise ValueError("max_depth must be 1..200")
    _check_depth(obj, max_depth)
    try:
        return rfc8785.dumps(obj)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError(str(exc)) from exc
    except (TypeError, ValueError, RecursionError) as exc:
        raise CanonicalizationError(type(exc).__name__) from exc


def digest_sha256(data: bytes) -> str:
    """The `sha256:` digest of `data`."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_object(obj: Any, *, max_depth: int = MAX_DEPTH) -> str:
    """The `sha256:` digest of the canonical JSON of `obj`."""
    return digest_sha256(canonicalize(obj, max_depth=max_depth))
