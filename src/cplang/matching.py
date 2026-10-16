"""Glob and regex matching. Regex is RE2 only (linear time); glob is a small deterministic matcher."""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Any

import re2

from cplang.values import EvalError

MAX_REGEX_LEN = 1024
_FLAG_GROUP = re.compile(r"\(\?([A-Za-z-]*)[:)]")


@lru_cache(maxsize=2048)
def compile_regex(pattern: str, max_len: int = MAX_REGEX_LEN) -> Any:
    """Compile an RE2 pattern. Raises ValueError (message = reason only) for a pattern the language forbids."""
    if len(pattern) > max_len:
        raise ValueError("regex pattern is too long")
    if "\\C" in pattern:
        raise ValueError("regex \\C is not allowed")
    for flags in _FLAG_GROUP.findall(pattern):
        if set(flags) - set("imsU-"):
            raise ValueError("regex flag is not allowed")
    try:
        options = re2.Options()
        options.max_mem = 8 * 1024 * 1024
        return re2.compile(pattern, options)
    except Exception as exc:  # re2.error is not a stable public type
        raise ValueError("invalid RE2 pattern") from exc


def regex_search(pattern: str, text: str, max_len: int = MAX_REGEX_LEN) -> bool:
    """True when the RE2 `pattern` matches anywhere in `text`."""
    try:
        compiled = compile_regex(pattern, max_len)
        return compiled.search(text) is not None
    except ValueError as exc:
        raise EvalError(str(exc)) from exc


def _normalize(text: str, mode: str | None) -> str:
    if mode == "command":
        from cplang.normalize import normalize_command

        text = normalize_command(text)
    elif mode == "path":
        from cplang.normalize import normalize_path

        text = normalize_path(text)
    return unicodedata.normalize("NFC", text)


def glob_match(
    pattern: str, text: str, *, sep: str | None = None, case_insensitive: bool = False, normalize: str | None = None
) -> bool:
    """Whole-string match: `*` any run, `?` one code point, `[abc]`/`[a-z]`/`[!abc]`, `\\` escape; with `sep`,
    `*`, `?` and classes never match `sep` and `**` crosses it."""
    text = _normalize(text, normalize)
    pattern = unicodedata.normalize("NFC", pattern)  # the pattern is compared in the same form as the text
    if case_insensitive:
        pattern, text = pattern.casefold(), text.casefold()
    return _glob(_tokens(pattern, sep), text, sep)


@lru_cache(maxsize=2048)
def _tokens(pattern: str, sep: str | None) -> tuple[tuple[str, Any], ...]:
    out: list[tuple[str, Any]] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            out.append(("lit", pattern[i + 1]))
            i += 2
        elif c == "*":
            j = i
            while j < n and pattern[j] == "*":
                j += 1
            out.append(("deep" if (j - i >= 2 and sep) else "star", None))
            i = j
        elif c == "?":
            out.append(("any", None))
            i += 1
        elif c == "[":
            end = pattern.find("]", i + 2)
            if end < 0:
                out.append(("lit", c))
                i += 1
                continue
            body = pattern[i + 1 : end]
            negate = body[:1] in ("!", "^")
            body = body[1:] if negate else body
            out.append(("class", (negate, _class_ranges(body))))
            i = end + 1
        else:
            out.append(("lit", c))
            i += 1
    return tuple(out)


def _class_ranges(body: str) -> tuple[tuple[str, str], ...]:
    ranges: list[tuple[str, str]] = []
    i = 0
    while i < len(body):
        if i + 2 < len(body) and body[i + 1] == "-":
            ranges.append((body[i], body[i + 2]))
            i += 3
        else:
            ranges.append((body[i], body[i]))
            i += 1
    return tuple(ranges)


def _glob(tokens: tuple[tuple[str, Any], ...], text: str, sep: str | None) -> bool:
    """Tracks every text position the pattern can have reached, so a `**` stays free to widen after later stars."""
    n = len(text)
    cur = [False] * (n + 1)
    cur[0] = True
    for kind, arg in tokens:
        nxt = [False] * (n + 1)
        if kind in ("star", "deep"):
            run = False
            for j in range(n + 1):
                if cur[j]:
                    run = True
                nxt[j] = run
                if run and kind == "star" and j < n and text[j] == sep:
                    run = False
        else:
            for j in range(n):
                if not cur[j]:
                    continue
                ch = text[j]
                if kind == "lit":
                    ok = ch == arg
                elif kind == "any":
                    ok = ch != sep
                else:
                    ok = ch != sep and (any(a <= ch <= b for a, b in arg[1]) != arg[0])
                if ok:
                    nxt[j + 1] = True
        cur = nxt
        if not any(cur):
            return False
    return cur[n]
