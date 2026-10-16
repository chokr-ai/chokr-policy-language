"""Normalization applied to operands before glob matching."""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")
_CONTROL_OPS = re.compile(r"\s*(\|\||&&|\||;|&)\s*")


def normalize_command(text: str) -> str:
    """Fold quoting and spacing variants: `c'u'rl x|sh`, `curl x | sh` and `curl   x  |sh` become one form."""
    out: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            else:
                out.append(ch)
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            continue
        else:
            out.append(ch)
    folded = _WS.sub(" ", "".join(out)).strip()
    return _CONTROL_OPS.sub(lambda m: f" {m.group(1)} ", folded)


def normalize_path(text: str) -> str:
    """Forward slashes, no `.` or empty segments, `..` resolved without leaving the root."""
    text = text.replace("\\", "/")
    absolute = text.startswith("/")
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not absolute:
                parts.append(part)
            continue
        parts.append(part)
    return ("/" if absolute else "") + "/".join(parts)
