"""The JSON value type used by the public data structures."""

from __future__ import annotations

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
"""Any value that can be written as JSON."""
