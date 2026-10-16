"""Where the language's data files live: bundled in the wheel, or in the checkout when run from source."""

from __future__ import annotations

from pathlib import Path

SCHEMAS = ("action", "signal", "verdict", "fixtures", "policy")


def data_dir() -> Path:
    """The directory that holds the bundled conformance vectors and schemas."""
    bundled = Path(__file__).resolve().parent / "data"
    return bundled if bundled.is_dir() else Path(__file__).resolve().parents[2]


def schema_path(name: str) -> Path:
    """The path of the bundled JSON Schema called `name`."""
    if name not in SCHEMAS:
        raise KeyError(name)
    return data_dir() / "schemas" / f"{name}.schema.json"
