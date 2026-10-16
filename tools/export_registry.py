"""Write registry/language.json from the reference engine: the outcomes, their order and the generic reason codes.
Run `python tools/export_registry.py` to refresh it; `--check` exits 1 when the file is stale."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cplang.registry import (
    OUTCOMES,
    RANK,
    REASON_CODES,
    REASON_TEXT,
    RESERVED_NAMESPACES,
    STANDARD_OUTCOME_REASON,
)

TARGET = Path(__file__).resolve().parent.parent / "registry" / "language.json"


def build() -> str:
    document = {
        "outcomes": list(OUTCOMES),
        "outcome_rank": dict(sorted(RANK.items(), key=lambda kv: kv[1])),
        "standard_outcome_reason": dict(sorted(STANDARD_OUTCOME_REASON.items())),
        "reason_codes": [{"code": c, "text": REASON_TEXT[c]} for c in sorted(REASON_CODES)],
        "reserved_namespaces": sorted(RESERVED_NAMESPACES),
    }
    return json.dumps(document, indent=2) + "\n"


def main() -> int:
    text = build()
    if "--check" in sys.argv:
        return 0 if TARGET.read_text("utf-8") == text else 1
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, "utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
