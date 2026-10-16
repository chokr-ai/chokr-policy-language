"""The package is fully typed: a consumer script type-checks strictly against it and runs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EMBED = ROOT / "examples" / "embedding" / "embed.py"


def test_the_embedding_example_passes_strict_type_checking() -> None:
    result = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-m", "mypy", "--strict", "--no-incremental", str(EMBED)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_embedding_example_runs() -> None:
    result = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, str(EMBED)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0 and result.stdout.split() == ["allow", "deny"], result.stderr


def test_the_package_ships_its_type_marker() -> None:
    import cplang

    assert (Path(cplang.__file__).parent / "py.typed").is_file()
