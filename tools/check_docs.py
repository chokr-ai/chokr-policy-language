"""Check the examples in the documentation site against the engine.

Every fenced block in `docs/**/*.md` that is followed by a `{: data-title="name"}` line is a file of the example. Files
accumulate per page in a scratch folder, in order, so a page can build an example up step by step.

- `*.policy.yaml`: must pass `cplang policy check` (add `data-error="CODE"` when the block shows a failure).
- `*.fixtures.yaml`: the cases must pass against the policy with the same stem.
- `*.decl.yaml`: must pass `cplang decl check`.
- `*.py`: must run and exit 0.
- A `console` block marked `data-output="file.py"` must match what that script printed.
- A `console` block marked `data-run="true"`: each `$ cplang ...` line is run in the scratch folder and its output must
  match the lines that follow it.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"
FENCE = re.compile(r"^```(\w*)\s*$")
ATTRS = re.compile(r"^\{:\s*(.*?)\s*\}\s*$")
ATTR = re.compile(r'([\w-]+)="([^"]*)"')
HASH = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass
class Block:
    lang: str
    body: str
    attrs: dict[str, str]
    line: int


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    checked: int = 0


def blocks(text: str) -> list[Block]:
    """Fenced blocks of a page with the attributes on the line that follows each one."""
    lines = text.splitlines()
    found: list[Block] = []
    i = 0
    while i < len(lines):
        match = FENCE.match(lines[i])
        if not match:
            i += 1
            continue
        start, body = i + 1, []
        i += 1
        while i < len(lines) and not lines[i].startswith("```"):
            body.append(lines[i])
            i += 1
        attrs: dict[str, str] = {}
        if i + 1 < len(lines) and (tail := ATTRS.match(lines[i + 1])):
            attrs = dict(ATTR.findall(tail.group(1)))
        found.append(Block(match.group(1), "\n".join(body) + "\n", attrs, start))
        i += 1
    return found


UTF8 = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}


def cplang(args: list[str], cwd: Path) -> tuple[int, str]:
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "cplang", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=UTF8,
        timeout=120,
        check=False,
    )
    return run.returncode, (run.stdout + run.stderr).replace("\r\n", "\n")


def stem(name: str) -> str:
    return name.split(".", 1)[0]


def check_file(block: Block, name: str, work: Path, printed: dict[str, str]) -> str | None:
    """Run the check that belongs to a file block; return a failure text or None."""
    target = work / name
    if block.attrs.get("data-check") == "false":
        return None
    expected = block.attrs.get("data-error")
    if name.endswith(".policy.yaml"):
        code, out = cplang(["policy", "check", name, "--root", "."], work)
    elif name.endswith(".decl.yaml"):
        code, out = cplang(["decl", "check", name], work)
    elif name.endswith(".fixtures.yaml"):
        policy = f"{stem(name)}.policy.yaml"
        if not (work / policy).exists():
            return f"{name}: no {policy} earlier on the page"
        code, out = cplang(["test", "--policy", policy, "--fixtures", name, "--root", "."], work)
    elif name.endswith(".py"):
        run = subprocess.run(  # noqa: S603
            [sys.executable, str(target)],
            cwd=work,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=UTF8,
            timeout=120,
            check=False,
        )
        code, out = run.returncode, run.stdout + run.stderr
        printed[name] = out.replace("\r\n", "\n")
    else:
        return None
    if expected:
        return None if code != 0 and expected in out else f"{name}: expected {expected}, got exit {code}: {out.strip()}"
    return None if code == 0 else f"{name}: exit {code}: {out.strip()}"


def commands(body: str) -> list[tuple[str, str]]:
    """Pairs of (command, expected output) in a console block."""
    pairs: list[tuple[str, list[str]]] = []
    for line in body.splitlines():
        if line.startswith("$ "):
            pairs.append((line[2:], []))
        elif pairs:
            pairs[-1][1].append(line)
    return [(cmd, "\n".join(out).strip()) for cmd, out in pairs]


def check_console(block: Block, work: Path) -> list[str]:
    problems = []
    for command, expected in commands(block.body):
        command = command.split("#", 1)[0].strip()
        if not command.startswith("cplang "):
            continue
        args = shlex.split(command.removeprefix("cplang "))
        _, out = cplang(args, work)
        got = HASH.sub("sha256:HASH", out.strip())
        want = HASH.sub("sha256:HASH", expected)
        if [ln.rstrip() for ln in got.splitlines()] != [ln.rstrip() for ln in want.splitlines()]:
            problems.append(f"`{command}` printed:\n{got}\nbut the page shows:\n{want}")
    return problems


def check_page(path: Path, report: Report) -> None:
    work = Path(tempfile.mkdtemp(prefix="docs-check-"))
    printed: dict[str, str] = {}
    for block in blocks(path.read_text(encoding="utf-8")):
        where = f"{path.relative_to(DOCS)}:{block.line}"
        name = block.attrs.get("data-title")
        if name and block.lang in ("yaml", "python", "csv", "json", "text"):
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(block.body, encoding="utf-8", newline="\n")
            report.checked += 1
            if (problem := check_file(block, name, work, printed)) is not None:
                report.failures.append(f"{where}: {problem}")
        elif block.lang == "console" and (script := block.attrs.get("data-output")):
            report.checked += 1
            if printed.get(script, "").strip() != block.body.strip():
                report.failures.append(
                    f"{where}: {script} printed:\n{printed.get(script, '')}\nbut the page shows:\n{block.body}"
                )
        elif block.lang == "console" and block.attrs.get("data-run") == "true":
            report.checked += 1
            report.failures += [f"{where}: {p}" for p in check_console(block, work)]


def main() -> int:
    report = Report()
    only = sys.argv[1:]
    for page in sorted(DOCS.rglob("*.md")):
        if "vendor" in page.parts or "_site" in page.parts or page.name == "README.md":
            continue
        if only and not any(o in page.as_posix() for o in only):
            continue
        check_page(page, report)
    for failure in report.failures:
        print(f"FAIL {failure}\n")
    print(f"{report.checked} example blocks checked, {len(report.failures)} failed")
    return 1 if report.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
