"""Platform independence: the same policy has the same fingerprint wherever and however it is checked out."""

from __future__ import annotations

import json
from pathlib import Path

from cplang import load_declarations, load_policy
from cplang.declarations import _Loader, write_lock
from cplang.runtime import CplLimits

POLICY = (
    'cpl: "1.0"\nid: p\nversion: 1\nimports:\n  - {from: ./lib/limits.decl.yaml}\ndefault: deny\n'
    "rules:\n  - {id: r, outcome: allow, when: {arguments.n: {lte: {ref: param.cap}}}}\n"
)
DECL = (
    "schema: cpl.declarations/1.0\nparameters:\n  cap: {type: integer, default: 5}\n"
    "tables:\n  t: {key: string, value: integer, source: ./t.csv}\n"
)
CSV = "key,value\na,1\nb,2\n"


def checkout(root: Path, *, crlf: bool) -> Path:
    def put(name: str, text: str) -> None:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode())

    put("main.policy.yaml", POLICY)
    put("lib/limits.decl.yaml", DECL)
    put("lib/t.csv", CSV)
    put("top.decl.yaml", "schema: cpl.declarations/1.0\nimports:\n  - {from: ./lib/limits.decl.yaml}\n")
    return root / "main.policy.yaml"


def test_the_fingerprint_does_not_depend_on_location_or_line_endings(tmp_path: Path) -> None:
    prints = set()
    for name, crlf in (("a", False), ("deeper/b", False), ("c", True)):
        policy = checkout(tmp_path / name, crlf=crlf)
        prints.add(load_policy([policy], roots=[policy.parent]).fingerprint)
    assert len(prints) == 1


def test_declaration_names_in_the_policy_are_relative_and_posix(tmp_path: Path) -> None:
    policy = checkout(tmp_path / "x", crlf=False)
    compiled = load_policy([policy], roots=[policy.parent])
    assert list(compiled.decls.files) == ["lib/limits.decl.yaml"]


def test_the_lock_file_is_portable(tmp_path: Path) -> None:
    locks = []
    for name, crlf in (("a", False), ("b", True)):
        top = checkout(tmp_path / name, crlf=crlf).parent / "top.decl.yaml"
        decls = load_declarations([top], roots=[top.parent])
        loader = _Loader([top.parent], CplLimits(), 16, None, None, False, None)
        loader.load(top)
        lock = tmp_path / f"{name}.lock"
        write_lock(decls, loader.lock_rows, lock)
        locks.append(json.loads(lock.read_text("utf-8")))
    assert locks[0] == locks[1] and locks[0]["imports"][0]["resolved"] == "lib/limits.decl.yaml"
    dumped = json.dumps(locks[0])
    assert tmp_path.as_posix() not in dumped and json.dumps(str(tmp_path))[1:-1] not in dumped
