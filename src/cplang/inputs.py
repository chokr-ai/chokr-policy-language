"""The standard input contract: the names a policy can read from an action, and the types of well-known paths.

Everything here is data. A host adds names with `Profile.roots`; a path that is not listed is typed from the way it is
used (or left `any`), so the tables improve type checking and the prover without limiting what an action can carry.
"""

from __future__ import annotations

ROOTS = frozenset(
    {
        "kind",
        "target",
        "action_uri",
        "resource",
        "audience",
        "environment",
        "actor",
        "origin",
        "arguments",
        "state",
        "time",
        "ext",
        "depth",
        "call_chain",
        "context",
        "id",
        "attribute_sources",
    }
)

# Roots that name declarations or other namespaces rather than input data, usable as condition keys.
CONDITION_ROOTS = (ROOTS - {"id", "attribute_sources"}) | {
    "attributes",
    "param",
    "const",
    "table",
    "computed",
    "var",
    "fn",
}

PATH_TYPES: dict[tuple[str, ...], str] = {
    ("kind",): "string",
    ("action_uri",): "string",
    ("audience",): "string",
    ("id",): "string",
    ("depth",): "integer",
    ("target", "name"): "string",
    ("target", "protocol"): "string",
    ("target", "server"): "string",
    ("target", "resource"): "string",
    ("target", "destination_host"): "string",
    ("target", "method"): "string",
    ("target", "path"): "string",
    ("actor", "subject"): "string",
    ("actor", "type"): "string",
    ("environment", "env"): "string",
    ("resource", "type"): "string",
    ("resource", "id"): "string",
    ("resource", "owner"): "string",
    ("resource", "count"): "integer",
}

STRING_PATHS = frozenset(".".join(path) for path, kind in PATH_TYPES.items() if kind == "string" and path != ("id",))
