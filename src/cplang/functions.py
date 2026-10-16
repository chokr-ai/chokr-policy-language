"""Functions a host registers for use in expressions, named `<namespace>/<name>`.

A function receives the action and a dict of arguments and returns a value; the same inputs must give the same
output."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping

from cplang.errors import AuthoringError, NamespaceViolation
from cplang.jsontypes import JsonValue
from cplang.model import Action

type HostFunction = Callable[[Action, Mapping[str, JsonValue]], JsonValue]
"""A function a host registers: it receives the action and a mapping of arguments and returns a JSON value."""

_NAME = re.compile(r"^(?P<ns>[a-z0-9][a-z0-9.-]{1,62})/(?P<fn>[a-z][a-z0-9_]*)$")


class FunctionRegistry:
    """Functions are keyed `<namespace>/<fn>`. `fn(action, args: dict) -> value`."""

    def __init__(self) -> None:
        self._fns: dict[str, tuple[HostFunction, str]] = {}

    def register(self, name: str, fn: HostFunction, *, version: str = "1") -> None:
        """Register `fn` under `name` (`<namespace>/<name>`); registering a name twice is an error."""
        if _NAME.fullmatch(name) is None:
            raise NamespaceViolation("a function is named <namespace>/<fn>", detail={"function": name})
        if name in self._fns:
            raise AuthoringError("DECLARATION_CONFLICT", f"function {name} is registered twice")
        self._fns[name] = (fn, version)

    def has(self, name: str) -> bool:
        """True when `name` is registered."""
        return name in self._fns

    def resolve(self, name: str) -> HostFunction:
        """The function registered under `name`."""
        try:
            return self._fns[name][0]
        except KeyError as exc:
            raise AuthoringError("EVALUATION_ERROR", f"function {name} is not registered") from exc

    def versions(self, names: set[str]) -> list[dict[str, str]]:
        """`{name, version}` of every function in `names`, for the policy fingerprint."""
        return [{"name": n, "version": self._fns[n][1]} for n in sorted(names) if n in self._fns]
