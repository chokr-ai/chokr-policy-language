"""Error types. Every error carries a stable UPPER_SNAKE `code`. Authoring errors are raised while loading
declarations and policies and carry a source location."""

from __future__ import annotations

import re
from typing import TypedDict

from cplang.jsontypes import JsonValue

_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class CplError(Exception):
    """Base of every typed error."""

    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, detail: dict[str, JsonValue] | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}
        if code is not None:
            if not _CODE_RE.fullmatch(code):
                raise ValueError(f"error code must be UPPER_SNAKE: {code!r}")
            self.code = code


class SchemaInvalid(CplError):
    """A document does not have the expected structure."""

    code = "SCHEMA_INVALID"


class NamespaceViolation(CplError):
    """A name does not follow the `namespace/name` form."""

    code = "NAMESPACE_VIOLATION"


class CanonicalizationError(CplError):
    """A value cannot be written as canonical JSON."""

    code = "CANONICALIZATION_ERROR"


class AuthoringErrorInfo(TypedDict):
    """An authoring error as the command line reports it."""

    code: str
    file: str | None
    line: int | None
    column: int | None
    path: str | None
    message: str


class AuthoringError(CplError):
    """`{code, file, line, column, path, message}` as the command line reports it."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        file: str | None = None,
        line: int | None = None,
        column: int | None = None,
        path: str | None = None,
    ) -> None:
        super().__init__(message, code=code)
        self.file, self.line, self.column, self.path = file, line, column, path
        self.expr_relative = False  # line/column are inside an expression until `located` is called

    def at_expression(self, column: int) -> AuthoringError:
        """Record that the error is at `column` of an expression."""
        self.line, self.column, self.expr_relative = 1, column, True
        self.detail["expression_column"] = column
        return self

    def located(
        self, file: str | None, line: int | None, column: int | None, path: str | None = None
    ) -> AuthoringError:
        """Fill in missing location parts; an expression-relative position is replaced by the source position."""
        self.file = self.file or file
        if self.expr_relative or self.line is None:
            self.line, self.column, self.expr_relative = line, column, False
        self.path = self.path or path
        return self

    def to_dict(self) -> AuthoringErrorInfo:
        """The error as a dictionary."""
        return {
            "code": self.code,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "path": self.path,
            "message": self.message,
        }

    def __str__(self) -> str:
        where = f"{self.file or '<input>'}"
        if self.line is not None:
            where += f":{self.line}:{self.column or 1}"
        return f"{self.code} {where}: {self.message}"
