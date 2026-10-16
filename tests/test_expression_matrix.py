"""Expression builtins and operators through the same entry point the conformance vectors use."""

from __future__ import annotations

from typing import Any

import pytest

from cplang.conformance import expression

ARGS = {
    "n": 5,
    "d": "1.5",
    "s": "Hello, World",
    "t": "  pad  ",
    "xs": [3, 1, 2],
    "m": {"a": 1, "b": 2},
    "ws": ["a", "b"],
    "u": "2026-03-01T10:00:00Z",
    "flag": True,
    "none": None,
}


def run(text: str) -> dict[str, Any]:
    return expression({"input": {"expression": text, "arguments": ARGS}})


VALID = [
    "arguments.n + 1",
    "arguments.n - 1",
    "arguments.n * 2",
    "arguments.n / 2",
    "arguments.n % 3",
    "-arguments.n",
    "arguments.n * arguments.n",
    "arguments.n > 1 and arguments.n < 9",
    "arguments.n == 5 or arguments.n == 6",
    "not (arguments.n == 5)",
    "arguments.n != 4",
    "arguments.n >= 5",
    "arguments.n <= 5",
    "arguments.s == 'x'",
    "arguments.s + '!'",
    "lower(arguments.s)",
    "upper(arguments.s)",
    "trim(arguments.t)",
    "size(arguments.s)",
    "count(arguments.xs)",
    "size(arguments.m)",
    "contains(arguments.s, 'World')",
    "starts_with(arguments.s, 'He')",
    "ends_with(arguments.s, 'ld')",
    "matches(arguments.s, 'W.rld')",
    "split(arguments.s, ', ')",
    "join(arguments.ws, '-')",
    "date_diff(timestamp(arguments.u), timestamp('2026-01-01T00:00:00Z'))",
    "abs(-3)",
    "min(1, 2)",
    "max(1, 2)",
    "round(1.5)",
    "floor(1.5)",
    "ceil(1.2)",
    "keys(arguments.m)",
    "values(arguments.m)",
    "sum(arguments.xs)",
    "arguments.n in arguments.xs",
    "arguments.n not in arguments.xs",
    "arguments.xs[0]",
    "arguments.m.a",
    "arguments.m['b']",
    "arguments.nothing",
    "arguments.flag and true",
    "timestamp(arguments.u) > timestamp('2026-01-01T00:00:00Z')",
    "duration('PT1H') > duration('PT30M')",
    "timestamp(arguments.u) + duration('PT1H')",
    "time.now > timestamp('2020-01-01T00:00:00Z')",
    "[1, 2, 3]",
    "'a' in ['a', 'b']",
    "true",
    "1.25 + 1",
    "100",
]


@pytest.mark.parametrize("text", VALID, ids=range(len(VALID)))
def test_valid_expressions_never_crash(text: str) -> None:
    result = run(text)
    assert "error" not in result or result["error"] in {
        "EVALUATION_ERROR",
        "EXPRESSION_SYNTAX",
        "TYPE_ERROR",
        "DECLARATION_UNKNOWN_NAME",
    }, (text, result)


INVALID = [
    "",
    "1 +",
    "(1",
    "1 2",
    "'unterminated",
    "arguments.",
    "nope(1)",
    "lower()",
    "lower(1, 2)",
    "size(1)",
    "1 + 'a'",
    "'a' - 1",
    "not 1",
    "-'a'",
    "1 < 'a'",
    "arguments.n / 0",
    "arguments.n % 0",
    "timestamp('nope')",
    "duration('nope')",
    "arguments.xs[99]",
    "arguments.m['zz']",
    "matches(arguments.s, '(')",
    "unknown.root",
    "var.x",
    "param.x",
    "const.x",
    "1 + " * 400,
    "(" * 200 + "1" + ")" * 200,
]


@pytest.mark.parametrize("text", INVALID, ids=range(len(INVALID)))
def test_invalid_expressions_report_an_error(text: str) -> None:
    result = run(text)
    assert "error" in result or result.get("absent") is True, (text, result)


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("1 + 2 * 3", 7),
        ("(1 + 2) * 3", 9),
        ("lower('AB')", "ab"),
        ("size('abc')", 3),
        ("'a' + 'b'", "ab"),
        ("arguments.n > 4", True),
        ("min(3, 2)", 2),
        ("join(['a','b'], '-')", "a-b"),
    ],
)
def test_expression_values(text: str, value: Any) -> None:
    assert run(text)["value"] == value
