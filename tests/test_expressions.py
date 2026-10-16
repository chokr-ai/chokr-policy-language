"""Expression language."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from tests.conftest import ALLOW_DEFAULT, DENY_DEFAULT, Project, authoring_code, make_env

from cplang import AuthoringError, CplLimits
from cplang.compile import Scope, compile_expression
from cplang.declarations import DeclarationSet
from cplang.runtime import Ctx, InputView
from cplang.values import ABSENT, EvalError


def run(src: str, *, env: Any = None, decls: DeclarationSet | None = None, limits: CplLimits | None = None) -> Any:
    limits = limits or CplLimits()
    decls = decls or DeclarationSet(limits)
    compiled = compile_expression(src, Scope(decls, limits=limits))
    view = InputView(env or make_env({"n": 5, "s": "héllo", "xs": [1, 2, 3], "m": {"k": 1}}), [], decls)
    return compiled.fn(Ctx(view, limits)).v


def code_of(src: str, limits: CplLimits | None = None) -> str:
    with pytest.raises(AuthoringError) as e:
        run(src, limits=limits)
    return e.value.code


class TestArithmetic:
    @pytest.mark.parametrize(
        "src,expected",
        [
            ("1 + 2 * 3", 7),
            ("(1 + 2) * 3", 9),
            ("10 - 4 - 3", 3),
            ("7 % 3", 1),
            ("-7 % 3", -1),
            ("7 % -3", 1),
            ("0.1 + 0.2 == 0.3", True),
            ("7 / 2", Decimal("3.5")),
            ("1 / 3 * 3 == 1", False),
            ("round(2.5, 0)", Decimal("2")),
            ("round(3.5, 0)", Decimal("4")),
            ("round(1.005, 2)", Decimal("1.00")),
            ("floor(-1.5)", -2),
            ("ceil(-1.5)", -1),
            ("abs(-3)", 3),
            ("min(3, 1, 2)", 1),
            ("max([4, 9, 2])", 9),
            ("sum([1, 2, 3.5])", Decimal("6.5")),
            ("-(2 + 3)", -5),
            ("2 * -3", -6),
        ],
    )
    def test_values(self, src: str, expected: Any) -> None:
        assert run(src) == expected

    def test_division_by_zero_and_overflow(self) -> None:
        for src in ("1 / 0", "5 % 0", "9223372036854775807 + 1", "-9223372036854775807 - 2", "9223372036854775807 * 2"):
            with pytest.raises(EvalError):
                run(src)
        assert run("9223372036854775807 + 0") == 9223372036854775807

    def test_integers_and_numbers_compare_by_value(self) -> None:
        assert run("1.0 == 1") is True
        assert run("2 > 1.5") is True

    def test_arguments_are_decimal_not_binary_floats(self) -> None:
        env = make_env({"a": 0.1, "b": 0.2})
        assert run("arguments.a + arguments.b == 0.3", env=env) is True


class TestStrings:
    @pytest.mark.parametrize(
        "src,expected",
        [
            ('"a" + "b"', "ab"),
            ('upper("ab")', "AB"),
            ('lower("AB")', "ab"),
            ('trim("  x ")', "x"),
            ("size(arguments.s)", 5),
            ('size("\U0001f600")', 1),
            ('starts_with("hello", "he")', True),
            ('ends_with("hello", "lo")', True),
            ('contains("hello", "ell")', True),
            ('split("a,b", ",")', ["a", "b"]),
            ('join(["a", "b"], "-")', "a-b"),
            ('matches("abc123", "[0-9]+")', True),
            ('matches("abc", "^[0-9]+$")', False),
            ('"b" > "a"', True),
            ('"\U0001f600" > "\uffff"', True),
        ],
    )
    def test_values(self, src: str, expected: Any) -> None:
        assert run(src) == expected

    def test_regex_pattern_must_be_static(self) -> None:
        assert code_of("matches(arguments.s, arguments.s)") == "TYPE_ERROR"
        assert code_of('matches("a", "(")') == "TYPE_ERROR"

    def test_regex_is_linear_time(self) -> None:
        env = make_env({"s": "a" * 100_000 + "!"})
        assert run('matches(arguments.s, "(a+)+$")', env=env) is False


class TestCollections:
    @pytest.mark.parametrize(
        "src,expected",
        [
            ("2 in [1, 2, 3]", True),
            ("5 in [1, 2, 3]", False),
            ('"a" in "cat"', True),
            ('"k" in arguments.m', True),
            ("all([1, 2, 3], it > 0)", True),
            ("all([1, 2, 3], it > 1)", False),
            ("any([1, 2, 3], it > 2)", True),
            ("filter([1, 2, 3, 4], it % 2 == 0)", [2, 4]),
            ("map([1, 2], it * 10)", [10, 20]),
            ("map([1, 2], x, x + 1)", [2, 3]),
            ("size(arguments.xs)", 3),
            ("arguments.xs[1]", 2),
            ('keys({"b": 1, "a": 2})', ["a", "b"]),
            ("count(arguments.xs)", 3),
            ("all([], it > 0)", True),
        ],
    )
    def test_values(self, src: str, expected: Any) -> None:
        assert run(src) == expected


class TestThreeValuedLogic:
    ABSENT_EQ = "arguments.missing == 1"

    def test_absent_propagates(self) -> None:
        assert run(self.ABSENT_EQ) is ABSENT
        assert run("arguments.missing + 1") is ABSENT
        assert run("size(arguments.missing)") is ABSENT

    def test_not_absent_is_never_true(self) -> None:
        assert run(f"!({self.ABSENT_EQ})") is ABSENT

    @pytest.mark.parametrize(
        "src,expected",
        [
            (f"{ABSENT_EQ} || true", True),
            (f"{ABSENT_EQ} || false", ABSENT),
            (f"{ABSENT_EQ} && false", False),
            (f"{ABSENT_EQ} && true", ABSENT),
            (f"false && {ABSENT_EQ}", False),
            (f"true || {ABSENT_EQ}", True),
            (f"{ABSENT_EQ} ? 1 : 2", ABSENT),
            ("true ? 1 : 2", 1),
            ("false ? 1 : 2", 2),
            ("has(arguments.missing)", False),
            ("has(arguments.n)", True),
            ("default(arguments.missing, 7)", 7),
            ("default(arguments.n, 7)", 5),
            ("coalesce(arguments.missing, arguments.n)", 5),
        ],
    )
    def test_tables(self, src: str, expected: Any) -> None:
        assert run(src) is expected or run(src) == expected


class TestTypeChecking:
    @pytest.mark.parametrize("src", ['"5" == 5', "true + 1", '1 < "a"', "!5", '"a" && true', "size(1, 2)"])
    def test_static_mismatch_is_type_error(self, src: str) -> None:
        assert code_of(src) == "TYPE_ERROR"

    def test_runtime_mismatch_is_evaluation_error(self) -> None:
        with pytest.raises(EvalError):
            run("arguments.s == 1")
        with pytest.raises(EvalError):
            run("arguments.s > arguments.n")

    def test_unknown_names(self) -> None:
        for src in ("param.nope", "const.nope", "fn.nope(1)", "var.nope", "unknownfn(1)"):
            assert code_of(src) == "DECLARATION_UNKNOWN_NAME"

    def test_undeclared_input_names_are_open_by_default_and_rejected_when_strict(self) -> None:
        assert run("whatever.x") is ABSENT
        strict = DeclarationSet()
        strict.strict_inputs = True
        with pytest.raises(AuthoringError) as e:
            run("whatever.x", decls=strict)
        assert e.value.code == "DECLARATION_UNKNOWN_NAME"

    @pytest.mark.parametrize("src", ["1 +", "(1", "1 2", '"abc', "1 < 2 < 3", "[1,", "@", "1 ? 2", "all([1])"])
    def test_syntax(self, src: str) -> None:
        assert code_of(src) == "EXPRESSION_SYNTAX"

    def test_syntax_error_has_a_column(self) -> None:
        with pytest.raises(AuthoringError) as e:
            run("1 + * 2")
        assert e.value.column == 5

    def test_only_declared_functions_are_callable(self) -> None:
        assert code_of("arguments.s.upper()") == "EXPRESSION_SYNTAX"


class TestLimits:
    def test_node_limit_boundary(self) -> None:
        limits = CplLimits(max_expression_nodes=5)
        assert run("1 + 2 + 3", limits=limits) == 6  # 3 literals + 2 operators = 5 nodes
        assert code_of("1 + 2 + 3 + 4", limits) == "EXPRESSION_LIMIT"  # 7 nodes

    def test_default_node_limit_is_256(self) -> None:
        ok = " + ".join(["1"] * 128)  # 255 nodes
        assert run(ok) == 128
        assert code_of(" + ".join(["1"] * 129)) == "EXPRESSION_LIMIT"  # 257 nodes

    def test_step_budget_boundary(self) -> None:
        assert run("1 + 2 + 3", limits=CplLimits(max_eval_steps=5)) == 6
        with pytest.raises(EvalError, match="step budget"):
            run("1 + 2 + 3", limits=CplLimits(max_eval_steps=4))

    def test_string_operand_limit(self) -> None:
        limits = CplLimits(max_value_chars=10)
        env = make_env({"s": "x" * 10})
        assert run('contains(arguments.s, "x")', env=env, limits=limits) is True
        with pytest.raises(EvalError, match="too long"):
            run('contains(arguments.s, "x")', env=make_env({"s": "x" * 11}), limits=limits)

    def test_deep_nesting_is_refused_not_crashed(self) -> None:
        assert code_of("(" * 200 + "1" + ")" * 200) in ("EXPRESSION_LIMIT", "EXPRESSION_SYNTAX")


class TestTime:
    def test_timestamps_and_durations(self) -> None:
        assert run('date_diff(timestamp("2026-01-02T00:00:00Z"), timestamp("2026-01-01T00:00:00Z"), "days")') == 1
        assert run('date_diff(timestamp("2026-01-01T00:00:00Z"), timestamp("2026-01-02T12:00:00Z"), "hours")') == -36
        assert run('timestamp("2026-01-01T00:00:00Z") + duration("PT90M") > timestamp("2026-01-01T01:00:00Z")') is True
        assert run('duration("P1DT1H") == duration("PT25H")') is True

    def test_literals_are_checked_at_load(self) -> None:
        assert code_of('timestamp("not a time")') == "TYPE_ERROR"
        assert code_of('duration("5 minutes")') == "TYPE_ERROR"

    def test_time_now_is_the_captured_at_of_the_envelope(self) -> None:
        assert run('time.now == timestamp("2026-01-01T12:00:00.000000Z")') is True


class TestTypeMismatchInLists:
    @pytest.mark.parametrize("operator", ["in", "nin"])
    def test_a_membership_test_on_the_wrong_type_is_an_error_not_a_miss(self, project: Project, operator: str) -> None:
        text = DENY_DEFAULT + f"  - {{id: r, outcome: allow, when: {{arguments.account: {{{operator}: [13, 42]}}}}}}\n"
        verdict = project.evaluator(text).evaluate(make_env({"account": "13"}), [])
        assert verdict.outcome == "deny" and verdict.reason_codes == ["EVALUATION_ERROR"]


class TestTimestamps:
    def test_an_offset_is_converted_to_utc(self) -> None:
        from cplang.values import parse_timestamp

        assert parse_timestamp("2026-01-01T10:00:00+05:30") == parse_timestamp("2026-01-01T04:30:00Z")

    @pytest.mark.parametrize("text", ["\u0662026-01-01T00:00:00Z", "2026-01-01T00:00:00+25:00"])
    def test_only_ascii_digits_and_real_offsets_parse(self, text: str) -> None:
        from cplang.values import EvalError, parse_timestamp

        with pytest.raises(EvalError):
            parse_timestamp(text)

    def test_arithmetic_cannot_leave_the_supported_years(self) -> None:
        from cplang.values import EvalError, Timestamp, checked_timestamp

        with pytest.raises(EvalError):
            checked_timestamp(Timestamp(253_402_300_800_000_000).us)


class TestNumbers:
    """Decimal arithmetic uses the language's own context."""

    def test_rounding_ignores_the_host_decimal_context(self) -> None:
        import decimal

        from cplang.values import EvalError, quantize, to_integer

        with decimal.localcontext() as ctx:
            ctx.prec = 2
            assert quantize(Decimal("123456.789"), Decimal("0.01"), decimal.ROUND_HALF_EVEN) == Decimal("123456.79")
        with pytest.raises(EvalError):
            to_integer(Decimal("1e30"), decimal.ROUND_FLOOR)


class TestExpressionLimits:
    """Expressions cannot be made to build huge values or nest without bound."""

    def test_concatenation_cannot_build_unbounded_strings(self, project: Project) -> None:
        expr = "s + s"
        for _ in range(6):
            expr = f"({expr}) + ({expr})"
        text = (
            ALLOW_DEFAULT
            + f'  - {{id: r, outcome: deny, let: {{s: arguments.s}}, when: {{expr: "size({expr}) > 0"}}}}\n'
        )
        try:
            ev = project.evaluator(text)
        except AuthoringError:
            return  # rejected as too large at load time
        verdict = ev.evaluate(make_env({"s": "x" * 600_000}), [])
        assert verdict.reason_codes == ["EVALUATION_ERROR"]

    def test_deeply_chained_unary_operators_are_rejected_at_load_time(self, project: Project) -> None:
        text = ALLOW_DEFAULT + f'  - {{id: r, outcome: deny, when: {{expr: "{"!" * 2000}true"}}}}\n'
        assert authoring_code(lambda: project.policy(text)) == "EXPRESSION_LIMIT"


def test_a_path_glued_to_a_call_is_a_host_call_and_the_error_says_how_to_divide() -> None:
    with pytest.raises(AuthoringError) as info:
        run("arguments.n/size([1])")
    assert "arguments.n / size(...)" in info.value.message
    assert run("arguments.n / size([1])") == 5
    with pytest.raises(AuthoringError) as info:
        run("acme/check(1)")
    assert "to divide" not in info.value.message
