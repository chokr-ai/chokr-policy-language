"""Strict document loading."""

from __future__ import annotations

import pytest

from cplang.errors import AuthoringError
from cplang.runtime import CplLimits
from cplang.source import parse_source


def load(data: bytes) -> object:
    return parse_source(data, "<doc>").data


def test_a_plain_document_loads() -> None:
    assert load(b"a: 1\nb: [x, y]\n") == {"a": 1, "b": ["x", "y"]}
    assert load(b'{"a": true}') == {"a": True}


@pytest.mark.parametrize(
    "text",
    [
        b"a: &x 1\nb: *x\n",
        b"a: &x 1\n",
        b"a: !custom 1\n",
        b"base: {x: 1}\nb:\n  <<: {x: 1}\n",
        b"a: 1\n---\nb: 2\n",
        b"a: 1\na: 2\n",
        b"a: [1\n",
        b"\xef\xbb\xbfa: 1\n",
        b"a: \xff\n",
        b"a: .inf\n",
        b"1: x\n",
    ],
)
def test_unsafe_or_malformed_documents_are_rejected(text: bytes) -> None:
    with pytest.raises(AuthoringError):
        load(text)


def test_oversized_documents_are_rejected() -> None:
    with pytest.raises(AuthoringError):
        load(b"a: " + b"x" * CplLimits().max_document_bytes)


def test_deeply_nested_documents_are_rejected() -> None:
    with pytest.raises(AuthoringError):
        load(b"a: " + b"[" * 200 + b"]" * 200)


def test_the_error_position_is_reported() -> None:
    with pytest.raises(AuthoringError) as e:
        load(b"a: 1\nb: [1\n")
    assert e.value.line is not None


def test_numbers_keep_their_decimal_text() -> None:
    data = load(b"a: 0.10\nb: 3\n")
    assert isinstance(data, dict) and str(data["a"]) == "0.10" and data["b"] == 3


class TestYamlLoading:
    @pytest.mark.parametrize(
        "text",
        [b"%YAML 1.1\n---\na: no\n", b"d: 2026-01-05\n", b"d: !!binary aGk=\n", b'a: "\\ud800"\n', b"n: 1e1000000\n"],
    )
    def test_documents_that_could_be_read_two_ways_are_rejected(self, text: bytes) -> None:
        from cplang.source import parse_source

        with pytest.raises(AuthoringError):
            parse_source(text, "x.yaml")

    def test_a_json_file_must_be_json(self) -> None:
        from cplang.source import parse_source

        with pytest.raises(AuthoringError):
            parse_source(b"{a: 1}", "x.json")
        assert parse_source(b'{"a": 1}', "x.json").data == {"a": 1}
