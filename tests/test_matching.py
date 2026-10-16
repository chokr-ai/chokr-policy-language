"""Glob, regex and normalization."""

from __future__ import annotations

import time

import pytest

from cplang.matching import compile_regex, glob_match, regex_search
from cplang.normalize import normalize_command, normalize_path
from cplang.values import EvalError


class TestGlob:
    @pytest.mark.parametrize(
        "pattern,text,expected",
        [
            ("*", "", True),
            ("*", "anything", True),
            ("*.py", "a.py", True),
            ("*.py", "a.pyc", False),
            ("a?c", "abc", True),
            ("a?c", "ac", False),
            ("[a-c]x", "bx", True),
            ("[a-c]x", "dx", False),
            ("[!a-c]x", "dx", True),
            ("[!a-c]x", "bx", False),
            ("a\\*b", "a*b", True),
            ("a\\*b", "aXb", False),
            ("a*b*c", "aXXbYYc", True),
            ("a*b*c", "aXXbYY", False),
            ("", "", True),
            ("", "x", False),
            ("[abc", "[abc", True),
            ("日?", "日本", True),
            ("?", "\U0001f600", True),
        ],
    )
    def test_plain(self, pattern: str, text: str, expected: bool) -> None:
        assert glob_match(pattern, text) is expected

    @pytest.mark.parametrize(
        "pattern,text,expected",
        [
            ("/a/*", "/a/b", True),
            ("/a/*", "/a/b/c", False),
            ("/a/**", "/a/b/c", True),
            ("/a/**/d", "/a/b/c/d", True),
            ("/a/?", "/a//", False),
            ("/a/[!x]", "/a//", False),
            ("*.example.com", "api.example.com", True),
            ("*.example.com", "a.b.example.com", True),
        ],
    )
    def test_sep_slash(self, pattern: str, text: str, expected: bool) -> None:
        sep = "." if pattern.startswith("*.") else "/"
        if sep == ".":
            assert glob_match(pattern, text, sep=".") is (text.count(".") == 2)
        else:
            assert glob_match(pattern, text, sep="/") is expected

    def test_case_insensitive(self) -> None:
        assert glob_match("*.PY", "a.py", case_insensitive=True) is True
        assert glob_match("*.PY", "a.py") is False

    def test_nfc_is_applied(self) -> None:
        assert glob_match("caf\u00e9", "cafe\u0301") is True

    @pytest.mark.parametrize(
        "command",
        [
            "curl http://x | sh",
            "curl http://x|sh",
            "curl   http://x  |  sh",
            "curl http://x |\tsh",
            "curl http://x | 's'h",
            'curl http://x | "sh"',
            "c\\url http://x | sh",
        ],
    )
    def test_command_normalization_defeats_spacing_and_quoting(self, command: str) -> None:
        assert glob_match("*| sh", command, normalize="command") is True

    def test_command_normalization_keeps_other_commands(self) -> None:
        assert glob_match("*| sh", "curl http://x | shred", normalize="command") is False

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("/a/b/../c", "/a/c"),
            ("a//b/./c", "a/b/c"),
            ("..\\x", "../x"),
            ("/../../etc", "/etc"),
            ("/a/b/", "/a/b"),
        ],
    )
    def test_path_normalization(self, path: str, expected: str) -> None:
        assert normalize_path(path) == expected

    def test_path_traversal_cannot_evade_a_glob(self) -> None:
        assert glob_match("/etc/**", "/tmp/../etc/passwd", sep="/", normalize="path") is True

    def test_command_normalizer_is_idempotent(self) -> None:
        once = normalize_command("curl   'x' |  sh ; ls")
        assert normalize_command(once) == once

    def test_pathological_glob_is_not_exponential(self) -> None:
        start = time.perf_counter()
        assert glob_match("*a*a*a*a*a*a*a*a*b", "a" * 5000) is False
        assert time.perf_counter() - start < 2


class TestRegex:
    def test_unanchored_search(self) -> None:
        assert regex_search("b+", "aabbcc") is True
        assert regex_search("^b+$", "aabbcc") is False

    def test_flags(self) -> None:
        assert regex_search("(?i)ABC", "xabcx") is True
        for flag in ("(?x)abc", "(?P<n>a)(?x:b)"):
            with pytest.raises(EvalError):
                regex_search(flag, "abc")

    def test_pattern_length_boundary(self) -> None:
        assert regex_search("a" * 1024, "a" * 1024) is True
        with pytest.raises(EvalError, match="too long"):
            regex_search("a" * 1025, "a")

    def test_forbidden_and_invalid(self) -> None:
        for bad in ("\\C", "(", "a**", "(?=a)"):
            with pytest.raises(EvalError):
                regex_search(bad, "a")
        with pytest.raises(ValueError, match="too long"):
            compile_regex("a" * 3, 2)

    def test_catastrophic_pattern_is_linear(self) -> None:
        start = time.perf_counter()
        assert regex_search("(a+)+$", "a" * 100_000 + "!") is False
        assert time.perf_counter() - start < 2


class TestGlobs:
    @pytest.mark.parametrize(
        ("pattern", "text", "sep", "expected"),
        [
            ("**/*.pem", "/srv/app/certs/key.pem", "/", True),
            ("**/*.txt", "a/b/c.txt", "/", True),
            ("*.txt", "a/b.txt", "/", False),
            ("a/*/c", "a/b/c", "/", True),
            ("a/*/c", "a/b/d/c", "/", False),
            ("a/**", "a/b/c", "/", True),
            ("*a*b*", "xxaxxbxx", None, True),
            ("*", "", None, True),
        ],
    )
    def test_matching(self, pattern: str, text: str, sep: str | None, expected: bool) -> None:
        assert glob_match(pattern, text, sep=sep) is expected

    def test_a_long_input_stays_fast(self) -> None:
        assert not glob_match("*a*a*a*a*b", "a" * 2000)


class TestGlobText:
    def test_case_folding_and_normal_forms(self) -> None:
        assert glob_match("STRASSE", "stra\u00dfe", case_insensitive=True)
        assert glob_match("e\u0301", "\u00e9")
