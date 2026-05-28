# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.validators — input validation utilities."""

from __future__ import annotations

import re

import pytest

from siyarix.exceptions import ValidationError
from siyarix.validators import (
    sanitize_target,
    validate_api_key,
    validate_cidr,
    validate_email,
    validate_hostname,
    validate_max_length,
    validate_min_length,
    validate_not_empty,
    validate_pattern,
    validate_port,
    validate_target,
    validate_url,
)


class TestValidateNotEmpty:
    def test_valid(self) -> None:
        assert validate_not_empty("hello", "test") is None

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="test cannot be empty"):
            validate_not_empty("", "test")

    def test_whitespace_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_not_empty("   ", "test")


class TestValidateMinLength:
    def test_valid(self) -> None:
        assert validate_min_length("hello", 3, "test") is None

    def test_exact(self) -> None:
        assert validate_min_length("abc", 3, "test") is None

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValidationError, match="test must be at least 5 characters"):
            validate_min_length("ab", 5, "test")


class TestValidateMaxLength:
    def test_valid(self) -> None:
        assert validate_max_length("ab", 5, "test") is None

    def test_exact(self) -> None:
        assert validate_max_length("abcde", 5, "test") is None

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValidationError, match="test must not exceed 3 characters"):
            validate_max_length("abcd", 3, "test")


class TestValidatePattern:
    def test_str_pattern_match(self) -> None:
        assert validate_pattern("abc123", r"^[a-z0-9]+$", "test") is None

    def test_compiled_pattern_match(self) -> None:
        assert validate_pattern("abc", re.compile(r"^[a-z]+$"), "test") is None

    def test_no_match_raises(self) -> None:
        with pytest.raises(ValidationError, match="test does not match required pattern"):
            validate_pattern("ABC", r"^[a-z]+$", "test")


class TestValidatePort:
    def test_valid_int(self) -> None:
        assert validate_port(80) is None

    def test_valid_str(self) -> None:
        assert validate_port("443") is None

    def test_valid_boundary_min(self) -> None:
        assert validate_port(1) is None

    def test_valid_boundary_max(self) -> None:
        assert validate_port(65535) is None

    def test_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_port(0)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_port(-1)

    def test_over_max_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_port(65536)

    def test_non_numeric_str_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_port("abc")

    def test_type_error_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_port(None)  # type: ignore[arg-type]


class TestValidateCidr:
    def test_valid_v4(self) -> None:
        assert validate_cidr("192.168.1.0/24") is None

    def test_valid_v6(self) -> None:
        assert validate_cidr("2001:db8::/32") is None

    def test_single_ip(self) -> None:
        assert validate_cidr("10.0.0.1") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CIDR"):
            validate_cidr("not-a-cidr")


class TestValidateHostname:
    def test_valid(self) -> None:
        assert validate_hostname("example.com") is None

    def test_with_port_stripped(self) -> None:
        assert validate_hostname("example.com:8080") is None

    def test_subdomain(self) -> None:
        assert validate_hostname("sub.example.com") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_hostname("-invalid-.com")


class TestValidateUrl:
    def test_valid_http(self) -> None:
        assert validate_url("http://example.com") is None

    def test_valid_https(self) -> None:
        assert validate_url("https://example.com/path?q=1") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_url("ftp://example.com")


class TestValidateEmail:
    def test_valid(self) -> None:
        assert validate_email("user@example.com") is None

    def test_valid_plus(self) -> None:
        assert validate_email("user+tag@example.co") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email"):
            validate_email("not-an-email")


class TestValidateApiKey:
    def test_valid(self) -> None:
        assert validate_api_key("a" * 20) is None

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_api_key("short", min_length=20)

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_api_key("", min_length=20)

    def test_custom_min_length(self) -> None:
        with pytest.raises(ValidationError):
            validate_api_key("abc", min_length=10)


class TestValidateTarget:
    def test_ipv4(self) -> None:
        result = validate_target("192.168.1.1")
        assert result == {"type": "ipv4", "normalized": "192.168.1.1"}

    def test_ipv6(self) -> None:
        result = validate_target("2001:db8::1")
        assert result["type"] == "ipv6"

    def test_cidr(self) -> None:
        result = validate_target("10.0.0.0/24")
        assert result["type"] == "cidr"

    def test_url(self) -> None:
        result = validate_target("https://example.com")
        assert result["type"] == "url"

    def test_hostname(self) -> None:
        result = validate_target("example.com")
        assert result["type"] == "hostname"

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid target"):
            validate_target("!!!invalid!!!")

    def test_empty_whitespace_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_target("   ")

    def test_strip_handles_whitespace(self) -> None:
        result = validate_target("  example.com  ")
        assert result["type"] == "hostname"
        assert result["normalized"] == "example.com"


class TestSanitizeTarget:
    def test_removes_shell_chars(self) -> None:
        result = sanitize_target("foo;rm -rf /|bar")
        assert result == "foorm -rf /bar"

    def test_removes_newlines(self) -> None:
        result = sanitize_target("foo\nbar\n")
        assert result == "foobar"

    def test_removes_backticks(self) -> None:
        result = sanitize_target("`ls`")
        assert result == "ls"

    def test_removes_dollar_and_parens(self) -> None:
        result = sanitize_target("$(cat /etc/passwd)")
        assert result == "cat /etc/passwd"

    def test_safe_string_unchanged(self) -> None:
        result = sanitize_target("192.168.1.1")
        assert result == "192.168.1.1"
