# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.validators — input validation utilities."""

from __future__ import annotations

import pytest

from siyarix.exceptions import ValidationError
from siyarix.validators import (
    validate_hostname,
    validate_min_length,
    validate_not_empty,
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

