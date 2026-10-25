# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for siyarix.target_scope (SX-004)."""

from __future__ import annotations

import os

import pytest

from siyarix.exceptions import PermissionDeniedError
from siyarix.target_scope import (
    assert_command_in_scope,
    domain_in_scope,
    extract_targets,
    ip_in_scope,
    parse_allowed_scope,
)


class TestParseAllowedScope:
    def test_empty(self) -> None:
        assert parse_allowed_scope("") == []
        assert parse_allowed_scope("  , , ") == []

    def test_normalizes(self) -> None:
        assert parse_allowed_scope("192.168.1.0/24, Example.COM") == [
            "192.168.1.0/24",
            "example.com",
        ]


class TestExtractTargets:
    def test_ipv4(self) -> None:
        ips, domains = extract_targets("nmap 10.0.0.5 -p 80")
        assert "10.0.0.5" in ips
        assert domains == []

    def test_ipv6_bracketed(self) -> None:
        ips, _ = extract_targets("curl https://[2001:db8::1]/443/")
        assert any("2001:db8" in ip for ip in ips)

    def test_ipv6_bare(self) -> None:
        ips, _ = extract_targets("ping6 2001:db8::dead")
        assert any(ip.endswith("dead") or "dead" in ip for ip in ips)

    def test_domains(self) -> None:
        ips, domains = extract_targets("nikto -h evil.example.com")
        assert "evil.example.com" in domains
        assert ips == []

    def test_localhost_token(self) -> None:
        _, domains = extract_targets("curl http://localhost:8080")
        assert "localhost" in domains


class TestIpInScope:
    def test_cidr_match(self) -> None:
        assert ip_in_scope("192.168.1.50", ["192.168.1.0/24"]) is True
        assert ip_in_scope("10.0.0.1", ["192.168.1.0/24"]) is False

    def test_exact_ip(self) -> None:
        assert ip_in_scope("10.0.0.1", ["10.0.0.1"]) is True

    def test_ipv6_cidr(self) -> None:
        assert ip_in_scope("2001:db8::1", ["2001:db8::/32"]) is True
        assert ip_in_scope("2001:db9::1", ["2001:db8::/32"]) is False


class TestDomainInScope:
    def test_exact(self) -> None:
        assert domain_in_scope("target.local", ["target.local"]) is True
        assert domain_in_scope("other.com", ["target.local"]) is False

    def test_wildcard(self) -> None:
        assert domain_in_scope("a.example.com", ["*.example.com"]) is True
        assert domain_in_scope("example.com", ["*.example.com"]) is True
        assert domain_in_scope("evil.com", ["*.example.com"]) is False

    def test_cidr_only_never_authorizes_domain(self) -> None:
        # SX-004: CIDR-only scopes must not silently allow domains
        assert domain_in_scope("github.com", ["10.0.0.0/8"]) is False
        assert domain_in_scope("evil.com", ["192.168.1.0/24"]) is False


class TestAssertCommandInScope:
    def test_noop_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SIYARIX_ALLOWED_SCOPE", raising=False)
        assert_command_in_scope("nmap github.com")  # no scope → no-op

    def test_blocks_out_of_scope_ipv4(self) -> None:
        with pytest.raises(PermissionDeniedError, match="out of authorized scope"):
            assert_command_in_scope("nmap 10.0.0.1", scope_env="192.168.1.0/24")

    def test_allows_in_scope_ipv4(self) -> None:
        assert_command_in_scope("nmap 192.168.1.5", scope_env="192.168.1.0/24")

    def test_blocks_ipv6_out_of_scope(self) -> None:
        with pytest.raises(PermissionDeniedError, match="out of authorized scope"):
            assert_command_in_scope("nmap -6 2001:db9::1", scope_env="2001:db8::/32")

    def test_allows_ipv6_in_scope(self) -> None:
        assert_command_in_scope("curl https://[2001:db8::1]/80/", scope_env="2001:db8::/32")

    def test_no_public_domain_exemption(self) -> None:
        # github.com must NOT be exempt when absent from explicit scope
        with pytest.raises(PermissionDeniedError, match="github.com"):
            assert_command_in_scope("curl https://github.com/", scope_env="192.168.0.0/16")

    def test_cidr_only_blocks_domains(self) -> None:
        with pytest.raises(PermissionDeniedError, match="evil.com"):
            assert_command_in_scope("nikto -h evil.com", scope_env="10.0.0.0/8")

    def test_explicit_domain_allowed(self) -> None:
        assert_command_in_scope(
            "nikto -h app.example.com",
            scope_env="192.168.1.0/24,*.example.com",
        )

    def test_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SIYARIX_ALLOWED_SCOPE", "10.0.0.0/8")
        with pytest.raises(PermissionDeniedError):
            assert_command_in_scope("nmap 192.168.1.1")
        assert_command_in_scope("nmap 10.1.2.3")
        monkeypatch.delenv("SIYARIX_ALLOWED_SCOPE", raising=False)
        assert "SIYARIX_ALLOWED_SCOPE" not in os.environ
