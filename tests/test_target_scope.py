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

    def test_blocks_percent_encoded_domain(self) -> None:
        with pytest.raises(PermissionDeniedError, match="evil.com"):
            assert_command_in_scope("curl http://evil%2ecom/", scope_env="example.com")

    def test_blocks_hex_ipv4(self) -> None:
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("curl http://0x7f000001/", scope_env="example.com")

    def test_blocks_decimal_ipv4(self) -> None:
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("curl http://2130706433/", scope_env="example.com")

    def test_blocks_octal_ipv4(self) -> None:
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("curl http://0177.0.0.1/", scope_env="example.com")

    def test_extract_decodes_percent_domain(self) -> None:
        ips, domains = extract_targets("curl http://evil%2ecom/")
        assert "evil.com" in domains
        assert ips == []

    def test_blocks_short_ipv4(self) -> None:
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("curl http://127.1/", scope_env="example.com")
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("curl http://127.0.1/", scope_env="example.com")

    def test_short_ipv4_does_not_mangle_full_quad(self) -> None:
        ips, _ = extract_targets("nmap 192.168.1.5")
        assert "192.168.1.5" in ips
        assert "192.168.0.1" not in ips

    def test_blocks_whole_octal_integer_ipv4(self) -> None:
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("nmap 017700000001", scope_env="10.0.0.0/8")
        ips, _ = extract_targets("nmap 017700000001")
        assert "127.0.0.1" in ips

    def test_hex_dotted_ipv4_expands_correctly(self) -> None:
        ips, _ = extract_targets("nmap 0x7f.1")
        assert "127.0.0.1" in ips
        assert "0.0.0.127" not in ips
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("nmap 0x7f.1", scope_env="10.0.0.0/8")
        ips2, _ = extract_targets("nmap 0x7f.0.0.1")
        assert ips2 == ["127.0.0.1"]
        # Must not emit phantom 0.0.0.0 from embedded ``0.0`` in hex octets.
        ips3, _ = extract_targets("nmap 0x7f.0x0.0x0.0x1")
        assert ips3 == ["127.0.0.1"]

    def test_inet_aton_short_octal_ipv4(self) -> None:
        # glibc/curl inet_aton: 0177.1 → 127.0.0.1 (not 177.0.0.1)
        ips, _ = extract_targets("nmap 0177.1")
        assert ips == ["127.0.0.1"]
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("nmap 0177.1", scope_env="10.0.0.0/8")
        with pytest.raises(PermissionDeniedError, match="127.0.0.1"):
            assert_command_in_scope("curl http://0177.1/", scope_env="177.0.0.0/8")
        # Hex-dotted must not claim leading-zero octal forms.
        from siyarix.target_scope import _expand_hex_dotted_ipv4

        assert _expand_hex_dotted_ipv4("0177.1") is None

    def test_non_http_schemes_blocked_under_scope(self) -> None:
        with pytest.raises(PermissionDeniedError, match="URL scheme not allowed"):
            assert_command_in_scope("curl file:///etc/passwd", scope_env="10.0.0.0/8")
        with pytest.raises(PermissionDeniedError, match="URL scheme not allowed"):
            assert_command_in_scope("curl ftp://evil.example/x", scope_env="example.com")
        with pytest.raises(PermissionDeniedError, match="URL scheme not allowed"):
            assert_command_in_scope("curl data:text/plain,hi", scope_env="10.0.0.0/8")
        with pytest.raises(PermissionDeniedError, match="URL scheme not allowed"):
            assert_command_in_scope("curl smb://fileserver/share", scope_env="10.0.0.0/8")
        with pytest.raises(PermissionDeniedError, match="URL scheme not allowed"):
            assert_command_in_scope("curl nfs://nas01/export", scope_env="*.lab.example")
        with pytest.raises(PermissionDeniedError, match="URL scheme not allowed"):
            assert_command_in_scope("ldapsearch -H ldap://dc01", scope_env="10.0.0.0/8")
        # No authorized scope → non-HTTP schemes remain unrestricted (opt-in gate).
        assert_command_in_scope("curl file:///etc/passwd")

    def test_single_label_hosts_fail_closed_under_scope(self) -> None:
        scope = "10.0.0.0/8,*.lab.example"
        with pytest.raises(PermissionDeniedError, match="bastion"):
            assert_command_in_scope("ssh bastion", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="dc01"):
            assert_command_in_scope("nmap dc01", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="dc01"):
            assert_command_in_scope("nmap -p 80 dc01", scope_env=scope)
        assert_command_in_scope("nmap 10.1.2.3", scope_env=scope)
        assert_command_in_scope("ssh jump.lab.example", scope_env=scope)

    def test_integer_hosts_and_idn_fail_closed(self) -> None:
        scope = "10.0.0.0/8,*.lab.example"
        with pytest.raises(PermissionDeniedError, match="0.0.0.0"):
            assert_command_in_scope("curl 0", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="0.0.0.1"):
            assert_command_in_scope("curl 1", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="0.0.0.0"):
            assert_command_in_scope("nc 0 80", scope_env=scope)
        # Cyrillic homoglyph in domain label.
        with pytest.raises(PermissionDeniedError, match="еxample"):
            assert_command_in_scope("nmap еxample.com", scope_env=scope)
        assert_command_in_scope("nmap -p 80 10.1.2.3", scope_env=scope)
        # IPv6 hextets must not be misread as integer IPv4 (``2001`` → 0.0.7.209).
        assert_command_in_scope("nmap -6 2001:db8::10", scope_env="2001:db8::/32")

    def test_path_qualified_host_tools_under_scope(self) -> None:
        scope = "10.0.0.0/8,*.lab.example"
        with pytest.raises(PermissionDeniedError, match="0.0.0.0"):
            assert_command_in_scope("/usr/bin/curl 0", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="0.0.0.0"):
            assert_command_in_scope(r"\curl 0", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="0.0.0.1"):
            assert_command_in_scope("./curl 1", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="bastion"):
            assert_command_in_scope("/usr/bin/ssh bastion", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="Command-substitution"):
            assert_command_in_scope("$(curl) 0", scope_env=scope)

    def test_curl_config_and_wget_input_fail_closed(self) -> None:
        scope = "10.0.0.0/8"
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("curl --config /tmp/cfg", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("curl -K /tmp/cfg", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("curl --config=-", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("wget -i /tmp/urls", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("wget --input-file=/tmp/urls", scope_env=scope)
        # curl -i is Include headers, not input-file.
        assert_command_in_scope("curl -i http://10.0.0.1/", scope_env=scope)

    def test_smbclient_unc_hosts_fail_closed_under_scope(self) -> None:
        scope = "10.0.0.0/8,example.com"
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("smbclient //evil-host/share", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope(r"smbclient \\evil-host\share", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("smbclient -L evil-host", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope(
                "mount -t cifs //evil-host/share /mnt", scope_env=scope
            )
        assert_command_in_scope("smbclient //example.com/share", scope_env=scope)
        assert_command_in_scope("smbclient //10.1.2.3/share", scope_env=scope)
        assert_command_in_scope("mount -t cifs //10.1.2.3/share /mnt", scope_env=scope)

    def test_scp_socat_ftp_host_tools_under_scope(self) -> None:
        scope = "10.0.0.0/8,example.com"
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("scp file evil-host:/tmp/", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("socat TCP:evil-host:80 -", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("ftp evil-host", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("enum4linux evil-host", scope_env=scope)
        assert_command_in_scope("scp file 10.1.2.3:/tmp/", scope_env=scope)
        assert_command_in_scope("socat TCP:10.1.2.3:80 -", scope_env=scope)

    def test_ssh_opt_sftp_rsync_aria2c_under_scope(self) -> None:
        scope = "10.0.0.0/8,example.com"
        with pytest.raises(PermissionDeniedError, match="jump"):
            assert_command_in_scope(
                "ssh -o ProxyJump=jump evilhost", scope_env=scope
            )
        with pytest.raises(PermissionDeniedError, match="evilhost"):
            assert_command_in_scope(
                "ssh -o ForwardAgent=yes evilhost", scope_env=scope
            )
        with pytest.raises(PermissionDeniedError, match="bastion"):
            assert_command_in_scope("sftp bastion", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="bastion"):
            assert_command_in_scope("rsync bastion:/path .", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("aria2c -i /tmp/urls", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="URL/config-from-file"):
            assert_command_in_scope("wget --config=/tmp/wgetrc", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil"):
            assert_command_in_scope(
                "curl -x socks5h://evil:1080 http://10.0.0.1/", scope_env=scope
            )
        with pytest.raises(PermissionDeniedError, match="bastion"):
            assert_command_in_scope(
                "scp -J bastion f 10.1.2.3:/t", scope_env=scope
            )
        assert_command_in_scope("ssh -o ForwardAgent=yes 10.1.2.3", scope_env=scope)
        assert_command_in_scope("rsync 10.1.2.3:/path .", scope_env=scope)
        assert_command_in_scope(
            "ssh -o ProxyJump=10.1.2.3 10.1.2.4", scope_env=scope
        )

    def test_shell_c_wrapper_and_socat_socks_under_scope(self) -> None:
        scope = "10.0.0.0/8,*.lab.example"
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope("bash -c 'nmap evil-host'", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="bastion"):
            assert_command_in_scope("sh -c 'ssh bastion'", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-host|proxy"):
            assert_command_in_scope(
                "socat SOCKS4A:proxy:evil-host:80 -", scope_env=scope
            )
        assert_command_in_scope("bash -c 'nmap 10.1.2.3'", scope_env=scope)
        assert_command_in_scope(
            "socat SOCKS4A:10.1.2.3:10.1.2.4:80 -", scope_env=scope
        )

    def test_glued_proxy_jump_and_quoted_ssh_o_under_scope(self) -> None:
        scope = "10.0.0.0/8,example.com"
        with pytest.raises(PermissionDeniedError, match="evil"):
            assert_command_in_scope("ssh -oProxyJump=evil 10.0.0.1", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="ProxyCommand"):
            assert_command_in_scope(
                "ssh -oProxyCommand=/bin/nc 10.0.0.1", scope_env=scope
            )
        with pytest.raises(PermissionDeniedError, match="11.1.1.1"):
            assert_command_in_scope(
                "curl -x11.1.1.1:8080 http://10.0.0.1/", scope_env=scope
            )
        with pytest.raises(PermissionDeniedError, match="11.1.1.1"):
            assert_command_in_scope("ssh -J11.1.1.1 10.0.0.1", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil"):
            assert_command_in_scope("ssh -o'ProxyJump=evil' 10.0.0.1", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evil-proxy"):
            assert_command_in_scope(
                "socat SOCKS4:evil-proxy:10.0.0.1:80 -", scope_env=scope
            )
        assert_command_in_scope(
            "ssh -o ProxyJump=10.1.2.3 10.1.2.4", scope_env=scope
        )

    def test_su_sudo_script_c_wrappers_under_scope(self) -> None:
        scope = "10.0.0.0/8,example.com"
        with pytest.raises(PermissionDeniedError, match="evilhost"):
            assert_command_in_scope("su user -c 'ssh evilhost'", scope_env=scope)
        with pytest.raises(PermissionDeniedError, match="evilhost"):
            assert_command_in_scope(
                "sudo -u root -c 'ssh evilhost'", scope_env=scope
            )
        with pytest.raises(PermissionDeniedError, match="evil-host"):
            assert_command_in_scope(
                "script -c 'nmap evil-host' /dev/null", scope_env=scope
            )
        assert_command_in_scope("su user -c 'ssh 10.1.2.3'", scope_env=scope)
