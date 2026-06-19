
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner
from typer import Typer
from typer.main import get_command

from siyarix.chat.commands import CommandProfile, CommandProfileStore
from siyarix.dlp import DLPEngine
from siyarix.security_commands import security_app

# SPDX-License-Identifier: AGPL-3.0-or-later






@pytest.fixture
def cli() -> Typer:
    app = Typer()
    app.add_typer(security_app, name="security")
    return app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def invoke_security(cli: Typer, runner: CliRunner, args: list[str]) -> str:
    command = get_command(cli)
    result = runner.invoke(command, ["security"] + args)
    assert result.exit_code == 0
    return result.output


class TestSecurityGroup:
    def test_help(self, cli: Typer, runner: CliRunner) -> None:
        command = get_command(cli)
        result = runner.invoke(command, ["security", "--help"])
        assert result.exit_code == 0
        assert "security" in result.output.lower()


class TestIncidentsCommand:
    def test_list_default(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incidents"])
        assert "INC-001" in output
        assert "Ransomware" in output

    def test_list_filter_by_status(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incidents", "--status", "open"])
        assert "INC-001" not in output
        assert "INC-002" in output
        assert "INC-003" in output

    def test_list_filter_by_severity(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incidents", "--severity", "critical"])
        assert "INC-001" in output
        assert "INC-005" in output
        assert "INC-002" not in output

    def test_list_json_output(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incidents", "--output", "json"])
        assert "{" in output
        assert "INC-001" in output

    def test_list_with_limit(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incidents", "--limit", "2"])
        lines = [l for l in output.split("\n") if "INC-" in l]
        assert len(lines) <= 2

    def test_filter_status_and_severity(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(
            cli, runner, ["incidents", "--status", "open", "--severity", "critical"]
        )
        assert "INC-001" not in output

    def test_empty_filter_result(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incidents", "--status", "closed"])
        assert "0 shown" in output


class TestIncidentDetail:
    def test_get_incident(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incident", "INC-001"])
        assert "Ransomware" in output
        assert "CRITICAL" in output

    def test_get_incident_different_id(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["incident", "INC-999"])
        assert "INC-999" in output


class TestCreateIncident:
    def test_create_incident_default_severity(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(
            cli,
            runner,
            [
                "incident-create",
                "--title",
                "SQL Injection",
                "--description",
                "SQLi on login",
                "--category",
                "intrusion",
            ],
        )
        assert "SQL Injection" in output
        assert "MEDIUM" in output

    def test_create_incident_custom_severity(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(
            cli,
            runner,
            [
                "incident-create",
                "--title",
                "Ransomware",
                "--description",
                "Encryption detected",
                "--category",
                "malware",
                "--severity",
                "critical",
            ],
        )
        assert "CRITICAL" in output


class TestVulnerabilitiesCommand:
    def test_list_default(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["vulnerabilities"])
        assert "CVE-2024-0001" in output
        assert "Log4Shell" in output

    def test_filter_by_severity(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["vulnerabilities", "--severity", "critical"])
        assert "CVE-2024-0001" in output
        assert "CVE-2024-0003" not in output

    def test_filter_by_status(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["vulnerabilities", "--status", "patched"])
        assert "CVE-2024-0003" in output
        assert "CVE-2024-0001" not in output

    def test_json_output(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["vulnerabilities", "--output", "json"])
        assert "CVE-2024-0001" in output
        assert "{" in output

    def test_empty_filter(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["vulnerabilities", "--status", "accepted"])
        assert "0 shown" in output


class TestRemediationPlan:
    def test_remediation_plan(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["remediation-plan"])
        assert "CVE-2024-0001" in output
        assert "Upgrade log4j" in output


class TestHuntCommands:
    def test_run_hunt(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["hunt", "q_ps_exec"])
        assert "q_ps_exec" in output

    def test_run_hunt_with_target(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["hunt", "q_rdp_brute", "--target", "10.0.0.1"])
        assert "10.0.0.1" in output


class TestQueriesCommand:
    def test_list_queries(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["queries"])
        assert "q_ps_exec" in output
        assert "PowerShell" in output

    def test_filter_by_tag(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["queries", "--tag", "network"])
        assert "q_dns_tunnel" in output
        assert "q_ps_exec" not in output

    def test_filter_by_mitre_tactic(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["queries", "--mitre-tactic", "Credential Access"])
        assert "q_rdp_brute" in output
        assert "q_dns_tunnel" not in output


class TestMitreCore:
    def test_mitre_coverage(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["mitre-coverage"])
        assert "T1059" in output
        assert "Covered" in output
        assert "Gap" in output


class TestDashboard:
    def test_dashboard(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["dashboard"])
        assert "Security Score" in output
        assert "MTTD" in output


class TestPlaybooks:
    def test_list_playbooks(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, ["playbooks"])
        assert "pb_ransomware" in output
        assert "Ransomware Response" in output
        assert "phishing" in output.lower()

class TestCommandsCore:
    """Cover missing commands.py lines."""

    def test_save_sets_created_at_when_empty(self, tmp_path):
        from siyarix.chat.commands import CommandProfileStore, CommandProfile
        store = CommandProfileStore()
        store._profiles_dir = tmp_path
        p = CommandProfile(name="test", command="ls")
        p.created_at = ""
        store.save(p)
        assert p.created_at != ""

    def test_list_credentials_skips_bad_json(self, tmp_path):
        from siyarix.chat.commands import CommandProfileStore
        store = CommandProfileStore()
        store._profiles_dir = tmp_path
        (tmp_path / "bad.json").write_text("not json")
        result = store.list_credentials()
        assert result == []

    def test_delete_returns_false_when_missing(self, tmp_path):
        from siyarix.chat.commands import CommandProfileStore
        store = CommandProfileStore()
        store._profiles_dir = tmp_path
        assert store.delete("nonexistent") is False

    def test_render_replaces_params(self):
        from siyarix.chat.commands import CommandProfileStore
        store = CommandProfileStore()
        result = store.render("hello {name}", {"name": "world"})
        assert result == "hello world"


# ═══════════════════════════════════════════════════════════════════
# chat/prompts.py (88% - missing line 34)
# ═══════════════════════════════════════════════════════════════════
class TestDLPCore:
    """Cover missing DLP lines."""

    def test_redact_non_string_returns_unchanged(self):
        engine = DLPEngine()
        assert engine.redact(42) == 42

    def test_redact_secrets(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        result = engine.redact("My key is AKIAIOSFODNN7EXAMPLE")
        assert "[REDACTED AWS_KEY]" in result

    def test_redact_pii(self):
        engine = DLPEngine(redact_secrets=False, redact_pii=True)
        result = engine.redact("Email: test@example.com")
        assert "[REDACTED EMAIL]" in result

    def test_redact_logs_when_changed(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        with patch("siyarix.dlp.logger") as mock_log:
            engine.redact("AKIAIOSFODNN7EXAMPLE")
            mock_log.debug.assert_called_once()

    def test_redact_dict_recursive(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        data = {"nested": {"key": "AKIAIOSFODNN7EXAMPLE"}, "list": ["secret AKIAIOSFODNN7EXAMPLE"]}
        result = engine.redact_dict(data)
        assert "[REDACTED AWS_KEY]" in result["nested"]["key"]
        assert "[REDACTED AWS_KEY]" in result["list"][0]

    def test_redact_dict_non_string_value_passthrough(self):
        engine = DLPEngine()
        result = engine.redact_dict({"num": 42, "flag": True})
        assert result["num"] == 42
        assert result["flag"] is True


# ═══════════════════════════════════════════════════════════════════
# executor.py (67% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
class TestCommandsSaveEdge:
    """Line 122-124: profile.created_at already set => skip assignment."""

    def test_save_with_created_at_already_set(self, tmp_path):
        store = CommandProfileStore()
        store._profiles_dir = tmp_path
        p = CommandProfile(name="existing", command="ls", created_at="2024-01-01T00:00:00")
        store.save(p)
        assert p.created_at == "2024-01-01T00:00:00"


# ═══════════════════════════════════════════════════════════════════
# 5. audit_log.py (91% - many uncovered lines)
# ═══════════════════════════════════════════════════════════════════
class TestDLPEngine:
    """Cover DLP filtering engine: exact match, regex, false positive, not_available branches."""

    def test_redact_non_string_returns_as_is(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        assert engine.redact(123) == 123
        assert engine.redact(None) is None
        assert engine.redact([1, 2, 3]) == [1, 2, 3]

    def test_redact_secrets_false_skips_secret_patterns(self):
        engine = DLPEngine(redact_secrets=False, redact_pii=False)
        text = "My AWS key is AKIAIOSFODNN7EXAMPLE"
        result = engine.redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" in result

    def test_redact_secrets_with_secret_enabled(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        text = "My AWS key is AKIAIOSFODNN7EXAMPLE"
        result = engine.redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED AWS_KEY]" in result

    def test_redact_pii_true_masks_pii(self):
        engine = DLPEngine(redact_secrets=False, redact_pii=True)
        text = "user@example.com and 123-45-6789"
        result = engine.redact(text)
        assert "user@example.com" not in result
        assert "123-45-6789" not in result
        assert "[REDACTED EMAIL]" in result
        assert "[REDACTED SSN]" in result

    def test_redact_both_secrets_and_pii(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=True)
        text = "AKIAIOSFODNN7EXAMPLE and user@example.com"
        result = engine.redact(text)
        assert "[REDACTED AWS_KEY]" in result
        assert "[REDACTED EMAIL]" in result

    def test_redact_no_change_logs_debug(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        with patch("siyarix.dlp.logger") as mock_log:
            engine.redact("nothing sensitive here")
            mock_log.debug.assert_not_called()

    def test_redact_with_change_logs_debug(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        with patch("siyarix.dlp.logger") as mock_log:
            engine.redact("key is AKIAIOSFODNN7EXAMPLE")
            mock_log.debug.assert_called_once()

    def test_redact_dict_string_value(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        data = {"key": "AKIAIOSFODNN7EXAMPLE"}
        result = engine.redact_dict(data)
        assert "[REDACTED AWS_KEY]" in str(result)

    def test_redact_dict_nested_dict(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        data = {"outer": {"inner": "AKIAIOSFODNN7EXAMPLE"}}
        result = engine.redact_dict(data)
        assert "[REDACTED AWS_KEY]" in str(result)

    def test_redact_dict_list_values(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        data = {"items": ["safe", "AKIAIOSFODNN7EXAMPLE"]}
        result = engine.redact_dict(data)
        assert result["items"][0] == "safe"
        assert "[REDACTED AWS_KEY]" in result["items"][1]

    def test_redact_dict_other_types_preserved(self):
        engine = DLPEngine(redact_secrets=True, redact_pii=False)
        data = {"num": 42, "flag": True, "none": None}
        result = engine.redact_dict(data)
        assert result["num"] == 42
        assert result["flag"] is True
        assert result["none"] is None


# ═══════════════════════════════════════════════════════════════════
# 2. chat/platform_utils.py (37% - missing 124-131, 139, 152-167, 180-201)
# ═══════════════════════════════════════════════════════════════════
