from __future__ import annotations


import pytest
from click.testing import CliRunner
from typer import Typer
from typer.main import get_command

from siyarix.security_commands import security_app


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
        output = invoke_security(cli, runner, ["incidents", "--status", "open", "--severity", "critical"])
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
        output = invoke_security(cli, runner, [
            "incident-create",
            "--title", "SQL Injection",
            "--description", "SQLi on login",
            "--category", "intrusion",
        ])
        assert "SQL Injection" in output
        assert "MEDIUM" in output

    def test_create_incident_custom_severity(self, cli: Typer, runner: CliRunner) -> None:
        output = invoke_security(cli, runner, [
            "incident-create",
            "--title", "Ransomware",
            "--description", "Encryption detected",
            "--category", "malware",
            "--severity", "critical",
        ])
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


class TestMitreCoverage:
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
