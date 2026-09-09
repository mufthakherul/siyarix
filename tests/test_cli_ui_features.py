# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for CLI-UI and feature quality enhancements."""

from __future__ import annotations

from pathlib import Path
from typer.testing import CliRunner

from siyarix.cli import app
from siyarix.compliance import ComplianceEngine


def test_cli_playbook_list_table() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["playbook", "list"])
    assert result.exit_code == 0
    assert "Available Playbooks" in result.output
    assert "web-vulnerability-scan" in result.output
    assert "network-recon" in result.output


def test_cli_playbook_show_by_name() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["playbook", "show", "web-vulnerability-scan"])
    assert result.exit_code == 0
    assert "Playbook Info" in result.output
    assert "Execution Steps (DAG)" in result.output
    assert "http-headers-check" in result.output
    assert "template-scan" in result.output


def test_cli_playbook_show_by_path() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["playbook", "show", "playbooks/network-recon.yaml"])
    assert result.exit_code == 0
    assert "network-recon" in result.output
    assert "Execution Steps" in result.output


def test_cli_playbook_show_nonexistent() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["playbook", "show", "nonexistent-playbook-xyz"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_cli_compliance_list() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["compliance", "list"])
    assert result.exit_code == 0
    assert "Supported Compliance Frameworks" in result.output
    assert "SOC2" in result.output
    assert "NIST" in result.output
    assert "ISO-27001" in result.output


def test_cli_compliance_run_url_target() -> None:
    runner = CliRunner()
    target = "https://test.internal:8443/api"
    result = runner.invoke(app, ["compliance", "run", "NIST", target])
    assert result.exit_code == 0
    assert "Compliance Assessment: NIST" in result.output
    assert "AC-2" in result.output
    assert "Evidence saved to" in result.output


def test_cli_compliance_reports() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["compliance", "reports"])
    assert result.exit_code == 0
    assert (
        "Compliance Evidence Reports" in result.output
        or "No compliance reports found" in result.output
    )


def test_cli_cache_status_rich_table() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["cache", "status"])
    assert result.exit_code == 0
    assert "Cache Storage" in result.output
    assert "Total Cached Entries" in result.output
    assert "Cache Hit Rate" in result.output


def test_cli_config_show_alias() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "Siyarix Configuration" in result.output
    assert "color_theme" in result.output


def test_cli_audit_show_alias() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["audit", "show", "--limit", "3"])
    assert result.exit_code == 0
    assert "Audit Trail" in result.output


def test_cli_security_findings_alias() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["security", "findings", "--limit", "5"])
    assert result.exit_code == 0
    assert "Vulnerabilities" in result.output


def test_cli_theme_list_active_indicator() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["theme", "list"])
    assert result.exit_code == 0
    assert "Available Color Themes" in result.output
    assert "active" in result.output
    assert "siyarix theme set" in result.output


def test_compliance_engine_safe_directory_naming(tmp_path: Path) -> None:
    engine = ComplianceEngine(base_dir=tmp_path / "evidence")
    import asyncio

    report = asyncio.run(engine.run_assessment("SOC2", "http://my-host.org:9000/app/test"))
    assert report.evidence_path.exists()
    assert ":" not in report.evidence_path.name
    assert "/" not in report.evidence_path.name
