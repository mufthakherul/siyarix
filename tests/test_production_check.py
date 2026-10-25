# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI production-check readiness command."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from siyarix.cli import app


def test_production_check_json() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    names = {c["name"] for c in payload["checks"]}
    assert {
        "python",
        "shell_review",
        "permission_gate",
        "tool_registry",
        "webhook",
        "allowed_scope",
        "command_review",
        "destructive_guard",
        "health",
    } <= names
    assert payload["fails"] == 0
    by_name = {c["name"]: c for c in payload["checks"]}
    assert by_name["destructive_guard"]["status"] == "pass"
    detail = by_name["destructive_guard"]["detail"]
    assert "hard-blocks" in detail
    assert "operator-safety" in detail
    assert "research tooling" in detail
    assert by_name["command_review"]["status"] in {"pass", "warn"}
    assert by_name["allowed_scope"]["status"] == "pass"
    assert "research tooling" in by_name["allowed_scope"]["detail"] or "engagement" in by_name[
        "allowed_scope"
    ]["detail"]
    assert isinstance(payload.get("score"), int)
    assert 0 <= payload["score"] <= 100
    assert payload.get("grade") in {"production-ready", "needs-attention", "not-ready"}
    assert isinstance(payload.get("remediations"), list)


def test_production_check_table() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["production-check"])
    assert result.exit_code == 0
    assert "Production Check" in result.stdout or "python" in result.stdout.lower()


def test_doctor_alias() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["doctor", "-o", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["fails"] == 0
    assert {c["name"] for c in payload["checks"]} >= {"python", "destructive_guard"}


def test_production_check_strict_fails_file_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SX-A06: --strict treats file_key vault as a hard failure."""
    monkeypatch.delenv("SIYARIX_MASTER_PASSWORD", raising=False)
    monkeypatch.delenv("SIYARIX_REQUIRE_MASTER_PASSWORD", raising=False)
    monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json", "--strict"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    by_name = {c["name"]: c for c in payload["checks"]}
    assert by_name["credentials"]["status"] == "fail"
    assert "file_key" in by_name["credentials"]["detail"]


def test_production_check_require_master_password_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SIYARIX_REQUIRE_MASTER_PASSWORD", "1")
    monkeypatch.delenv("SIYARIX_MASTER_PASSWORD", raising=False)
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json"])
    # CredentialStore may refuse init → warn unavailable, or fail file_key row.
    payload = json.loads(result.stdout)
    by_name = {c["name"]: c for c in payload["checks"]}
    cred = by_name["credentials"]
    assert cred["status"] in {"fail", "warn"}
    assert result.exit_code in {0, 1, 2}
