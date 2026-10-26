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
    assert (
        "research tooling" in by_name["allowed_scope"]["detail"]
        or "engagement" in by_name["allowed_scope"]["detail"]
    )
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
    monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
    monkeypatch.delenv("SIYARIX_MASTER_PASSWORD", raising=False)
    monkeypatch.delenv("SIYARIX_ALLOWED_SCOPE", raising=False)
    monkeypatch.delenv("SIYARIX_ALLOW_UNSCOPED", raising=False)
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json"])
    # Vault-only hardening must not force engagement-scope fail (residual #5).
    payload = json.loads(result.stdout)
    by_name = {c["name"]: c for c in payload["checks"]}
    cred = by_name["credentials"]
    assert cred["status"] in {"fail", "warn"}
    assert by_name["allowed_scope"]["status"] == "pass"
    assert result.exit_code in {0, 1, 2}


def test_production_check_scope_fail_under_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SEC-03: production posture without scope fails allowed_scope."""
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.delenv("SIYARIX_ALLOWED_SCOPE", raising=False)
    monkeypatch.delenv("SIYARIX_ALLOW_UNSCOPED", raising=False)
    monkeypatch.delenv("SIYARIX_MASTER_PASSWORD", raising=False)
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json"])
    payload = json.loads(result.stdout)
    by_name = {c["name"]: c for c in payload["checks"]}
    assert by_name["allowed_scope"]["status"] == "fail"
    assert "ALLOW_UNSCOPED" in by_name["allowed_scope"]["detail"]
    assert result.exit_code == 1


def test_production_check_allow_unscoped_warns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SEC-03: SIYARIX_ALLOW_UNSCOPED=1 opts out with a warn, not a fail."""
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_ALLOW_UNSCOPED", "1")
    monkeypatch.delenv("SIYARIX_ALLOWED_SCOPE", raising=False)
    monkeypatch.setenv("SIYARIX_MASTER_PASSWORD", "test-master-password-for-prod-check")
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json"])
    payload = json.loads(result.stdout)
    by_name = {c["name"]: c for c in payload["checks"]}
    assert by_name["allowed_scope"]["status"] == "warn"
    assert "ALLOW_UNSCOPED" in by_name["allowed_scope"]["detail"]


def test_production_check_lab_scope_unset_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SEC-03: lab default (production off) keeps unset scope as pass."""
    monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
    monkeypatch.delenv("SIYARIX_REQUIRE_MASTER_PASSWORD", raising=False)
    monkeypatch.delenv("SIYARIX_ALLOWED_SCOPE", raising=False)
    monkeypatch.delenv("SIYARIX_ALLOW_UNSCOPED", raising=False)
    runner = CliRunner()
    result = runner.invoke(app, ["production-check", "-o", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    by_name = {c["name"]: c for c in payload["checks"]}
    assert by_name["allowed_scope"]["status"] == "pass"
    assert "research tooling" in by_name["allowed_scope"]["detail"]
