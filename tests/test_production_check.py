# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI production-check readiness command."""

from __future__ import annotations

import json

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
    assert "hard-blocks" in by_name["destructive_guard"]["detail"]
    assert "file://" in by_name["destructive_guard"]["detail"]
    assert by_name["command_review"]["status"] in {"pass", "warn"}
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
