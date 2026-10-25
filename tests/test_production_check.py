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
    assert {"python", "shell_review", "permission_gate", "tool_registry", "webhook", "health"} <= names
    assert payload["fails"] == 0


def test_production_check_table() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["production-check"])
    assert result.exit_code == 0
    assert "Production Check" in result.stdout or "python" in result.stdout.lower()
