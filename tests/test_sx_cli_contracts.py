# SPDX-License-Identifier: AGPL-3.0-or-later

"""CLI contract regressions for SX-013/014/018/019."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from siyarix.cli import app
from siyarix.output import OutputEngine, OutputFormat


runner = CliRunner()


def test_config_override_loads_json_theme(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "override.json"
    cfg.write_text(json.dumps({"color_theme": "arctic"}), encoding="utf-8")
    monkeypatch.delenv("SIYARIX_CONFIG", raising=False)
    result = runner.invoke(app, ["--config", str(cfg), "config", "get", "color_theme"])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "arctic" in result.stdout


def test_json_stdout_is_parseable() -> None:
    engine = OutputEngine(output_format=str(OutputFormat.JSON))
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        engine.print_json([{"id": 1, "title": "a"}, {"id": 2, "extra": True}])
    parsed = json.loads(buf.getvalue())
    assert parsed[0]["id"] == 1
    assert parsed[1]["extra"] is True


def test_run_resume_without_command_is_accepted() -> None:
    # Missing persistence backend should exit 1 (not argparse exit 2 for missing arg).
    result = runner.invoke(app, ["run", "--resume", "latest", "--no-banner"])
    assert result.exit_code != 2


def test_builtin_playbooks_listable_without_cwd(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["playbook", "list"])
    assert result.exit_code == 0, result.stdout
    assert "network-recon" in result.stdout
