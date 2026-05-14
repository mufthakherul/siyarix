from __future__ import annotations

from click.testing import CliRunner
from typer import Typer
from typer.main import get_command

from cosmicsec_agent.security_commands import register_security_commands


def test_security_group_registers_and_shows_help() -> None:
    cli = Typer()
    register_security_commands(cli)

    command = get_command(cli)
    runner = CliRunner()
    result = runner.invoke(command, ["--help"])

    assert result.exit_code == 0
    assert "security" in result.output.lower()
