"""Command Replay System.

Allows operators to replay commands from a previous session or replay a
specific workflow step-by-step for verification or time-travel debugging.
"""

from rich.console import Console

from phalanx.session_manager import command_history


class CommandReplayer:
    """Replays commands from the SQLite command history."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def list_recent(self, limit: int = 10) -> None:
        """Display recent commands available for replay."""
        history = command_history.recent(limit=limit)
        if not history:
            self.console.print("[dim]No command history found.[/dim]")
            return

        self.console.print(f"[bold cyan]Recent Commands (Last {limit})[/bold cyan]")
        for idx, row in enumerate(history, start=1):
            cmd = row["command"]
            ts = row["timestamp"]
            res = row["result"]
            color = "green" if res == "success" else "red"
            self.console.print(f"  [bold]{idx}.[/bold] [{color}]{res}[/{color}] - {cmd} [dim]({ts})[/dim]")

    def replay_session(self, session_id: str) -> list[str]:
        """Fetch all commands from a specific session ID, returning them in chronological order."""
        rows = command_history._get_conn().execute(
            """SELECT command FROM command_history
               WHERE session_id = ?
               ORDER BY timestamp ASC""",
            (session_id,)
        ).fetchall()
        
        commands = [r["command"] for r in rows]
        if not commands:
            self.console.print(f"[yellow]No commands found for session: {session_id}[/yellow]")
            return []

        self.console.print(f"[bold green]Prepared {len(commands)} commands for replay from session {session_id}[/bold green]")
        return commands

    def replay_last(self) -> str | None:
        """Fetch the very last executed command."""
        history = command_history.recent(limit=1)
        if not history:
            return None
        return history[0]["command"]


replayer = CommandReplayer()
