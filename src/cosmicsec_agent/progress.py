"""CosmicSec CLI — CA-2.2 Real-Time Scan Progress.

Provides Rich Live-based progress display for concurrent tool execution.
Supports per-tool spinners, overall progress bars, live findings counter,
and graceful Ctrl+C cancellation (two-stage: cancel-tool then cancel-all).
"""

from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

_SEVERITY_STYLES = {
    "critical": ("🔴", "bold red"),
    "high": ("🟠", "bold yellow"),
    "medium": ("🟡", "yellow"),
    "low": ("🔵", "blue"),
    "info": ("⚪", "dim"),
}

@dataclass
class ScanProgressState:
    """Mutable state shared between the progress display and the async executor."""

    tools_total: int = 0
    tools_done: int = 0
    current_tools: list[str] = field(default_factory=list)
    finding_counts: dict[str, int] = field(default_factory=dict)
    start_time: float = field(default_factory=time.monotonic)
    cancelled: bool = False
    cancel_all: bool = False
    _task_ids: dict[str, TaskID] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def total_findings(self) -> int:
        return sum(self.finding_counts.values())

    def add_finding(self, severity: str) -> None:
        key = severity.lower()
        self.finding_counts[key] = self.finding_counts.get(key, 0) + 1

class ScanProgressDisplay:
    """Rich Live UI for real-time scan progress.

    Usage::

        state = ScanProgressState(tools_total=3)
        display = ScanProgressDisplay(state)
        with display:
            # Update state from async workers
            state.add_finding("critical")
            state.current_tools.append("nmap")
    """

    def __init__(self, state: ScanProgressState) -> None:
        self._state = state
        self._console = Console()
        self._overall_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
            expand=False,
        )
        self._tool_progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[cyan]{task.description}"),
            TimeElapsedColumn(),
            console=self._console,
            expand=False,
        )
        self._overall_task: TaskID | None = None
        self._live: Live | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> ScanProgressDisplay:
        self._overall_task = self._overall_progress.add_task("Scanning…", total=self._state.tools_total)
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        if self._live:
            self._live.__exit__(*args)

    # ------------------------------------------------------------------
    # Public API (call from async workers)
    # ------------------------------------------------------------------

    def tool_started(self, tool_name: str) -> None:
        """Mark a tool as started — adds a spinner row."""
        tid = self._tool_progress.add_task(f"{tool_name}…", total=None)
        self._state._task_ids[tool_name] = tid
        if self._live:
            self._live.update(self._render())

    def tool_done(self, tool_name: str, finding_count: int) -> None:
        """Mark a tool as complete — stops spinner, advances overall bar."""
        tid = self._state._task_ids.get(tool_name)
        if tid is not None:
            self._tool_progress.update(
                tid,
                description=f"[green]✅ {tool_name}[/green] ({finding_count} findings)",
            )
            self._tool_progress.stop_task(tid)
        self._state.tools_done += 1
        if self._overall_task is not None:
            self._overall_progress.update(self._overall_task, advance=1)
        if self._live:
            self._live.update(self._render())

    def tool_error(self, tool_name: str, error: str) -> None:
        """Mark a tool as failed."""
        tid = self._state._task_ids.get(tool_name)
        if tid is not None:
            self._tool_progress.update(
                tid,
                description=f"[red]❌ {tool_name}[/red] ({error[:40]})",
            )
            self._tool_progress.stop_task(tid)
        self._state.tools_done += 1
        if self._overall_task is not None:
            self._overall_progress.update(self._overall_task, advance=1)
        if self._live:
            self._live.update(self._render())

    def refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_findings_summary(self) -> Table:
        t = Table.grid(padding=(0, 2))
        t.add_column(no_wrap=True)
        t.add_column(no_wrap=True)
        for severity, (icon, style) in _SEVERITY_STYLES.items():
            count = self._state.finding_counts.get(severity, 0)
            if count > 0:
                t.add_row(
                    Text(f"{icon} {severity.capitalize()}: ", style=style),
                    Text(str(count), style=style),
                )
        return t

    def _render(self) -> Group:
        elapsed = self._state.elapsed
        m, s = divmod(int(elapsed), 60)
        header = Text(
            f"CosmicSec Scan  ⏱ {m:02d}:{s:02d}  Findings: {self._state.total_findings}",
            style="bold",
        )
        items = [
            Panel(
                Group(self._overall_progress, self._tool_progress),
                title=header,
                border_style="cyan",
            ),
        ]
        if self._state.total_findings:
            items.append(Panel(self._render_findings_summary(), title="Live Findings", border_style="dim"))
        return Group(*items)

    # ------------------------------------------------------------------
    # Summary (printed after Live exits)
    # ------------------------------------------------------------------

    def print_summary(self, target: str) -> None:
        """Print the final scan summary box."""
        elapsed = self._state.elapsed
        m, s = divmod(int(elapsed), 60)
        counts = self._state.finding_counts
        total = self._state.total_findings

        lines = [
            f"[bold]Scan Complete — {target}[/bold]",
            f"Duration: {m:02d}m {s:02d}s · Tools: "
            f"{self._state.tools_done}/{self._state.tools_total} · "
            f"Findings: {total}",
        ]
        severity_parts = []
        for sev, (icon, style) in _SEVERITY_STYLES.items():
            n = counts.get(sev, 0)
            severity_parts.append(f"[{style}]{icon} {sev.capitalize()}: {n}[/{style}]")
        lines.append("  ".join(severity_parts))
        if total == 0:
            lines.append("[green]✅ No findings — target looks clean.[/green]")
        else:
            lines.append("[dim]cosmicsec-agent history list  — view full results[/dim]")

        self._console.print(Panel("\n".join(lines), border_style="green", expand=False))

# ---------------------------------------------------------------------------
# Graceful cancellation (Ctrl+C two-stage)
# ---------------------------------------------------------------------------

class CancellationToken:
    """Shared token for two-stage Ctrl+C cancellation."""

    def __init__(self) -> None:
        self._press_count = 0
        self._last_press: float = 0.0

    @property
    def cancel_current(self) -> bool:
        return self._press_count >= 1

    @property
    def cancel_all(self) -> bool:
        return self._press_count >= 2

    def _handle_sigint(self, *_: object) -> None:
        now = time.monotonic()
        if now - self._last_press < 2.0:
            self._press_count = 2  # second press within 2s → cancel all
        else:
            self._press_count = 1  # first press → cancel current
        self._last_press = now

    def install(self) -> None:
        """Install SIGINT handler."""
        signal.signal(signal.SIGINT, self._handle_sigint)

    def uninstall(self) -> None:
        """Restore default SIGINT handler."""
        signal.signal(signal.SIGINT, signal.SIG_DFL)

# ---------------------------------------------------------------------------
# Concurrent scanner executor
# ---------------------------------------------------------------------------

async def run_tools_with_progress(
    tools: list[dict],  # list of {"name": str, "path": str, "args": list[str]}
    target: str,
    max_parallel: int = 3,
) -> tuple[list[dict], ScanProgressState]:
    """Run security tools concurrently with a live progress display.

    Returns (all_findings, state).
    """
    from .executor import run_tool_complete
    from .parsers import (
        BurpsuiteParser,
        FfufParser,
        GobusterParser,
        HashcatParser,
        HydraParser,
        JohnParser,
        MasscanParser,
        MetasploitParser,
        NiktoParser,
        NmapParser,
        NucleiParser,
        SqlmapParser,
        WpscanParser,
        ZaproxyParser,
    )

    _PARSERS = {
        "nmap": NmapParser(),
        "nikto": NiktoParser(),
        "nuclei": NucleiParser(),
        "gobuster": GobusterParser(),
        "sqlmap": SqlmapParser(),
        "ffuf": FfufParser(),
        "masscan": MasscanParser(),
        "wpscan": WpscanParser(),
        "hydra": HydraParser(),
        "zaproxy": ZaproxyParser(),
        "john": JohnParser(),
        "hashcat": HashcatParser(),
        "metasploit": MetasploitParser(),
        "burpsuite": BurpsuiteParser(),
    }

    state = ScanProgressState(tools_total=len(tools))
    token = CancellationToken()
    token.install()
    tool_results: list[dict] = []
    display = ScanProgressDisplay(state)

    semaphore = asyncio.Semaphore(max_parallel)

    async def _run_one(tool_info: dict) -> None:
        async with semaphore:
            if token.cancel_all:
                return
            name = tool_info["name"]
            display.tool_started(name)
            try:
                result = await run_tool_complete(
                    tool_info["path"],
                    [*tool_info.get("args", []), target],
                )
                parser = _PARSERS.get(name)
                findings = parser.parse(result.stdout) if parser else []
                for f in findings:
                    state.add_finding(f.get("severity", "info"))
                    display.refresh()
                if result.exit_code == 0:
                    display.tool_done(name, len(findings))
                else:
                    display.tool_error(name, f"exit {result.exit_code}")
                tool_results.append(
                    {
                        "name": name,
                        "exit_code": result.exit_code,
                        "findings": findings,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                )
            except Exception as exc:
                display.tool_error(name, str(exc))
                tool_results.append(
                    {
                        "name": name,
                        "exit_code": 1,
                        "findings": [],
                        "stdout": "",
                        "stderr": str(exc),
                    }
                )

    with display:
        tasks = [asyncio.create_task(_run_one(t)) for t in tools]
        await asyncio.gather(*tasks, return_exceptions=True)

    token.uninstall()
    display.print_summary(target)
    return tool_results, state
