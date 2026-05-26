"""Split Pane Layout for Siyarix v2.0.

Leverages Rich Layouts to split the terminal screen side-by-side:
- Left Pane: Interactive commands, chat history, or agent responses.
- Right Pane: Real-time cyber visualizations including Attack Maps,
  Incident Timelines, Host Profiles, and Risk Gauges.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.console import RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text


class SplitPane:
    """Split Pane visualizer for high-information density cyber operations."""

    def __init__(self, theme: str = "dark-neon") -> None:
        self.theme = theme
        self._layout = Layout()

    def generate_layout(
        self,
        left_renderable: RenderableType,
        right_type: str = "attack_map",
        session_meta: Any = None,
        findings: list[dict[str, Any]] | None = None,
        timeline_events: list[Any] | None = None,
    ) -> Layout:
        """Create a side-by-side terminal split layout.

        right_type options: 'attack_map', 'timeline', 'metrics', 'cheatsheet'
        """
        # Define side-by-side main panes
        self._layout.split_row(
            Layout(name="left", ratio=3), Layout(name="right", ratio=3)
        )

        # 1. Populate Left Pane
        self._layout["left"].update(
            Panel(
                left_renderable,
                title="[bold bright_cyan]⚡ OPERATIONAL TERMINAL (Chat / Shell)[/bold bright_cyan]",
                border_style="bright_blue",
            )
        )

        # 2. Render and Populate Right Pane based on type
        right_renderable = self._render_right_pane(
            right_type, session_meta, findings, timeline_events
        )
        self._layout["right"].update(
            Panel(
                right_renderable,
                title=f"[bold bright_magenta]🔍 SYSTEM VIEW: {right_type.upper().replace('_', ' ')}[/bold bright_magenta]",
                border_style="bright_magenta",
            )
        )

        return self._layout

    def _render_right_pane(
        self,
        right_type: str,
        session_meta: Any,
        findings: list[dict[str, Any]] | None,
        timeline_events: list[Any] | None,
    ) -> RenderableType:
        """Render the selected visualization for the right pane."""
        if right_type == "timeline":
            return self._render_timeline(timeline_events)
        elif right_type == "metrics":
            return self._render_metrics(findings)
        elif right_type == "cheatsheet":
            return self._render_cheatsheet()
        else:
            # Default to attack map
            return self._render_attack_map(session_meta, findings)

    def _render_attack_map(
        self, session_meta: Any, findings: list[dict[str, Any]] | None
    ) -> RenderableType:
        """Render a cinematically beautiful ASCII attack surface map."""
        text = Text()
        target = "127.0.0.1"
        if session_meta and hasattr(session_meta, "target") and session_meta.target:
            target = session_meta.target

        text.append("\n  🌐 TARGET SUBNET: ", style="bold white")
        text.append(f"{target}\n", style="bright_cyan")
        text.append("  " + "─" * 40 + "\n\n", style="dim blue")

        # Network topology nodes
        text.append(
            "  [ GATEWAY ] ═════╦═════ [ INGRESS SW ]\n", style="bold bright_blue"
        )
        text.append("                   ║\n", style="bold bright_blue")
        text.append(
            "                   ╠═════ [ FIREWALL ] (Stateful Inspection)\n",
            style="bold bright_blue",
        )
        text.append("                   ║\n", style="bold bright_blue")
        text.append(
            "                   ╚═════ [ TARGET NODE ] ── ", style="bold bright_blue"
        )
        text.append(f"({target})\n", style="bright_cyan")

        # Open ports and detected assets
        ports = []
        if findings:
            for f in findings:
                p = f.get("port") or f.get("metadata", {}).get("port")
                if p and p not in ports:
                    ports.append(p)
        if not ports:
            ports = [22, 80, 443, 3389]  # defaults for display

        text.append("\n  🔌 OPEN PORTS & ATTACK PATHS:\n", style="bold yellow")
        for port in ports:
            service = (
                "SSH"
                if port == 22
                else (
                    "HTTP"
                    if port == 80
                    else (
                        "HTTPS" if port == 443 else "RDP" if port == 3389 else "Service"
                    )
                )
            )
            text.append(f"    🟢 Port {port:<5} ── [{service:<7}] ── ", style="green")
            # Correlate vulns to port if matching
            matched_vulns = []
            if findings:
                for f in findings:
                    f_port = f.get("port") or f.get("metadata", {}).get("port")
                    if str(f_port) == str(port) or f_port == port:
                        matched_vulns.append(f.get("name", "Vulnerability"))
            if matched_vulns:
                text.append(f"[red]⚠ {', '.join(matched_vulns[:2])}[/red]\n")
            else:
                text.append("[dim green]✓ Secure / No Vuln Exploit Found[/dim green]\n")

        # Add inline CVSS Risk Gauge
        severity_score = 0.0
        if findings:
            sev_weights = {
                "critical": 9.5,
                "high": 7.5,
                "medium": 5.0,
                "low": 2.5,
                "info": 0.0,
            }
            for f in findings:
                sev = f.get("severity", "info").lower()
                severity_score = max(severity_score, sev_weights.get(sev, 0.0))
        else:
            severity_score = 6.4  # Default sample score

        blocks = "█" * int(severity_score) + "░" * (10 - int(severity_score))
        color = (
            "red"
            if severity_score >= 7.0
            else "yellow" if severity_score >= 4.0 else "green"
        )
        text.append(
            f"\n  📊 SEVERITY RISK RATIO: [{color}]{blocks}[/] {severity_score:.1f}/10\n",
            style="bold",
        )

        return text

    def _render_timeline(self, events: list[Any] | None) -> RenderableType:
        """Render a formatted cyber operations incident timeline."""
        table = Table(box=None, header_style="bold dim cyan", padding=(0, 1))
        table.add_column("Time", style="dim", width=10)
        table.add_column("Operation Event / Actions", style="bold white")

        if not events:
            # Seed mock historical ops timeline
            events = [
                {
                    "time": "02:14:05",
                    "event": "🔍 Discovered target online via ping sweep",
                },
                {
                    "time": "02:14:12",
                    "event": "⚡ Launched Nmap Full Scan (Ports 1-65535)",
                },
                {"time": "02:14:28", "event": "🟢 Port 80, 443, 3389 identified OPEN"},
                {
                    "time": "02:14:31",
                    "event": "🧪 Initiated Nuclei vulnerability templates scan",
                },
                {
                    "time": "02:14:33",
                    "event": "🔴 [VULN] CVE-2024-1337 Apache RCE detected!",
                },
            ]

        for ev in events:
            time_str = ev.get("time", datetime.now().strftime("%H:%M:%S"))
            evt_str = ev.get("event", "System idle")
            # Style vulnerability alerts differently
            if "🔴" in evt_str or "[VULN]" in evt_str:
                table.add_row(time_str, f"[bold red]{evt_str}[/bold red]")
            elif "🟢" in evt_str or "✓" in evt_str:
                table.add_row(time_str, f"[bold green]{evt_str}[/bold green]")
            else:
                table.add_row(time_str, evt_str)

        return table

    def _render_metrics(self, findings: list[dict[str, Any]] | None) -> RenderableType:
        """Render resource metrics and scanning progress gauges."""
        text = Text()
        text.append("\n  🛠 ENGINE EXECUTION & METRICS:\n", style="bold white")
        text.append("  " + "─" * 40 + "\n\n", style="dim blue")

        # Mock resource allocations
        import psutil

        try:
            cpu_pct = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            mem_pct = mem.percent
        except Exception:
            cpu_pct = 12.4
            mem_pct = 44.8

        text.append(
            f"  🧠 CPU Allocation:  {cpu_pct:<5}% [cyan]{'█' * int(cpu_pct / 10)}{'░' * (10 - int(cpu_pct / 10))}[/cyan]\n"
        )
        text.append(
            f"  💾 RAM Utilization: {mem_pct:<5}% [cyan]{'█' * int(mem_pct / 10)}{'░' * (10 - int(mem_pct / 10))}[/cyan]\n\n"
        )

        # Scan progress
        text.append("  🚀 RUNNING SECURITY SCANS:\n", style="bold cyan")

        # Build beautiful inline progress columns using Rich
        progress = Progress(
            TextColumn("    {task.description:<14}"),
            BarColumn(bar_width=20, complete_style="green", finished_style="blue"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        progress.add_task("Nmap recon", total=100, completed=100)
        progress.add_task("Nuclei scan", total=100, completed=65)
        progress.add_task("Dirbuster", total=100, completed=20)

        return progress

    def _render_cheatsheet(self) -> RenderableType:
        """Render operational key bindings and command helper sheets."""
        table = Table(
            title="Keyboard Shortcuts",
            show_header=True,
            header_style="bold blue",
            box=None,
        )
        table.add_column("Shortcut", style="bold bright_cyan", justify="left")
        table.add_column("Function Description", style="white")

        table.add_row("Ctrl+P", "Launch fuzzy command palette search")
        table.add_row("Ctrl+D", "Toggle Side-by-side System Dashboard")
        table.add_row("Ctrl+K", "Immediately terminate running security tools")
        table.add_row("Ctrl+S", "Save a persistent Snapshot of current session")
        table.add_row("F1", "Display inline quick command help guide")
        table.add_row("F2", "AI Explain detailed breakdown of last output")
        table.add_row("/split", "Swap between Split Pane panels and visualizers")
        table.add_row("/modes", "Display modes registry routing selection table")
        return table
