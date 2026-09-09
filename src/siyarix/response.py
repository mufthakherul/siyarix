from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel


@dataclass
class FindingGroup:
    severity: str
    items: list[dict[str, Any]]
    count: int = 0

    def __post_init__(self) -> None:
        self.count = len(self.items)


@dataclass
class SummarySection:
    title: str
    lines: list[str] = field(default_factory=list)
    style: str = "white"


class ResponseGenerator:
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    SEVERITY_COLORS = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }
    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🔴",
        "medium": "🟡",
        "low": "🟢",
        "info": "ℹ️",
    }

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def render_results(
        self,
        success: bool,
        summary: str,
        findings: list[dict],
        step_results: list[Any],
        duration_ms: float,
        goal: str,
    ) -> None:
        sections: list[SummarySection] = []

        # ── Executive Summary ──────────────────────────────────────────────
        status_text = "Completed" if success else "Partially Completed"
        status_icon = "✓" if success else "✗"
        status_color = "green" if success else "red"
        sections.append(
            SummarySection(
                title=f"{status_icon} {status_text}",
                lines=[f"[dim]{summary}[/dim]"],
                style=status_color,
            )
        )

        # ── Step Overview ──────────────────────────────────────────────────
        step_lines = []
        for r in step_results:
            s_val = getattr(r, "status", "")
            s_str = s_val.value if hasattr(s_val, "value") else str(s_val)
            s_icon = "✓" if s_str == "completed" else "✗"
            s_color = "green" if s_str == "completed" else "red"
            step_id = getattr(r, "step_id", "?")
            output = (getattr(r, "output", "") or "")[:80].replace("\n", " ")
            step_lines.append(f"  [{s_color}]{s_icon}[/] [bold]{step_id}[/] [dim]{output}[/dim]")
        if step_lines:
            sections.append(SummarySection(title="Steps", lines=step_lines, style="cyan"))

        # ── Findings by Severity ───────────────────────────────────────────
        groups = self._group_findings(findings)
        for sev in self.SEVERITY_ORDER:
            if sev not in groups:
                continue
            group = groups[sev]
            color = self.SEVERITY_COLORS.get(sev, "white")
            icon = self.SEVERITY_ICONS.get(sev, "•")
            lines = []
            for f in group.items[:12]:
                title = f.get("title", f.get("description", f.get("detail", "")))
                target = f.get("target", f.get("host", ""))
                port = f.get("port", "")
                detail_parts = []
                if target:
                    detail_parts.append(f"[cyan]{target}[/]")
                if port:
                    detail_parts.append(f"port [yellow]{port}[/]")
                if detail_parts:
                    lines.append(f"  {icon} {title} [dim]({' '.join(detail_parts)})[/dim]")
                else:
                    lines.append(f"  {icon} {title}")
            if len(group.items) > 12:
                lines.append(f"  [dim]… and {len(group.items) - 12} more[/dim]")
            sections.append(
                SummarySection(
                    title=f"{sev.upper()} ({group.count})",
                    lines=lines,
                    style=color,
                )
            )

        # ── Insights ───────────────────────────────────────────────────────
        insights = self._generate_insights(findings)
        if insights:
            sections.append(
                SummarySection(
                    title="Insights",
                    lines=[f"  💡 {insight}" for insight in insights],
                    style="cyan",
                )
            )

        # ── Stats Bar ──────────────────────────────────────────────────────
        stats = self._build_stats(success, step_results, findings, duration_ms)

        # Render
        for section in sections:
            if section.lines:
                self._console.print(
                    Panel(
                        "\n".join(section.lines),
                        title=f"[bold {section.style}]{section.title}[/bold {section.style}]",
                        border_style=section.style,
                        padding=(1, 2),
                    )
                )

        # Stats bar
        self._console.print(
            Panel(
                " │ ".join(stats),
                border_style="dim",
                padding=(0, 2),
            )
        )

    def render_plan(self, steps: list[Any]) -> None:
        lines = []
        for i, s in enumerate(steps, 1):
            tool = getattr(s, "tool", "") or ""
            desc = getattr(s, "description", "") or ""
            cmd = getattr(s, "command", "") or ""
            label = f"$ {cmd}" if cmd else tool
            lines.append(f"  {i}. [bold]{label}[/bold] — [dim]{desc}[/dim]")
        if lines:
            self._console.print(
                Panel(
                    "\n".join(lines),
                    title="[bold cyan]Plan[/bold cyan]",
                    border_style="cyan",
                    padding=(1, 2),
                )
            )

    def _group_findings(self, findings: list[dict]) -> dict[str, FindingGroup]:
        groups: dict[str, list[dict]] = {}
        for f in findings:
            sev = f.get("severity", "info")
            groups.setdefault(sev, []).append(f)
        return {sev: FindingGroup(severity=sev, items=items) for sev, items in groups.items()}

    def _generate_insights(self, findings: list[dict]) -> list[str]:
        insights = []
        sevs = [f.get("severity", "info") for f in findings]

        critical_count = sevs.count("critical")
        high_count = sevs.count("high")
        open_ports = [f for f in findings if f.get("port")]

        if critical_count:
            insights.append(
                f"[red]{critical_count} critical[/red] issues require immediate attention"
            )
        if high_count:
            insights.append(f"[red]{high_count} high[/red] severity findings should be reviewed")
        if open_ports:
            ports = sorted(
                set(int(f["port"]) for f in open_ports if str(f.get("port", "")).isdigit())
            )
            if ports:
                insights.append(
                    f"[yellow]{len(ports)}[/yellow] open ports detected: {', '.join(str(p) for p in ports[:10])}{'...' if len(ports) > 10 else ''}"
                )
        if not findings:
            insights.append(
                "No findings discovered — the target appears clean for the selected checks"
            )

        return insights

    def _build_stats(
        self, success: bool, step_results: list[Any], findings: list[dict], duration_ms: float
    ) -> list[str]:
        completed = 0
        for r in step_results:
            s = getattr(r, "status", "")
            if (s.value if hasattr(s, "value") else str(s)) == "completed":
                completed += 1
        total = len(step_results)
        duration_s = duration_ms / 1000
        return [
            f"{'✓' if success else '✗'} {'Success' if success else 'Partial'}",
            f"Steps [cyan]{completed}/{total}[/cyan]",
            f"Findings [yellow]{len(findings)}[/yellow]",
            f"Duration [magenta]{duration_s:.1f}s[/magenta]",
        ]


__all__ = [
    "ResponseGenerator",
    "FindingGroup",
    "SummarySection",
]
