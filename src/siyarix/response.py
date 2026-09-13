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

    @classmethod
    def deduplicate_findings(cls, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate findings while preserving order and highest CVSS score."""
        seen: dict[str, dict[str, Any]] = {}
        ordered_keys: list[str] = []

        for f in findings:
            tool = f.get("tool", "")
            title = f.get("title", f.get("description", ""))
            port = f.get("port", 0)
            target = f.get("target", f.get("host", ""))
            key = f"{tool}:{title}:{port}:{target}".strip().lower()

            if key not in seen:
                seen[key] = f
                ordered_keys.append(key)
            else:
                # Keep the one with higher CVSS if available
                existing_cvss = seen[key].get("cvss_score", 0.0) or 0.0
                new_cvss = f.get("cvss_score", 0.0) or 0.0
                if new_cvss > existing_cvss:
                    seen[key] = f

        return [seen[k] for k in ordered_keys]

    def render_advisory_card(self, finding: dict[str, Any]) -> None:
        """Render a single structured security advisory card."""
        sev = (finding.get("severity") or "info").lower()
        color = self.SEVERITY_COLORS.get(sev, "white")
        icon = self.SEVERITY_ICONS.get(sev, "•")
        title = finding.get("title") or finding.get("description") or "Security Finding"
        target = finding.get("target") or finding.get("host") or ""
        port = finding.get("port")
        cvss = finding.get("cvss_score", 0.0)
        desc = finding.get("description") or ""
        evidence = finding.get("evidence") or ""

        lines = [
            f"[bold {color}]{icon} {title}[/bold {color}]",
            f"[dim]Target: {target}{f' (Port {port})' if port else ''} | Severity: {sev.upper()} | CVSS: {cvss:.1f}[/dim]",
        ]
        if desc and desc != title:
            lines.append(f"\n[white]{desc[:300]}[/white]")
        if evidence:
            lines.append(f"\n[bold cyan]Evidence / PoC:[/bold cyan]\n[dim]{evidence[:300]}[/dim]")

        self._console.print(
            Panel(
                "\n".join(lines),
                title=f"[{color}]Advisory: {sev.upper()}[/{color}]",
                border_style=color,
                padding=(1, 2),
            )
        )

    def render_attack_chain(self, steps: list[dict[str, Any]]) -> None:
        """Render a visual attack chain flow."""
        from rich.tree import Tree

        tree = Tree("[bold cyan]⚔ Attack Execution Chain[/bold cyan]")
        for i, s in enumerate(steps, 1):
            phase = s.get("phase", f"Step {i}")
            action = s.get("action") or s.get("command") or s.get("description", "Action")
            status = s.get("status", "completed")
            icon = "✓" if status == "completed" else "▶"
            branch = tree.add(
                f"[bold white]{icon} Phase {i}: {phase}[/bold white] — [dim]{action}[/dim]"
            )
            if s.get("findings"):
                for f in s["findings"]:
                    branch.add(f"[red]• {f}[/red]")

        self._console.print(Panel(tree, border_style="cyan", padding=(1, 2)))

    def render_executive_summary(
        self,
        target: str,
        findings: list[dict[str, Any]],
        duration_ms: float = 0.0,
    ) -> None:
        """Render an executive-level security assessment summary."""
        deduped = self.deduplicate_findings(findings)
        sevs = [f.get("severity", "info").lower() for f in deduped]
        crit_count = sevs.count("critical")
        high_count = sevs.count("high")
        med_count = sevs.count("medium")
        low_count = sevs.count("low")

        # Posture grade
        if crit_count > 0:
            posture_grade = "[bold red]CRITICAL RISK (Grade F)[/bold red]"
            posture_border = "red"
        elif high_count > 0:
            posture_grade = "[bold red]HIGH RISK (Grade D)[/bold red]"
            posture_border = "red"
        elif med_count > 0:
            posture_grade = "[bold yellow]MODERATE RISK (Grade C)[/bold yellow]"
            posture_border = "yellow"
        else:
            posture_grade = "[bold green]HARDENED (Grade A)[/bold green]"
            posture_border = "green"

        summary_lines = [
            f"[bold white]Target Assessment:[/bold white] [cyan]{target or 'All Assets'}[/cyan]",
            f"[bold white]Security Posture:[/bold white] {posture_grade}",
            f"[bold white]Findings Breakdown:[/bold white] [red]{crit_count} Critical[/red] │ [red]{high_count} High[/red] │ [yellow]{med_count} Medium[/yellow] │ [green]{low_count} Low[/green]",
            f"[bold white]Total Unique Findings:[/bold white] {len(deduped)}",
            f"[bold white]Assessment Duration:[/bold white] {duration_ms / 1000:.1f}s",
        ]

        if crit_count > 0 or high_count > 0:
            summary_lines.append("\n[bold yellow]Priority Action Required:[/bold yellow]")
            top_issues = [
                f for f in deduped if f.get("severity", "").lower() in ("critical", "high")
            ][:3]
            for i, issue in enumerate(top_issues, 1):
                t = issue.get("title", "Vulnerability")
                summary_lines.append(f"  {i}. [red]{t}[/red]")

        self._console.print(
            Panel(
                "\n".join(summary_lines),
                title="[bold cyan]🛡 Executive Security Summary[/bold cyan]",
                border_style=posture_border,
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

    def render_thought(self, thought: str) -> None:
        """Render strategic reasoning thinking tokens in a dedicated styled panel."""
        if not thought or not thought.strip():
            return
        lines = [line.strip() for line in thought.strip().split("\n")]
        formatted_lines = [f"[dim]{line}[/dim]" for line in lines]
        self._console.print(
            Panel(
                "\n".join(formatted_lines),
                title="[bold cyan]🧠 Strategic Reasoning[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    def render_grounding_audit(self, grounding: Any) -> None:
        """Render anti-hallucination grounding verification audit."""
        if not grounding or getattr(grounding, "total_claims", 0) == 0:
            return

        is_grounded = getattr(grounding, "is_grounded", True)
        score = getattr(grounding, "score", 1.0)
        border_color = "green" if is_grounded else "yellow"
        title = f"[bold {border_color}]🛡 Evidence Grounding Audit: {int(score * 100)}% Verified[/bold {border_color}]"

        content_lines = [
            f"[bold white]Status:[/bold white] [{'green' if is_grounded else 'yellow'}]{grounding.summary}[/]",
        ]

        advisories = getattr(grounding, "advisories", [])
        if advisories:
            content_lines.append("\n[bold yellow]Verification Advisories:[/bold yellow]")
            for adv in advisories:
                content_lines.append(f"  [yellow]•[/yellow] {adv}")

        citations = getattr(grounding, "citations", [])
        if citations:
            content_lines.append("\n[bold cyan]Evidence Citations:[/bold cyan]")
            for cit in citations[:6]:
                content_lines.append(f"  [green]•[/green] {cit}")
            if len(citations) > 6:
                content_lines.append(f"  [dim]...and {len(citations) - 6} more citations[/dim]")

        self._console.print(
            Panel(
                "\n".join(content_lines),
                title=title,
                border_style=border_color,
                padding=(1, 2),
            )
        )

    def render_enterprise_report(
        self,
        target: str,
        findings: list[dict[str, Any]],
        duration_ms: float = 0.0,
        grounding: Any = None,
    ) -> None:
        """Render full enterprise cybersecurity assessment report."""
        self.render_executive_summary(target, findings, duration_ms=duration_ms)
        if grounding:
            self.render_grounding_audit(grounding)


__all__ = [
    "ResponseGenerator",
    "FindingGroup",
    "SummarySection",
]
