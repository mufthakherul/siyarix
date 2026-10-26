# SPDX-License-Identifier: AGPL-3.0-or-later

"""Report generation engine — formats, CVSS enrichment, sections.

Backward-compatible re-exports from ``siyarix.report.models``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..cvss_scorer import CVSSScorer
from .models import Report, ReportConfig, ReportFormat, ReportSection

logger = logging.getLogger(__name__)


def _csp_sha256(content: str) -> str:
    """CSP2 sha256 source expression for a constant inline script/style body."""
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")

__all__ = [
    "Report",
    "ReportConfig",
    "ReportEngine",
    "ReportFormat",
    "ReportSection",
]


class ReportEngine:
    """Generates formatted security assessment reports."""

    def __init__(self, cvss_scorer: CVSSScorer | None = None) -> None:
        self._cvss = cvss_scorer or CVSSScorer()

    def build_report_from_kg(
        self,
        knowledge_graph: Any,
        target: str = "",
        config: ReportConfig | None = None,
    ) -> Report:
        """Build a report from a KnowledgeGraph by extracting finding nodes."""
        findings = []
        for node_id, node in knowledge_graph.nodes.items():
            props = getattr(node, "properties", {}) or {}
            nt = getattr(node, "node_type", None)
            nt_val = getattr(nt, "value", nt) if nt is not None else None
            is_finding = isinstance(nt_val, str) and nt_val in {"finding", "vulnerability"}
            if not is_finding:
                is_finding = props.get("category") == "finding"
            if not is_finding:
                continue
            findings.append(
                {
                    "severity": props.get("severity", "info"),
                    "type": props.get("type", props.get("cve", "unknown")),
                    "target": props.get("target", ""),
                    "description": getattr(node, "label", "") or props.get("description", ""),
                    "evidence": props.get("evidence", ""),
                    "port": props.get("port"),
                    "service": props.get("service"),
                    "cve": props.get("cve"),
                    "cvss_score": props.get("cvss_score"),
                    "title": getattr(node, "label", "") or props.get("title", ""),
                }
            )
        return self.build_report(findings, target, config)

    def build_report(
        self,
        findings: list[dict[str, Any]],
        target: str = "",
        config: ReportConfig | None = None,
    ) -> Report:
        cfg = config or ReportConfig()
        cvss_scored = self._enrich_findings_with_cvss(findings) if cfg.cvss_scoring else findings
        sorted_findings = self._sort_findings(cvss_scored)

        report = Report(config=cfg, findings=sorted_findings)
        report.metadata = {
            "target": target,
            "total_findings": len(sorted_findings),
            "severity_counts": self._count_severities(sorted_findings),
            "generated_by": "Siyarix Report Engine v1.2.0",
        }

        sections = []

        if cfg.include_executive_summary:
            sections.append(self._build_executive_summary(sorted_findings, target))

        if cfg.include_methodology:
            sections.append(self._build_methodology())

        if cfg.include_findings:
            sections.append(self._build_findings_section(sorted_findings))

        if cfg.include_evidence:
            sections.append(self._build_evidence_section(sorted_findings))

        if cfg.include_remediation:
            sections.append(self._build_remediation_section(sorted_findings))

        if cfg.include_appendix:
            sections.append(self._build_appendix(sorted_findings))

        report.sections = sections
        return report

    def render(self, report: Report, fmt: ReportFormat = ReportFormat.MARKDOWN) -> str:
        renderers = {
            ReportFormat.MARKDOWN: self._render_markdown,
            ReportFormat.HTML: self._render_html,
            ReportFormat.JSON: self._render_json,
            ReportFormat.SARIF: self._render_sarif,
        }
        renderer = renderers.get(fmt)
        if not renderer:
            raise ValueError(f"Unsupported format: {fmt}")
        return renderer(report)

    def save(self, report: Report, path: Path, fmt: ReportFormat = ReportFormat.MARKDOWN) -> Path:
        content = self.render(report, fmt)
        ext_map = {
            ReportFormat.MARKDOWN: ".md",
            ReportFormat.HTML: ".html",
            ReportFormat.JSON: ".json",
            ReportFormat.SARIF: ".sarif",
        }
        output_path = path.with_suffix(ext_map.get(fmt, ".md"))
        output_path.write_text(content, encoding="utf-8")
        logger.info("Report saved to %s", output_path)
        return output_path

    def _enrich_findings_with_cvss(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched = []
        for finding in findings:
            f = dict(finding)
            cvss = self._cvss.score_from_finding(finding)
            f["cvss"] = {
                "score": cvss.score,
                "severity": cvss.severity.value,
                "vector": cvss.vector_string,
            }
            enriched.append(f)
        return enriched

    def _sort_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    def _count_severities(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _build_executive_summary(
        self, findings: list[dict[str, Any]], target: str
    ) -> ReportSection:
        counts = self._count_severities(findings)
        total = len(findings)
        section = ReportSection(title="Executive Summary")
        lines = [
            "## Executive Summary",
            "",
            f"**Assessment Target:** {target or 'N/A'}",
            f"**Date:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total Findings:** {total}",
            "",
            "### Severity Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev, 0) > 0:
                lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

        if total > 0:
            critical_high = counts.get("critical", 0) + counts.get("high", 0)
            if critical_high > 0:
                lines.append(
                    f"\n**⚠️ {critical_high} critical/high severity finding(s) require immediate attention.**",
                )
            else:
                lines.append("\nNo critical or high severity findings detected.")

        section.content = "\n".join(lines)
        return section

    def _build_methodology(self) -> ReportSection:
        section = ReportSection(title="Methodology")
        section.content = """## Methodology

### Assessment Approach
- Automated vulnerability scanning using industry-standard security tools
- Multi-phase assessment: Reconnaissance → Scanning → Enumeration → Exploitation
- CVSS 3.1 scoring for all identified vulnerabilities
- Evidence collection and chain-of-custody tracking

### Tools Used
- Network scanning: nmap, masscan
- Web application testing: nuclei, nikto, gobuster, ffuf
- Vulnerability assessment: nuclei CVE templates
- Exploitation verification: sqlmap, hydra (as applicable)"""
        return section

    def _build_findings_section(self, findings: list[dict[str, Any]]) -> ReportSection:
        section = ReportSection(title="Findings")
        subsections = []

        sev_groups: dict[str, list[dict]] = {}
        for f in findings:
            sev = f.get("severity", "info")
            sev_groups.setdefault(sev, []).append(f)

        for sev in ("critical", "high", "medium", "low", "info"):
            if sev not in sev_groups:
                continue
            sub = ReportSection(
                title=f"{sev.capitalize()} Severity Findings ({len(sev_groups[sev])})",
            )
            lines = [f"### {sev.capitalize()} Severity Findings\n"]
            for i, finding in enumerate(sev_groups[sev], 1):
                title = finding.get("title", "Unknown")
                desc = finding.get("description", "")
                evidence = finding.get("evidence", "")
                tool = finding.get("tool", "")
                cvss = finding.get("cvss", {})
                lines.append(f"**Finding #{i}: {title}**  ")
                lines.append(f"- **Tool:** {tool}  ")
                lines.append(f"- **Description:** {desc}  ")
                if cvss:
                    lines.append(
                        f"- **CVSS Score:** {cvss.get('score', 'N/A')} ({cvss.get('severity', 'N/A')})  ",
                    )
                    lines.append(f"- **CVSS Vector:** {cvss.get('vector', 'N/A')}  ")
                if evidence:
                    lines.append(f"- **Evidence:** {evidence}  ")
                lines.append("")
            sub.content = "\n".join(lines)
            subsections.append(sub)

        section.subsections = subsections
        return section

    def _build_evidence_section(self, findings: list[dict[str, Any]]) -> ReportSection:
        section = ReportSection(title="Evidence")
        lines = ["## Evidence Collection\n"]
        for i, f in enumerate(findings[:20], 1):
            evidence = f.get("evidence", "")
            target = f.get("target", "unknown")
            tool = f.get("tool", "unknown")
            if evidence:
                lines.append(f"{i}. **[{tool}]** `{target}` — `{evidence[:120]}`")
        if len(findings) > 20:
            lines.append(f"\n*{len(findings) - 20} additional findings omitted for brevity*")
        section.content = "\n".join(lines)
        return section

    def _build_remediation_section(self, findings: list[dict[str, Any]]) -> ReportSection:
        section = ReportSection(title="Remediation Guidance")
        sev_map: dict[str, str] = {
            "critical": "Immediate remediation required within 24 hours",
            "high": "Remediation required within 7 days",
            "medium": "Remediation recommended within 30 days",
            "low": "Remediation recommended within 90 days",
            "info": "Informational — no remediation required",
        }
        lines = ["## Remediation Guidance\n"]
        for i, f in enumerate(findings[:15], 1):
            sev = f.get("severity", "info")
            title = f.get("title", "Unknown")
            lines.append(f"**{i}. {title}**  ")
            lines.append(f"   - Priority: {sev.upper()}  ")
            lines.append(f"   - Timeline: {sev_map.get(sev, 'Review')}  ")
            if "cvss" in f:
                lines.append(f"   - CVSS: {f['cvss'].get('score', 'N/A')}/10  ")
            lines.append("")
        section.content = "\n".join(lines)
        return section

    def _build_appendix(self, findings: list[dict[str, Any]]) -> ReportSection:
        section = ReportSection(title="Appendix: Raw Findings Data")
        lines = ["## Appendix: Tool Output Summary\n"]
        tool_counts: dict[str, int] = {}
        for f in findings:
            tool = f.get("tool", "unknown")
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        lines.append("### Tool Usage Summary\n")
        lines.append("| Tool | Findings |")
        lines.append("|------|----------|")
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {tool} | {count} |")
        section.content = "\n".join(lines)
        return section

    def _render_markdown(self, report: Report) -> str:
        lines = [
            f"# {report.config.title}",
            "",
            f"**Report ID:** {report.report_id}",
            f"**Generated:** {report.generated_at}",
            f"**Author:** {report.config.author}",
            "",
            "---",
            "",
        ]
        for section in report.sections:
            if section.content:
                lines.append(section.content)
                lines.append("")
            for sub in section.subsections:
                if sub.content:
                    lines.append(sub.content)
                    lines.append("")
        return "\n".join(lines)

    _SEVERITY_CSS_CLASS = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    # SEC-11: ``css|safe`` / ``js|safe`` / ``csp|safe`` are *engine constants*
    # only (never finding/metadata — those stay Jinja-autoescaped). CSP uses
    # sha256 hashes of the CSS/JS bodies; ``script-src`` has no ``'unsafe-inline'``.
    _HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{{ csp|safe }}">
<title>{{ title }}</title>
{% if not offline %}
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;800&amp;family=Fira+Code&amp;display=swap" rel="stylesheet">
{% endif %}
<style>{{ css|safe }}</style>
<script>{{ js|safe }}</script>
</head>
<body>
<div class="dashboard">
  <div class="header">
    <h1>{{ title }}</h1>
    <div class="meta-tags">
      <span>Target: <b>{{ target }}</b></span> |
      <span>Generated: {{ generated_at }}</span> |
      <span>ID: {{ report_id }}</span>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="stat-val">{{ total }}</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card"><div class="stat-val crit">{{ counts.critical }}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-val high">{{ counts.high }}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-val med">{{ counts.medium }}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card"><div class="stat-val low">{{ counts.low }}</div><div class="stat-label">Low</div></div>
  </div>

  <div class="filter-bar">
    <button type="button" class="filter-btn active" data-sev="all">All Findings</button>
    <button type="button" class="filter-btn" data-sev="critical">Critical</button>
    <button type="button" class="filter-btn" data-sev="high">High</button>
    <button type="button" class="filter-btn" data-sev="medium">Medium</button>
    <button type="button" class="filter-btn" data-sev="low">Low</button>
    <button type="button" class="filter-btn" data-sev="info">Info</button>
  </div>

  <div class="findings-list">
  {% for f in findings %}
    <details class="finding-card {{ f.sev_class }}">
      <summary>{{ f.title }} <span class="badge badge-{{ f.sev_class }}">{{ f.severity_label }}</span></summary>
      <div class="finding-details">
        <div class="detail-row"><span class="detail-label">Description</span>{{ f.description }}</div>
        {% if f.cvss %}
        <div class="detail-row"><span class="detail-label">CVSS Score</span>{{ f.cvss.score }} ({{ f.cvss.vector }})</div>
        {% endif %}
        <div class="detail-row"><span class="detail-label">Tool</span><code>{{ f.tool }}</code> targeting <code>{{ f.target }}</code></div>
        {% if f.evidence %}
        <div class="detail-row"><span class="detail-label">Evidence Snapshot</span><pre>{{ f.evidence }}</pre></div>
        {% endif %}
      </div>
    </details>
  {% endfor %}
  </div>

  <h2 class="raw-table-heading">Raw Data Table</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Tool</th><th>Target</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td>{{ f.severity_label }}</td>
        <td>{{ f.title }}</td>
        <td>{{ f.tool }}</td>
        <td>{{ f.target }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</body>
</html>
"""

    _HTML_OFFLINE_FONT_CSS = (
        "body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}"
        "code,pre{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace}"
    )

    _HTML_CSS = """
:root {
    --bg-main: #0B0F19; --bg-card: rgba(20, 25, 40, 0.6);
    --border-glow: rgba(0, 255, 170, 0.2);
    --text-main: #E2E8F0; --text-muted: #94A3B8;
    --crit: #FF2A55; --high: #FF8B3D; --med: #FFD166; --low: #4DABF7; --info: #A8B2C1;
    --crit-fg: #FFFFFF; --high-fg: #1A1A1A; --med-fg: #1A1A1A;
    --low-fg: #0B0F19; --info-fg: #0B0F19;
    --accent: #00F0FF;
}
body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg-main) radial-gradient(circle at 50% 0%, rgba(0,240,255,0.05) 0%, transparent 50%);
    color: var(--text-main); margin: 0; padding: 2rem;
    line-height: 1.6;
}
.dashboard { max-width: 1200px; margin: 0 auto; }
.header { text-align: center; margin-bottom: 3rem; padding-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
h1 { font-size: 2.5rem; margin-bottom: 0.5rem; color: #FFF; text-shadow: 0 0 20px var(--border-glow); }
.meta-tags { display: flex; justify-content: center; gap: 1rem; color: var(--text-muted); font-size: 0.9rem; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }
.stat-card {
    background: var(--bg-card); backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.05); border-radius: 12px;
    padding: 1.5rem; text-align: center;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    transition: transform 0.2s, box-shadow 0.2s;
}
.stat-card:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0,0,0,0.3); }
.stat-val { font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem; }
.stat-label { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }
.crit { color: var(--crit); text-shadow: 0 0 15px rgba(255,42,85,0.4); }
.high { color: var(--high); text-shadow: 0 0 15px rgba(255,139,61,0.4); }
.med { color: var(--med); }
.low { color: var(--low); }
.info { color: var(--info); }
.filter-bar { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
.filter-btn {
    background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
    color: var(--text-main); padding: 0.5rem 1.5rem; border-radius: 20px;
    cursor: pointer; font-size: 0.9rem; transition: all 0.2s;
}
.filter-btn:hover, .filter-btn.active { background: rgba(255,255,255,0.15); border-color: rgba(255,255,255,0.3); }
.finding-card {
    background: var(--bg-card); border-left: 4px solid var(--info);
    border-radius: 8px; margin-bottom: 1rem; overflow: hidden;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
}
.finding-card.critical { border-color: var(--crit); }
.finding-card.high { border-color: var(--high); }
.finding-card.medium { border-color: var(--med); }
.finding-card.low { border-color: var(--low); }
.finding-card.info { border-color: var(--info); }
summary {
    padding: 1.2rem 1.5rem; cursor: pointer; list-style: none;
    display: flex; justify-content: space-between; align-items: center;
    font-weight: 600; font-size: 1.1rem;
}
summary::-webkit-details-marker { display: none; }
summary:hover { background: rgba(255,255,255,0.02); }
.badge {
    font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 12px;
    margin-left: 1rem; font-weight: 700; letter-spacing: 0.03em;
}
.badge-critical { background: var(--crit); color: var(--crit-fg); }
.badge-high { background: var(--high); color: var(--high-fg); }
.badge-medium { background: var(--med); color: var(--med-fg); }
.badge-low { background: var(--low); color: var(--low-fg); }
.badge-info { background: var(--info); color: var(--info-fg); }
.finding-details { padding: 1.5rem; border-top: 1px solid rgba(255,255,255,0.05); background: rgba(0,0,0,0.2); }
.detail-row { margin-bottom: 1rem; }
.detail-label { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 0.3rem; }
code, pre { font-family: 'Fira Code', monospace; background: rgba(0,0,0,0.4); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
pre { padding: 1rem; overflow-x: auto; border: 1px solid rgba(255,255,255,0.05); }
table { width: 100%; border-collapse: collapse; margin: 2rem 0; background: var(--bg-card); border-radius: 8px; overflow: hidden; }
th, td { padding: 1rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); }
th { background: rgba(0,0,0,0.3); color: var(--text-muted); font-weight: 500; }
.raw-table-heading { margin-top: 4rem; margin-bottom: 1rem; }
"""

    _HTML_JS = (
        "document.addEventListener('DOMContentLoaded', function () {"
        "  document.querySelectorAll('.filter-btn').forEach(function (btn) {"
        "    btn.addEventListener('click', function () {"
        "      var sev = btn.getAttribute('data-sev') || 'all';"
        "      document.querySelectorAll('.filter-btn').forEach(function (b) { b.classList.remove('active'); });"
        "      btn.classList.add('active');"
        "      document.querySelectorAll('.finding-card').forEach(function (card) {"
        "        if (sev === 'all' || card.classList.contains(sev)) {"
        "          card.style.display = 'block';"
        "        } else {"
        "          card.style.display = 'none';"
        "        }"
        "      });"
        "    });"
        "  });"
        "});"
    )

    def _build_html_csp(self, *, offline: bool, css: str, js: str) -> str:
        """Build CSP with sha256 hashes of constant CSS/JS (no script unsafe-inline)."""
        style_src = f"style-src '{_csp_sha256(css)}'"
        if not offline:
            style_src += " https://fonts.googleapis.com"
        parts = [
            "default-src 'none'",
            style_src,
        ]
        if not offline:
            parts.append("font-src https://fonts.gstatic.com")
        parts.extend(
            [
                f"script-src '{_csp_sha256(js)}'",
                "img-src data:",
                "base-uri 'none'",
                "form-action 'none'",
                "frame-ancestors 'none'",
            ]
        )
        return "; ".join(parts)

    def _render_html(self, report: Report) -> str:
        """Render an HTML dashboard with autoescaped finding/metadata fields."""
        from jinja2 import Environment

        counts_raw = self._count_severities(report.findings)
        counts = {
            "critical": counts_raw.get("critical", 0),
            "high": counts_raw.get("high", 0),
            "medium": counts_raw.get("medium", 0),
            "low": counts_raw.get("low", 0),
            "info": counts_raw.get("info", 0),
        }

        findings_ctx: list[dict[str, Any]] = []
        for f in report.findings:
            sev = str(f.get("severity", "info") or "info").lower()
            sev_class = self._SEVERITY_CSS_CLASS.get(sev, "info")
            cvss = f.get("cvss")
            cvss_ctx = None
            if isinstance(cvss, dict):
                cvss_ctx = {
                    "score": cvss.get("score", ""),
                    "vector": cvss.get("vector", ""),
                }
            findings_ctx.append(
                {
                    "title": f.get("title", "Unknown Finding"),
                    "description": f.get("description", "N/A"),
                    "tool": f.get("tool", "N/A"),
                    "target": f.get("target", "N/A"),
                    "evidence": f.get("evidence") or "",
                    "severity_label": sev.upper(),
                    "sev_class": sev_class,
                    "cvss": cvss_ctx,
                }
            )

        offline = bool(getattr(report.config, "offline", True))
        # Constant CSS/JS only — hashed into CSP; |safe must never carry findings.
        css = self._HTML_CSS
        if offline:
            css = self._HTML_OFFLINE_FONT_CSS + css
        js = self._HTML_JS
        csp = self._build_html_csp(offline=offline, css=css, js=js)

        env = Environment(autoescape=True)
        template = env.from_string(self._HTML_TEMPLATE)
        return template.render(
            title=report.config.title,
            target=report.metadata.get("target", "N/A"),
            generated_at=report.generated_at,
            report_id=report.report_id,
            total=len(report.findings),
            counts=counts,
            findings=findings_ctx,
            offline=offline,
            csp=csp,
            css=css,
            js=js,
        )

    def _render_json(self, report: Report) -> str:
        data = {
            "report_id": report.report_id,
            "title": report.config.title,
            "generated_at": report.generated_at,
            "metadata": report.metadata,
            "findings_count": len(report.findings),
            "findings": report.findings,
            "sections": [
                {
                    "title": s.title,
                    "subsections": [
                        {"title": sub.title, "finding_count": len(sub.findings)}
                        for sub in s.subsections
                    ],
                }
                for s in report.sections
            ],
        }
        return json.dumps(data, indent=2, default=str)

    def _render_sarif(self, report: Report) -> str:
        results = []
        for i, f in enumerate(report.findings):
            cvss = f.get("cvss", {})
            result = {
                "ruleId": f.get("tool", "siyarix") + "-" + str(i),
                "level": f.get("severity", "warning"),
                "message": {"text": f.get("description", f.get("title", ""))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("target", "unknown")},
                            "region": {"snippet": {"text": f.get("evidence", "")[:100]}},
                        },
                    },
                ],
            }
            if cvss:
                result["properties"] = {
                    "cvssScore": cvss.get("score", 0),
                    "cvssVector": cvss.get("vector", ""),
                }
            results.append(result)

        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Siyarix", "version": "1.2.0"}},
                    "results": results,
                    "properties": {
                        "report_id": report.report_id,
                        "generated_at": report.generated_at,
                        "total_findings": len(report.findings),
                    },
                },
            ],
        }
        return json.dumps(sarif_output, indent=2, default=str)
