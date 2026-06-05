# SPDX-License-Identifier: AGPL-3.0-or-later

"""Report generation engine.

Generates security assessment reports in Markdown, HTML, JSON, and SARIF formats.

TODO(v3.0): Refactor into ``report/`` package:
  - report/__init__.py     — backward-compatible re-exports
  - report/models.py       — Report, ReportConfig, ReportSection, ReportFormat
  - report/builder.py      — ReportEngine.build_report section builders
  - report/renderers.py    — Markdown, HTML, JSON, SARIF renderers
  - report/cvss.py         — CVSS enrichment utilities
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .cvss_scorer import CVSSScorer

logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"


@dataclass
class ReportSection:
    """A section within a report."""

    title: str
    content: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    subsections: list[ReportSection] = field(default_factory=list)


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    title: str = "Siyarix Security Assessment Report"
    author: str = "Siyarix Automated Agent"
    company: str = ""
    logo_url: str = ""
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_findings: bool = True
    include_evidence: bool = True
    include_remediation: bool = True
    include_appendix: bool = True
    cvss_scoring: bool = True
    template_name: str = "default"


@dataclass
class Report:
    """A complete security assessment report."""

    config: ReportConfig = field(default_factory=ReportConfig)
    sections: list[ReportSection] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    report_id: str = ""

    def __post_init__(self) -> None:
        if not self.report_id:
            raw = f"{self.generated_at}{json.dumps(self.metadata, sort_keys=True)}"
            self.report_id = hashlib.sha256(raw.encode()).hexdigest()[:16]


class ReportEngine:
    """Generates formatted security assessment reports."""

    def __init__(self, cvss_scorer: CVSSScorer | None = None) -> None:
        self._cvss = cvss_scorer or CVSSScorer()

    def build_report(
        self,
        findings: list[dict[str, Any]],
        target: str = "",
        config: ReportConfig | None = None,
    ) -> Report:
        cfg = config or ReportConfig()
        cvss_scored = (
            self._enrich_findings_with_cvss(findings) if cfg.cvss_scoring else findings
        )
        sorted_findings = self._sort_findings(cvss_scored)

        report = Report(config=cfg, findings=sorted_findings)
        report.metadata = {
            "target": target,
            "total_findings": len(sorted_findings),
            "severity_counts": self._count_severities(sorted_findings),
            "generated_by": "Siyarix Report Engine v1.0.0",
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

    def save(
        self, report: Report, path: Path, fmt: ReportFormat = ReportFormat.MARKDOWN
    ) -> Path:
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

    def _enrich_findings_with_cvss(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
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
        return sorted(
            findings, key=lambda f: sev_order.get(f.get("severity", "info"), 5)
        )

    def _count_severities(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _build_executive_summary(
        self, findings: list[dict], target: str
    ) -> ReportSection:
        counts = self._count_severities(findings)
        total = len(findings)
        section = ReportSection(title="Executive Summary")
        lines = [
            "## Executive Summary",
            "",
            f"**Assessment Target:** {target or 'N/A'}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
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
                    f"\n**⚠️ {critical_high} critical/high severity finding(s) require immediate attention.**"
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

    def _build_findings_section(self, findings: list[dict]) -> ReportSection:
        section = ReportSection(title="Findings")
        subsections = []

        # Group by severity
        sev_groups: dict[str, list[dict]] = {}
        for f in findings:
            sev = f.get("severity", "info")
            sev_groups.setdefault(sev, []).append(f)

        for sev in ("critical", "high", "medium", "low", "info"):
            if sev not in sev_groups:
                continue
            sub = ReportSection(
                title=f"{sev.capitalize()} Severity Findings ({len(sev_groups[sev])})"
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
                        f"- **CVSS Score:** {cvss.get('score', 'N/A')} ({cvss.get('severity', 'N/A')})  "
                    )
                    lines.append(f"- **CVSS Vector:** {cvss.get('vector', 'N/A')}  ")
                if evidence:
                    lines.append(f"- **Evidence:** {evidence}  ")
                lines.append("")
            sub.content = "\n".join(lines)
            subsections.append(sub)

        section.subsections = subsections
        return section

    def _build_evidence_section(self, findings: list[dict]) -> ReportSection:
        section = ReportSection(title="Evidence")
        lines = ["## Evidence Collection\n"]
        for i, f in enumerate(findings[:20], 1):
            evidence = f.get("evidence", "")
            target = f.get("target", "unknown")
            tool = f.get("tool", "unknown")
            if evidence:
                lines.append(f"{i}. **[{tool}]** `{target}` — `{evidence[:120]}`")
        if len(findings) > 20:
            lines.append(
                f"\n*{len(findings) - 20} additional findings omitted for brevity*"
            )
        section.content = "\n".join(lines)
        return section

    def _build_remediation_section(self, findings: list[dict]) -> ReportSection:
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

    def _build_appendix(self, findings: list[dict]) -> ReportSection:
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
            lines.append(section.content)
            lines.append("")
            for sub in section.subsections:
                lines.append(sub.content)
                lines.append("")
        return "\n".join(lines)

    def _render_html(self, report: Report) -> str:
        md = self._render_markdown(report)
        # Basic markdown-to-HTML conversion
        html_parts = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            f"<title>{report.config.title}</title>",
            "<style>body{font-family:sans-serif;max-width:900px;margin:auto;padding:2em}",
            "h1{color:#1a1a2e}h2{color:#16213e}h3{color:#0f3460}",
            "table{border-collapse:collapse;width:100%}",
            "td,th{border:1px solid #ddd;padding:8px}",
            "tr:nth-child(even){background:#f2f2f2}</style></head><body>",
        ]
        in_code = False
        for line in md.split("\n"):
            if line.startswith("# "):
                html_parts.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_parts.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_parts.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("| "):
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if "---" not in line:
                    html_parts.append(
                        f"<tr>{''.join(f'<td>{c}</td>' for c in cells)}</tr>"
                    )
            elif line.startswith("---"):
                pass
            elif line.startswith("```"):
                in_code = not in_code
            else:
                html_parts.append(f"<p>{line}</p>" if line.strip() else "<br>")
        html_parts.append("</body></html>")
        return "\n".join(html_parts)

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
        """Render findings in SARIF format (Static Analysis Results Interchange Format)."""
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
                            "region": {
                                "snippet": {"text": f.get("evidence", "")[:100]}
                            },
                        }
                    }
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
                    "tool": {"driver": {"name": "Siyarix", "version": "1.0.0"}},
                    "results": results,
                    "properties": {
                        "report_id": report.report_id,
                        "generated_at": report.generated_at,
                        "total_findings": len(report.findings),
                    },
                }
            ],
        }
        return json.dumps(sarif_output, indent=2, default=str)


__all__ = [
    "ReportEngine",
    "Report",
    "ReportConfig",
    "ReportSection",
    "ReportFormat",
]
