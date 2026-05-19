"""Premium Executive Reporting — Generates Markdown and HTML reports from Findings."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from siyarix.knowledge_graph import KnowledgeGraph, NodeType
from siyarix.security.attack_path import AttackPathAnalyzer

class ReportGenerator:
    """Generates premium executive and technical reports."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self.graph = graph

    def generate_markdown(self) -> str:
        """Generate a full markdown report."""
        stats = self.graph.stats()
        
        # 1. Header
        md = []
        md.append("# Siyarix Premium Executive Security Report")
        md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append("\n## 📊 Executive Summary\n")
        
        vuln_nodes = self.graph.find_nodes(NodeType.VULNERABILITY)
        high_vulns = [v for v in vuln_nodes if v.properties.get("severity", "info").lower() in ("high", "critical")]
        
        md.append(f"- **Total Assets Discovered:** {stats['nodes_by_type'].get('host', 0) + stats['nodes_by_type'].get('domain', 0)}")
        md.append(f"- **Total Vulnerabilities:** {len(vuln_nodes)}")
        md.append(f"- **High/Critical Severity:** {len(high_vulns)}")
        
        # 2. Attack Paths (Premium Feature)
        md.append("\n## 🛑 Exploit & Attack Paths\n")
        analyzer = AttackPathAnalyzer(self.graph)
        paths = analyzer.find_all_paths()
        
        if paths:
            for p in paths:
                icon = "🔥" if p.severity in ("critical", "high") else "⚠️"
                md.append(f"### {icon} [{p.severity.upper()}] {p.description}")
                md.append(f"- **Origin:** {p.origin_id}")
                md.append(f"- **Target:** {p.target_id}")
                md.append(f"- **Steps:** {' -> '.join(p.path_nodes)}")
                md.append("")
        else:
            md.append("*No multi-step attack paths identified.*")
            
        # 3. Detailed Findings
        md.append("\n## 🔍 Technical Findings\n")
        if vuln_nodes:
            for v in vuln_nodes:
                md.append(f"### {v.label}")
                md.append(f"- **Severity:** {v.properties.get('severity', 'info')}")
                md.append(f"- **Description:** {v.properties.get('description', 'N/A')}")
                md.append(f"- **Discovered By:** {v.discovered_by}")
                md.append("")
        else:
            md.append("*No vulnerabilities detected.*")

        return "\n".join(md)

    def generate_html(self) -> str:
        """Generate a premium HTML report using simple CSS styling."""
        md_content = self.generate_markdown()
        
        # A very simple, modern HTML wrapper
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Siyarix Security Report</title>
    <style>
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
            padding: 40px;
            max-width: 900px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: #38bdf8; }}
        h1 {{ border-bottom: 2px solid #1e293b; padding-bottom: 10px; }}
        .card {{
            background: #1e293b;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        pre {{ background: #0b0f19; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        ul {{ padding-left: 20px; }}
    </style>
</head>
<body>
    <div class="card">
        <pre>{md_content}</pre>
    </div>
</body>
</html>"""
        return html

    def save_report(self, format: str = "markdown", path: Path | None = None) -> Path:
        """Save the generated report to disk."""
        if path is None:
            ext = "html" if format == "html" else "md"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = Path(f"siyarix_report_{timestamp}.{ext}")
            
        content = self.generate_html() if format == "html" else self.generate_markdown()
        path.write_text(content, encoding="utf-8")
        return path
