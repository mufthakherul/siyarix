# SPDX-License-Identifier: AGPL-3.0-or-later
"""Automated Report Generation for Siyarix."""

from __future__ import annotations

import logging
from pathlib import Path
from datetime import datetime

from jinja2 import Environment, BaseLoader

from siyarix.knowledge_graph import KnowledgeGraph
from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Siyarix Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1, h2, h3 { color: #38bdf8; }
        .header { border-bottom: 2px solid #334155; padding-bottom: 10px; margin-bottom: 20px; }
        .finding { background: #334155; padding: 15px; border-radius: 6px; margin-bottom: 15px; border-left: 4px solid #38bdf8; }
        .high { border-left-color: #ef4444; }
        .medium { border-left-color: #f59e0b; }
        .low { border-left-color: #3b82f6; }
        .finding-title { font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }
        .meta { font-size: 0.9em; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Siyarix Security Assessment Report</h1>
            <p>Generated: {{ date }}</p>
        </div>

        <h2>Executive Summary</h2>
        <p>This report contains automated security findings extracted by the Siyarix AI Offensive Security assistant.</p>

        <h2>Findings ({{ findings|length }})</h2>
        {% for f in findings %}
        <div class="finding {{ f.severity|lower }}">
            <div class="finding-title">{{ f.type }} (Severity: {{ f.severity }})</div>
            <div class="meta">Target: {{ f.target }}</div>
            <p>{{ f.description }}</p>
            {% if f.evidence %}
            <h4>Evidence:</h4>
            <pre><code>{{ f.evidence }}</code></pre>
            {% endif %}
        </div>
        {% endfor %}

        {% if not findings %}
        <p>No findings recorded in the Knowledge Graph.</p>
        {% endif %}
    </div>
</body>
</html>
"""

class ReportEngine:
    """Generates professional HTML/PDF reports from Knowledge Graph data."""

    def __init__(self, kg: KnowledgeGraph) -> None:
        self.kg = kg

    def generate_html_report(self, output_path: Path | str | None = None) -> Path:
        """Generate an HTML report of all findings."""
        if output_path is None:
            output_path = get_config_dir() / f"siyarix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        output_path = Path(output_path)

        findings = []
        for node_id, data in self.kg.nodes.items():
            if data.properties.get("category") == "finding":
                findings.append(data)

        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(REPORT_TEMPLATE)

        html_content = template.render(
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            findings=findings
        )

        output_path.write_text(html_content, encoding="utf-8")
        logger.info("Generated HTML report at %s", output_path)
        return output_path
