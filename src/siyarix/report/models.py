# SPDX-License-Identifier: AGPL-3.0-or-later

"""Report data models — Report, ReportConfig, ReportSection, ReportFormat."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


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
