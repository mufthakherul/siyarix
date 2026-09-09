# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compliance and Evidence Collection Engine."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)

FRAMEWORK_METADATA: dict[str, dict[str, str]] = {
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "Trust Services Criteria for Security, Availability, and Confidentiality",
        "governing_body": "AICPA",
    },
    "NIST": {
        "name": "NIST SP 800-53",
        "description": "Security and Privacy Controls for Information Systems and Organizations",
        "governing_body": "NIST",
    },
    "GDPR": {
        "name": "GDPR",
        "description": "General Data Protection Regulation Security and Data Safeguards",
        "governing_body": "European Union",
    },
    "PCI-DSS": {
        "name": "PCI-DSS v4.0",
        "description": "Payment Card Industry Data Security Standard Requirements",
        "governing_body": "PCI SSC",
    },
    "ISO-27001": {
        "name": "ISO/IEC 27001",
        "description": "Information Security Management System (ISMS) Controls",
        "governing_body": "ISO/IEC",
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act Security Safeguards",
        "governing_body": "HHS OCR",
    },
}


@dataclass
class ComplianceResult:
    check_id: str
    status: str
    evidence_data: dict[str, Any] = field(default_factory=dict)
    message: str = ""


@dataclass
class ComplianceReport:
    framework: str
    target: str
    results: list[ComplianceResult]
    evidence_path: Path
    timestamp: float = field(default_factory=time.time)

    def to_json(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "target": self.target,
            "timestamp": self.timestamp,
            "results": [
                {
                    "check_id": r.check_id,
                    "status": r.status,
                    "message": r.message,
                    "evidence_data": r.evidence_data,
                }
                for r in self.results
            ],
            "evidence_path": str(self.evidence_path),
        }


class ComplianceCheck:
    def __init__(self, check_id: str, target: str) -> None:
        self.check_id = check_id
        self.target = target

    async def run(self) -> ComplianceResult:
        # Stub check implementation — no real evaluation performed yet
        return ComplianceResult(
            check_id=self.check_id,
            status="NOT_EVALUATED",
            evidence_data={"target": self.target},
            message="Control mapped; awaiting automated telemetry collection.",
        )


class ComplianceEngine:
    """Engine for running compliance assessments and collecting evidence."""

    FRAMEWORKS = {
        "SOC2": ["cc1.1", "cc6.1", "cc6.2"],
        "NIST": ["AC-2", "AC-3", "AU-2"],
        "GDPR": ["Art. 32", "Art. 33"],
        "PCI-DSS": ["Req-1.1", "Req-6.1", "Req-10.1"],
        "ISO-27001": ["A.5.1", "A.8.1", "A.12.1"],
        "HIPAA": ["164.308(a)(1)", "164.312(a)(1)"],
    }

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir or get_config_dir() / "evidence"
        self._base_dir.mkdir(parents=True, exist_ok=True)

    async def _run_framework_checks(self, framework: str, target: str) -> list[ComplianceResult]:
        check_ids = self.FRAMEWORKS.get(framework, [])
        checks = [ComplianceCheck(cid, target) for cid in check_ids]
        if not checks:
            logger.warning("No checks defined for framework %s", framework)
            return []

        results = await asyncio.gather(*[c.run() for c in checks])
        return list(results)

    def _collect_evidence(self, report: ComplianceReport) -> None:
        report.evidence_path.mkdir(parents=True, exist_ok=True)
        report_file = report.evidence_path / "report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report.to_json(), f, indent=2)

    async def run_assessment(self, framework: str, target: str) -> ComplianceReport:
        if framework not in self.FRAMEWORKS:
            raise ValueError(f"Unknown framework: {framework}")

        results = await self._run_framework_checks(framework, target)

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^\w\.-]", "_", target).strip("_")
        evidence_dir = self._base_dir / f"{framework}_{safe_target}_{timestamp_str}"

        report = ComplianceReport(
            framework=framework,
            target=target,
            results=results,
            evidence_path=evidence_dir,
        )
        self._collect_evidence(report)
        return report

    def list_reports(self) -> list[dict[str, Any]]:
        """List previously generated compliance reports in the evidence directory."""
        reports: list[dict[str, Any]] = []
        if not self._base_dir.exists():
            return reports
        for report_file in sorted(self._base_dir.glob("*/report.json"), reverse=True):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                reports.append(
                    {
                        "framework": data.get("framework", "Unknown"),
                        "target": data.get("target", "Unknown"),
                        "timestamp": data.get("timestamp", 0.0),
                        "checks_count": len(data.get("results", [])),
                        "evidence_path": str(report_file.parent),
                    }
                )
            except Exception as exc:
                logger.debug("Failed to read report %s: %s", report_file, exc)
        return reports


__all__ = [
    "FRAMEWORK_METADATA",
    "ComplianceCheck",
    "ComplianceEngine",
    "ComplianceReport",
    "ComplianceResult",
]
