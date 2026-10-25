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
from typing import Any, Callable, Awaitable

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

    def summary(self) -> dict[str, int]:
        counts = {"PASS": 0, "FAIL": 0, "NOT_EVALUATED": 0, "other": 0}
        for r in self.results:
            key = r.status if r.status in counts else "other"
            counts[key] += 1
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "target": self.target,
            "timestamp": self.timestamp,
            "summary": self.summary(),
            "disclaimer": (
                "PASS/FAIL only apply to local technical probes Siyarix can evaluate. "
                "NOT_EVALUATED means insufficient automated evidence — never treat as a pass."
            ),
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


async def _probe_audit_logging(target: str) -> ComplianceResult:
    """Local probe for auditability controls (AU-2 / logging)."""
    try:
        from siyarix.audit_log import AuditLogger

        logger_inst = AuditLogger()
        chain = logger_inst.verify_chain()
        ok = bool(chain.get("valid", chain.get("chain_integrity", False)))
        return ComplianceResult(
            check_id="",
            status="PASS" if ok else "FAIL",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "probe": "audit_chain",
                "chain": chain,
            },
            message=(
                "Audit hash chain integrity verified."
                if ok
                else "Audit hash chain integrity check failed."
            ),
        )
    except Exception as exc:
        return ComplianceResult(
            check_id="",
            status="NOT_EVALUATED",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": False,
                "error": str(exc),
            },
            message=f"Audit logging probe unavailable: {exc}",
        )


async def _probe_access_gate(target: str) -> ComplianceResult:
    """Local probe for command execution access control (fail-closed review)."""
    try:
        from siyarix.shell_review import is_preauthorized

        preauth = is_preauthorized()
        # Fail-closed non-interactive review is the secure default.
        ok = not preauth
        return ComplianceResult(
            check_id="",
            status="PASS" if ok else "FAIL",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "probe": "shell_review_preauthorized",
                "preauthorized": preauth,
            },
            message=(
                "Shell review is fail-closed (SIYARIX_PREAUTHORIZED unset)."
                if ok
                else "SIYARIX_PREAUTHORIZED=1 disables interactive review — not production-safe."
            ),
        )
    except Exception as exc:
        return ComplianceResult(
            check_id="",
            status="NOT_EVALUATED",
            evidence_data={"target": target, "evaluated": False, "error": str(exc)},
            message=f"Access-gate probe unavailable: {exc}",
        )


async def _probe_credential_store(target: str) -> ComplianceResult:
    """Local probe for secrets handling / asset inventory storage."""
    try:
        from siyarix.credential_store import CredentialStore

        store = CredentialStore()
        return ComplianceResult(
            check_id="",
            status="PASS",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "probe": "credential_store",
                "store": type(store).__name__,
            },
            message="Credential store is available for encrypted secret handling.",
        )
    except Exception as exc:
        return ComplianceResult(
            check_id="",
            status="FAIL",
            evidence_data={"target": target, "evaluated": True, "error": str(exc)},
            message=f"Credential store unavailable: {exc}",
        )


async def _probe_permission_gate(target: str) -> ComplianceResult:
    """Local probe: PermissionGate / SIYARIX_SAFE_MODE production default."""
    try:
        from siyarix.registry_factory import make_tool_registry, permission_gate_enabled

        enabled = permission_gate_enabled()
        reg = make_tool_registry()
        gated = getattr(reg, "_permission_gate", None) is not None
        ok = enabled and gated
        return ComplianceResult(
            check_id="",
            status="PASS" if ok else "FAIL",
            message=(
                "PermissionGate enabled by default (SIYARIX_SAFE_MODE)."
                if ok
                else "PermissionGate disabled — set SIYARIX_SAFE_MODE=1 for production."
            ),
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "safe_mode": enabled,
                "registry_gated": gated,
            },
        )
    except Exception as exc:
        return ComplianceResult(
            check_id="",
            status="NOT_EVALUATED",
            message=f"PermissionGate probe error: {exc}",
            evidence_data={"target": target, "evaluated": False, "error": str(exc)},
        )


async def _probe_webhook_policy(target: str) -> ComplianceResult:
    """Local probe: webhook destination policy when SIYARIX_WEBHOOK_URL is set."""
    import os

    from siyarix.webhooks import _validate_url

    url = (os.environ.get("SIYARIX_WEBHOOK_URL") or "").strip()
    if not url:
        return ComplianceResult(
            check_id="",
            status="PASS",
            message="SIYARIX_WEBHOOK_URL unset (no outbound webhook SSRF surface).",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "webhook_configured": False,
            },
        )
    try:
        _validate_url(url, allow_ip=False)
        return ComplianceResult(
            check_id="",
            status="PASS",
            message="Configured webhook URL passes SSRF destination policy.",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "webhook_configured": True,
            },
        )
    except ValueError as exc:
        return ComplianceResult(
            check_id="",
            status="FAIL",
            message=f"Webhook URL fails SSRF policy: {exc}",
            evidence_data={
                "target": target,
                "capability": "local_probe",
                "evaluated": True,
                "webhook_configured": True,
                "error": str(exc),
            },
        )


# Controls we can partially evaluate with local technical probes.
_EVALUATORS: dict[str, Callable[[str], Awaitable[ComplianceResult]]] = {
    "AU-2": _probe_audit_logging,
    "Req-10.1": _probe_audit_logging,
    "cc6.1": _probe_access_gate,
    "AC-3": _probe_access_gate,
    "164.312(a)(1)": _probe_access_gate,
    "A.8.1": _probe_credential_store,
    "cc6.2": _probe_credential_store,
    "A.12.1": _probe_permission_gate,
    "Req-1.1": _probe_webhook_policy,
}


class ComplianceCheck:
    def __init__(self, check_id: str, target: str) -> None:
        self.check_id = check_id
        self.target = target

    async def run(self) -> ComplianceResult:
        evaluator = _EVALUATORS.get(self.check_id)
        if evaluator is not None:
            result = await evaluator(self.target)
            result.check_id = self.check_id
            return result

        # Remaining controls stay mapping-only until evidence collectors exist.
        return ComplianceResult(
            check_id=self.check_id,
            status="NOT_EVALUATED",
            evidence_data={
                "target": self.target,
                "capability": "mapping_scaffold",
                "evaluated": False,
            },
            message=(
                "Control mapped only — automated evaluation is not implemented. "
                "Status is NOT_EVALUATED (insufficient evidence), not a pass/fail result."
            ),
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
                        "summary": data.get("summary", {}),
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
