"""Compliance framework assessment runner.

Evaluates targets against industry compliance frameworks including
PCI-DSS, ISO 27001, NIST 800-53, SOC 2, GDPR, and HIPAA
as described in Chapter 24.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ComplianceFramework(str, Enum):
    PCI_DSS = "pci-dss"
    ISO_27001 = "iso-27001"
    NIST_800_53 = "nist-800-53"
    SOC_2 = "soc-2"
    GDPR = "gdpr"
    HIPAA = "hipaa"


@dataclass
class ComplianceControl:
    """A single compliance control/requirement."""

    control_id: str = ""
    title: str = ""
    description: str = ""
    compliant: bool = False
    severity: str = "medium"
    evidence: str = ""
    remediation: str = ""
    applicable: bool = True


@dataclass
class ComplianceResult:
    """Result of a compliance assessment."""

    framework: ComplianceFramework
    target: str = ""
    controls: list[ComplianceControl] = field(default_factory=list)
    assessed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    assessment_id: str = ""


_COMPLIANCE_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "pci-dss": [
        {
            "id": "PCI-6.5",
            "title": "Address common coding vulnerabilities",
            "description": "Secure coding practices must address common vulnerabilities (OWASP Top 10)",
            "severity": "critical",
            "remediation": "Implement secure coding training and SAST tools",
        },
        {
            "id": "PCI-6.6",
            "title": "Application security monitoring",
            "description": "Public-facing web applications must be monitored for attacks",
            "severity": "high",
            "remediation": "Deploy WAF and maintain security monitoring",
        },
        {
            "id": "PCI-11.3",
            "title": "Penetration testing",
            "description": "External and internal penetration testing at least annually and after changes",
            "severity": "high",
            "remediation": "Schedule and perform regular penetration tests",
        },
        {
            "id": "PCI-10.2",
            "title": "Audit trails",
            "description": "Implement automated audit trails for all system components",
            "severity": "high",
            "remediation": "Enable comprehensive audit logging",
        },
    ],
    "iso-27001": [
        {
            "id": "ISO-A.12.6.1",
            "title": "Management of technical vulnerabilities",
            "description": "Timely information about technical vulnerabilities obtained and acted upon",
            "severity": "high",
            "remediation": "Implement vulnerability management program",
        },
        {
            "id": "ISO-A.14.2.1",
            "title": "Secure development policy",
            "description": "Rules for secure development of software established and applied",
            "severity": "high",
            "remediation": "Establish secure SDLC policy",
        },
        {
            "id": "ISO-A.12.4.1",
            "title": "Event logging",
            "description": "Event logs recording activities produced, kept, and regularly reviewed",
            "severity": "medium",
            "remediation": "Configure and review system event logging",
        },
    ],
    "nist-800-53": [
        {
            "id": "RA-5",
            "title": "Vulnerability scanning",
            "description": "Vulnerability scanning tools used to identify vulnerabilities",
            "severity": "high",
            "remediation": "Deploy and maintain vulnerability scanning",
        },
        {
            "id": "SI-4",
            "title": "System monitoring",
            "description": "System monitored to detect attacks and unauthorized connections",
            "severity": "high",
            "remediation": "Implement continuous security monitoring",
        },
        {
            "id": "CA-2",
            "title": "Security assessments",
            "description": "Security assessments conducted on systems and applications",
            "severity": "medium",
            "remediation": "Schedule periodic security assessments",
        },
    ],
    "soc-2": [
        {
            "id": "CC7.1",
            "title": "System monitoring",
            "description": "System infrastructure monitored to detect deviations from standards",
            "severity": "high",
            "remediation": "Implement infrastructure monitoring",
        },
        {
            "id": "CC7.2",
            "title": "Security incident management",
            "description": "Security incidents identified, logged, and responded to",
            "severity": "high",
            "remediation": "Establish incident response procedures",
        },
    ],
    "gdpr": [
        {
            "id": "GDPR-32",
            "title": "Security of processing",
            "description": "Appropriate technical measures to ensure security of personal data",
            "severity": "critical",
            "remediation": "Implement encryption, pseudonymization, and access controls",
        },
        {
            "id": "GDPR-33",
            "title": "Data breach notification",
            "description": "Personal data breaches notified to supervisory authority within 72 hours",
            "severity": "high",
            "remediation": "Establish breach notification procedures",
        },
    ],
    "hipaa": [
        {
            "id": "HIPAA-164.308",
            "title": "Security management process",
            "description": "Risk analysis and security measures to protect ePHI",
            "severity": "critical",
            "remediation": "Conduct risk analysis and implement safeguards",
        },
        {
            "id": "HIPAA-164.312",
            "title": "Access controls",
            "description": "Unique user identification, emergency access, and automatic logoff",
            "severity": "high",
            "remediation": "Implement strong access control measures",
        },
    ],
}


class ComplianceRunner:
    """Assesses targets against compliance frameworks."""

    def __init__(self) -> None:
        self._results: list[ComplianceResult] = []

    def assess(self, framework: ComplianceFramework, target: str = "") -> ComplianceResult:
        import uuid

        controls_data = _COMPLIANCE_CONTROLS.get(framework.value, [])
        controls: list[ComplianceControl] = []

        for c in controls_data:
            compliant = self._check_compliance(framework, c["id"], target)
            evidence = self._gather_evidence(framework, c["id"], target)
            control = ComplianceControl(
                control_id=c["id"],
                title=c["title"],
                description=c["description"],
                severity=c.get("severity", "medium"),
                remediation=c.get("remediation", ""),
                compliant=compliant,
                evidence=evidence,
            )
            controls.append(control)

        result = ComplianceResult(
            framework=framework,
            target=target,
            controls=controls,
            assessment_id=f"ASSESS-{uuid.uuid4().hex[:8].upper()}",
        )

        self._results.append(result)
        logger.info(
            "Compliance assessment %s: %s — %d/%d compliant",
            result.assessment_id,
            framework.value,
            sum(1 for c in controls if c.compliant and c.applicable),
            sum(1 for c in controls if c.applicable),
        )
        return result

    def assess_all(self, target: str = "") -> dict[str, ComplianceResult]:
        return {fw.value: self.assess(fw, target) for fw in ComplianceFramework}

    def run_framework(self, framework_name: str, target: str = "") -> ComplianceResult:
        try:
            fw = ComplianceFramework(framework_name.lower().replace(" ", "-"))
        except ValueError:
            available = [f.value for f in ComplianceFramework]
            raise ValueError(f"Unknown framework '{framework_name}'. Available frameworks: {available}")
        return self.assess(fw, target)

    def _check_compliance(
        self, framework: ComplianceFramework, control_id: str, target: str
    ) -> bool:
        if not target:
            return False
        try:
            if framework == ComplianceFramework.PCI_DSS:
                return self._check_pci_dss(control_id, target)
            elif framework == ComplianceFramework.ISO_27001:
                return self._check_iso_27001(control_id, target)
            elif framework == ComplianceFramework.NIST_800_53:
                return self._check_nist(control_id, target)
            elif framework == ComplianceFramework.SOC_2:
                return self._check_soc2(control_id, target)
            elif framework == ComplianceFramework.GDPR:
                return self._check_gdpr(control_id, target)
            elif framework == ComplianceFramework.HIPAA:
                return self._check_hipaa(control_id, target)
            return False
        except Exception:
            logger.debug("Compliance check failed for %s/%s", framework.value, control_id, exc_info=True)
            return False

    def _check_pci_dss(self, control_id: str, target: str) -> bool:
        if control_id == "PCI-6.5":
            return self._check_tool_installed("bandit") or self._check_tool_installed("semgrep")
        elif control_id == "PCI-6.6":
            return self._check_process_running("nginx") or self._check_process_running("httpd") or self._check_tool_installed("modsecurity")
        elif control_id == "PCI-11.3":
            return self._check_tool_installed("nmap") or self._check_tool_installed("sqlmap")
        elif control_id == "PCI-10.2":
            return self._check_service_exists("auditd") or self._check_service_exists("syslog") or self._check_service_exists("EventLog")
        return False

    def _check_iso_27001(self, control_id: str, target: str) -> bool:
        if control_id == "ISO-A.12.6.1":
            return self._check_tool_installed("trivy") or self._check_tool_installed("grype") or self._check_tool_installed("nessus")
        elif control_id == "ISO-A.14.2.1":
            return self._check_tool_installed("bandit") or self._check_tool_installed("semgrep") or self._check_tool_installed("sonarscanner")
        elif control_id == "ISO-A.12.4.1":
            return self._check_service_exists("auditd") or self._check_service_exists("syslog") or self._check_service_exists("EventLog")
        return False

    def _check_nist(self, control_id: str, target: str) -> bool:
        if control_id == "RA-5":
            return self._check_tool_installed("nmap") or self._check_tool_installed("openvas") or self._check_tool_installed("trivy")
        elif control_id == "SI-4":
            return self._check_process_running("auditd") or self._check_process_running("wazuh") or self._check_tool_installed("ossec")
        elif control_id == "CA-2":
            return self._check_tool_installed("nmap") or self._check_tool_installed("openvas")
        return False

    def _check_soc2(self, control_id: str, target: str) -> bool:
        if control_id == "CC7.1":
            return self._check_process_running("prometheus") or self._check_process_running("nagios") or self._check_process_running("zabbix")
        elif control_id == "CC7.2":
            return self._check_tool_installed("thehive") or self._check_tool_installed("ir") or self._check_dir_exists("/var/log/incidents")
        return False

    def _check_gdpr(self, control_id: str, target: str) -> bool:
        if control_id == "GDPR-32":
            return self._check_dir_exists("/etc/ssl") or self._check_dir_exists("/etc/letsencrypt") or bool(os.environ.get("SSL_CERT_FILE"))
        elif control_id == "GDPR-33":
            return self._check_dir_exists("/var/log/breach") or os.path.exists("/etc/breach-notification.conf")
        return False

    def _check_hipaa(self, control_id: str, target: str) -> bool:
        if control_id == "HIPAA-164.308":
            return self._check_dir_exists("/etc/ssl") or self._check_tool_installed("openssl")
        elif control_id == "HIPAA-164.312":
            return self._check_dir_exists("/etc/ssl") or self._check_tool_installed("openssl")
        return False

    def _check_tool_installed(self, tool_name: str) -> bool:
        try:
            result = subprocess.run(
                [sys.executable, "-m", tool_name, "--help"] if tool_name in ("bandit", "semgrep", "trivy")
                else (["where", tool_name] if sys.platform == "win32" else ["which", tool_name]),
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        try:
            result = subprocess.run(
                ["where", tool_name] if sys.platform == "win32" else [tool_name, "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_process_running(self, process_name: str) -> bool:
        try:
            if sys.platform == "win32":
                cmd = ["tasklist", "/FI", f"IMAGENAME eq {process_name}.exe"]
            else:
                cmd = ["pgrep", "-x", process_name]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_service_exists(self, service_name: str) -> bool:
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["sc", "query", service_name],
                    capture_output=True,
                    timeout=5,
                )
                return "RUNNING" in result.stdout.decode() or "STOPPED" in result.stdout.decode()
            else:
                result = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_dir_exists(self, path: str) -> bool:
        return os.path.isdir(path)

    def _gather_evidence(self, framework: ComplianceFramework, control_id: str, target: str) -> str:
        parts: list[str] = []
        if target:
            parts.append(f"target={target}")
        parts.append(f"framework={framework.value}")
        parts.append(f"control={control_id}")

        try:
            if framework == ComplianceFramework.PCI_DSS:
                parts.append(self._gather_pci_dss_evidence(control_id, target))
            elif framework == ComplianceFramework.ISO_27001:
                parts.append(self._gather_iso_27001_evidence(control_id, target))
            elif framework == ComplianceFramework.NIST_800_53:
                parts.append(self._gather_nist_evidence(control_id, target))
            elif framework == ComplianceFramework.SOC_2:
                parts.append(self._gather_soc2_evidence(control_id, target))
            elif framework == ComplianceFramework.GDPR:
                parts.append(self._gather_gdpr_evidence(control_id, target))
            elif framework == ComplianceFramework.HIPAA:
                parts.append(self._gather_hipaa_evidence(control_id, target))
        except Exception:
            parts.append("evidence_collection_error")

        return " | ".join(parts)

    def _gather_pci_dss_evidence(self, control_id: str, target: str) -> str:
        if control_id == "PCI-6.5":
            tools = [t for t in ("bandit", "semgrep") if self._check_tool_installed(t)]
            return f"sast_tools={','.join(tools) if tools else 'none'}"
        elif control_id == "PCI-6.6":
            procs = [p for p in ("nginx", "httpd") if self._check_process_running(p)]
            return f"waf_proxies={','.join(procs) if procs else 'none'}"
        elif control_id == "PCI-11.3":
            tools = [t for t in ("nmap", "sqlmap") if self._check_tool_installed(t)]
            return f"pentest_tools={','.join(tools) if tools else 'none'}"
        elif control_id == "PCI-10.2":
            svcs = [s for s in ("auditd", "syslog", "EventLog") if self._check_service_exists(s)]
            return f"audit_services={','.join(svcs) if svcs else 'none'}"
        return "no_specific_evidence"

    def _gather_iso_27001_evidence(self, control_id: str, target: str) -> str:
        if control_id == "ISO-A.12.6.1":
            tools = [t for t in ("trivy", "grype", "nessus") if self._check_tool_installed(t)]
            return f"vuln_scanners={','.join(tools) if tools else 'none'}"
        elif control_id == "ISO-A.14.2.1":
            tools = [t for t in ("bandit", "semgrep", "sonarscanner") if self._check_tool_installed(t)]
            return f"sast_tools={','.join(tools) if tools else 'none'}"
        elif control_id == "ISO-A.12.4.1":
            svcs = [s for s in ("auditd", "syslog", "EventLog") if self._check_service_exists(s)]
            return f"logging_services={','.join(svcs) if svcs else 'none'}"
        return "no_specific_evidence"

    def _gather_nist_evidence(self, control_id: str, target: str) -> str:
        if control_id == "RA-5":
            tools = [t for t in ("nmap", "openvas", "trivy") if self._check_tool_installed(t)]
            return f"scanners={','.join(tools) if tools else 'none'}"
        elif control_id == "SI-4":
            procs = [p for p in ("auditd", "wazuh", "ossec") if self._check_process_running(p)]
            return f"monitoring={','.join(procs) if procs else 'none'}"
        elif control_id == "CA-2":
            tools = [t for t in ("nmap", "openvas") if self._check_tool_installed(t)]
            return f"assessment_tools={','.join(tools) if tools else 'none'}"
        return "no_specific_evidence"

    def _gather_soc2_evidence(self, control_id: str, target: str) -> str:
        if control_id == "CC7.1":
            procs = [p for p in ("prometheus", "nagios", "zabbix") if self._check_process_running(p)]
            return f"monitoring_tools={','.join(procs) if procs else 'none'}"
        elif control_id == "CC7.2":
            dirs = [d for d in ("/var/log/incidents",) if self._check_dir_exists(d)]
            tools = [t for t in ("thehive", "ir") if self._check_tool_installed(t)]
            return f"ir_tools={','.join(tools) if tools else 'none'}, dirs={','.join(dirs) if dirs else 'none'}"
        return "no_specific_evidence"

    def _gather_gdpr_evidence(self, control_id: str, target: str) -> str:
        if control_id == "GDPR-32":
            dirs = [d for d in ("/etc/ssl", "/etc/letsencrypt") if self._check_dir_exists(d)]
            ssl_env = "SSL_CERT_FILE" if os.environ.get("SSL_CERT_FILE") else None
            return f"encryption_dirs={','.join(dirs) if dirs else 'none'}, ssl_env={ssl_env or 'unset'}"
        elif control_id == "GDPR-33":
            found = []
            if self._check_dir_exists("/var/log/breach"):
                found.append("/var/log/breach")
            if os.path.exists("/etc/breach-notification.conf"):
                found.append("/etc/breach-notification.conf")
            return f"breach_docs={','.join(found) if found else 'none'}"
        return "no_specific_evidence"

    def _gather_hipaa_evidence(self, control_id: str, target: str) -> str:
        if control_id == "HIPAA-164.308":
            has_ssl = self._check_dir_exists("/etc/ssl")
            has_openssl = self._check_tool_installed("openssl")
            return f"encryption=ssl_dir:{has_ssl}, openssl:{has_openssl}"
        elif control_id == "HIPAA-164.312":
            has_ssl = self._check_dir_exists("/etc/ssl")
            has_openssl = self._check_tool_installed("openssl")
            return f"access_controls=ssl_dir:{has_ssl}, openssl:{has_openssl}"
        return "no_specific_evidence"

    def get_frameworks_summary(self) -> dict[str, Any]:
        return {
            "total_assessments": len(self._results),
            "frameworks": {
                fw.value: {
                    "total": sum(1 for r in self._results if r.framework == fw for c in r.controls),
                    "compliant": sum(
                        1
                        for r in self._results
                        if r.framework == fw
                        for c in r.controls
                        if c.compliant and c.applicable
                    ),
                    "non_compliant": sum(
                        1
                        for r in self._results
                        if r.framework == fw
                        for c in r.controls
                        if not c.compliant and c.applicable
                    ),
                    "not_applicable": sum(
                        1
                        for r in self._results
                        if r.framework == fw
                        for c in r.controls
                        if not c.applicable
                    ),
                }
                for fw in ComplianceFramework
            },
        }


__all__ = ["ComplianceRunner", "ComplianceResult", "ComplianceControl", "ComplianceFramework"]
