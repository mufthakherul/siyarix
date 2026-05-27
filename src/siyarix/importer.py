"""Data format import module — imports findings from Nessus, Burp Suite, Metasploit,
STIX/TAXII, OpenIOC, and other security tool output formats.

Supports conversion to the internal Siyarix finding format for unified
analysis and reporting.
"""

from __future__ import annotations

import json
import logging
from defusedxml import ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ImportedFinding:
    source: str = ""
    original_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"
    cve: str = ""
    cwe: str = ""
    cvss_score: float = 0.0
    host: str = ""
    port: int = 0
    protocol: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportResult:
    source_format: str = ""
    total_imported: int = 0
    errors: list[str] = field(default_factory=list)
    findings: list[ImportedFinding] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


SEVERITY_MAP = {
    0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical",
    "none": "info", "low": "low", "medium": "medium",
    "high": "high", "critical": "critical",
    "informational": "info", "low severity": "low",
    "medium severity": "medium", "high severity": "high",
    "critical severity": "critical",
}


class SecurityImporter:
    """Imports findings from various security tool formats."""

    def import_nessus(self, path: str | Path) -> ImportResult:
        result = ImportResult(source_format="nessus")
        p = Path(path)
        if not p.exists():
            result.errors.append(f"File not found: {path}")
            return result

        try:
            tree = ET.parse(p)
            root = tree.getroot()
            for report_host in root.iter("ReportHost"):
                host_name = report_host.get("name", "")
                for item in report_host.iter("ReportItem"):
                    finding = ImportedFinding(
                        source="nessus",
                        original_id=item.get("pluginID", ""),
                        title=item.findtext("pluginName", ""),
                        description=item.findtext("description", ""),
                        severity=SEVERITY_MAP.get(item.get("severity", "0").lower(), "info"),
                        cve=item.findtext("cve", ""),
                        cwe=item.findtext("cwe", "") or item.findtext("cwe_id", ""),
                        cvss_score=float(item.findtext("cvss3_base_score", "0") or "0"),
                        host=host_name,
                        port=int(item.get("port", "0") or "0"),
                        protocol=item.get("protocol", ""),
                        remediation=item.findtext("solution", ""),
                        references=[r.text or "" for r in item.iter("see_also") if r.text],
                    )
                    result.findings.append(finding)
            result.total_imported = len(result.findings)
        except Exception as exc:
            result.errors.append(f"Nessus parse error: {exc}")

        return result

    def import_burp(self, path: str | Path) -> ImportResult:
        result = ImportResult(source_format="burp")
        p = Path(path)
        if not p.exists():
            result.errors.append(f"File not found: {path}")
            return result

        try:
            root = ET.parse(p).getroot()
            for issue in root.iter("issue"):
                finding = ImportedFinding(
                    source="burp",
                    original_id=issue.findtext("serialNumber", ""),
                    title=issue.findtext("name", ""),
                    description=issue.findtext("issueBackground", "") or issue.findtext("issueDetail", ""),
                    severity=SEVERITY_MAP.get(issue.findtext("severity", "info").lower(), "info"),
                    cwe=issue.findtext("cwe", ""),
                    host=issue.findtext("host", ""),
                    port=int(issue.findtext("port", "0") or "0"),
                    remediation=issue.findtext("remediationBackground", "") or issue.findtext("remediationDetail", ""),
                    references=[r.text or "" for r in issue.iter("reference") if r.text],
                )
                result.findings.append(finding)
            result.total_imported = len(result.findings)
        except Exception as exc:
            result.errors.append(f"Burp parse error: {exc}")

        return result

    def import_metasploit(self, path: str | Path) -> ImportResult:
        result = ImportResult(source_format="metasploit")
        p = Path(path)
        if not p.exists():
            result.errors.append(f"File not found: {path}")
            return result

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            hosts = data if isinstance(data, list) else data.get("hosts", [])
            for host in hosts:
                host_str = host.get("address", host.get("host", ""))
                vulns = host.get("vulns", host.get("findings", []))
                for vuln in vulns:
                    finding = ImportedFinding(
                        source="metasploit",
                        title=vuln.get("name", vuln.get("title", "")),
                        description=vuln.get("description", ""),
                        severity=SEVERITY_MAP.get(vuln.get("severity", "medium").lower(), "medium"),
                        cve=vuln.get("cve", ""),
                        host=host_str,
                        port=vuln.get("port", 0),
                        remediation=vuln.get("solution", vuln.get("remediation", "")),
                    )
                    result.findings.append(finding)
            result.total_imported = len(result.findings)
        except Exception as exc:
            result.errors.append(f"Metasploit parse error: {exc}")

        return result

    def import_stix(self, path: str | Path) -> ImportResult:
        result = ImportResult(source_format="stix")
        p = Path(path)
        if not p.exists():
            result.errors.append(f"File not found: {path}")
            return result

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            objects = data if isinstance(data, list) else data.get("objects", [])
            for obj in objects:
                if obj.get("type") not in ("vulnerability", "indicator", "malware", "attack-pattern"):
                    continue
                finding = ImportedFinding(
                    source="stix",
                    original_id=obj.get("id", ""),
                    title=obj.get("name", ""),
                    description=obj.get("description", ""),
                    severity=SEVERITY_MAP.get(obj.get("severity", "medium").lower(), "medium"),
                    cve=obj.get("external_references", [{}])[0].get("external_id", "") if obj.get("external_references") else "",
                )
                result.findings.append(finding)
            result.total_imported = len(result.findings)
        except Exception as exc:
            result.errors.append(f"STIX parse error: {exc}")

        return result

    def import_openioc(self, path: str | Path) -> ImportResult:
        result = ImportResult(source_format="openioc")
        p = Path(path)
        if not p.exists():
            result.errors.append(f"File not found: {path}")
            return result

        try:
            root = ET.parse(p).getroot()
            for indicator in root.iter("Indicator"):
                finding = ImportedFinding(
                    source="openioc",
                    original_id=indicator.get("id", ""),
                    title=indicator.findtext("Title", "") or indicator.get("description", ""),
                    description=indicator.findtext("Description", ""),
                    severity=SEVERITY_MAP.get(indicator.get("severity", "medium").lower(), "medium"),
                )
                result.findings.append(finding)
            result.total_imported = len(result.findings)
        except Exception as exc:
            result.errors.append(f"OpenIOC parse error: {exc}")

        return result

    def auto_import(self, path: str | Path) -> ImportResult:
        p = Path(path)
        if not p.exists():
            result = ImportResult(source_format="unknown")
            result.errors.append(f"File not found: {path}")
            return result

        name = p.name.lower()
        ext = p.suffix.lower()

        format_detectors = [
            (lambda n, e: n.endswith(".nessus"), self.import_nessus),
            (lambda n, e: "burp" in n and e == ".xml", self.import_burp),
            (lambda n, e: "msf" in n or "metasploit" in n or "database" in n, self.import_metasploit),
            (lambda n, e: e == ".json" and ("stix" in n or "taxii" in n), self.import_stix),
            (lambda n, e: "ioc" in n and e == ".xml", self.import_openioc),
            (lambda n, e: e == ".xml" and "nessus" in n, self.import_nessus),
            (lambda n, e: e == ".json", self.import_metasploit),
        ]

        for detector, importer_fn in format_detectors:
            if detector(name, ext):
                return importer_fn(p)

        # Last resort: try each format
        results = [
            self.import_nessus(p),
            self.import_burp(p),
            self.import_metasploit(p),
        ]
        best = max(results, key=lambda r: r.total_imported)
        return best

    def to_siyarix_findings(self, imported: ImportResult) -> list[dict[str, Any]]:
        return [
            {
                "source": f.source,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "cve": f.cve,
                "cwe": f.cwe,
                "cvss_score": f.cvss_score,
                "host": f.host,
                "port": f.port,
                "protocol": f.protocol,
                "remediation": f.remediation,
            }
            for f in imported.findings
        ]


security_importer = SecurityImporter()


__all__ = ["SecurityImporter", "ImportedFinding", "ImportResult", "security_importer"]
