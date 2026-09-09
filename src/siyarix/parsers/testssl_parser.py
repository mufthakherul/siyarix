# SPDX-License-Identifier: AGPL-3.0-or-later

"""testssl.sh output parser — extracts findings by severity level, CVE IDs, and descriptions."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_FINDING_RE = re.compile(
    r"^\s*\[(?P<severity>INFO|LOW|MEDIUM|HIGH|CRITICAL)\]\s+(?P<description>.+)",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_HOSTNAME_RE = re.compile(
    r"(?:Testing|Scanning|scanning)\s+(?:now\s+)?(?:at\s+)?(\S+)",
    re.IGNORECASE,
)
_SEVERITY_MAP = {
    "INFO": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


class TestsslParser:
    """Parse testssl.sh output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        target = "unknown"
        lines = output.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            host_m = _HOSTNAME_RE.search(line_stripped)
            if host_m:
                target = host_m.group(1).strip()

            m = _FINDING_RE.match(line_stripped)
            if not m:
                continue

            severity_raw = m.group("severity").upper()
            description = m.group("description").strip()
            severity = _SEVERITY_MAP.get(severity_raw, "info")

            cve_ids = _CVE_RE.findall(description)
            cve_str = ", ".join(cve_ids) if cve_ids else ""

            dedup_key = cve_str or description[:80]
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            title = description.split("(")[0].split("—")[0].strip()
            if len(title) > 80:
                title = title[:77] + "..."

            evidence = line_stripped
            if cve_str:
                evidence += f" | CVEs: {cve_str}"

            findings.append(
                {
                    "title": f"testssl: {title}",
                    "severity": severity,
                    "description": f"[{severity_raw}] {description}",
                    "evidence": evidence,
                    "tool": "testssl",
                    "target": target,
                    "timestamp": _now_iso(),
                },
            )

        return findings
