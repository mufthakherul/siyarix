# SPDX-License-Identifier: AGPL-3.0-or-later

"""Syft SBOM generation output parser — parses Syft JSON output."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")

_SEVERITY_PACKAGES = {
    "openssl": "high",
    "libssl": "high",
    "log4j": "critical",
    "log4j-core": "critical",
    "log4j-api": "critical",
    "spring": "high",
    "spring-framework": "high",
    "struts": "critical",
    "tomcat": "medium",
    "nginx": "medium",
    "apache": "medium",
    "bash": "medium",
    "sudo": "high",
    "python": "low",
    "node": "low",
    "go": "low",
    "curl": "low",
    "wget": "low",
    "busybox": "medium",
    "musl": "low",
    "alpine": "low",
}


class SyftParser:
    """Parse Syft JSON SBOM output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        if not _JSON_RE.match(output):
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        artifacts = data.get("artifacts", [])
        if isinstance(artifacts, list):
            for art in artifacts:
                name = art.get("name", "unknown")
                version = art.get("version", "")
                ptype = art.get("type", art.get("metadata", {}).get("packageType", "unknown"))
                art.get("locations", [])
                licenses = art.get("licenses", [])

                dedup_key = f"{name}|{version}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity = "info"
                for pkg_name, sev in _SEVERITY_PACKAGES.items():
                    if pkg_name in name.lower():
                        severity = sev
                        break

                findings.append(
                    {
                        "title": f"Package: {name} ({version})",
                        "severity": severity,
                        "description": f"Syft discovered {ptype} package {name} version {version}"
                        + (f" [{', '.join(licenses[:3])}]" if licenses else ""),
                        "evidence": f"Package: {name} | Version: {version} | Type: {ptype}",
                        "tool": "syft",
                        "target": "container",
                        "timestamp": _now_iso(),
                    },
                )

        return findings
