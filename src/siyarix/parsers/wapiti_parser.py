# SPDX-License-Identifier: AGPL-3.0-or-later

"""Wapiti vulnerability scanner parser — extracts vulnerability types, URLs, parameters and evidence."""

from __future__ import annotations

from . import _now_iso

import json
import re

_VULN_TYPE_RE = re.compile(
    r"(\w+(?:\s+\w+)*)\s+(?:\{|\():?\s*(\d+)", re.IGNORECASE
)
_URL_RE = re.compile(r"(https?://\S+)", re.IGNORECASE)
_PARAM_RE = re.compile(r"(?:Parameter|param|argument)[:\s]+(\S+)", re.IGNORECASE)
_EVIDENCE_RE = re.compile(r"(?:Evidence|Proof|Payload|description)[:\s]+(.+)", re.IGNORECASE)
_DESCRIPTION_RE = re.compile(r"^(?:\s{2,}|\t+)(\S.+)$")
_SEVERITY_MAP = {
    "sql injection": "critical",
    "xss": "high",
    "cross site scripting": "high",
    "file inclusion": "critical",
    "command execution": "critical",
    "path traversal": "high",
    "csrf": "medium",
    "xxe": "high",
    "ssrf": "high",
    "open redirect": "medium",
    "information disclosure": "low",
    "directory listing": "medium",
    "backup file": "medium",
    "weak credentials": "high",
}


class WapitiParser:
    """Parse wapiti vulnerability scanner output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        stripped = output.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                for vuln_key in ("vulnerabilities", "infos"):
                    vuln_list = data.get(vuln_key, {})
                    if isinstance(vuln_list, list):
                        for vuln in vuln_list:
                            if isinstance(vuln, dict):
                                dedup_key = json.dumps(vuln, sort_keys=True)[:100]
                                if dedup_key not in seen:
                                    seen.add(dedup_key)
                                    severity = vuln.get("severity", "info")
                                    url = vuln.get("url", "unknown")
                                    vuln_type = vuln.get("type", vuln.get("name", "unknown"))
                                    desc = vuln.get("description", vuln.get("detail", ""))
                                    findings.append({
                                        "title": f"Wapiti: {vuln_type}",
                                        "severity": severity,
                                        "description": desc or f"{vuln_type} at {url}",
                                        "evidence": json.dumps(vuln),
                                        "tool": "wapiti",
                                        "target": url,
                                        "timestamp": _now_iso(),
                                    })
                            elif isinstance(vuln, str):
                                dedup_key = vuln[:100]
                                if dedup_key not in seen:
                                    seen.add(dedup_key)
                                    findings.append({
                                        "title": f"Wapiti: {vuln[:60]}",
                                        "severity": "info",
                                        "description": vuln,
                                        "evidence": vuln,
                                        "tool": "wapiti",
                                        "target": "unknown",
                                        "timestamp": _now_iso(),
                                    })
                    elif isinstance(vuln_list, dict):
                        for vuln_type, vuln_items in vuln_list.items():
                            if isinstance(vuln_items, list):
                                for vuln in vuln_items:
                                    dedup_key = f"{vuln_type}:{str(vuln)[:80]}"
                                    if dedup_key not in seen:
                                        seen.add(dedup_key)
                                        url = vuln if isinstance(vuln, str) else vuln.get("url", "unknown")
                                        findings.append({
                                            "title": f"Wapiti: {vuln_type}",
                                            "severity": "info",
                                            "description": f"{vuln_type} at {url}",
                                            "evidence": json.dumps(vuln) if not isinstance(vuln, str) else vuln,
                                            "tool": "wapiti",
                                            "target": url if isinstance(url, str) else "unknown",
                                            "timestamp": _now_iso(),
                                        })
                if findings:
                    return findings
            except json.JSONDecodeError:
                pass

        lines = output.splitlines()
        current_vuln_type = ""
        current_url = ""
        current_param = ""
        current_evidence = ""
        target = "unknown"

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            url_m = _URL_RE.search(line_stripped)
            vuln_m = _VULN_TYPE_RE.search(line_stripped)

            if vuln_m and url_m:
                if current_vuln_type and current_url:
                    dedup_key = f"{current_vuln_type}:{current_url}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        severity = "info"
                        for key, val in _SEVERITY_MAP.items():
                            if key in current_vuln_type.lower():
                                severity = val
                                break
                        findings.append({
                            "title": f"Wapiti: {current_vuln_type.strip()}",
                            "severity": severity,
                            "description": f"{current_vuln_type.strip()} at {current_url}",
                            "evidence": current_evidence or current_url,
                            "tool": "wapiti",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        })

                current_vuln_type = vuln_m.group(1).strip()
                current_url = url_m.group(1)
                current_param = ""
                current_evidence = ""
                continue

            if url_m and not vuln_m:
                current_url = url_m.group(1)

            param_m = _PARAM_RE.search(line_stripped)
            if param_m:
                current_param = param_m.group(1)

            ev_m = _EVIDENCE_RE.search(line_stripped)
            if ev_m:
                current_evidence = ev_m.group(1)

            if current_vuln_type and current_url and _DESCRIPTION_RE.match(line_stripped):
                dedup_key = f"{current_vuln_type}:{current_url}:{line_stripped}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    severity = "info"
                    for key, val in _SEVERITY_MAP.items():
                        if key in current_vuln_type.lower():
                            severity = val
                            break
                    findings.append({
                        "title": f"Wapiti: {current_vuln_type.strip()}",
                        "severity": severity,
                        "description": f"{current_vuln_type.strip()} at {current_url} — {line_stripped}",
                        "evidence": current_evidence or line_stripped,
                        "tool": "wapiti",
                        "target": current_url,
                        "timestamp": _now_iso(),
                    })
                    current_vuln_type = ""
                    current_url = ""
                    current_param = ""
                    current_evidence = ""

        if current_vuln_type and current_url:
            dedup_key = f"{current_vuln_type}:{current_url}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                severity = "info"
                for key, val in _SEVERITY_MAP.items():
                    if key in current_vuln_type.lower():
                        severity = val
                        break
                findings.append({
                    "title": f"Wapiti: {current_vuln_type.strip()}",
                    "severity": severity,
                    "description": f"{current_vuln_type.strip()} at {current_url}",
                    "evidence": current_evidence or current_url,
                    "tool": "wapiti",
                    "target": current_url,
                    "timestamp": _now_iso(),
                })

        return findings
