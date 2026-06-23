# SPDX-License-Identifier: AGPL-3.0-or-later

"""Commix output parser — parses command injection scanner results (text + JSON)."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_VULN_RE = re.compile(
    r"(?:vulnerable|command injection|injection found|os command|RCE|injectable|cmdi)",
    re.IGNORECASE,
)

_PAYLOAD_RE = re.compile(
    r"(?:payload|command|injected|executed)[:\s]+(.+)",
    re.IGNORECASE,
)

_TECH_RE = re.compile(
    r"(?:technique|method|type)[:\s]+(\S+)",
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r"(?:URL|url|target)[:\s]+(\S+)",
    re.IGNORECASE,
)

_PARAM_RE = re.compile(
    r"(?:parameter|param|injectable)[:\s]+(\S+)",
    re.IGNORECASE,
)

_OS_RE = re.compile(
    r"(?:OS|platform|system|detected\s+os)[:\s]+(\S+)",
    re.IGNORECASE,
)

_SHELL_RE = re.compile(
    r"(?:shell|pseudo[\-\s]?shell)\s+(?:obtained|gained|spawned|opened)",
    re.IGNORECASE,
)

_SHELL_TYPE_RE = re.compile(
    r"(?:interactive|blind|out[\-\s]?of[\-\s]?band|oob|dns)",
    re.IGNORECASE,
)

_CMD_RESULT_RE = re.compile(
    r"(?:output|result|response)[:\s]+(.+)",
    re.IGNORECASE,
)

_SEVERITY: dict[str, str] = {
    "classic": "critical",
    "time-based": "critical",
    "blind": "high",
    "out-of-band": "critical",
    "oob": "critical",
    "dns": "critical",
    "error-based": "high",
}

_SUMMARY_RE = re.compile(
    r"(?:Total|Found|Vulnerable|Injected)[:\s]*(\d+)",
    re.IGNORECASE,
)


class CommixParser:
    """Parse commix output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        trimmed = output.strip()

        if not trimmed:
            return findings

        # Try JSON output format
        if trimmed.startswith("{"):
            try:
                record = json.loads(trimmed)
                findings.extend(self._parse_json_record(record, seen))
                if findings:
                    return findings
            except json.JSONDecodeError:
                pass

        if trimmed.startswith("["):
            try:
                records = json.loads(trimmed)
                if isinstance(records, list):
                    for rec in records:
                        findings.extend(self._parse_json_record(rec, seen))
                    return findings
            except json.JSONDecodeError:
                pass

        current_url = "unknown"
        current_param = ""
        current_tech = ""
        current_os = ""
        shell_obtained = False

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            m = _SUMMARY_RE.search(line)
            if m:
                key = "summary:total"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Commix: {m.group(1)} findings",
                            "severity": "info",
                            "description": f"Commix reported {m.group(1)} vulnerable findings",
                            "evidence": raw.strip(),
                            "tool": "commix",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )

            m = _URL_RE.search(line)
            if m:
                current_url = m.group(1).strip()
                continue

            m = _PARAM_RE.search(line)
            if m:
                current_param = m.group(1).strip()
                continue

            m = _TECH_RE.search(line)
            if m:
                current_tech = m.group(1).strip().lower()
                continue

            m = _OS_RE.search(line)
            if m:
                current_os = m.group(1).strip()
                continue

            if _SHELL_RE.search(line):
                shell_type_match = _SHELL_TYPE_RE.search(line)
                shell_type = shell_type_match.group(0).lower() if shell_type_match else "unknown"
                key = f"shell:{current_url}:{current_param}:{shell_type}"
                if key not in seen:
                    seen.add(key)
                    shell_obtained = True
                    evidence_parts = [line.strip()]
                    if current_url:
                        evidence_parts.append(f"URL: {current_url}")
                    if current_param:
                        evidence_parts.append(f"Param: {current_param}")
                    if current_os:
                        evidence_parts.append(f"OS: {current_os}")
                    findings.append(
                        {
                            "title": f"{shell_type.capitalize()} shell obtained (commix)",
                            "severity": "critical",
                            "description": f"commix obtained a {shell_type} pseudo-shell on {current_url} via parameter {current_param}"
                            + (f" (OS: {current_os})" if current_os else ""),
                            "evidence": " | ".join(evidence_parts),
                            "tool": "commix",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _CMD_RESULT_RE.search(line)
            if m and shell_obtained:
                key = f"cmd-result:{current_url}:{m.group(1)[:50]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": "Command execution result",
                            "severity": "info",
                            "description": f"commix command output on {current_url}: {m.group(1)[:100]}",
                            "evidence": m.group(1)[:200],
                            "tool": "commix",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            if _VULN_RE.search(line):
                severity = _SEVERITY.get(current_tech, "critical")
                key = f"vuln:{current_url}:{current_param}:{current_tech}"
                if key not in seen:
                    seen.add(key)
                    evidence_parts = [f"URL: {current_url}"]
                    if current_param:
                        evidence_parts.append(f"Param: {current_param}")
                    if current_tech:
                        evidence_parts.append(f"Tech: {current_tech}")
                    if current_os:
                        evidence_parts.append(f"OS: {current_os}")
                    findings.append(
                        {
                            "title": f"Command injection vulnerability ({current_tech or 'unknown'})",
                            "severity": severity,
                            "description": f"commix identified command injection on {current_url} via parameter {current_param}"
                            + (f" using {current_tech} technique" if current_tech else "")
                            + (f" (OS: {current_os})" if current_os else ""),
                            "evidence": " | ".join(evidence_parts),
                            "tool": "commix",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )

        return findings

    def _parse_json_record(self, record: dict, seen: set[str] | None = None) -> list[dict[str, Any]]:
        if seen is None:
            seen = set()
        findings: list[dict[str, Any]] = []
        url = record.get("url", record.get("target", "unknown"))
        param = record.get("parameter", record.get("param", ""))
        technique = record.get("technique", record.get("type", ""))
        os_detected = record.get("os", record.get("platform", ""))
        shell_type = record.get("shell_type", record.get("shell", ""))
        vulnerable = record.get("vulnerable", record.get("found", False))
        cmd_output = record.get("output", record.get("result", ""))

        if vulnerable:
            severity = _SEVERITY.get(technique.lower(), "critical")
            key = f"vuln:{url}:{param}:{technique}"
            if key not in seen:
                seen.add(key)
                evidence_parts = [f"URL: {url}"]
                if param:
                    evidence_parts.append(f"Param: {param}")
                if technique:
                    evidence_parts.append(f"Tech: {technique}")
                if os_detected:
                    evidence_parts.append(f"OS: {os_detected}")
                findings.append(
                    {
                        "title": f"Command injection vulnerability ({technique or 'unknown'})",
                        "severity": severity,
                        "description": f"commix identified command injection on {url}"
                        + (f" via parameter {param}" if param else "")
                        + (f" using {technique}" if technique else "")
                        + (f" (OS: {os_detected})" if os_detected else ""),
                        "evidence": " | ".join(evidence_parts),
                        "tool": "commix",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

        if shell_type:
            key = f"shell:{url}:{shell_type}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"{shell_type.capitalize()} shell obtained (commix)",
                        "severity": "critical",
                        "description": f"commix obtained a {shell_type} pseudo-shell on {url}",
                        "evidence": f"Shell: {shell_type} | URL: {url}",
                        "tool": "commix",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

        if cmd_output:
            key = f"cmd:{url}:{str(cmd_output)[:50]}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": "Command execution result",
                        "severity": "info",
                        "description": f"commix command output on {url}: {cmd_output[:100]}",
                        "evidence": str(cmd_output)[:200],
                        "tool": "commix",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
