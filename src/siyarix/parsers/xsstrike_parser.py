# SPDX-License-Identifier: AGPL-3.0-or-later

"""XSStrike output parser — parses XSS scanner findings (text + JSON)."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_VULN_RE = re.compile(
    r"(?:vulnerab|xss|reflected|injected|payload\s+works|dom\s*based)",
    re.IGNORECASE,
)

_PAYLOAD_RE = re.compile(
    r"(?:payload|vector|code)[:\s]+(.+)",
    re.IGNORECASE,
)

_PARAM_RE = re.compile(
    r"(?:parameter|param)[:\s]+(\S+)",
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r"(?:URL|url|target)[:\s]+(\S+)",
    re.IGNORECASE,
)

_CONFIDENCE_RE = re.compile(
    r"(?:confidence|certainty)[:\s]*(\d+)%?",
    re.IGNORECASE,
)

_TYPE_RE = re.compile(
    r"(?:type|attack\s+type)[:\s]+(.+)",
    re.IGNORECASE,
)

_DOM_RE = re.compile(
    r"(?:dom|dom[-\s]?based|DOM\s*XSS)",
    re.IGNORECASE,
)

_SUMMARY_RE = re.compile(
    r"(?:found|vulnerable|detected)[:\s]*(\d+)",
    re.IGNORECASE,
)


class XsstrikeParser:
    """Parse XSStrike output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        trimmed = output.strip()

        if not trimmed:
            return findings

        # Try JSON array
        if trimmed.startswith("["):
            try:
                records = json.loads(trimmed)
                if isinstance(records, list):
                    for rec in records:
                        findings.extend(self._parse_json_record(rec, seen))
                    return findings
            except json.JSONDecodeError:
                pass

        # Try JSON object
        if trimmed.startswith("{"):
            try:
                record = json.loads(trimmed)
                findings.extend(self._parse_json_record(record, seen))
                if findings:
                    return findings
            except json.JSONDecodeError:
                pass

        current_url = "unknown"
        current_param = "unknown"
        current_payload = ""
        current_type = "reflected"
        current_confidence = 0

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            m = _SUMMARY_RE.search(line)
            m.group(1) if m else None

            m = _URL_RE.search(line)
            if m:
                current_url = m.group(1).strip()

            m = _PARAM_RE.search(line)
            if m:
                current_param = m.group(1).strip()

            m = _TYPE_RE.search(line)
            if m:
                current_type = m.group(1).strip().lower()

            m = _CONFIDENCE_RE.search(line)
            if m:
                current_confidence = int(m.group(1))

            m = _PAYLOAD_RE.search(line)
            if m:
                current_payload = m.group(1).strip()

            is_dom = bool(_DOM_RE.search(line))

            if _VULN_RE.search(line):
                if is_dom:
                    xss_type = "DOM-based"
                    severity = "high"
                elif current_type in ("reflected", "stored"):
                    xss_type = current_type
                    severity = "high" if current_type == "stored" else "high"
                else:
                    xss_type = current_type or "reflected"
                    severity = "medium"

                if current_confidence >= 80:
                    severity = "critical" if xss_type != "reflected" else "high"

                key = f"xss:{current_url}:{current_param}:{xss_type}"
                if key not in seen:
                    seen.add(key)
                    evidence_parts = [f"URL: {current_url}", f"Param: {current_param}"]
                    if current_payload:
                        evidence_parts.append(f"Payload: {current_payload[:100]}")
                    if current_confidence:
                        evidence_parts.append(f"Confidence: {current_confidence}%")
                    if is_dom:
                        evidence_parts.append("DOM-based")

                    findings.append(
                        {
                            "title": f"XSS vulnerability ({xss_type})",
                            "severity": severity,
                            "description": f"XSStrike identified {xss_type} XSS on parameter {current_param} at {current_url}",
                            "evidence": " | ".join(evidence_parts),
                            "tool": "xsstrike",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )

            if not _VULN_RE.search(line) and current_payload and current_url != "unknown":
                key = f"payload:{current_url}:{current_param}:{current_payload[:50]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": "XSS payload generated",
                            "severity": "info",
                            "description": f"XSStrike generated payload for {current_url} param {current_param}",
                            "evidence": f"Payload: {current_payload[:200]}",
                            "tool": "xsstrike",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )

        return findings

    def _parse_json_record(
        self, record: dict, seen: set[str] | None = None
    ) -> list[dict[str, Any]]:
        if seen is None:
            seen = set()
        findings: list[dict[str, Any]] = []
        url = record.get("url", record.get("target", "unknown"))
        param = record.get("parameter", record.get("param", "unknown"))
        payload = record.get("payload", "")
        confidence = record.get("confidence", 0)
        xss_type = record.get("type", "reflected")
        is_dom = record.get("dom", False) or xss_type.lower() == "dom"

        if record.get("vulnerable") or record.get("found"):
            if is_dom:
                severity = "high"
                label = "DOM-based"
            elif xss_type == "stored":
                severity = "high"
                label = "stored"
            elif confidence and confidence >= 80:
                severity = "high"
                label = xss_type
            else:
                severity = "medium"
                label = xss_type

            key = f"xss:{url}:{param}:{label}"
            if key not in seen:
                seen.add(key)
                evidence_parts = [f"URL: {url}", f"Param: {param}"]
                if payload:
                    evidence_parts.append(f"Payload: {payload[:100]}")
                if confidence:
                    evidence_parts.append(f"Confidence: {confidence}%")
                if is_dom:
                    evidence_parts.append("DOM-based")

                findings.append(
                    {
                        "title": f"XSS vulnerability ({label})",
                        "severity": severity,
                        "description": f"XSStrike identified {label} XSS on parameter {param} at {url}",
                        "evidence": " | ".join(evidence_parts),
                        "tool": "xsstrike",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

        if payload:
            key = f"payload:{url}:{param}:{payload[:50]}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": "XSS payload generated",
                        "severity": "info",
                        "description": f"XSStrike generated payload for {url} param {param}",
                        "evidence": f"Payload: {payload[:200]}",
                        "tool": "xsstrike",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
