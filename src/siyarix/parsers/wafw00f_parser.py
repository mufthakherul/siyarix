# SPDX-License-Identifier: AGPL-3.0-or-later

"""wafw00f output parser — parses WAF detection text and JSON output."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_WAF_RE = re.compile(
    r"(?:WAF\s+)?(?:detected|identified|found|behind)\s*[:\s]*(?P<waf>.+)",
    re.IGNORECASE,
)

_NORMAL_RE = re.compile(
    r"(?:no\s+)?(?:WAF|firewall)\s+(?:detected|found|identified)",
    re.IGNORECASE,
)

_URL_RE = re.compile(
    r"(?:Testing|Checking|Target)[\s:]+(?P<url>\S+)",
    re.IGNORECASE,
)

_MULTI_WAF_RE = re.compile(
    r"(?:multiple|several|many)\s+(?:WAF|firewall)s?\s+(?:detected|found)",
    re.IGNORECASE,
)

_CONFIDENCE_RE = re.compile(
    r"(?:confidence|score|rating)[:\s]*(\d+)%?",
    re.IGNORECASE,
)

_WAF_NAMES = {
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "aws waf",
    "azure waf",
    "fastly",
    "sucuri",
    "barracuda",
    "f5 big-ip",
    "modsecurity",
    "comodo",
    "fortinet",
    "citrix",
    "denyall",
    "sophos",
    "radware",
    "safe3waf",
    "webknight",
    "dotdefender",
    "profense",
    "binarysec",
    "siteguard",
    "varnish",
    "keycdn",
    "stackpath",
    "section.io",
    "reboot",
    "wordfence",
    "securesphere",
    "airlock",
    "appwall",
    "serverdefender",
}

_SUMMARY_RE = re.compile(
    r"(?:Total|Tested|Found)[:\s]*(\d+)",
    re.IGNORECASE,
)


def _normalize_waf_name(raw: str) -> str:
    raw_lower = raw.lower().strip()
    for known in sorted(_WAF_NAMES, key=len, reverse=True):
        if known in raw_lower:
            return known
    return raw.strip()


class Wafw00fParser:
    """Parse wafw00f output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        trimmed = output.strip()

        if not trimmed:
            return findings

        # Try JSON output
        if trimmed.startswith(("{", "[")):
            try:
                data = json.loads(trimmed)
                if isinstance(data, list):
                    for item in data:
                        findings.extend(self._parse_json_record(item, seen))
                    return findings
                if isinstance(data, dict):
                    findings.extend(self._parse_json_record(data, seen))
                    return findings
            except json.JSONDecodeError:
                pass

        target = "unknown"
        last_url = ""
        multi_waf = False

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            m = _SUMMARY_RE.search(line)
            if m:
                key = "summary:wafs"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"wafw00f: {m.group(1)} WAFs detected",
                            "severity": "info",
                            "description": f"wafw00f detected {m.group(1)} WAF(s)",
                            "evidence": raw.strip(),
                            "tool": "wafw00f",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _URL_RE.search(line)
            if m:
                last_url = m.group("url")
                target = last_url
                continue

            if _MULTI_WAF_RE.search(line):
                multi_waf = True
                continue

            if _NORMAL_RE.search(line):
                key = f"no-waf:{target}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": "No WAF detected",
                            "severity": "info",
                            "description": f"wafw00f found no Web Application Firewall in front of {target}",
                            "evidence": raw,
                            "tool": "wafw00f",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _WAF_RE.search(line)
            if m:
                waf_raw = m.group("waf").strip()
                waf_name = _normalize_waf_name(waf_raw)

                confidence = 0
                conf_m = _CONFIDENCE_RE.search(line)
                if conf_m:
                    confidence = int(conf_m.group(1))

                severity = "medium"
                if confidence >= 80:
                    severity = "high"
                elif confidence <= 30:
                    severity = "low"

                key = f"waf:{waf_name}:{target}"
                if key not in seen:
                    seen.add(key)
                    evidence_parts = [f"WAF: {waf_name}"]
                    if confidence:
                        evidence_parts.append(f"Confidence: {confidence}%")
                    if multi_waf:
                        evidence_parts.append("Multiple WAFs detected")

                    findings.append(
                        {
                            "title": f"WAF detected: {waf_name}",
                            "severity": severity,
                            "description": f"wafw00f identified {waf_name} protecting {target}"
                            + (f" (confidence: {confidence}%)" if confidence else ""),
                            "evidence": " | ".join(evidence_parts),
                            "tool": "wafw00f",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )

        return findings

    def _parse_json_record(self, record: dict, seen: set[str] | None = None) -> list[dict[str, Any]]:
        if seen is None:
            seen = set()
        findings: list[dict[str, Any]] = []
        url = record.get("url", record.get("target", "unknown"))
        detected = record.get("detected", record.get("waf_detected", False))

        if not detected:
            key = f"no-waf-json:{url}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": "No WAF detected",
                        "severity": "info",
                        "description": f"wafw00f found no Web Application Firewall in front of {url}",
                        "evidence": json.dumps(record)[:200],
                        "tool": "wafw00f",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )
            return findings

        wafs = record.get("waf", [])
        if isinstance(wafs, str):
            wafs = [wafs]

        app_name = record.get("app", record.get("name", ""))
        if app_name and app_name not in wafs:
            wafs.append(app_name)

        if not wafs:
            wafs = ["unknown"]

        for waf_name in wafs:
            confidence = record.get("confidence", record.get("score", 0))
            if isinstance(confidence, str):
                confidence = (
                    int(re.sub(r"[^0-9]", "", confidence)) if re.search(r"\d", confidence) else 0
                )

            severity = "medium"
            if isinstance(confidence, (int, float)):
                if confidence >= 80:
                    severity = "high"
                elif confidence <= 30:
                    severity = "low"

            key = f"json-waf:{waf_name}:{url}"
            if key not in seen:
                seen.add(key)
                evidence_parts = [f"WAF: {waf_name}"]
                if confidence:
                    evidence_parts.append(f"Confidence: {confidence}%")

                findings.append(
                    {
                        "title": f"WAF detected: {waf_name}",
                        "severity": severity,
                        "description": f"wafw00f identified {waf_name} protecting {url}"
                        + (f" (confidence: {confidence}%)" if confidence else ""),
                        "evidence": " | ".join(evidence_parts),
                        "tool": "wafw00f",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
