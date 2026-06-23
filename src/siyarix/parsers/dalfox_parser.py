# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dalfox XSS scanner parser — parses JSON output with text fallback for XSS findings."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_TEXT_POC_RE = re.compile(r"(?:POC|PoC|poc|Payload|param|parameter)[:\s]+(.+)", re.IGNORECASE)
_TEXT_VULN_RE = re.compile(r"(?:XSS|vulnerability|found|detected)", re.IGNORECASE)
_TEXT_URL_RE = re.compile(r"(https?://\S+)", re.IGNORECASE)
_TEXT_PARAM_RE = re.compile(r"(?:Parameter|param)[:\s]+(\S+)", re.IGNORECASE)


class DalfoxParser:
    """Parse dalfox XSS scanner JSON output (with text fallback) into normalized finding dicts."""

    def parse(self: DalfoxParser, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        if output.strip().startswith(("{", "[")):
            return self._parse_json(output)
        return self._parse_text(output)

    def _parse_json(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            if isinstance(obj, list):
                for item in obj:
                    r = self._json_item(item, seen)
                    if r:
                        findings.append(r)
            else:
                r = self._json_item(obj, seen)
                if r:
                    findings.append(r)
        return findings

    def _json_item(self, obj: dict, seen: set[str]) -> dict | None:
        vuln_type = obj.get("type", obj.get("vuln_type", "XSS"))
        param = obj.get("param", obj.get("parameter", ""))
        evidence = obj.get("evidence", obj.get("payload", obj.get("PoC", obj.get("poc", ""))))
        url = obj.get("url", obj.get("target", ""))
        severity = obj.get("severity", "high").lower()

        dedup_key = f"{url}:{param}:{evidence}"
        if dedup_key in seen:
            return None
        seen.add(dedup_key)

        if not evidence and not param:
            return None

        title = f"Dalfox: {vuln_type} on {param}" if param else f"Dalfox: {vuln_type}"
        return {
            "title": title,
            "severity": severity,
            "description": f"XSS vulnerability in parameter {param} at {url}"
            if param
            else f"XSS vulnerability at {url}",
            "evidence": str(evidence),
            "tool": "dalfox",
            "target": url,
            "timestamp": _now_iso(),
        }

    def _parse_text(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        target = "unknown"
        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            url_m = _TEXT_URL_RE.search(line_stripped)
            param_m = _TEXT_PARAM_RE.search(line_stripped)

            if _TEXT_VULN_RE.search(line_stripped) or _TEXT_POC_RE.search(line_stripped):
                url = url_m.group(1) if url_m else target
                param = param_m.group(1) if param_m else "unknown"
                poc = _TEXT_POC_RE.search(line_stripped)
                evidence = poc.group(1) if poc else line_stripped

                dedup_key = f"{url}:{param}:{evidence}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(
                    {
                        "title": f"Dalfox: Potential XSS on {param}",
                        "severity": "high",
                        "description": f"Potential XSS: parameter {param} at {url}",
                        "evidence": evidence,
                        "tool": "dalfox",
                        "target": url,
                        "timestamp": _now_iso(),
                    },
                )

            if url_m and "target" in line_stripped.lower():
                target = url_m.group(1)

        return findings
