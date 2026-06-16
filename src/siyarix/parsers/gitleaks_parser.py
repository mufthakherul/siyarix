# SPDX-License-Identifier: AGPL-3.0-or-later

"""Gitleaks JSON output parser — extracts secrets, rule IDs, file paths, and entropy."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")

_SUMMARY_RE = re.compile(
    r"(?:leaks|secrets|findings|audit)[:\s]*(\d+)",
    re.IGNORECASE,
)


class GitleaksParser:
    """Parse Gitleaks JSON output (one JSON object per line) into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped or not _JSON_LINE_RE.match(line_stripped):
                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            if isinstance(obj, list):
                for item in obj:
                    r = self._extract(item, seen)
                    if r:
                        findings.append(r)
            else:
                r = self._extract(obj, seen)
                if r:
                    findings.append(r)

        summary_m = _SUMMARY_RE.search(output)
        if summary_m:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"Gitleaks: {summary_m.group(1)} secrets",
                        "severity": "info",
                        "description": f"Gitleaks detected {summary_m.group(1)} secrets",
                        "evidence": f"Total: {summary_m.group(1)}",
                        "tool": "gitleaks",
                        "target": "",
                        "timestamp": _now_iso(),
                    }
                )

        return findings

    def _extract(self, obj: dict, seen: set[str]) -> dict | None:
        file_name = obj.get("file", obj.get("fileName", ""))
        rule_id = obj.get("ruleID", obj.get("rule_id", obj.get("RuleID", "unknown")))
        start_line = obj.get("startLine", obj.get("start-line", obj.get("line", 0)))
        secret = obj.get("secret", "")
        entropy = obj.get("entropy", obj.get("Entropy", ""))

        if not rule_id or rule_id == "unknown":
            return None

        key = f"{file_name}:{rule_id}:{start_line}"
        if key in seen:
            return None
        seen.add(key)

        severity = "high"
        if "entropy" in str(entropy).lower():
            try:
                ent_val = float(entropy) if entropy else 0
                if ent_val > 4.5:
                    severity = "critical"
                elif ent_val > 3.5:
                    severity = "high"
                else:
                    severity = "medium"
            except (ValueError, TypeError):
                pass

        if "private-key" in rule_id.lower() or "ssh" in rule_id.lower():
            severity = "critical"

        description = f"Secret detected in {file_name}:{start_line}"
        if rule_id:
            description += f" [{rule_id}]"

        return {
            "title": f"Gitleaks: {rule_id}",
            "severity": severity,
            "description": description,
            "evidence": f"{file_name}:{start_line} | secret: {secret[:60] if secret else '(redacted)'}",
            "tool": "gitleaks",
            "target": file_name,
            "timestamp": _now_iso(),
        }
