# SPDX-License-Identifier: AGPL-3.0-or-later

"""Lynis audit output parser — extracts warnings, suggestions, and findings by severity."""

from __future__ import annotations

from . import _now_iso

import re

_WARNING_RE = re.compile(r"^\[\!\]\s*(.*)")
_SUGGESTION_RE = re.compile(r"^\[\*\]\s*(.*)")
_INFO_POS_RE = re.compile(r"^\[\+\]\s*(.*)")
_INFO_NEG_RE = re.compile(r"^\[\-\]\s*(.*)")
_TEST_RE = re.compile(r"(?:test|check|audit)[:\s]+(\S+)", re.IGNORECASE)
_SEVERITY_TAG_RE = re.compile(r"\((\d+)\)|severity[:\s]+(\w+)", re.IGNORECASE)
_SUMMARY_RE = re.compile(
    r"(?:hardening\s+index|warnings|suggestions|tests\s+performed)[:\s]+(\d+)",
    re.IGNORECASE,
)


class LynisParser:
    """Parse Lynis audit output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        target = "localhost"
        summary_data: dict[str, str] = {}

        for raw in output.splitlines():
            line_stripped = raw.strip()
            if not line_stripped:
                continue

            m = _SUMMARY_RE.search(line_stripped)
            if m:
                summary_data["lynis_summary"] = line_stripped
                continue

            if line_stripped.lower().startswith("hostname"):
                parts = line_stripped.split(":", 1)
                if len(parts) == 2:
                    target = parts[1].strip()

            m = _WARNING_RE.match(line_stripped)
            if m:
                msg = m.group(1).strip()
                test_name = "warning"
                tm = _TEST_RE.search(msg)
                if tm:
                    test_name = tm.group(1)
                key = f"warning:{test_name}:{msg[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Lynis: Warning — {test_name}",
                        "severity": "medium",
                        "description": msg,
                        "evidence": raw,
                        "tool": "lynis",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _SUGGESTION_RE.match(line_stripped)
            if m:
                msg = m.group(1).strip()
                key = f"suggestion:{msg[:80]}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": "Lynis: Suggestion",
                        "severity": "low",
                        "description": msg,
                        "evidence": raw,
                        "tool": "lynis",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _INFO_POS_RE.match(line_stripped)
            if m:
                msg = m.group(1).strip()
                sev_m = _SEVERITY_TAG_RE.search(msg)
                severity = "info"
                if sev_m:
                    num = sev_m.group(1) or sev_m.group(2)
                    try:
                        score = int(num)
                        if score >= 10:
                            severity = "high"
                        elif score >= 7:
                            severity = "medium"
                    except (ValueError, TypeError):
                        pass

                test_name = msg.split(":")[0].strip()
                key = f"info-pos:{test_name}:{msg[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Lynis: {test_name}",
                        "severity": severity,
                        "description": msg,
                        "evidence": raw,
                        "tool": "lynis",
                        "target": target,
                        "timestamp": _now_iso(),
                    })

            m = _INFO_NEG_RE.match(line_stripped)
            if m:
                msg = m.group(1).strip()
                if any(kw in msg.lower() for kw in ("vulnerable", "not found", "missing", "error", "disabled")):
                    key = f"neg:{msg[:80]}"
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "title": "Lynis: Issue detected",
                            "severity": "medium",
                            "description": msg,
                            "evidence": raw,
                            "tool": "lynis",
                            "target": target,
                            "timestamp": _now_iso(),
                        })

        if summary_data:
            for k, v in summary_data.items():
                key = f"summary:{k}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Lynis: {k.replace('_', ' ').title()}",
                        "severity": "info",
                        "description": v[:200],
                        "evidence": v[:200],
                        "tool": "lynis",
                        "target": target,
                        "timestamp": _now_iso(),
                    })

        return findings
