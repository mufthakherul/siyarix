"""Nuclei output parser — parses nuclei JSONL output."""

from __future__ import annotations

from . import _now_iso

import json

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

class NucleiParser:
    """Parses nuclei JSONL output (one JSON object per line) into finding dicts."""

    def parse(self, jsonl_output: str) -> list[dict]:
        """Parse nuclei JSONL *output* and return a list of finding dicts."""
        findings: list[dict] = []

        for line in jsonl_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = record.get("info", {})
            severity_raw = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(severity_raw, "info")

            template_id = record.get("template-id", "unknown")
            name = info.get("name", template_id)
            matched_at = record.get("matched-at", record.get("host", "unknown"))
            description = info.get("description", "")
            timestamp = record.get("timestamp", _now_iso())

            # Build evidence string
            evidence_parts = [matched_at]
            matcher_name = record.get("matcher-name", "")
            if matcher_name:
                evidence_parts.append(f"matcher: {matcher_name}")
            extracted = record.get("extracted-results", [])
            if extracted:
                evidence_parts.append(
                    f"extracted: {', '.join(str(e) for e in extracted[:3])}"
                )

            findings.append(
                {
                    "title": f"[{template_id}] {name}",
                    "severity": severity,
                    "description": description
                    or f"Nuclei template {template_id} matched at {matched_at}",
                    "evidence": " | ".join(evidence_parts),
                    "tool": "nuclei",
                    "target": record.get("host", matched_at),
                    "timestamp": timestamp,
                }
            )

        return findings
