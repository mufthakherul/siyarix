# SPDX-License-Identifier: AGPL-3.0-or-later

"""TruffleHog JSON output parser — extracts SourceMetadata, DetectorName, RawV2, and verified status."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")

_SUMMARY_RE = re.compile(
    r"(?:secrets|findings|results|total)[:\s]*(\d+)",
    re.IGNORECASE,
)


class TrufflehogParser:
    """Parse TruffleHog JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            for line in output.splitlines():
                line_stripped = line.strip()
                if not line_stripped or not _JSON_LINE_RE.match(line_stripped):
                    continue
                try:
                    data = json.loads(line_stripped)
                except json.JSONDecodeError:
                    continue
                r = self._extract(data, seen)
                if r:
                    findings.append(r)
            return findings

        if isinstance(data, list):
            for item in data:
                r = self._extract(item, seen)
                if r:
                    findings.append(r)
        else:
            r = self._extract(data, seen)
            if r:
                findings.append(r)

        summary_m = _SUMMARY_RE.search(output)
        if summary_m:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"TruffleHog: {summary_m.group(1)} secrets",
                    "severity": "info",
                    "description": f"TruffleHog detected {summary_m.group(1)} secrets",
                    "evidence": f"Total: {summary_m.group(1)}",
                    "tool": "trufflehog",
                    "target": "",
                    "timestamp": _now_iso(),
                })

        return findings

    def _extract(self, obj: dict, seen: set[str]) -> dict | None:
        detector = obj.get("DetectorName", obj.get("detector_name", "unknown"))
        verified = obj.get("Verified", obj.get("verified", False))

        source_metadata = obj.get("SourceMetadata", {}) or {}
        if isinstance(source_metadata, dict):
            data = source_metadata.get("Data", {}) or {}
        else:
            data = {}

        raw_v2 = obj.get("RawV2", obj.get("raw", obj.get("Raw", "")))
        raw = obj.get("raw", raw_v2)

        repo = ""
        file_path = ""
        line_num = 0
        for key in ("Git", "Filesystem", "S3", "GCS", "Azure"):
            md = data.get(key, {}) if isinstance(data, dict) else {}
            if isinstance(md, dict):
                repo = md.get("repository", md.get("repo", ""))  # type: ignore
                file_path = md.get("file", md.get("path", ""))  # type: ignore
                line_num = md.get("line", 0)

        if not file_path and isinstance(data, dict):
            file_path = data.get("file", data.get("path", ""))  # type: ignore

        target = file_path or repo or "unknown"

        dedup_key = f"{detector}:{target}:{line_num}"
        if dedup_key in seen:
            return None
        seen.add(dedup_key)

        severity = "high" if verified else "medium"

        description = f"Secret detected by detector '{detector}'"
        if verified:
            description += " [VERIFIED]"
        if target:
            description += f" in {target}"
        if line_num:
            description += f":{line_num}"

        return {
            "title": f"TruffleHog: {detector}" + (" (verified)" if verified else ""),
            "severity": severity,
            "description": description,
            "evidence": f"Detector: {detector}, Target: {target}, Line: {line_num}",
            "tool": "trufflehog",
            "target": target,
            "timestamp": _now_iso(),
        }
