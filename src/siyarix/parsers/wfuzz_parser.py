# SPDX-License-Identifier: AGPL-3.0-or-later

"""WFuzz output parser — parses wfuzz fuzzer columnar output into normalized findings."""

from __future__ import annotations

from . import _now_iso

import re

_ROW_RE = re.compile(
    r"^(?P<id>\S+)\s+"
    r"Response:\s*(?P<status>\d+)\s+"
    r"Lines:\s*(?P<lines>\d+)\s+"
    r"Word:\s*(?P<words>\d+)\s+"
    r"Chars:\s*(?P<chars>\d+)\s+"
    r"(?:Request:\s*)?(?P<payload>\S+)"
)
_ID_RE = re.compile(r"^(?P<id>\d+)\s+(?P<status>\d+)\s+(?P<lines>\d+)\s+(?P<words>\d+)\s+(?P<chars>\d+)\s+(?P<payload>\S+)")
_SIMPLE_ROW_RE = re.compile(
    r"ID:\s*(?P<payload>\S+)\s+Response:\s*(?P<status>\d+)(?:\s+Size:\s*(?P<size>\d+))?",
)
_TARGET_URL_RE = re.compile(r"(?:Target|URL|url)[:\s]+(https?://\S+)", re.IGNORECASE)
_BASELINE_RE = re.compile(r"(?i)(baseline|filter|excluded|discarded)")
_SEVERITY_BY_STATUS = {
    200: "info", 201: "info", 204: "info",
    301: "low", 302: "low", 307: "low", 308: "low",
    401: "medium", 403: "medium", 404: "info",
    500: "high", 502: "high", 503: "high",
}


class WfuzzParser:
    """Parse wfuzz output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        target = "unknown"

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if _BASELINE_RE.search(line_stripped):
                continue

            tm = _TARGET_URL_RE.search(line_stripped)
            if tm:
                target = tm.group(1)
                continue

            m = _SIMPLE_ROW_RE.match(line_stripped) or _ROW_RE.match(line_stripped) or _ID_RE.match(line_stripped)
            if not m:
                continue

            if "size" in m.groupdict() and m.group("size") is not None:
                status = int(m.group("status"))
                payload = m.group("payload")
                lines_count = words_count = "0"
                chars_count = m.group("size")
            else:
                status = int(m.group("status"))
                payload = m.group("payload")
                lines_count = m.group("lines")
                words_count = m.group("words")
                chars_count = m.group("chars")

            dedup_key = f"{target}:{payload}:{status}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = _SEVERITY_BY_STATUS.get(status, "info")

            findings.append({
                "title": f"WFuzz: {payload} (HTTP {status})",
                "severity": severity,
                "description": f"Fuzzed payload {payload!r} returned HTTP {status} — lines {lines_count}, words {words_count}, chars {chars_count}",
                "evidence": f"Status: {status}, Lines: {lines_count}, Words: {words_count}, Chars: {chars_count}, Payload: {payload}",
                "tool": "wfuzz",
                "target": target,
                "timestamp": _now_iso(),
            })

        return findings
