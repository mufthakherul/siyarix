# SPDX-License-Identifier: AGPL-3.0-or-later

"""DIRB output parser --- parses web directory brute-force text output."""

from __future__ import annotations

from . import _now_iso

import json
import re
from typing import Any

_FIND_RE = re.compile(
    r"==>\s*(?P<url>\S+)\s*[<\-]+.*?(?:CODE[:\s]*(?P<code>\d+))?(?:.*?SIZE[:\s]*(?P<size>\d+))?",
    re.IGNORECASE,
)

_CODE_RE = re.compile(
    r"\+(?P<code>\d{3})\s+(?P<url>\S+)\s+",
)

_LINE_RE = re.compile(
    r"^(?P<code>\d{3})\s+(?P<size>\d+)\s+(?P<url>\S+)",
)

_BASE_RE = re.compile(
    r"BASE_URL\s*[:\s]*(?P<url>\S+)",
    re.IGNORECASE,
)

_URL_CODE_SIZE_RE = re.compile(
    r"(?P<url>https?://\S+)\s+\(CODE:(?P<code>\d+)\|SIZE:(?P<size>\d+)\)",
    re.IGNORECASE,
)

_REDIRECT_RE = re.compile(r"(?i)(?:-->|->|Location:|redirect.*to)\s*(?P<redirect>\S+)")

_STATS_RE = re.compile(r"(?i)(?:Finished|Tested|Time|Downloaded|Found|Scanned|Recursive)")

_SEVERITY_MAP: dict[int, str] = {
    200: "info",
    204: "info",
    301: "info",
    302: "info",
    307: "info",
    308: "info",
    400: "medium",
    401: "medium",
    403: "medium",
    500: "high",
}


class DirbParser:
    """Parse DIRB output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        if not output.strip():
            return []
        first_line = next((line for line in output.splitlines() if line.strip()), "")
        if first_line.lstrip().startswith("[") or first_line.lstrip().startswith("{"):
            try:
                data = json.loads(output)
                return self._parse_json(data)
            except (json.JSONDecodeError, ValueError):
                pass
        return self._parse_text(output)

    def _parse_json(self, data: Any) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        results = data if isinstance(data, list) else data.get("results", data.get("sites", [data]))
        if isinstance(results, dict):
            results = [results]
        for r in results:
            if not isinstance(r, dict):
                continue
            url = r.get("url", r.get("URL", ""))
            code = int(r.get("code", r.get("status", 0)))
            size = r.get("size", r.get("content_length", ""))
            redirect = r.get("redirect", r.get("location", ""))
            dedup_key = f"{url}:{code}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            severity = _SEVERITY_MAP.get(code, "info")
            desc = f"DIRB discovered {url} returning HTTP {code}"
            if size:
                desc += f" (size: {size})"
            if redirect:
                desc += f" (redirect: {redirect})"
            findings.append(
                {
                    "title": f"DIRB discovered: {url} (HTTP {code})",
                    "severity": severity,
                    "description": desc,
                    "evidence": f"{url} -> HTTP {code}" + (f" -> {redirect}" if redirect else ""),
                    "tool": "dirb",
                    "target": url.rstrip("/").rsplit("/", 1)[0] if "/" in url.rstrip("/") else url,
                    "timestamp": _now_iso(),
                }
            )
        return findings

    def _parse_text(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        base_url = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if _STATS_RE.match(line):
                continue

            m = _BASE_RE.search(line)
            if m:
                base_url = m.group("url")
                continue

            redirect_m = _REDIRECT_RE.search(line)
            if redirect_m:
                for f in reversed(findings):
                    if "redirect" not in f["evidence"]:
                        f["evidence"] += f" -> {redirect_m.group('redirect')}"
                        f["description"] += f" (redirect: {redirect_m.group('redirect')})"
                        break
                continue

            m = _URL_CODE_SIZE_RE.match(line)
            if m:
                code = int(m.group("code"))
                url = m.group("url")
                size = m.group("size")
                dedup_key = f"{url}:{code}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _SEVERITY_MAP.get(code, "info")
                findings.append(
                    {
                        "title": f"DIRB discovered: {url} (HTTP {code})",
                        "severity": severity,
                        "description": f"DIRB discovered {url} returning HTTP {code} (size: {size})",
                        "evidence": f"{url} -> HTTP {code}",
                        "tool": "dirb",
                        "target": url.rstrip("/").rsplit("/", 1)[0]
                        if "/" in url.rstrip("/")
                        else url,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            m = _LINE_RE.match(line)
            if m:
                code = int(m.group("code"))
                url = m.group("url")
                size = m.group("size")
                dedup_key = f"{url}:{code}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _SEVERITY_MAP.get(code, "info")
                target = base_url if base_url != "unknown" else url
                full_url = (
                    f"{base_url.rstrip('/')}/{url.lstrip('/')}" if base_url != "unknown" else url
                )
                findings.append(
                    {
                        "title": f"DIRB discovered: {url} (HTTP {code})",
                        "severity": severity,
                        "description": f"DIRB discovered {url} returning HTTP {code} (size: {size})",
                        "evidence": full_url + f" -> HTTP {code}",
                        "tool": "dirb",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            m = _CODE_RE.match(line)
            if m:
                code = int(m.group("code"))
                url = m.group("url")
                dedup_key = f"{url}:{code}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _SEVERITY_MAP.get(code, "info")
                findings.append(
                    {
                        "title": f"DIRB discovered: {url} (HTTP {code})",
                        "severity": severity,
                        "description": f"DIRB discovered {url} returning HTTP {code}",
                        "evidence": url,
                        "tool": "dirb",
                        "target": base_url if base_url != "unknown" else "unknown",
                        "timestamp": _now_iso(),
                    }
                )
                continue

            m = _FIND_RE.search(line)
            if m:
                url = m.group("url")
                code = int(m.group("code")) if m.group("code") else 0
                size = m.group("size") or "?"
                dedup_key = f"{url}:{code}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _SEVERITY_MAP.get(code, "info")
                findings.append(
                    {
                        "title": f"DIRB discovered: {url} (HTTP {code})"
                        if code
                        else f"DIRB discovered: {url}",
                        "severity": severity,
                        "description": f"DIRB discovered {url} (size: {size})",
                        "evidence": url,
                        "tool": "dirb",
                        "target": base_url if base_url != "unknown" else "unknown",
                        "timestamp": _now_iso(),
                    }
                )

        return findings
