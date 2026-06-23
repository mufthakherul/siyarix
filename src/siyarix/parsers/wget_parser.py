# SPDX-License-Identifier: AGPL-3.0-or-later

"""wget output parser --- parses wget download/transfer output, --spider mode, and recursive results."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_ERROR_RE = re.compile(
    r"(?i)(?:ERROR|Failed|unable to resolve|cannot connect|connection refused|timeout|name or service not known)",
)

_HTTP_ERROR_RE = re.compile(
    r"(?i)(?P<code>404|403|500|502|503|401|400)\s+(?P<text>Not Found|Forbidden|Server Error|Bad Gateway|Service Unavailable|Unauthorized|Bad Request)",
)

_URL_RE = re.compile(
    r"(?:URL|--\d{4}-\d{2}-\d{2}|http|https)[\s:]*(?P<url>https?://\S+)",
    re.IGNORECASE,
)

_DOWNLOAD_RE = re.compile(
    r"(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\S*\s+(?P<url>\S+)",
)

_SIZE_RE = re.compile(
    r"(?P<size>[\d.]+[KMG]?)\s+[\d.]+\s[KMGb]+\/s\s+\[{1,2}\s*\]",
)

_LENGTH_RE = re.compile(
    r"Length:\s*(?P<bytes>\d+)\s*\[(?P<type>\w+)\]",
)

_SAVED_RE = re.compile(
    r"'(?P<file>.+?)'\s+saved",
)

_SPIDER_RE = re.compile(
    r"(?i)(?:Spider mode enabled|Remote file exists|Remote file does not exist|URL:.*\d+)",
)

_RECURSIVE_RE = re.compile(
    r"(?i)(?:Entering\s+(?P<dir>\S+)|(?P<downloaded>\d+) files? downloaded|Found \d+ links?)",
)

_STATUS_LINE_RE = re.compile(
    r"(?i)^HTTP request sent, awaiting response\.\.\.\s*(?P<code>\d+)\s+(?P<text>.+)$",
)

_STATUS_SEVERITY: dict[str, str] = {
    "200": "info",
    "204": "info",
    "301": "info",
    "302": "info",
    "303": "info",
    "307": "info",
    "308": "info",
    "400": "medium",
    "401": "medium",
    "403": "medium",
    "404": "low",
    "500": "high",
    "502": "high",
    "503": "high",
}


class WgetParser:
    """Parse wget output into normalized finding dictionaries.

    Handles standard downloads, recursive downloads, --spider mode,
    and error detection with status-code-based severity.
    """

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output.strip():
            return []
        first_line = next((line for line in output.splitlines() if line.strip()), "")
        stripped = first_line.lstrip()

        if stripped.startswith(("[", "{")):
            try:
                data = json.loads(output)
                return self._parse_json(data)
            except (json.JSONDecodeError, ValueError):
                pass
        return self._parse_text(output)

    def _parse_json(self, data: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", item.get("URL", "unknown")))
            status_code = str(item.get("status_code", item.get("status", "")))
            size = item.get("size", item.get("length", ""))
            filename = item.get("filename", item.get("file", ""))
            item.get("error", "")

            dedup_key = f"{url}:{status_code}:{filename}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = _STATUS_SEVERITY.get(status_code, "info") if status_code else "info"
            title_parts = []
            desc_parts = [f"wget request to {url}"]
            if status_code:
                title_parts.append(f"HTTP {status_code}")
                desc_parts.append(f"returned {status_code}")
            if filename:
                title_parts.append(filename)
                desc_parts.append(f"file: {filename}")
            if size:
                desc_parts.append(f"size: {size}b")
            title = "wget: " + (" ".join(title_parts) if title_parts else url)
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "description": " | ".join(desc_parts),
                    "evidence": json.dumps(item, default=str),
                    "tool": "wget",
                    "target": url,
                    "timestamp": _now_iso(),
                },
            )
        return findings

    def _parse_text(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        current_url = "unknown"
        spider_mode = False

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if _SPIDER_RE.search(line):
                spider_mode = True

            m = _URL_RE.search(line)
            if m:
                current_url = m.group("url").strip()
                continue

            m = _DOWNLOAD_RE.search(line)
            if m:
                current_url = m.group("url").strip()
                dedup_key = f"download:{current_url}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": f"wget download started: {current_url}",
                            "severity": "info",
                            "description": f"wget started downloading {current_url}",
                            "evidence": f"URL: {current_url}",
                            "tool": "wget",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            sl = _STATUS_LINE_RE.match(line)
            if sl:
                code = sl.group("code")
                text = sl.group("text")
                dedup_key = f"status:{current_url}:{code}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = _STATUS_SEVERITY.get(code, "info")
                findings.append(
                    {
                        "title": f"wget HTTP {code} {text}"[:120],
                        "severity": severity,
                        "description": f"wget request to {current_url} returned HTTP {code} {text}",
                        "evidence": f"HTTP {code} {text}",
                        "tool": "wget",
                        "target": current_url,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _ERROR_RE.search(line):
                error_text = line.strip()
                dedup_key = f"error:{current_url}:{error_text[:60]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = "medium"
                http_m = _HTTP_ERROR_RE.search(line)
                if http_m:
                    code = http_m.group("code")
                    severity = _STATUS_SEVERITY.get(code, "medium")
                findings.append(
                    {
                        "title": f"wget error: {error_text[:60]}",
                        "severity": severity,
                        "description": f"wget encountered an error for {current_url}: {error_text}",
                        "evidence": error_text,
                        "tool": "wget",
                        "target": current_url,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            rec_m = _RECURSIVE_RE.search(line)
            if rec_m:
                downloaded = rec_m.group("downloaded")
                if downloaded:
                    dedup_key = f"recursive:{current_url}:{downloaded}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append(
                            {
                                "title": f"wget recursive download complete ({downloaded} files)",
                                "severity": "info",
                                "description": f"wget recursively downloaded {downloaded} files from {current_url}",
                                "evidence": f"files: {downloaded}",
                                "tool": "wget",
                                "target": current_url,
                                "timestamp": _now_iso(),
                            },
                        )
                continue

            m = _LENGTH_RE.search(line)
            if m:
                dedup_key = f"length:{current_url}:{m.group('bytes')}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": f"wget resource size: {m.group('bytes')} bytes",
                            "severity": "info",
                            "description": f"wget determined resource at {current_url} is {m.group('bytes')} bytes ({m.group('type')})",
                            "evidence": line.strip(),
                            "tool": "wget",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _SAVED_RE.search(line)
            if m:
                dedup_key = f"saved:{current_url}:{m.group('file')}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": f"wget downloaded: {m.group('file')}",
                            "severity": "info",
                            "description": f"wget successfully downloaded {m.group('file')} from {current_url}",
                            "evidence": f"file: {m.group('file')}",
                            "tool": "wget",
                            "target": current_url,
                            "timestamp": _now_iso(),
                        },
                    )

        if spider_mode and not findings:
            findings.append(
                {
                    "title": "wget spider scan completed",
                    "severity": "info",
                    "description": f"wget spider mode scan of {current_url} completed",
                    "evidence": f"spider: {current_url}",
                    "tool": "wget",
                    "target": current_url,
                    "timestamp": _now_iso(),
                },
            )

        return findings
