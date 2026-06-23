# SPDX-License-Identifier: AGPL-3.0-or-later

"""S3Scanner bucket enumeration output parser — parses JSON/text results."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")
_BUCKET_RE = re.compile(
    r"(?P<bucket>[a-zA-Z0-9.\-]+)\s*(?:::\s*)?(?P<region>\S+)?\s*(?P<access>OPEN|CLOSED|AUTH|READ|LIST|WRITE)?",
    re.IGNORECASE,
)

_SUMMARY_RE = re.compile(
    r"(?:buckets?|found|total|scanned)[:\s]*(\d+)",
    re.IGNORECASE,
)


class S3scannerParser:
    """Parse s3scanner output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        summary_m = _SUMMARY_RE.search(output)
        summary_count = summary_m.group(1) if summary_m else None

        if _JSON_RE.match(output):
            try:
                data = json.loads(output)
                if isinstance(data, list):
                    for entry in data:
                        bucket = entry.get("bucket", entry.get("name", "unknown"))
                        region = entry.get("region", entry.get("Bucket_Region", ""))
                        exists = entry.get("exists", entry.get("Exists", True))
                        accessible = entry.get("accessible", entry.get("Accessable", False))
                        acl = entry.get("acl", entry.get("permission", ""))

                        if not exists:
                            continue

                        key = f"bucket:{bucket}"
                        if key in seen:
                            continue
                        seen.add(key)

                        severity = "info"
                        if accessible:
                            severity = "high" if "WRITE" in str(acl).upper() else "medium"

                        findings.append(
                            {
                                "title": f"S3 bucket: {bucket}",
                                "severity": severity,
                                "description": f"s3scanner discovered bucket {bucket}"
                                + (f" in {region}" if region else "")
                                + (" (ACCESSIBLE)" if accessible else ""),
                                "evidence": f"Bucket: {bucket} | Region: {region} | ACL: {acl}",
                                "tool": "s3scanner",
                                "target": bucket,
                                "timestamp": _now_iso(),
                            },
                        )
            except json.JSONDecodeError:
                pass

        for raw in output.splitlines():
            line = raw.strip()
            if not line or _JSON_RE.match(output):
                continue
            m = _BUCKET_RE.match(line)
            if m:
                bucket = m.group("bucket")
                region = m.group("region") or ""
                access = m.group("access") or ""
                key = f"bucket:{bucket}"
                if key in seen:
                    continue
                seen.add(key)
                severity = (
                    "high"
                    if access and access.upper() in ("OPEN", "WRITE", "LIST", "READ")
                    else "info"
                )
                findings.append(
                    {
                        "title": f"S3 bucket: {bucket}",
                        "severity": severity,
                        "description": f"s3scanner discovered bucket {bucket}"
                        + (f" [Region: {region}]" if region else "")
                        + (f" ({access})" if access else ""),
                        "evidence": raw,
                        "tool": "s3scanner",
                        "target": bucket,
                        "timestamp": _now_iso(),
                    },
                )

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"s3scanner: {summary_count} buckets",
                        "severity": "info",
                        "description": f"s3scanner found {summary_count} buckets",
                        "evidence": f"Total: {summary_count}",
                        "tool": "s3scanner",
                        "target": "",
                        "timestamp": _now_iso(),
                    },
                )

        return findings
