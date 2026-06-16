# SPDX-License-Identifier: AGPL-3.0-or-later

"""recon-ng output parser — parses recon-ng framework result output."""

from __future__ import annotations

from . import _now_iso

import re
import json

_TABLE_RE = re.compile(
    r"\|\s*(?P<row>\d+)\s*\|.*\|",
)

_KEYVAL_RE = re.compile(
    r"\s+(?P<key>\w[\w\s]*?)\s*(?:\||:)\s*(?P<value>\S.*)",
)

_JSON_LINE_RE = re.compile(r"^\s*\{.*\}\s*$")

_FOUND_RE = re.compile(
    r"\[\+\]\s+'([^']+)'\s+found",
    re.IGNORECASE,
)

_MODULE_RE = re.compile(
    r"\[module\]\s*(?P<module>\S+)",
    re.IGNORECASE,
)

_TARGET_KEYS = {
    "host",
    "ip_address",
    "domain",
    "ip",
    "email",
    "name",
    "first_name",
    "last_name",
    "username",
    "contact",
    "url",
}


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.splitlines()[0].strip().startswith(("[", "{"))


class ReconNgParser:
    """Parse recon-ng output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        if _looks_like_json(output):
            try:
                return self._parse_json(output)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        return self._parse_text(output)

    def _parse_json(self, json_str: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        data = json.loads(json_str)
        records = data if isinstance(data, list) else [data]

        for record in records:
            for k, v in record.items():
                target = str(v) if k in _TARGET_KEYS else "unknown"
                dedup_key = f"{target}:{k}:{v}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"recon-ng {k}: {str(v)[:80]}",
                        "severity": "info",
                        "description": f"recon-ng data point: {k} = {v}",
                        "evidence": json.dumps({k: v}) if not isinstance(v, str) else str(v),
                        "tool": "recon-ng",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
        return findings

    def _parse_text(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        headers: list[str] = []
        current_module = ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            mm = _MODULE_RE.match(line)
            if mm:
                current_module = mm.group("module")

            if line.startswith("+") and line.endswith("+"):
                continue

            if line.startswith("|") and line.endswith("|"):
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if not headers:
                    headers = cells
                elif len(cells) > 1 and cells[0].isdigit():
                    row_data = dict(zip(headers[1:], cells[1:]))
                    target = "unknown"
                    for tk in _TARGET_KEYS:
                        if tk in row_data and row_data[tk]:
                            target = row_data[tk]
                            break
                    dedup_key = f"{target}:" + ";".join(f"{k}={v}" for k, v in row_data.items())
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    desc_parts = [f"{k}={v}" for k, v in row_data.items()]
                    findings.append(
                        {
                            "title": f"recon-ng result: {target}",
                            "severity": "info",
                            "description": f"recon-ng row data: {'; '.join(desc_parts)}"
                            + (f" [module: {current_module}]" if current_module else ""),
                            "evidence": " | ".join(desc_parts),
                            "tool": "recon-ng",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            fm = _FOUND_RE.search(line)
            if fm:
                value = fm.group(1)
                dedup_key = f"found:{value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                target = "unknown"
                if "@" in value:
                    target = value.split("@")[1]
                findings.append(
                    {
                        "title": f"recon-ng found: {value}",
                        "severity": "info",
                        "description": f"recon-ng discovered: {value}",
                        "evidence": line,
                        "tool": "recon-ng",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            kv = _KEYVAL_RE.match(line)
            if kv:
                key = kv.group("key").strip()
                value = kv.group("value").strip()
                target = value if key in _TARGET_KEYS else "unknown"
                dedup_key = f"{target}:{key}:{value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"recon-ng {key}: {value[:60]}",
                        "severity": "info",
                        "description": f"recon-ng key-value: {key} = {value}"
                        + (f" [module: {current_module}]" if current_module else ""),
                        "evidence": f"{key}: {value}",
                        "tool": "recon-ng",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
