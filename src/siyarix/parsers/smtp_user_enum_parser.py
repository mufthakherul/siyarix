# SPDX-License-Identifier: AGPL-3.0-or-later

"""smtp-user-enum output parser — parses SMTP user enumeration results (VRFY, EXPN, RCPT TO)."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_EXISTS_RE = re.compile(
    r"(?:exists|found|valid|user|accepted|OK)[\s:]+(\S+)",
    re.IGNORECASE,
)

_NOT_EXISTS_RE = re.compile(
    r"(?:not\s+found|invalid|rejected|denied|does\s+not\s+exist|no\s+such)",
    re.IGNORECASE,
)

_METHOD_RE = re.compile(
    r"(?:mode|method|type|check)[:\s]+(\S+)",
    re.IGNORECASE,
)

_HOST_RE = re.compile(
    r"(?:host|server|target|IP|domain)[:\s]+(\S+)",
    re.IGNORECASE,
)

_PORT_RE = re.compile(
    r"(?:port)[:\s]+(\d+)",
    re.IGNORECASE,
)

_USER_BY_NAME_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<status>exists|found|valid|not\s+found|invalid)",
    re.IGNORECASE,
)

_VRFY_RE = re.compile(
    r"(?:VRFY|vrfy|verify)[:\s]+(\S+)",
    re.IGNORECASE,
)

_EXPN_RE = re.compile(
    r"(?:EXPN|expn|expand)[:\s]+(\S+)",
    re.IGNORECASE,
)

_RCPT_RE = re.compile(
    r"(?:RCPT|rcpt|RCPT\s+TO)[:\s]+(\S+)",
    re.IGNORECASE,
)

_BANNER_RE = re.compile(
    r"(?:220|banner|connected|connecting)[\s:]*(\S+)",
    re.IGNORECASE,
)

_SMTP_RESPONSE_RE = re.compile(
    r"^(\d{3})\s+(.+)$",
)

_RESULTS_SUMMARY_RE = re.compile(
    r"(\d+)\s+user\w*\s+(?:exist|found|valid)",
    re.IGNORECASE,
)

_JSON_RE = re.compile(r"^\s*[{\[]")


class SmtpUserEnumParser:
    """Parse smtp-user-enum output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen_users: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    user = item.get("user", item.get("username", ""))
                    exists = item.get("exists", item.get("found", item.get("status", "")))
                    method = item.get("method", item.get("type", "VRFY"))
                    host = item.get("host", item.get("server", "unknown"))
                    port = item.get("port", 25)
                    if user and exists in (True, "true", "True", "exists", "found", "valid"):
                        if user in seen_users:
                            continue
                        seen_users.add(user)
                        findings.append(
                            {
                                "title": f"SMTP user exists: {user}",
                                "severity": "medium",
                                "description": f"smtp-user-enum confirmed user {user} exists on {host}:{port} via {method}",
                                "evidence": json.dumps(item),
                                "tool": "smtp-user-enum",
                                "target": host,
                                "timestamp": _now_iso(),
                            },
                        )
                    elif user and exists in (
                        False,
                        "false",
                        "False",
                        "not found",
                        "invalid",
                        "rejected",
                    ):
                        findings.append(
                            {
                                "title": f"SMTP user does not exist: {user}",
                                "severity": "info",
                                "description": f"smtp-user-enum confirmed user {user} does not exist on {host}:{port} via {method}",
                                "evidence": json.dumps(item),
                                "tool": "smtp-user-enum",
                                "target": host,
                                "timestamp": _now_iso(),
                            },
                        )
                return findings
            except json.JSONDecodeError:
                pass

        host = "unknown"
        port = 25
        method = "VRFY"
        banner_found = False
        in_user_list = False

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                in_user_list = False
                continue

            m = _HOST_RE.search(line)
            if m and host == "unknown":
                host = m.group(1).strip()
                continue

            m = _PORT_RE.search(line)
            if m:
                port = int(m.group(1))
                continue

            m = _METHOD_RE.search(line)
            if m:
                method = m.group(1).strip().upper()
                continue

            bm = _BANNER_RE.match(line)
            if bm and "banner" in line.lower():
                banner_found = True
                findings.append(
                    {
                        "title": "SMTP banner received",
                        "severity": "info",
                        "description": f"SMTP server banner: {line}",
                        "evidence": line,
                        "tool": "smtp-user-enum",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            sr = _SMTP_RESPONSE_RE.match(line)
            if sr:
                code = sr.group(1)
                smtp_msg = sr.group(2)
                if code == "220" and not banner_found:
                    banner_found = True
                    findings.append(
                        {
                            "title": "SMTP connection established",
                            "severity": "info",
                            "description": f"SMTP server responded with code {code}: {smtp_msg}",
                            "evidence": line,
                            "tool": "smtp-user-enum",
                            "target": host,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            vrfy = _VRFY_RE.search(line)
            expn = _EXPN_RE.search(line)
            rcpt = _RCPT_RE.search(line)

            if vrfy:
                method = "VRFY"
            elif expn:
                method = "EXPN"
            elif rcpt:
                method = "RCPT TO"

            if line.lower().startswith("found users") or line.lower().startswith("users found"):
                in_user_list = True
                continue

            if in_user_list and not any(
                r.search(line)
                for r in [
                    _EXISTS_RE,
                    _NOT_EXISTS_RE,
                    _METHOD_RE,
                    _HOST_RE,
                    _PORT_RE,
                    _BANNER_RE,
                    _SMTP_RESPONSE_RE,
                    _VRFY_RE,
                    _EXPN_RE,
                    _RCPT_RE,
                    _USER_BY_NAME_RE,
                    _RESULTS_SUMMARY_RE,
                ]
            ):
                if line not in seen_users:
                    seen_users.add(line)
                    findings.append(
                        {
                            "title": f"SMTP user exists: {line}",
                            "severity": "medium",
                            "description": f"smtp-user-enum confirmed user {line} exists on {host}:{port} via {method}",
                            "evidence": f"host: {host} port: {port} method: {method} user: {line} status: exists",
                            "tool": "smtp-user-enum",
                            "target": host,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _USER_BY_NAME_RE.match(line)
            if m:
                user = m.group("user")
                status = m.group("status").lower()
                if status in ("exists", "found", "valid"):
                    if user not in seen_users:
                        seen_users.add(user)
                        findings.append(
                            {
                                "title": f"SMTP user exists: {user}",
                                "severity": "medium",
                                "description": f"smtp-user-enum confirmed user {user} exists on {host}:{port} via {method}",
                                "evidence": f"host: {host} port: {port} method: {method} user: {user} status: exists",
                                "tool": "smtp-user-enum",
                                "target": host,
                                "timestamp": _now_iso(),
                            },
                        )
                elif user not in seen_users:
                    findings.append(
                        {
                            "title": f"SMTP user does not exist: {user}",
                            "severity": "info",
                            "description": f"smtp-user-enum confirmed user {user} does not exist on {host}:{port} via {method}",
                            "evidence": f"host: {host} port: {port} method: {method} user: {user} status: {status}",
                            "tool": "smtp-user-enum",
                            "target": host,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            em = _EXISTS_RE.search(line)
            if em and not _NOT_EXISTS_RE.search(line):
                user = em.group(1).strip()
                if user not in seen_users and len(user) > 1:
                    seen_users.add(user)
                    findings.append(
                        {
                            "title": f"SMTP user exists: {user}",
                            "severity": "medium",
                            "description": f"smtp-user-enum confirmed user {user} exists on {host}:{port} via {method}",
                            "evidence": f"host: {host} port: {port} method: {method} user: {user} status: exists",
                            "tool": "smtp-user-enum",
                            "target": host,
                            "timestamp": _now_iso(),
                        },
                    )

            rs = _RESULTS_SUMMARY_RE.search(line)
            if rs:
                findings.append(
                    {
                        "title": "SMTP user enumeration summary",
                        "severity": "info",
                        "description": f"smtp-user-enum found {rs.group(1)} valid users on {host}:{port}",
                        "evidence": line,
                        "tool": "smtp-user-enum",
                        "target": host,
                        "timestamp": _now_iso(),
                    },
                )

        if not seen_users:
            findings.append(
                {
                    "title": "SMTP user enumeration complete",
                    "severity": "info",
                    "description": f"smtp-user-enum completed on {host}:{port} via {method} — no confirmed users found",
                    "evidence": f"host: {host} port: {port} method: {method}",
                    "tool": "smtp-user-enum",
                    "target": host,
                    "timestamp": _now_iso(),
                },
            )

        return findings
