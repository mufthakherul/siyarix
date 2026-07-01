# SPDX-License-Identifier: AGPL-3.0-or-later

"""Mimikatz output parser — extracts credentials from logonpasswords, DCSync, golden ticket, and sekurlsa output."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_WDIGEST_RE = re.compile(r"wdigest", re.IGNORECASE)
_KERBEROS_RE = re.compile(r"kerberos", re.IGNORECASE)
_USERNAME_FIELD_RE = re.compile(r"\*\s*Username\s*:\s*(.+)", re.IGNORECASE)
_DOMAIN_FIELD_RE = re.compile(r"\*\s*Domain\s*:\s*(.+)", re.IGNORECASE)
_PASSWORD_FIELD_RE = re.compile(r"\*\s*Password\s*:\s*(.+)", re.IGNORECASE)
_NTLM_FIELD_RE = re.compile(r"\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})")
_LOGPON_RE = re.compile(r"sekurlsa::logonpasswords", re.IGNORECASE)
_DCSYNC_RE = re.compile(r"lsadump::dcsync", re.IGNORECASE)
_GOLDEN_RE = re.compile(r"kerberos::golden", re.IGNORECASE)
_TICKET_RE = re.compile(r"(?:\[ticket\]|Ticket|\.kirbi)", re.IGNORECASE)
_MSV_CREDS_RE = re.compile(r"msv\s*\[", re.IGNORECASE)

_JSON_RE = re.compile(r"^\s*[{\[]")


class MimikatzParser:
    """Parse mimikatz output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                import json

                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    user = item.get("username", item.get("user", ""))
                    domain = item.get("domain", "")
                    ntlm = item.get("ntlm", item.get("NTLM", ""))
                    password = item.get("password", "")
                    if user and domain:
                        dedup_key = f"{user}|{domain}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        if ntlm:
                            findings.append(
                                {
                                    "title": f"Mimikatz: credential found for {user}",
                                    "severity": "critical",
                                    "description": f"User: {user}, Domain: {domain}, NTLM: {ntlm}",
                                    "evidence": json.dumps(item),
                                    "tool": "mimikatz",
                                    "target": domain,
                                    "timestamp": _now_iso(),
                                },
                            )
                        if password and "(null)" not in password:
                            findings.append(
                                {
                                    "title": f"Mimikatz: plaintext password for {user}",
                                    "severity": "critical",
                                    "description": f"User: {user}, Domain: {domain}, Password: {password}",
                                    "evidence": json.dumps(item),
                                    "tool": "mimikatz",
                                    "target": domain,
                                    "timestamp": _now_iso(),
                                },
                            )
                return findings
            except json.JSONDecodeError:
                pass

        lines = output.splitlines()
        current_section = ""
        target = "unknown"

        current_user = ""
        current_domain = ""
        current_password = ""
        current_ntlm = ""

        for line in lines:
            line_stripped = line.strip()

            if _LOGPON_RE.search(line_stripped):
                findings.append(
                    {
                        "title": "Mimikatz: sekurlsa::logonpasswords executed",
                        "severity": "critical",
                        "description": "Mimikatz ran sekurlsa::logonpasswords — credential dumping detected",
                        "evidence": line_stripped,
                        "tool": "mimikatz",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _DCSYNC_RE.search(line_stripped):
                findings.append(
                    {
                        "title": "Mimikatz: lsadump::dcsync executed",
                        "severity": "critical",
                        "description": "Mimikatz ran lsadump::dcsync — domain credential replication detected",
                        "evidence": line_stripped,
                        "tool": "mimikatz",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _GOLDEN_RE.search(line_stripped):
                findings.append(
                    {
                        "title": "Mimikatz: kerberos::golden executed",
                        "severity": "critical",
                        "description": "Mimikatz golden ticket creation detected",
                        "evidence": line_stripped,
                        "tool": "mimikatz",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _TICKET_RE.search(line_stripped):
                findings.append(
                    {
                        "title": "Mimikatz: Kerberos ticket extracted",
                        "severity": "high",
                        "description": "Kerberos ticket (.kirbi) extracted from memory or disk",
                        "evidence": line_stripped,
                        "tool": "mimikatz",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            if _MSV_CREDS_RE.search(line_stripped):
                current_section = "msv"
                continue

            if _WDIGEST_RE.search(line_stripped) and ":" not in line_stripped:
                current_section = "wdigest"
                continue

            if _KERBEROS_RE.search(line_stripped) and ":" not in line_stripped:
                current_section = "kerberos"
                continue

            if "Username" in line_stripped and "*" in line_stripped:
                current_user = (
                    _USERNAME_FIELD_RE.sub(r"\1", line_stripped)
                    if _USERNAME_FIELD_RE.search(line_stripped)
                    else ""
                )
                continue

            if "Domain" in line_stripped and "*" in line_stripped:
                current_domain = (
                    _DOMAIN_FIELD_RE.sub(r"\1", line_stripped)
                    if _DOMAIN_FIELD_RE.search(line_stripped)
                    else ""
                )
                continue

            if "NTLM" in line_stripped and "*" in line_stripped:
                ntlm_m = _NTLM_FIELD_RE.search(line_stripped)
                if ntlm_m:
                    current_ntlm = ntlm_m.group(1)
                    dedup_key = f"{current_user}|{current_domain}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        title = f"Mimikatz: {current_section.upper()} credential found"
                        description = f"User: {current_user}, Domain: {current_domain}"
                        if current_ntlm:
                            description += f", NTLM hash: {current_ntlm}"
                        findings.append(
                            {
                                "title": title,
                                "severity": "critical",
                                "description": description,
                                "evidence": f"User: {current_user} Domain: {current_domain} NTLM: {current_ntlm} Section: {current_section}",
                                "tool": "mimikatz",
                                "target": target,
                                "timestamp": _now_iso(),
                            },
                        )
                    current_user = ""
                    current_domain = ""
                    current_ntlm = ""
                continue

            if "Password" in line_stripped and "*" in line_stripped:
                pw_m = _PASSWORD_FIELD_RE.search(line_stripped)
                if pw_m:
                    current_password = pw_m.group(1).strip()
                    if current_password and "(null)" not in current_password:
                        dedup_key = f"{current_user}|{current_domain}|{current_password[:16]}"
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            findings.append(
                                {
                                    "title": f"Mimikatz: {current_section.upper()} plaintext password",
                                    "severity": "critical",
                                    "description": f"User: {current_user}, Domain: {current_domain}, Password: {current_password}",
                                    "evidence": f"User: {current_user} Domain: {current_domain} Password: {current_password} Section: {current_section}",
                                    "tool": "mimikatz",
                                    "target": target,
                                    "timestamp": _now_iso(),
                                },
                            )

        return findings
