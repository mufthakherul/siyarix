"""Impacket output parser — Windows protocol abuse results."""

from __future__ import annotations

import re
from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


_SAMBA_CRED_RE = re.compile(r"(\S+)\s*:\s*(\d+)\s*:\s*(\S+)\s*:\s*(\S+)\s*:::?")


class ImpacketParser:
    """Parse impacket output into normalized findings."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lowered = line.lower()
            sm = _SAMBA_CRED_RE.search(line)
            if sm and len(sm.groups()) >= 4:
                findings.append(
                    {
                        "title": "Impacket extracted credentials",
                        "severity": "critical",
                        "description": f"Credentials extracted for {sm.group(1)}",
                        "evidence": line,
                        "tool": "impacket",
                        "target": sm.group(1),
                        "timestamp": _now_iso(),
                    }
                )
            elif "krb5" in lowered or "kerberos" in lowered:
                findings.append(
                    {
                        "title": "Impacket Kerberos attack",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "impacket",
                        "target": "domain",
                        "timestamp": _now_iso(),
                    }
                )
            elif "wmi" in lowered and ("exec" in lowered or "result" in lowered):
                findings.append(
                    {
                        "title": "Impacket WMI execution",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "impacket",
                        "target": "windows",
                        "timestamp": _now_iso(),
                    }
                )
            elif "smb" in lowered and ("share" in lowered or "open" in lowered):
                findings.append(
                    {
                        "title": "Impacket SMB share accessed",
                        "severity": "medium",
                        "description": line,
                        "evidence": line,
                        "tool": "impacket",
                        "target": "smb",
                        "timestamp": _now_iso(),
                    }
                )
        return findings
