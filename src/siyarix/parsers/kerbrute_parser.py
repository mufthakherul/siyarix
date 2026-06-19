# SPDX-License-Identifier: AGPL-3.0-or-later

"""Kerbrute output parser — extracts valid/invalid users, AS-REP roasting hashes, and TGT data."""

from __future__ import annotations

from . import _now_iso

import re

_VALID_USER_RE = re.compile(
    r"(?:\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+>\s+)?\[\+\]\s+(?:VALID USER(?:NAME)?|Found|User found)[:\s]\s*(\S+)",
    re.IGNORECASE,
)
_INVALID_USER_RE = re.compile(r"^\[\-\]\s+(.*?)(?:invalid|not found|does not exist)", re.IGNORECASE)
_ASREP_HASH_RE = re.compile(r"(?:AS.REP|as_rep|ASREP|roast).*?(?:\$krb5|hash)", re.IGNORECASE)
_TGT_RE = re.compile(r"(?:TGT|ticket).*?(?:captured|received|extracted)", re.IGNORECASE)
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_USERNAME_EXTRACT_RE = re.compile(r"(\S+@\S+|\S+\$)")
_HASH_RE = re.compile(r"(\$krb5.+?\$.+?\$.+)", re.IGNORECASE)
_USER_STATS_RE = re.compile(r"(\d+)\s+valid\s+user", re.IGNORECASE)

_JSON_RE = re.compile(r"^\s*[{\[]")


class KerbruteParser:
    """Parse kerbrute output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        target = "unknown"
        stripped = output.strip()
        if not stripped:
            return findings

        seen_users: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                import json

                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    user = item.get("username", item.get("user", ""))
                    valid = item.get("valid", item.get("status", ""))
                    if user and valid in (True, "true", "valid"):
                        if user in seen_users:
                            continue
                        seen_users.add(user)
                        target = str(item.get("domain", item.get("host", target)))
                        findings.append(
                            {
                                "title": f"Kerbrute: Valid user — {user}",
                                "severity": "high",
                                "description": f"Valid Kerberos user discovered: {user}",
                                "evidence": json.dumps(item),
                                "tool": "kerbrute",
                                "target": target,
                                "timestamp": _now_iso(),
                            }
                        )
                    hash_val = item.get("hash", item.get("asrep", ""))
                    if hash_val:
                        findings.append(
                            {
                                "title": "Kerbrute: AS-REP roast hash captured",
                                "severity": "critical",
                                "description": "AS-REP roasting hash captured",
                                "evidence": hash_val[:120],
                                "tool": "kerbrute",
                                "target": target,
                                "timestamp": _now_iso(),
                            }
                        )
                return findings
            except json.JSONDecodeError:
                pass

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            vm = _VALID_USER_RE.search(line_stripped)
            if vm:
                username = vm.group(2).strip() if len(vm.groups()) >= 2 else vm.group(1).strip()
                username_m = _USERNAME_EXTRACT_RE.search(username)
                if username_m:
                    username = username_m.group(1)

                if username in seen_users:
                    continue
                seen_users.add(username)
                findings.append(
                    {
                        "title": f"Kerbrute: Valid user — {username}",
                        "severity": "high",
                        "description": f"Valid Kerberos user discovered: {username}",
                        "evidence": line_stripped,
                        "tool": "kerbrute",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            im = _INVALID_USER_RE.search(line_stripped)
            if im:
                findings.append(
                    {
                        "title": "Kerbrute: Invalid user",
                        "severity": "info",
                        "description": f"Invalid/non-existent user: {im.group(1).strip()}",
                        "evidence": line_stripped,
                        "tool": "kerbrute",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if _ASREP_HASH_RE.search(line_stripped):
                hash_m = _HASH_RE.search(line_stripped)
                hash_val = hash_m.group(1) if hash_m else line_stripped
                dedup_key = f"asrep|{hash_val[:40]}"
                if dedup_key in seen_users:
                    continue
                seen_users.add(dedup_key)
                findings.append(
                    {
                        "title": "Kerbrute: AS-REP roast hash captured",
                        "severity": "critical",
                        "description": "AS-REP roasting hash captured — user does not require Kerberos pre-authentication",
                        "evidence": hash_val[:120],
                        "tool": "kerbrute",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if _TGT_RE.search(line_stripped):
                findings.append(
                    {
                        "title": "Kerbrute: TGT captured",
                        "severity": "high",
                        "description": "Kerberos TGT captured from the domain controller",
                        "evidence": line_stripped,
                        "tool": "kerbrute",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            ip_m = _IP_RE.search(line_stripped)
            if ip_m and (
                "dc" in line_stripped.lower()
                or "domain" in line_stripped.lower()
                or "krb" in line_stripped.lower()
            ):
                target = ip_m.group(1)

            if "PASS" in line_stripped or "password" in line_stripped.lower():
                findings.append(
                    {
                        "title": "Kerbrute: Password spray result",
                        "severity": "info",
                        "description": line_stripped,
                        "evidence": line_stripped,
                        "tool": "kerbrute",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

            us = _USER_STATS_RE.search(line_stripped)
            if us:
                findings.append(
                    {
                        "title": "Kerbrute: User enumeration stats",
                        "severity": "info",
                        "description": f"kerbrute found {us.group(1)} valid users",
                        "evidence": line_stripped,
                        "tool": "kerbrute",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
