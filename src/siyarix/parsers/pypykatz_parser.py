# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pypykatz credential extraction output parser — parses pypykatz JSON results."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")

_PASSWORD_LINE_RE = re.compile(
    r"(?:password|passwd|pw)\s*:\s*(\S+)",
    re.IGNORECASE,
)

_USERNAME_LINE_RE = re.compile(
    r"(?:username|user|login)\s*[:=]?\s*([^,\s]+)",
    re.IGNORECASE,
)


class PypykatzParser:
    """Parse pypykatz JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        stripped = output.strip()
        if not stripped:
            return findings

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for record in items:
                    if not isinstance(record, dict):
                        continue
                    logon_session = record.get("LogonSession", {})
                    username = logon_session.get("Username", "unknown")
                    domain = logon_session.get("DomainName", "unknown")

                    credentials = record.get("Credentials", {})
                    if isinstance(credentials, dict):
                        for cred_type, cred_list in credentials.items():
                            if isinstance(cred_list, list):
                                for cred in cred_list:
                                    password = cred.get("Password", "")
                                    nt_hash = cred.get("NTHash", "")
                                    dedup_key = f"{username}|{domain}|{cred_type}"
                                    if dedup_key in seen:
                                        continue
                                    if password or (
                                        nt_hash and nt_hash != "aad3b435b51404eeaad3b435b51404ee"
                                    ):
                                        seen.add(dedup_key)
                                        findings.append(
                                            {
                                                "title": f"Credential ({cred_type}): {username}",
                                                "severity": "critical",
                                                "description": f"pypykatz extracted {cred_type} credential for {username}@{domain}",
                                                "evidence": f"User: {username} | Domain: {domain}"
                                                + (
                                                    f" | Password: {password[:40]}"
                                                    if password
                                                    else ""
                                                )
                                                + (
                                                    f" | NTLM: {nt_hash[:40]}"
                                                    if nt_hash
                                                    and nt_hash
                                                    != "aad3b435b51404eeaad3b435b51404ee"
                                                    else ""
                                                ),
                                                "tool": "pypykatz",
                                                "target": domain,
                                                "timestamp": _now_iso(),
                                            },
                                        )

                    for section in ("MSV", "WDIGEST", "LIVESS", "SSP", "SSP_CRED"):
                        section_data = credentials.get(section, {})
                        if isinstance(section_data, dict):
                            for subtype, sub_creds in section_data.items():
                                if isinstance(sub_creds, list):
                                    for sc in sub_creds:
                                        pw = sc.get("Password", "")
                                        nt = sc.get("NTHash", "")
                                        dedup_key = f"{username}|{domain}|{section}/{subtype}"
                                        if dedup_key in seen:
                                            continue
                                        if pw or (nt and nt != "aad3b435b51404eeaad3b435b51404ee"):
                                            seen.add(dedup_key)
                                            findings.append(
                                                {
                                                    "title": f"Credential ({section}/{subtype}): {username}",
                                                    "severity": "critical",
                                                    "description": f"pypykatz extracted {section} credential for {username}@{domain}",
                                                    "evidence": f"Type: {section}/{subtype} | User: {username}"
                                                    + (f" | Password: {pw[:40]}" if pw else "")
                                                    + (
                                                        f" | NTLM: {nt[:40]}"
                                                        if nt
                                                        and nt != "aad3b435b51404eeaad3b435b51404ee"
                                                        else ""
                                                    ),
                                                    "tool": "pypykatz",
                                                    "target": domain,
                                                    "timestamp": _now_iso(),
                                                },
                                            )
                return findings
            except json.JSONDecodeError:
                pass

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                pm = _PASSWORD_LINE_RE.search(line)
                if pm:
                    pwd = pm.group(1)
                    um = _USERNAME_LINE_RE.search(line)
                    user = um.group(1) if um else "unknown"
                    dedup_key = f"text:pwd:{user}:{pwd}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append(
                            {
                                "title": f"Credential (plaintext): {user}",
                                "severity": "critical",
                                "description": f"pypykatz extracted plaintext credential for {user}",
                                "evidence": f"User: {user} | Password: {pwd}",
                                "tool": "pypykatz",
                                "target": "unknown",
                                "timestamp": _now_iso(),
                            },
                        )
                continue

            logon_session = record.get("LogonSession", {})
            username = logon_session.get("Username", "unknown")
            domain = logon_session.get("DomainName", "unknown")

            credentials = record.get("Credentials", {})
            if isinstance(credentials, dict):
                for cred_type, cred_list in credentials.items():
                    if isinstance(cred_list, list):
                        for cred in cred_list:
                            password = cred.get("Password", "")
                            nt_hash = cred.get("NTHash", "")
                            dedup_key = f"{username}|{domain}|{cred_type}"
                            if dedup_key in seen:
                                continue
                            if password or (
                                nt_hash and nt_hash != "aad3b435b51404eeaad3b435b51404ee"
                            ):
                                seen.add(dedup_key)
                                findings.append(
                                    {
                                        "title": f"Credential ({cred_type}): {username}",
                                        "severity": "critical",
                                        "description": f"pypykatz extracted {cred_type} credential for {username}@{domain}",
                                        "evidence": f"User: {username} | Domain: {domain}"
                                        + (f" | Password: {password[:40]}" if password else "")
                                        + (
                                            f" | NTLM: {nt_hash[:40]}"
                                            if nt_hash
                                            and nt_hash != "aad3b435b51404eeaad3b435b51404ee"
                                            else ""
                                        ),
                                        "tool": "pypykatz",
                                        "target": domain,
                                        "timestamp": _now_iso(),
                                    },
                                )

            for section in ("MSV", "WDIGEST", "LIVESS", "SSP", "SSP_CRED"):
                section_data = credentials.get(section, {})
                if isinstance(section_data, dict):
                    for subtype, sub_creds in section_data.items():
                        if isinstance(sub_creds, list):
                            for sc in sub_creds:
                                pw = sc.get("Password", "")
                                nt = sc.get("NTHash", "")
                                dedup_key = f"{username}|{domain}|{section}/{subtype}"
                                if dedup_key in seen:
                                    continue
                                if pw or (nt and nt != "aad3b435b51404eeaad3b435b51404ee"):
                                    seen.add(dedup_key)
                                    findings.append(
                                        {
                                            "title": f"Credential ({section}/{subtype}): {username}",
                                            "severity": "critical",
                                            "description": f"pypykatz extracted {section} credential for {username}@{domain}",
                                            "evidence": f"Type: {section}/{subtype} | User: {username}"
                                            + (f" | Password: {pw[:40]}" if pw else "")
                                            + (
                                                f" | NTLM: {nt[:40]}"
                                                if nt and nt != "aad3b435b51404eeaad3b435b51404ee"
                                                else ""
                                            ),
                                            "tool": "pypykatz",
                                            "target": domain,
                                            "timestamp": _now_iso(),
                                        },
                                    )

        return findings
