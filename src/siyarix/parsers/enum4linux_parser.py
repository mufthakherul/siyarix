# SPDX-License-Identifier: AGPL-3.0-or-later

"""enum4linux output parser — parses SMB enumeration text and JSON (enum4linux-ng) output."""

from __future__ import annotations

import json
import re

from . import _now_iso

_USER_RE = re.compile(
    r"(?:user|username)[:\s]+(?P<user>\S+)",
    re.IGNORECASE,
)

_SHARE_RE = re.compile(
    r"(?P<share>\S+)\s+disk\s+",
    re.IGNORECASE,
)

_OS_RE = re.compile(
    r"(?:OS|operating system|platform)[:\s]+(.+)",
    re.IGNORECASE,
)

_SID_RE = re.compile(
    r"S-1-5-21-\d+-\d+-\d+-\d+",
)

_POLICY_RE = re.compile(
    r"Password\s+(?:policy|complexity|history|min|max|lockout)",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"Domain\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)

_WORKGROUP_RE = re.compile(
    r"(?:Workgroup|Group|Domain)\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)

_PRINTER_RE = re.compile(
    r"Printer|print\s+queue|spool",
    re.IGNORECASE,
)

_GROUP_RE = re.compile(
    r"(?:Group|domain\s+group)\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)

_SESSION_RE = re.compile(
    r"(?:Session|logged\s+in|active\s+user)[:\s]+(.+)",
    re.IGNORECASE,
)

_RID_RE = re.compile(
    r"\[RID\]\s*[:\s]+(\S+)\s+(.+)",
    re.IGNORECASE,
)

_SECTION_HEADER_RE = re.compile(
    r"^\[?[+*]\]?\s*(.+)$",
)

_POLICY_DETAIL_RE = re.compile(
    r"(Minimum\s+password|Maximum\s+password|Password\s+history|Lockout|Account\s+lockout)",
    re.IGNORECASE,
)

_JSON_RE = re.compile(r"^\s*[{\[]")


class Enum4linuxParser:
    """Parse enum4linux output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen_shares: set[str] = set()
        seen_users: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if "username" in item or "user" in item:
                        user = item.get("user", item.get("username", ""))
                        if user:
                            if user in seen_users:
                                continue
                            seen_users.add(user)
                            findings.append(
                                {
                                    "title": f"User: {user}",
                                    "severity": "medium",
                                    "description": f"enum4linux discovered user {user!r}",
                                    "evidence": json.dumps(item),
                                    "tool": "enum4linux",
                                    "target": item.get("host", item.get("target", "unknown")),
                                    "timestamp": _now_iso(),
                                }
                            )
                    if "share" in item:
                        share_name = item["share"]
                        if share_name in seen_shares:
                            continue
                        seen_shares.add(share_name)
                        findings.append(
                            {
                                "title": f"SMB share: {share_name}",
                                "severity": "medium",
                                "description": f"enum4linux discovered SMB share {share_name!r}",
                                "evidence": json.dumps(item),
                                "tool": "enum4linux",
                                "target": item.get("host", "unknown"),
                                "timestamp": _now_iso(),
                            }
                        )
                    if "os" in item:
                        findings.append(
                            {
                                "title": f"OS: {item['os']}",
                                "severity": "info",
                                "description": f"OS identified as {item['os']}",
                                "evidence": json.dumps(item),
                                "tool": "enum4linux",
                                "target": item.get("host", "unknown"),
                                "timestamp": _now_iso(),
                            }
                        )
                return findings
            except json.JSONDecodeError:
                pass

        target = "unknown"

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue

            lower = line.lower()

            sh = _SECTION_HEADER_RE.match(line)
            if sh:
                sh.group(1).strip()

            if "target" in lower and ":" in line and len(line.split()) < 6:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    target = parts[-1].strip()
                continue

            rm = _RID_RE.match(line)
            if rm:
                rid_val = rm.group(1)
                rid_desc = rm.group(2).strip()
                dedup_key = f"rid|{rid_val}"
                if dedup_key in seen_shares:
                    continue
                seen_shares.add(dedup_key)
                findings.append(
                    {
                        "title": f"RID entry: {rid_val}",
                        "severity": "low",
                        "description": f"RID {rid_val} -> {rid_desc}",
                        "evidence": line,
                        "tool": "enum4linux",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if "workgroup" in lower and ":" in line:
                wm = _WORKGROUP_RE.match(line)
                if wm:
                    wg = wm.group(1).strip()
                    findings.append(
                        {
                            "title": f"Workgroup: {wg}",
                            "severity": "info",
                            "description": f"enum4linux discovered workgroup/domain {wg} on {target}",
                            "evidence": line,
                            "tool": "enum4linux",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _USER_RE.search(line)
            if m:
                user = m.group("user").strip()
                if user and len(user) > 1 and user not in seen_users:
                    seen_users.add(user)
                    findings.append(
                        {
                            "title": f"User: {user}",
                            "severity": "medium",
                            "description": f"enum4linux discovered user {user!r} on {target}",
                            "evidence": f"user: {user} target: {target}",
                            "tool": "enum4linux",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _SHARE_RE.match(line)
            if m:
                share = m.group("share").strip()
                if share and share not in seen_shares:
                    seen_shares.add(share)
                    findings.append(
                        {
                            "title": f"SMB share: {share}",
                            "severity": "medium",
                            "description": f"enum4linux discovered SMB share {share!r} on {target}",
                            "evidence": f"share: {share} target: {target}",
                            "tool": "enum4linux",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            if _PRINTER_RE.search(lower):
                findings.append(
                    {
                        "title": "Printer information discovered",
                        "severity": "low",
                        "description": f"Printer/spooler info: {line}",
                        "evidence": line,
                        "tool": "enum4linux",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if _GROUP_RE.search(lower):
                gm = _GROUP_RE.match(line)
                if gm:
                    findings.append(
                        {
                            "title": f"Domain group: {gm.group(1).strip()}",
                            "severity": "low",
                            "description": f"Domain group on {target}: {gm.group(1).strip()}",
                            "evidence": line,
                            "tool": "enum4linux",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            if _SESSION_RE.search(lower):
                sm = _SESSION_RE.match(line)
                if sm:
                    findings.append(
                        {
                            "title": "Active SMB sessions",
                            "severity": "medium",
                            "description": f"SMB session info: {sm.group(1).strip()}",
                            "evidence": line,
                            "tool": "enum4linux",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            if _POLICY_RE.search(lower) or _POLICY_DETAIL_RE.search(lower):
                findings.append(
                    {
                        "title": "Password policy information",
                        "severity": "low",
                        "description": f"enum4linux gathered password policy info from {target}: {line}",
                        "evidence": line,
                        "tool": "enum4linux",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            if _OS_RE.match(line):
                os_info = _OS_RE.match(line).group(1).strip()  # type: ignore
                if os_info:
                    findings.append(
                        {
                            "title": f"OS: {os_info}",
                            "severity": "info",
                            "description": f"enum4linux identified OS of {target} as {os_info}",
                            "evidence": line,
                            "tool": "enum4linux",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            sids = _SID_RE.findall(line)
            for sid in sids:
                dedup_key = f"sid|{sid}"
                if dedup_key in seen_shares:
                    continue
                seen_shares.add(dedup_key)
                findings.append(
                    {
                        "title": f"SID: {sid}",
                        "severity": "low",
                        "description": f"enum4linux discovered SID {sid} on {target}",
                        "evidence": line,
                        "tool": "enum4linux",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
