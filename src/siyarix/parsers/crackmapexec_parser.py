# SPDX-License-Identifier: AGPL-3.0-or-later

"""CrackMapExec / NetExec output parser — extracts SMB, SAM, DCSync and Pwn3d findings."""

from __future__ import annotations

from . import _now_iso

import re

_SMB_VERSION_RE = re.compile(r"SMB\s+version[:\s]*(\S+)", re.IGNORECASE)
_PWNED_RE = re.compile(r"(Pwn3d!|PWNED)", re.IGNORECASE)
_SUCCESS_RE = re.compile(r"\[\+\]\s*(.*)")
_FAILURE_RE = re.compile(r"\[-\]\s*(.*)")
_SAM_RE = re.compile(r"(?:SAM|Local).*?(?:admin|hash|cred)", re.IGNORECASE)
_DCSYNC_RE = re.compile(r"DCSync|dc-sync", re.IGNORECASE)
_CREDS_RE = re.compile(r"(\S+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})")
_SIGNING_RE = re.compile(r"signing[:\s]*(true|false)", re.IGNORECASE)
_SMBV1_RE = re.compile(r"SMBv1[:\s]*(true|false)", re.IGNORECASE)
_OS_RE = re.compile(r"(?:OS|os)[:\s]*(.+)", re.IGNORECASE)
_HOST_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

_JSON_RE = re.compile(r"^\s*[{\[]")


class CrackmapexecParser:
    """Parse crackmapexec/netexec output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        target = "unknown"
        stripped = output.strip()
        if not stripped:
            return findings

        seen_hosts: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                import json
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    host = item.get("host", item.get("ip", "unknown"))
                    if host != "unknown":
                        target = host  # type: ignore
                    user = item.get("username", item.get("user", ""))
                    nt_hash = item.get("nt_hash", item.get("hash", ""))
                    if user and nt_hash:
                        dedup_key = f"cred|{host}|{user}"
                        if dedup_key in seen_hosts:
                            continue
                        seen_hosts.add(dedup_key)
                        findings.append({
                            "title": f"CrackMapExec: Credential pair ({user})",
                            "severity": "high",
                            "description": f"Username: {user}, NT hash: {nt_hash}",
                            "evidence": json.dumps(item),
                            "tool": "crackmapexec",
                            "target": host,
                            "timestamp": _now_iso(),
                        })
                    pwned = item.get("pwned", item.get("admin", False))
                    if pwned:
                        dedup_key = f"pwned|{host}"
                        if dedup_key in seen_hosts:
                            continue
                        seen_hosts.add(dedup_key)
                        findings.append({
                            "title": "CrackMapExec: Pwn3d!",
                            "severity": "critical",
                            "description": f"Target {host} is fully compromised",
                            "evidence": json.dumps(item),
                            "tool": "crackmapexec",
                            "target": host,
                            "timestamp": _now_iso(),
                        })
                return findings
            except json.JSONDecodeError:
                pass

        lines = output.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            ip_m = _HOST_RE.match(line_stripped)
            if ip_m:
                target = ip_m.group(1)

            m = _SUCCESS_RE.search(line_stripped)
            if m:
                msg = m.group(1)
                dedup_key = f"result|{target}|{msg[:40]}"

                if _PWNED_RE.search(msg):
                    pwn_key = f"pwned|{target}"
                    if pwn_key not in seen_hosts:
                        seen_hosts.add(pwn_key)
                        findings.append({
                            "title": "CrackMapExec: Pwn3d!",
                            "severity": "critical",
                            "description": f"Target is fully compromised: {msg}",
                            "evidence": line_stripped,
                            "tool": "crackmapexec",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                elif _SAM_RE.search(msg):
                    if dedup_key not in seen_hosts:
                        seen_hosts.add(dedup_key)
                        findings.append({
                            "title": "CrackMapExec: SAM credentials harvested",
                            "severity": "high",
                            "description": f"SAM/Local credentials extracted: {msg}",
                            "evidence": line_stripped,
                            "tool": "crackmapexec",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                elif _DCSYNC_RE.search(msg):
                    if dedup_key not in seen_hosts:
                        seen_hosts.add(dedup_key)
                        findings.append({
                            "title": "CrackMapExec: DCSync credentials harvested",
                            "severity": "critical",
                            "description": f"DCSync credentials extracted: {msg}",
                            "evidence": line_stripped,
                            "tool": "crackmapexec",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                elif "SMB" in msg or "smb" in msg:
                    sv = _SMB_VERSION_RE.search(msg)
                    if sv:
                        findings.append({
                            "title": "CrackMapExec: SMB version detected",
                            "severity": "info",
                            "description": f"SMB version: {sv.group(1)}",
                            "evidence": line_stripped,
                            "tool": "crackmapexec",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                elif ":" in msg:
                    parts = msg.split(":", 1)
                    user = parts[0].strip()
                    pwd = parts[1].strip()
                    dedup_key = f"cred|{target}|{user}"
                    if dedup_key not in seen_hosts:
                        seen_hosts.add(dedup_key)
                        findings.append({
                            "title": f"CrackMapExec: Credential pair ({user})",
                            "severity": "high",
                            "description": f"Valid credentials found: {user}:{pwd}",
                            "evidence": line_stripped,
                            "tool": "crackmapexec",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                continue

            m = _FAILURE_RE.search(line_stripped)
            if m:
                msg = m.group(1)
                if "login" in msg.lower() or "auth" in msg.lower():
                    findings.append({
                        "title": "CrackMapExec: Login failure",
                        "severity": "info",
                        "description": f"Authentication failure: {msg}",
                        "evidence": line_stripped,
                        "tool": "crackmapexec",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                continue

            cm = _CREDS_RE.search(line_stripped)
            if cm:
                username = cm.group(1)
                rid = cm.group(2)
                lm_hash = cm.group(3)
                nt_hash = cm.group(4)
                dedup_key = f"cred|{target}|{username}"
                if dedup_key not in seen_hosts:
                    seen_hosts.add(dedup_key)
                    findings.append({
                        "title": f"CrackMapExec: Credential pair ({username})",
                        "severity": "high",
                        "description": f"Username: {username}, RID: {rid}, NT hash: {nt_hash}",
                        "evidence": line_stripped,
                        "tool": "crackmapexec",
                        "target": target,
                        "timestamp": _now_iso(),
                    })

            sv = _SMB_VERSION_RE.search(line_stripped)
            if sv:
                findings.append({
                    "title": "CrackMapExec: SMB version detected",
                    "severity": "info",
                    "description": f"SMB version: {sv.group(1)}",
                    "evidence": line_stripped,
                    "tool": "crackmapexec",
                    "target": target,
                    "timestamp": _now_iso(),
                })

            if "SMBv1" in line_stripped:
                findings.append({
                    "title": "CrackMapExec: SMBv1 enabled",
                    "severity": "medium",
                    "description": "SMBv1 protocol is enabled — vulnerable to EternalBlue-like attacks",
                    "evidence": line_stripped,
                    "tool": "crackmapexec",
                    "target": target,
                    "timestamp": _now_iso(),
                })

            if "signing" in line_stripped.lower() and "false" in line_stripped.lower():
                findings.append({
                    "title": "CrackMapExec: SMB signing disabled",
                    "severity": "medium",
                    "description": "SMB signing is disabled — relay attacks possible",
                    "evidence": line_stripped,
                    "tool": "crackmapexec",
                    "target": target,
                    "timestamp": _now_iso(),
                })

        return findings
