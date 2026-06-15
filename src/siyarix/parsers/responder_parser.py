# SPDX-License-Identifier: AGPL-3.0-or-later

"""Responder output parser — extracts LLMNR/NBT-NS/MDNS poison hashes and challenge/response pairs."""

from __future__ import annotations

from . import _now_iso

import re

_HASH_CAPTURED_RE = re.compile(
    r"\[(\w+)\]\s*(?:Captured| Poisoned| sending ).*?(?:hash|NTLMv2|challenge|response)",
    re.IGNORECASE,
)
_PROTOCOL_CAPTURE_RE = re.compile(r"\[(\w+)\].*?(?:from|client).*?(?:\d{1,3}\.){3}\d{1,3}")
_CHALLENGE_RESPONSE_RE = re.compile(
    r"NTLMv2\s*(?:Client|Server|Challenge|Response|Hash).*?:?\s*(\S+)", re.IGNORECASE
)
_CLIENT_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_USERNAME_RE = re.compile(r"(?:USER|Username|User)\s*[:\-]\s*(\S+)", re.IGNORECASE)
_NBTNS_RE = re.compile(r"NBT-NS|NBTNS|LLMNR|MDNS", re.IGNORECASE)
_HASH_VALUE_RE = re.compile(r"(\$?\w+[\w:+$]*\$)")

_JSON_RE = re.compile(r"^\s*[{\[]")


class ResponderParser:
    """Parse Responder output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen_hashes: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                import json
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    hash_val = item.get("hash", item.get("ntlmv2", item.get("challenge", "")))
                    if hash_val:
                        dedup_key = f"hash|{hash_val[:40]}"
                        if dedup_key in seen_hashes:
                            continue
                        seen_hashes.add(dedup_key)
                        protocol = item.get("protocol", "SMB")
                        target = item.get("client_ip", item.get("from", "unknown"))
                        findings.append({
                            "title": f"Responder: {protocol} hash captured",
                            "severity": "high",
                            "description": f"NTLM hash captured via {protocol} poisoning from {target}",
                            "evidence": json.dumps(item),
                            "tool": "responder",
                            "target": target,
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

            m = _HASH_CAPTURED_RE.search(line_stripped)
            if m:
                protocol = m.group(1)
                severity = "high"
                if protocol.upper() in ("MDNS",):
                    severity = "medium"

                target = "unknown"
                ip_m = _CLIENT_IP_RE.search(line_stripped)
                if ip_m:
                    target = ip_m.group(1)

                username = "unknown"
                u_m = _USERNAME_RE.search(line_stripped)
                if u_m:
                    username = u_m.group(1)

                hv = _HASH_VALUE_RE.search(line_stripped)
                dedup_key = f"hash|{target}|{username}|{protocol}"
                if hv:
                    dedup_key = f"hash|{hv.group(1)[:40]}"
                if dedup_key in seen_hashes:
                    continue
                seen_hashes.add(dedup_key)

                description = f"NTLM hash captured via {protocol} poisoning"
                if username != "unknown":
                    description += f" for user {username}"

                findings.append({
                    "title": f"Responder: {protocol} hash captured",
                    "severity": severity,
                    "description": description,
                    "evidence": line_stripped,
                    "tool": "responder",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            m = _PROTOCOL_CAPTURE_RE.search(line_stripped)
            if m:
                protocol = m.group(1)
                target = "unknown"
                ip_m = _CLIENT_IP_RE.search(line_stripped)
                if ip_m:
                    target = ip_m.group(1)

                findings.append({
                    "title": f"Responder: {protocol} capture event",
                    "severity": "info",
                    "description": f"Protocol {protocol} request captured from {target}",
                    "evidence": line_stripped,
                    "tool": "responder",
                    "target": target,
                    "timestamp": _now_iso(),
                })

            cm = _CHALLENGE_RESPONSE_RE.search(line_stripped)
            if cm:
                dedup_key = f"challenge|{cm.group(1)[:40]}"
                if dedup_key in seen_hashes:
                    continue
                seen_hashes.add(dedup_key)
                findings.append({
                    "title": "Responder: Challenge/Response pair",
                    "severity": "high",
                    "description": f"NTLMv2 challenge/response data: {cm.group(1)[:80]}",
                    "evidence": line_stripped,
                    "tool": "responder",
                    "target": target if "target" in dir() else "unknown",
                    "timestamp": _now_iso(),
                })

            if _NBTNS_RE.search(line_stripped) and "pois" in line_stripped.lower():
                findings.append({
                    "title": "Responder: NBT-NS/LLMNR poison response sent",
                    "severity": "medium",
                    "description": "Responder sent a poison response to a NBT-NS or LLMNR query",
                    "evidence": line_stripped,
                    "tool": "responder",
                    "target": "unknown",
                    "timestamp": _now_iso(),
                })

        return findings
