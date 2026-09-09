# SPDX-License-Identifier: AGPL-3.0-or-later

"""ike-scan output parser — parses IKE VPN discovery results (text + --showback)."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_VENDOR_RE = re.compile(
    r"(?:Vendor|Fingerprint|vendor\s*ID)[:\s]+(.+)",
    re.IGNORECASE,
)

_HANDSHAKE_RE = re.compile(
    r"(?:Handshake|Aggressive|Main\s+Mode|responding|established)",
    re.IGNORECASE,
)

_RETURNED_RE = re.compile(
    r"(?P<ip>[\d.]+)\s+(?P<state>\S+)\s+(?P<transform>.+)",
)

_BANNER_RE = re.compile(
    r"(?:banner|notify|message|notification)[:\s]+(.+)",
    re.IGNORECASE,
)

_SHOWBACK_RE = re.compile(
    r"(?P<ip>[\d.]+)\s+(?P<status>SA|Handshake|\?|No\s+Response)\s+"
    r"(?P<enc>[\w\-]+)\s+(?P<hash>[\w\-]+)\s+(?P<auth>[\w\-]+)\s+"
    r"(?P<dh>\d+)",
    re.IGNORECASE,
)

_TRANSFORM_ATTR_RE = re.compile(
    r"(?P<ip>[\d.]+)\s+(?P<state>\S+)\s+"
    r"(?P<enc>[\w\-]+)\s+(?P<hash>[\w\-]+)\s+(?P<auth>[\w\-]+)\s+"
    r"(?P<dh>\w+)",
)

_AGGRESSIVE_RE = re.compile(
    r"(?:Aggressive|aggressive\s+mode|XAuth)",
    re.IGNORECASE,
)

_ENCRYPTION_NAMES = {
    "1": "DES-CBC",
    "2": "IDEA-CBC",
    "3": "BLOWFISH-CBC",
    "5": "AES-CBC-128",
    "6": "AES-CBC-192",
    "7": "AES-CBC-256",
    "8": "AES-CTR-128",
    "9": "AES-CTR-192",
    "10": "AES-CTR-256",
}

_HASH_NAMES = {
    "1": "MD5",
    "2": "SHA1",
    "3": "SHA2-256",
    "4": "SHA2-384",
    "5": "SHA2-512",
}

_AUTH_NAMES = {
    "1": "PSK",
    "2": "DSS",
    "3": "RSA-SIG",
    "5": "XAUTH",
    "64221": "HYBRID",
    "65001": "XAUTH-PSK",
}

_DH_NAMES = {
    "1": "768-bit MODP",
    "2": "1024-bit MODP",
    "5": "1536-bit MODP",
    "14": "2048-bit MODP",
    "15": "3072-bit MODP",
    "16": "4096-bit MODP",
}

_SUMMARY_RE = re.compile(
    r"(?:Ending|Scanned|Received|Total)[:\s]+(\d+)",
    re.IGNORECASE,
)


class IkeScanParser:
    """Parse ike-scan output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        current_ip = "unknown"

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            m = _SUMMARY_RE.search(line)
            if m:
                key = "summary:scanned"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"ike-scan: {m.group(1)} hosts",
                            "severity": "info",
                            "description": f"ike-scan scanned {m.group(1)} hosts",
                            "evidence": raw.strip(),
                            "tool": "ike-scan",
                            "target": current_ip,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            if "ike-scan" in line.lower() and ":" in line:
                parts = line.split()
                for p in parts:
                    if p.count(".") == 3 and all(c.isdigit() or c == "." for c in p):
                        current_ip = p.strip("():,")
                        break
                continue

            # --showback format
            m = _SHOWBACK_RE.search(line)
            if m:
                ip = m.group("ip")
                status = m.group("status").upper()
                enc = m.group("enc")
                hash_algo = m.group("hash")
                auth = m.group("auth")
                dh = m.group("dh")

                enc_name = _ENCRYPTION_NAMES.get(enc, enc)
                hash_name = _HASH_NAMES.get(hash_algo, hash_algo)
                auth_name = _AUTH_NAMES.get(auth, auth)
                dh_name = _DH_NAMES.get(dh, dh)

                transform_desc = f"Enc={enc_name} Hash={hash_name} Auth={auth_name} DH={dh_name}"

                key = f"showback:{ip}:{status}"
                if key not in seen:
                    seen.add(key)
                    if status in {"SA", "HANDSHAKE"}:
                        current_ip = ip
                        findings.append(
                            {
                                "title": f"IKE response: {ip} ({status})",
                                "severity": "high",
                                "description": f"ike-scan received {status} from {ip}: {transform_desc}",
                                "evidence": f"Encryption: {enc_name} | Hash: {hash_name} | Auth: {auth_name} | DH: {dh_name}",
                                "tool": "ike-scan",
                                "target": ip,
                                "timestamp": _now_iso(),
                            },
                        )
                continue

            # Transform attribute line
            m = _TRANSFORM_ATTR_RE.match(line)
            if m:
                ip = m.group("ip")
                state = m.group("state")
                enc = m.group("enc")
                hash_algo = m.group("hash")
                auth = m.group("auth")
                dh = m.group("dh")

                current_ip = ip
                enc_name = _ENCRYPTION_NAMES.get(enc, enc)
                hash_name = _HASH_NAMES.get(hash_algo, hash_algo)
                auth_name = _AUTH_NAMES.get(auth, auth)
                dh_name = _DH_NAMES.get(dh, dh)

                transform_desc = f"Enc={enc_name} Hash={hash_name} Auth={auth_name} DH={dh_name}"
                severity = "high" if state.lower() in ("responding", "handshake", "sa") else "info"

                key = f"transform:{ip}:{state}:{enc}:{hash_algo}:{auth}:{dh}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"IKE transform: {ip} ({state})",
                            "severity": severity,
                            "description": f"ike-scan received {state} from {ip}: {transform_desc}",
                            "evidence": f"Enc={enc_name} Hash={hash_name} Auth={auth_name} DH={dh_name}",
                            "tool": "ike-scan",
                            "target": ip,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _HANDSHAKE_RE.search(line)
            if m:
                m.group(0)
                key = f"handshake:{current_ip}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": "IKE handshake received",
                            "severity": "high",
                            "description": f"ike-scan received IKE handshake from {current_ip} — VPN gateway identified",
                            "evidence": raw,
                            "tool": "ike-scan",
                            "target": current_ip,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            if _AGGRESSIVE_RE.search(line):
                key = f"aggressive:{current_ip}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": "IKE aggressive mode detected",
                            "severity": "high",
                            "description": f"ike-scan detected aggressive mode from {current_ip} — vulnerable to PSK cracking",
                            "evidence": raw,
                            "tool": "ike-scan",
                            "target": current_ip,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _RETURNED_RE.match(line)
            if m:
                current_ip = m.group("ip")
                state = m.group("state")
                transform = m.group("transform")
                severity = "high" if state.lower() in ("responding", "handshake") else "info"
                key = f"returned:{current_ip}:{state}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"IKE response: {current_ip} ({state})",
                            "severity": severity,
                            "description": f"ike-scan received {state} from {current_ip}: {transform}",
                            "evidence": raw,
                            "tool": "ike-scan",
                            "target": current_ip,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _VENDOR_RE.search(line)
            if m:
                vendor = m.group(1).strip()
                key = f"vendor:{current_ip}:{vendor[:40]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"IKE vendor ID: {vendor[:40]}",
                            "severity": "info",
                            "description": f"ike-scan identified vendor fingerprint {vendor} on {current_ip}",
                            "evidence": raw,
                            "tool": "ike-scan",
                            "target": current_ip,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            m = _BANNER_RE.search(line)
            if m:
                banner = m.group(1).strip()
                key = f"banner:{current_ip}:{banner[:40]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"IKE banner: {banner[:40]}",
                            "severity": "info",
                            "description": f"ike-scan received banner from {current_ip}: {banner}",
                            "evidence": raw,
                            "tool": "ike-scan",
                            "target": current_ip,
                            "timestamp": _now_iso(),
                        },
                    )

        return findings
