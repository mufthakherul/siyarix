# SPDX-License-Identifier: AGPL-3.0-or-later

"""jwt_tool output parser — parses JWT analysis and attack results (text + JSON)."""

from __future__ import annotations

from . import _now_iso

import json
import re

_VULN_RE = re.compile(
    r"(?:vulnerability|issue|attack|weakness|finding)[\s:]+(.+)",
    re.IGNORECASE,
)

_CLAIM_RE = re.compile(
    r"\s*(?P<key>[\w_]+)\s*[=:]\s*(?P<value>\S+)",
)

_ALGO_RE = re.compile(
    r"(?:algorithm|alg)[\s:=]+(\S+)",
    re.IGNORECASE,
)

_SIGNED_RE = re.compile(
    r"(?:verified|signature\s+verified|valid\s+signature)",
    re.IGNORECASE,
)

_NONE_RE = re.compile(
    r"(?:none|no\s+(?:signature|algorithm)|alg\s*:\s*none)",
    re.IGNORECASE,
)

_EXPIRED_RE = re.compile(
    r"(?:expired|token\s+expired|expiration)",
    re.IGNORECASE,
)

_KID_RE = re.compile(
    r"(?:kid|key\s+id)[:\s]+(\S+)",
    re.IGNORECASE,
)

_ROLE_RE = re.compile(
    r"(?:role|admin|is_admin|privilege)[:\s]*(\S+)",
    re.IGNORECASE,
)


class JwtToolParser:
    """Parse jwt_tool output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        current_token = ""
        algo = "unknown"
        decoded_payload: dict = {}
        signature_valid = None

        trimmed = output.strip()
        if not trimmed:
            return findings

        # Try JSON output format (jwt_tool --json)
        if trimmed.startswith("{"):
            try:
                record = json.loads(trimmed)
                return self._parse_json_output(record)
            except json.JSONDecodeError:
                pass

        if trimmed.startswith("["):
            try:
                records = json.loads(trimmed)
                if isinstance(records, list):
                    for rec in records:
                        findings.extend(self._parse_json_output(rec))
                    return findings
            except json.JSONDecodeError:
                pass

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            if len(line) > 80 and line.count(".") == 2:
                current_token = line
                try:
                    parts = line.split(".")
                    if len(parts) >= 2:
                        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        decoded_payload = json.loads(
                            __import__("base64").urlsafe_b64decode(padded).decode("utf-8", errors="replace")
                        )
                except Exception:
                    pass
                continue

            m = _ALGO_RE.search(line)
            if m:
                algo = m.group(1).strip().lower()

            if _SIGNED_RE.search(line):
                signature_valid = True
                continue

            if _NONE_RE.search(line):
                key = "vuln:none-algorithm"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": "JWT algorithm set to 'none'",
                        "severity": "critical",
                        "description": "JWT accepts 'none' algorithm — attacker can forge arbitrary tokens",
                        "evidence": raw,
                        "tool": "jwt_tool",
                        "target": current_token[:40] + "..." if current_token else "unknown",
                        "timestamp": _now_iso(),
                    })
                continue

            if algo in ("none", "null", "nonealgorithm"):
                key = f"vuln:none-algo:{algo}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": "JWT 'none' algorithm attack possible",
                        "severity": "critical",
                        "description": f"JWT uses algorithm '{algo}' enabling signature bypass",
                        "evidence": raw,
                        "tool": "jwt_tool",
                        "target": current_token[:40] + "..." if current_token else "unknown",
                        "timestamp": _now_iso(),
                    })
                continue

            m = _VULN_RE.search(line)
            if m:
                vuln = m.group(1).strip()
                key = f"vuln:{vuln[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"JWT vulnerability: {vuln[:60]}",
                        "severity": "high",
                        "description": f"jwt_tool identified: {vuln}",
                        "evidence": raw,
                        "tool": "jwt_tool",
                        "target": current_token[:40] + "..." if current_token else "unknown",
                        "timestamp": _now_iso(),
                    })
                continue

            m = _ROLE_RE.search(line)
            if m:
                role_val = m.group(1).strip().lower()
                if role_val in ("1", "true", "admin", "administrator"):
                    key = f"role:{current_token[:40]}:{role_val}"
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "title": "JWT privilege escalation possible",
                            "severity": "high",
                            "description": f"JWT contains privilege claim: {raw.strip()}",
                            "evidence": raw,
                            "tool": "jwt_tool",
                            "target": current_token[:40] + "..." if current_token else "unknown",
                            "timestamp": _now_iso(),
                        })
                continue

        if decoded_payload:
            for k, v in decoded_payload.items():
                key = f"claim:{k}:{v}"
                if key not in seen:
                    seen.add(key)
                    if k.lower() in ("role", "admin", "is_admin", "privilege", "isadmin"):
                        severity = "high"
                    elif k.lower() in ("sub", "iss", "aud", "iat", "exp", "nbf", "jti"):
                        severity = "info"
                    else:
                        severity = "info"
                    findings.append({
                        "title": f"JWT claim: {k} = {v}",
                        "severity": severity,
                        "description": f"Decoded JWT claim {k}: {v}",
                        "evidence": f"{k}={v}",
                        "tool": "jwt_tool",
                        "target": current_token[:40] + "..." if current_token else "unknown",
                        "timestamp": _now_iso(),
                    })

        if signature_valid is not None:
            key = f"sig-valid:{signature_valid}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": "JWT signature verification result",
                    "severity": "info" if signature_valid else "high",
                    "description": f"JWT signature verification: {'valid' if signature_valid else 'invalid'}",
                    "evidence": f"Signature verified: {signature_valid}",
                    "tool": "jwt_tool",
                    "target": current_token[:40] + "..." if current_token else "unknown",
                    "timestamp": _now_iso(),
                })

        return findings

    def _parse_json_output(self, record: dict) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        token = record.get("token", "")
        algo = record.get("algorithm", "unknown")
        key = f"json-algo:{algo}"
        if key not in seen:
            seen.add(key)
            findings.append({
                "title": f"JWT analysis: algorithm={algo}",
                "severity": "info",
                "description": f"JWT token analyzed: algorithm={algo}, claims={json.dumps(record.get('payload', {}))}",
                "evidence": f"Token: {token[:40]}... | Algorithm: {algo}",
                "tool": "jwt_tool",
                "target": token[:40] + "..." if token else "unknown",
                "timestamp": _now_iso(),
            })

        payload = record.get("payload", {})
        if isinstance(payload, dict):
            for k, v in payload.items():
                key = f"json-claim:{k}:{v}"
                if key not in seen:
                    seen.add(key)
                    sev = "high" if k.lower() in ("role", "admin", "is_admin", "privilege") else "info"
                    findings.append({
                        "title": f"JWT claim: {k} = {v}",
                        "severity": sev,
                        "description": f"Decoded JWT claim {k}: {v}",
                        "evidence": f"{k}={v}",
                        "tool": "jwt_tool",
                        "target": token[:40] + "..." if token else "unknown",
                        "timestamp": _now_iso(),
                    })

        issues = record.get("issues", [])
        if isinstance(issues, list):
            for issue in issues:
                key = f"json-issue:{issue}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"JWT issue: {issue}",
                        "severity": "high",
                        "description": f"jwt_tool identified issue: {issue}",
                        "evidence": issue,
                        "tool": "jwt_tool",
                        "target": token[:40] + "..." if token else "unknown",
                        "timestamp": _now_iso(),
                    })

        if record.get("signature_valid") is not None:
            sv = record["signature_valid"]
            key = f"json-sig:{sv}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": "JWT signature verification",
                    "severity": "info" if sv else "high",
                    "description": f"Signature verification: {'passed' if sv else 'failed'}",
                    "evidence": f"valid: {sv}",
                    "tool": "jwt_tool",
                    "target": token[:40] + "..." if token else "unknown",
                    "timestamp": _now_iso(),
                })

        return findings
