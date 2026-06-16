# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hash-identifier output parser — extracts hash type and possible algorithm matches."""

from __future__ import annotations

from . import _now_iso

import re

_HASH_TYPE_RE = re.compile(r"(?:Hash|hash)[:\s]+(\S+)", re.IGNORECASE)
_POSSIBLE_RE = re.compile(r"(?:Possible|algorithm|type)[:\s]+(.+)", re.IGNORECASE)
_LINE_RE = re.compile(r"^\s*[+\-*]\s*(.*)")
_SUMMARY_RE = re.compile(
    r"(?:Total|Analyzed|Found)[:\s]*(\d+)",
    re.IGNORECASE,
)


class HashIdentifierParser:
    """Parse hash-identifier output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        target = "unknown"
        output.splitlines()
        summary_match = _SUMMARY_RE.search(output)
        summary_count = summary_match.group(1) if summary_match else None

        for raw in output.splitlines():
            line_stripped = raw.strip()
            if not line_stripped:
                continue

            m = _HASH_TYPE_RE.match(line_stripped)
            if m:
                target = m.group(1).strip()
                key = f"hash:{target[:40]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Hash-identifier: Hash string — {target[:40]}",
                            "severity": "info",
                            "description": f"Hash value identified: {target[:60]}",
                            "evidence": raw,
                            "tool": "hash_identifier",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _POSSIBLE_RE.match(line_stripped)
            if m:
                algorithms = m.group(1).strip()
                key = f"possible:{algorithms[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": "Hash-identifier: Possible algorithm match",
                            "severity": "info",
                            "description": f"Possible hash algorithms: {algorithms}",
                            "evidence": raw,
                            "tool": "hash_identifier",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _LINE_RE.match(line_stripped)
            if m and any(
                kw in line_stripped.lower()
                for kw in (
                    "md5",
                    "sha",
                    "ntlm",
                    "bcrypt",
                    "sha1",
                    "sha256",
                    "sha512",
                    "ripemd",
                    "whirlpool",
                    "gost",
                    "lm",
                    "mysql",
                    "postgres",
                )
            ):
                algorithm = m.group(1).strip()
                key = f"candidate:{algorithm}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"Hash-identifier: Candidate — {algorithm}",
                            "severity": "info",
                            "description": f"Hash may be {algorithm}",
                            "evidence": raw,
                            "tool": "hash_identifier",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

        if summary_count:
            key = "summary:total"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "title": f"Hash-identifier: {summary_count} candidates",
                        "severity": "info",
                        "description": f"Hash-identifier found {summary_count} algorithm candidates",
                        "evidence": f"Total: {summary_count}",
                        "tool": "hash_identifier",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
