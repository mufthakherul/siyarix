# SPDX-License-Identifier: AGPL-3.0-or-later

"""finger output parser — parses user information disclosure results (varied output formats)."""

from __future__ import annotations

import json
import re

from . import _now_iso

_LOGIN_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<terminal>\S+)\s+(?P<idle>\S+)\s+(?P<login_time>.+?)\s+(?P<host>\S.*)",
)

_LOGIN_SHORT_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<terminal>\S+)\s+(?P<idle>\S+)\s+(?P<login_time>.+)",
)

_DETAIL_RE = re.compile(
    r"^(?P<label>[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s*[:\-]+\s*(?P<value>.+)",
)

_PLAN_RE = re.compile(
    r"^Plan\s*[:\-]?\s*$",
    re.IGNORECASE,
)

_PROJECT_RE = re.compile(
    r"^Project\s*[:\-]?\s*$",
    re.IGNORECASE,
)

_IDLE_RE = re.compile(
    r"^(\d+)\s*$|^(\d+):(\d+)\s*$|^(\d+)d\s*$|^(\d+):(\d+):(\d+)\s*$",
)

_LOGIN_HEADER_RE = re.compile(
    r"^Login\s+Name\s+Tty\s+Idle",
    re.IGNORECASE,
)

_DETAIL_LABELS = {
    "login", "name", "directory", "shell", "office",
    "phone", "room", "home phone",
}

_JSON_RE = re.compile(r"^\s*[{\[]")


class FingerParser:
    """Parse finger output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen_users: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    user = item.get("user", item.get("login", item.get("username", "")))
                    realname = item.get("name", item.get("realname", ""))
                    home = item.get("home", item.get("directory", ""))
                    shell = item.get("shell", "")
                    if user:
                        target = item.get("host", item.get("target", "unknown"))
                        if user in seen_users:
                            continue
                        seen_users.add(user)
                        findings.append({
                            "title": f"User info: {user}",
                            "severity": "medium",
                            "description": f"finger returned user info for {user}: realname={realname} home={home} shell={shell}",
                            "evidence": json.dumps(item),
                            "tool": "finger",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                    plan = item.get("plan", item.get("plan_file", ""))
                    if plan:
                        findings.append({
                            "title": f"Plan file: {user}",
                            "severity": "medium",
                            "description": f"finger retrieved plan file for user {user}",
                            "evidence": plan[:500],
                            "tool": "finger",
                            "target": item.get("host", "unknown"),
                            "timestamp": _now_iso(),
                        })
                return findings
            except json.JSONDecodeError:
                pass

        target = "unknown"
        in_plan = False
        plan_lines: list[str] = []
        current_user = "unknown"

        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                in_plan = False
                if plan_lines:
                    plan_content = "\n".join(plan_lines)
                    findings.append({
                        "title": f"Plan file: {current_user}",
                        "severity": "medium",
                        "description": f"finger retrieved plan file for user {current_user} on {target}:\n{plan_content[:200]}",
                        "evidence": plan_content,
                        "tool": "finger",
                        "target": target,
                        "timestamp": _now_iso(),
                    })
                    plan_lines = []
                continue

            if "finger: " in line.lower() or "cannot" in line.lower() or "no such" in line.lower():
                findings.append({
                    "title": "finger lookup failed",
                    "severity": "low",
                    "description": line,
                    "evidence": line,
                    "tool": "finger",
                    "target": target,
                    "timestamp": _now_iso(),
                })
                continue

            if _PLAN_RE.match(line):
                in_plan = True
                continue

            if in_plan:
                plan_lines.append(line)
                continue

            if _PROJECT_RE.match(line):
                continue

            if _LOGIN_HEADER_RE.match(line):
                continue

            fields = line.split()
            if len(fields) >= 5 and not fields[0].startswith("Login"):
                m = _LOGIN_RE.match(line)
                if m:
                    username = m.group("name")
                    host = m.group("host")
                    idle_raw = m.group("idle")
                    idle_desc = ""
                    im = _IDLE_RE.match(idle_raw)
                    if im:
                        groups = im.groups()
                        if groups[0] and not groups[1] and not groups[2]:
                            idle_desc = f"{groups[0]} minutes"
                        elif groups[1] and groups[2]:
                            idle_desc = f"{groups[1]}h {groups[2]}m"
                        elif groups[3]:
                            idle_desc = f"{groups[3]} days"
                        elif groups[4] and groups[5] and groups[6]:
                            idle_desc = f"{groups[4]}d {groups[5]}h {groups[6]}m"
                        else:
                            idle_desc = idle_raw
                    else:
                        idle_desc = idle_raw

                    if username not in seen_users:
                        seen_users.add(username)
                        findings.append({
                            "title": f"Logged-in user: {username}",
                            "severity": "medium",
                            "description": f"finger discovered user {username} logged in from {host} on {target} (idle: {idle_desc})",
                            "evidence": f"user: {username} host: {host} idle: {idle_desc} terminal: {m.group('terminal')}",
                            "tool": "finger",
                            "target": target,
                            "timestamp": _now_iso(),
                        })
                    current_user = username
                    continue

                if len(fields) >= 4:
                    m = _LOGIN_SHORT_RE.match(line)
                    if m:
                        username = m.group("name")
                        idle_raw = m.group("idle")
                        if username not in seen_users:
                            seen_users.add(username)
                            findings.append({
                                "title": f"Logged-in user: {username}",
                                "severity": "medium",
                                "description": f"finger discovered user {username} logged in on {target} (idle: {idle_raw})",
                                "evidence": f"user: {username} idle: {idle_raw}",
                                "tool": "finger",
                                "target": target,
                                "timestamp": _now_iso(),
                            })
                        current_user = username
                        continue

            m = _DETAIL_RE.match(line)
            if m:
                label = m.group("label").lower()
                value = m.group("value").strip()
                if label in _DETAIL_LABELS:
                    if label == "login":
                        current_user = value
                    sev = "info" if label in ("directory", "shell", "office", "phone", "room", "home phone") else "medium"
                    findings.append({
                        "title": f"User {label}: {value}",
                        "severity": sev,
                        "description": f"finger returned user detail: {label} = {value}",
                        "evidence": f"{label}: {value}",
                        "tool": "finger",
                        "target": target,
                        "timestamp": _now_iso(),
                    })

        if plan_lines:
            plan_content = "\n".join(plan_lines)
            findings.append({
                "title": f"Plan file: {current_user}",
                "severity": "medium",
                "description": f"finger retrieved plan file for user {current_user} on {target}:\n{plan_content[:200]}",
                "evidence": plan_content,
                "tool": "finger",
                "target": target,
                "timestamp": _now_iso(),
            })

        return findings
