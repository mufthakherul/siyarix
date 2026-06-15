# SPDX-License-Identifier: AGPL-3.0-or-later

"""Volatility memory forensics output parser — parses Volatility 3 JSON output."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_RE = re.compile(r"^\s*[{\[]")

_VOLATILITY_PLUGINS = {
    "windows.pslist": "process", "windows.psscan": "process",
    "windows.pstree": "process", "windows.netscan": "network",
    "windows.netstat": "network", "windows.cmdline": "command",
    "windows.cmdscan": "command", "windows.dlldump": "module",
    "windows.modscan": "module", "windows.malfind": "malware",
    "windows.hivelist": "registry", "windows.registry": "registry",
    "windows.filescan": "file", "windows.mftscan": "file",
    "windows.envars": "environment",
    "windows.privileges": "privilege", "windows.token": "token",
    "windows.callbacks": "callback", "windows.ssdt": "ssdt",
    "linux.pslist": "process", "linux.pstree": "process",
    "linux.netstat": "network", "linux.bash": "command",
    "linux.malfind": "malware", "mac.pslist": "process",
}

_SUMMARY_RE = re.compile(
    r"(?:finished|completed|scanned|total)[:\s]+(\d+)",
    re.IGNORECASE,
)


class VolatilityParser:
    """Parse Volatility 3 JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        if _JSON_RE.match(output):
            try:
                data = json.loads(output)
                columns = data.get("columns", [])
                rows = data.get("rows", [])
                plugin = data.get("plugin", {}).get("name", "unknown") if isinstance(data.get("plugin"), dict) else "unknown"

                if isinstance(rows, list) and isinstance(columns, list):
                    for row in rows:
                        if isinstance(row, list):
                            row_dict = dict(zip(columns, row))
                            self._process_row(plugin, row_dict, findings, seen)
            except json.JSONDecodeError:
                pass

        if not findings:
            for raw in output.splitlines():
                line = raw.strip()
                if not line:
                    continue
                if "scanned" in line.lower() or "finished" in line.lower():
                    continue
                key = f"raw:{line[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Volatility: {line[:60]}",
                        "severity": "info",
                        "description": line[:200],
                        "evidence": raw.strip(),
                        "tool": "volatility",
                        "target": "memory",
                        "timestamp": _now_iso(),
                    })

        return findings

    def _process_row(self, plugin: str, row: dict, findings: list, seen: set) -> None:
        plugin_type = _VOLATILITY_PLUGINS.get(plugin, "unknown")
        pid = row.get("PID", row.get("Pid", row.get("pid", "")))
        name = row.get("ImageFileName", row.get("Image", row.get("name", row.get("FileName", "?"))))
        offset = row.get("Offset", row.get("offset", ""))
        ppid = row.get("PPID", row.get("ppid", ""))

        if plugin_type == "process":
            suspicions = []
            if name and name.lower() in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
                suspicions.append("suspicious process")
            if name and name.lower() in ("mimikatz.exe", "procdump.exe", "pwdump.exe"):
                suspicions.append("known tool")
            severity = "medium" if suspicions else "info"
            key = f"proc:{pid}:{name}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"Process: {name} (PID: {pid})",
                    "severity": severity,
                    "description": f"Volatility discovered process {name} (PID {pid})"
                    + (" - " + ", ".join(suspicions) if suspicions else ""),
                    "evidence": f"PID: {pid} | Name: {name}" + (f" | PPID: {ppid}" if ppid else ""),
                    "tool": "volatility",
                    "target": "memory",
                    "timestamp": _now_iso(),
                })
        elif plugin_type == "network":
            proto = row.get("Proto", row.get("protocol", ""))
            local = row.get("LocalAddr", row.get("local", row.get("LocalAddress", "")))
            remote = row.get("ForeignAddr", row.get("remote", row.get("ForeignAddress", "")))
            state = row.get("State", row.get("state", ""))
            key = f"net:{local}:{remote}:{proto}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"Net: {local} <-> {remote} ({proto})",
                    "severity": "info",
                    "description": f"Volatility discovered {proto} connection: {local} -> {remote} [{state}]",
                    "evidence": f"Local: {local} | Remote: {remote} | State: {state}",
                    "tool": "volatility",
                    "target": "memory",
                    "timestamp": _now_iso(),
                })
        elif plugin_type == "malware":
            key = f"malware:{pid}:{name}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"Potential malware: {name} (PID: {pid})",
                    "severity": "high",
                    "description": f"Volatility malfind detected potential injected code in {name} (PID {pid})",
                    "evidence": f"PID: {pid} | Process: {name}" + (f" | Offset: {offset}" if offset else ""),
                    "tool": "volatility",
                    "target": "memory",
                    "timestamp": _now_iso(),
                })
        elif plugin_type == "file":
            key = f"file:{name}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"File: {name}",
                    "severity": "info",
                    "description": f"Volatility discovered file reference: {name}",
                    "evidence": f"File: {name} | Offset: {offset}",
                    "tool": "volatility",
                    "target": "memory",
                    "timestamp": _now_iso(),
                })
        elif plugin_type == "registry":
            key = f"reg:{name}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"Registry: {name}",
                    "severity": "info",
                    "description": f"Volatility discovered registry hive: {name}",
                    "evidence": f"Hive: {name} | Offset: {offset}",
                    "tool": "volatility",
                    "target": "memory",
                    "timestamp": _now_iso(),
                })
