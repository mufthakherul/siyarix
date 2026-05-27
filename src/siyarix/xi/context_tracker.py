"""XI Context Tracker — Real-time awareness of user operations and environment.

Tracks:
  • Current operation state (recon → scan → exploit → report)
  • Target inventory (IPs, domains, ports discovered)
  • Tool execution history within the session
  • Findings accumulation
  • User skill indicators
"""

from __future__ import annotations

import logging
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

__all__ = ["ContextTracker", "OperationPhase", "TrackedTarget"]

logger = logging.getLogger(__name__)


class OperationPhase:
    """Phases of a security operation lifecycle."""

    IDLE = "idle"
    RECON = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    REPORTING = "reporting"
    CLEANUP = "cleanup"

    _PHASE_ORDER = [
        IDLE,
        RECON,
        SCANNING,
        ENUMERATION,
        EXPLOITATION,
        POST_EXPLOIT,
        REPORTING,
        CLEANUP,
    ]

    @classmethod
    def next_phase(cls, current: str) -> str:
        """Suggest the next logical phase."""
        try:
            idx = cls._PHASE_ORDER.index(current)
            if idx < len(cls._PHASE_ORDER) - 1:
                return cls._PHASE_ORDER[idx + 1]
        except ValueError:
            pass
        return cls.IDLE


@dataclass
class TrackedTarget:
    """A target being tracked during a session."""

    address: str  # IP, hostname, or URL
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    findings_count: int = 0
    tools_used: list[str] = field(default_factory=list)
    os_guess: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class ToolExecution:
    """Record of a tool execution."""

    tool: str
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: float = 0.0
    success: bool = True
    findings_count: int = 0


class ContextTracker:
    """Real-time context awareness engine for Siyarix sessions."""

    def __init__(self) -> None:
        self._phase: str = OperationPhase.IDLE
        self._targets: dict[str, TrackedTarget] = {}
        self._executions: deque[ToolExecution] = deque(maxlen=500)
        self._tool_frequency: Counter[str] = Counter()
        self._total_findings: int = 0
        self._session_start: datetime = datetime.now()
        self._last_activity: datetime = datetime.now()
        self._command_count: int = 0

    # ── Phase tracking ─────────────────────────────────────────────────

    @property
    def phase(self) -> str:
        return self._phase

    def set_phase(self, phase: str) -> None:
        """Manually set the current operation phase."""
        self._phase = phase
        logger.debug("Operation phase: %s", phase)

    def auto_detect_phase(self, tool: str, command: str = "") -> str:
        """Auto-detect phase from tool/command being used."""
        tool_lower = tool.lower()
        cmd_lower = command.lower()

        recon_tools = {
            "whois",
            "dig",
            "nslookup",
            "theHarvester",
            "amass",
            "subfinder",
            "assetfinder",
        }
        scan_tools = {"nmap", "masscan", "rustscan", "zmap", "unicornscan"}
        enum_tools = {
            "gobuster",
            "ffuf",
            "dirb",
            "dirsearch",
            "nikto",
            "wpscan",
            "nuclei",
        }
        exploit_tools = {
            "sqlmap",
            "hydra",
            "john",
            "hashcat",
            "msfconsole",
            "metasploit",
        }

        if tool_lower in recon_tools or "recon" in cmd_lower:
            self._phase = OperationPhase.RECON
        elif tool_lower in scan_tools or "scan" in cmd_lower:
            self._phase = OperationPhase.SCANNING
        elif tool_lower in enum_tools or "enum" in cmd_lower:
            self._phase = OperationPhase.ENUMERATION
        elif tool_lower in exploit_tools or "exploit" in cmd_lower:
            self._phase = OperationPhase.EXPLOITATION
        elif "report" in cmd_lower:
            self._phase = OperationPhase.REPORTING

        return self._phase

    def suggest_next_phase(self) -> str:
        """Suggest the next logical operation phase."""
        return OperationPhase.next_phase(self._phase)

    # ── Target tracking ────────────────────────────────────────────────

    def track_target(self, address: str) -> TrackedTarget:
        """Add or update a tracked target."""
        if address not in self._targets:
            self._targets[address] = TrackedTarget(address=address)
        else:
            self._targets[address].last_seen = datetime.now()
        return self._targets[address]

    def add_port(self, address: str, port: int, service: str = "") -> None:
        """Record an open port on a target."""
        target = self.track_target(address)
        if port not in target.open_ports:
            target.open_ports.append(port)
        if service and service not in target.services:
            target.services.append(service)

    def add_finding(self, address: str, tool: str) -> None:
        """Record a finding against a target."""
        target = self.track_target(address)
        target.findings_count += 1
        if tool not in target.tools_used:
            target.tools_used.append(tool)
        self._total_findings += 1

    @property
    def targets(self) -> dict[str, TrackedTarget]:
        return self._targets

    @property
    def total_findings(self) -> int:
        return self._total_findings

    # ── Execution tracking ─────────────────────────────────────────────

    def record_execution(
        self,
        tool: str,
        target: str = "",
        duration_ms: float = 0.0,
        success: bool = True,
        findings_count: int = 0,
    ) -> None:
        """Record a tool execution."""
        self._command_count += 1
        self._last_activity = datetime.now()
        self._tool_frequency[tool] += 1

        exec_record = ToolExecution(
            tool=tool,
            target=target,
            duration_ms=duration_ms,
            success=success,
            findings_count=findings_count,
        )
        self._executions.append(exec_record)

        if target:
            self.track_target(target)
            for _ in range(findings_count):
                self.add_finding(target, tool)

        self.auto_detect_phase(tool)

    @property
    def command_count(self) -> int:
        return self._command_count

    @property
    def most_used_tools(self) -> list[tuple[str, int]]:
        return self._tool_frequency.most_common(10)

    @property
    def recent_executions(self) -> list[ToolExecution]:
        return list(self._executions)[-20:]

    # ── Session stats ──────────────────────────────────────────────────

    @property
    def session_duration_seconds(self) -> float:
        return (datetime.now() - self._session_start).total_seconds()

    @property
    def idle_seconds(self) -> float:
        return (datetime.now() - self._last_activity).total_seconds()

    def summary(self) -> dict[str, Any]:
        """Build a context summary dict."""
        return {
            "phase": self._phase,
            "targets_count": len(self._targets),
            "total_findings": self._total_findings,
            "commands_run": self._command_count,
            "session_duration_s": round(self.session_duration_seconds),
            "idle_s": round(self.idle_seconds),
            "top_tools": self.most_used_tools[:5],
            "suggested_next": self.suggest_next_phase(),
            "targets": {
                addr: {
                    "ports": t.open_ports[:10],
                    "services": t.services[:5],
                    "findings": t.findings_count,
                }
                for addr, t in list(self._targets.items())[:10]
            },
        }

    def reset(self) -> None:
        """Reset the tracker for a new operation."""
        self._phase = OperationPhase.IDLE
        self._targets.clear()
        self._executions.clear()
        self._tool_frequency.clear()
        self._total_findings = 0
        self._command_count = 0
        self._session_start = datetime.now()
        self._last_activity = datetime.now()
