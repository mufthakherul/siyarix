"""Command interpreter — classifies natural language instructions into structured tasks.

Provides heuristic-based rule interpretation for the execution engine.
The interpreter handles common security patterns without requiring a 
language model, while also supporting task classification for 
autonomous execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

class TaskCategory(StrEnum):
    """High-level categories for interpreted tasks."""

    SCAN = "scan"
    RECON = "recon"
    EXPLOIT = "exploit"
    ANALYZE = "analyze"
    REPORT = "report"
    MONITOR = "monitor"
    COMPLIANCE = "compliance"
    CLOUD = "cloud"
    CONFIG = "config"
    WORKFLOW = "workflow"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

@dataclass
class InterpretedTask:
    """Structured representation of an interpreted user instruction."""

    category: TaskCategory
    action: str
    targets: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    flags: dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    confidence: float = 0.0
    sub_tasks: list[InterpretedTask] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output or processing context."""
        return {
            "category": self.category.value,
            "action": self.action,
            "targets": self.targets,
            "tools": self.tools,
            "flags": self.flags,
            "raw_text": self.raw_text,
            "confidence": self.confidence,
            "sub_tasks": [s.to_dict() for s in self.sub_tasks],
        }

# ---------------------------------------------------------------------------
# Pattern definitions for heuristic-based interpretation
# ---------------------------------------------------------------------------

_TARGET_PATTERN = re.compile(
    r"""
    (?:(?:against|on|at|for|target|host|scan)\s+)?  # optional action prefix
    (
        \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}         # IPv4 address (e.g. 192.168.1.1)
        (?:/\d{1,2})?                                 # optional CIDR notation (e.g. /24)
        |
        (?:https?://)?                                # optional URL scheme (http:// or https://)
        [a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?  # hostname label (RFC 1123)
        (?:\.[a-zA-Z]{2,})+                           # one or more TLD segments (e.g. .com, .co.uk)
        (?::\d+)?                                     # optional port number (e.g. :8080)
        (?:/[^\s]*)?                                  # optional URL path (e.g. /api/v1)
    )
    """,
    re.VERBOSE,
)

_TOOL_ALIASES: dict[str, str] = {
    "nmap": "nmap",
    "port scan": "nmap",
    "port scanner": "nmap",
    "network scan": "nmap",
    "nikto": "nikto",
    "web scan": "nikto",
    "web scanner": "nikto",
    "nuclei": "nuclei",
    "vuln scan": "nuclei",
    "vulnerability scan": "nuclei",
    "template scan": "nuclei",
    "gobuster": "gobuster",
    "directory scan": "gobuster",
    "dir enum": "gobuster",
    "dirbusting": "gobuster",
    "sqlmap": "sqlmap",
    "sql injection": "sqlmap",
    "sqli": "sqlmap",
    "ffuf": "ffuf",
    "fuzzing": "ffuf",
    "fuzz": "ffuf",
    "masscan": "masscan",
    "fast scan": "masscan",
    "wpscan": "wpscan",
    "wordpress": "wpscan",
    "hydra": "hydra",
    "brute force": "hydra",
    "bruteforce": "hydra",
    "password attack": "hydra",
    "hashcat": "hashcat",
    "hash crack": "hashcat",
    "john": "john",
    "john the ripper": "john",
    "password crack": "john",
    "metasploit": "msfconsole",
    "msfconsole": "msfconsole",
    "exploit": "msfconsole",
    "zaproxy": "zap.sh",
    "zap": "zap.sh",
    "owasp zap": "zap.sh",
    "burp": "burpsuite",
    "burpsuite": "burpsuite",
    "burp suite": "burpsuite",
    "rustscan": "rustscan",
    "feroxbuster": "feroxbuster",
    "trufflehog": "trufflehog",
    "secret scan": "trufflehog",
    "playwright": "playwright",
    "live test": "playwright",
    "browser test": "playwright",
    "pytest": "pytest",
    "test": "pytest",
    "unit test": "pytest",
}

_SCAN_KEYWORDS = {
    "scan",
    "check",
    "probe",
    "discover",
    "detect",
    "find",
    "enumerate",
    "test",
    "audit",
    "assess",
    "inspect",
    "investigate",
    "look for",
    "search for",
}

_RECON_KEYWORDS = {
    "recon",
    "reconnaissance",
    "discover",
    "enumerate",
    "map",
    "footprint",
    "gather",
    "information gathering",
    "osint",
}

_EXPLOIT_KEYWORDS = {
    "exploit",
    "attack",
    "penetrate",
    "pwn",
    "hack",
    "breach",
    "crack",
    "brute",
}

_ANALYZE_KEYWORDS = {
    "analyze",
    "analyse",
    "explain",
    "summarize",
    "summary",
    "correlate",
    "compare",
    "review",
    "interpret",
    "understand",
}

_REPORT_KEYWORDS = {
    "report",
    "export",
    "generate",
    "document",
    "pdf",
    "html",
    "markdown",
    "save",
}

_MONITOR_KEYWORDS = {
    "monitor",
    "watch",
    "alert",
    "continuous",
    "dashboard",
    "live",
    "stream",
    "real-time",
}

_WORKFLOW_KEYWORDS = {
    "workflow",
    "pipeline",
    "automate",
    "chain",
    "sequence",
    "then",
    "and then",
    "after that",
    "followed by",
    "next",
    "finally",
}

_INTENSITY_PATTERNS: dict[str, dict[str, Any]] = {
    "quick": {"depth": "fast", "timeout": 60},
    "fast": {"depth": "fast", "timeout": 60},
    "deep": {"depth": "thorough", "timeout": 1800},
    "thorough": {"depth": "thorough", "timeout": 1800},
    "full": {"depth": "thorough", "timeout": 1800},
    "comprehensive": {"depth": "thorough", "timeout": 1800},
    "aggressive": {"depth": "aggressive", "timeout": 3600},
    "stealth": {"depth": "stealth", "timing": "slow"},
    "quiet": {"depth": "stealth", "timing": "slow"},
}

class RuleInterpreter:
    """Heuristic interpreter for common security command patterns.

    This component provides fast, deterministic command interpretation
    and works completely offline without any model dependencies.
    """

    def interpret(self, text: str) -> InterpretedTask:
        """Interpret natural language *text* into a structured :class:`InterpretedTask`."""
        text_lower = text.lower().strip()

        # Check for multi-step workflows (contains "then", "and then", etc.)
        if self._is_workflow(text_lower):
            return self._interpret_workflow(text, text_lower)

        # Single task
        return self._interpret_single(text, text_lower)

    def _is_workflow(self, text_lower: str) -> bool:
        """Detect if the text describes a multi-step workflow."""
        workflow_connectors = [" then ", " and then ", " after that ", " followed by ", " next "]
        return any(conn in text_lower for conn in workflow_connectors)

    def _interpret_workflow(self, raw: str, text_lower: str) -> InterpretedTask:
        """Split a multi-step instruction into sub-tasks."""
        # Split on workflow connectors
        parts = re.split(
            r"\s+(?:then|and then|after that|followed by|next|finally)\s+",
            text_lower,
        )
        sub_tasks = [self._interpret_single(part.strip(), part.strip().lower()) for part in parts]

        return InterpretedTask(
            category=TaskCategory.WORKFLOW,
            action="multi_step",
            targets=list({t for si in sub_tasks for t in si.targets}),
            tools=list({t for si in sub_tasks for t in si.tools}),
            raw_text=raw,
            confidence=min(si.confidence for si in sub_tasks) if sub_tasks else 0.0,
            sub_tasks=sub_tasks,
        )

    def _interpret_single(self, raw: str, text_lower: str) -> InterpretedTask:
        """Interpret a single instruction from text."""
        category = self._classify_category(text_lower)
        targets = self._extract_targets(raw)
        tools = self._extract_tools(text_lower)
        flags = self._extract_flags(text_lower)
        action = self._infer_action(text_lower, category, tools)

        # Calculate confidence based on how much we could interpret
        confidence = self._calculate_confidence(category, targets, tools, flags)

        return InterpretedTask(
            category=category,
            action=action,
            targets=targets,
            tools=tools,
            flags=flags,
            raw_text=raw,
            confidence=confidence,
        )

    def _classify_category(self, text_lower: str) -> TaskCategory:
        """Classify the instruction into a high-level task category."""
        words = set(text_lower.split())

        # Check in priority order
        if words & _WORKFLOW_KEYWORDS:
            return TaskCategory.WORKFLOW
        if words & _EXPLOIT_KEYWORDS:
            return TaskCategory.EXPLOIT
        if words & _ANALYZE_KEYWORDS:
            return TaskCategory.ANALYZE
        if words & _REPORT_KEYWORDS:
            return TaskCategory.REPORT
        if words & _MONITOR_KEYWORDS:
            return TaskCategory.MONITOR
        if words & _RECON_KEYWORDS:
            return TaskCategory.RECON
        if words & _SCAN_KEYWORDS:
            return TaskCategory.SCAN

        # Check for tool names that imply scanning
        for alias in _TOOL_ALIASES:
            if alias in text_lower:
                return TaskCategory.SCAN

        return TaskCategory.UNKNOWN

    def _extract_targets(self, text: str) -> list[str]:
        """Extract target hosts/IPs/URLs from the instruction."""
        matches = _TARGET_PATTERN.findall(text)
        # Deduplicate while preserving order
        seen: set[str] = set()
        targets: list[str] = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                targets.append(m)
        return targets

    def _extract_tools(self, text_lower: str) -> list[str]:
        """Extract tool names from instruction using alias mapping."""
        found: list[str] = []
        seen: set[str] = set()

        # Sort aliases by length (longest first) to avoid partial matches
        for alias in sorted(_TOOL_ALIASES, key=len, reverse=True):
            if alias in text_lower and _TOOL_ALIASES[alias] not in seen:
                tool = _TOOL_ALIASES[alias]
                seen.add(tool)
                found.append(tool)

        return found

    def _extract_flags(self, text_lower: str) -> dict[str, Any]:
        """Extract instruction flags and intensity modifiers."""
        flags: dict[str, Any] = {}

        for keyword, settings in _INTENSITY_PATTERNS.items():
            if keyword in text_lower:
                flags.update(settings)
                break

        # Detect "all tools" / "everything"
        if any(p in text_lower for p in ["all tools", "everything", "all available"]):
            flags["all_tools"] = True

        # Detect output format preferences
        for fmt in ["json", "xml", "csv", "html", "pdf", "sarif"]:
            if fmt in text_lower:
                flags["output_format"] = fmt

        return flags

    def _infer_action(self, text_lower: str, category: TaskCategory, tools: list[str]) -> str:
        """Infer a specific action verb."""
        if category == TaskCategory.SCAN:
            if tools:
                return f"run_{tools[0]}"
            return "scan_target"
        if category == TaskCategory.RECON:
            return "reconnaissance"
        if category == TaskCategory.EXPLOIT:
            return "exploit_target"
        if category == TaskCategory.ANALYZE:
            return "analyze_findings"
        if category == TaskCategory.REPORT:
            return "generate_report"
        if category == TaskCategory.MONITOR:
            return "monitor_target"
        return "execute"

    def _calculate_confidence(
        self,
        category: TaskCategory,
        targets: list[str],
        tools: list[str],
        flags: dict[str, Any],
    ) -> float:
        """Estimate interpretation confidence (0.0–1.0)."""
        score = 0.0

        if category != TaskCategory.UNKNOWN:
            score += 0.3
        if targets:
            score += 0.3
        if tools:
            score += 0.25
        if flags:
            score += 0.15

        return min(score, 1.0)
