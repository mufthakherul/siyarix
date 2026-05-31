# SPDX-License-Identifier: AGPL-3.0-or-later

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
    "rustscan": "rustscan",
    "feroxbuster": "feroxbuster",
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
    # OSINT
    "amass": "amass",
    "subfinder": "subfinder",
    "subdomain": "subfinder",
    "subdomain enum": "subfinder",
    "theharvester": "theHarvester",
    "email harvest": "theHarvester",
    "osint": "amass",
    "httpx": "httpx",
    "http probe": "httpx",
    "dnsx": "dnsx",
    "dns brute": "dnsx",
    "trufflehog": "trufflehog",
    "secret scan": "trufflehog",
    "gitleaks": "gitleaks",
    "playwright": "playwright",
    "live test": "playwright",
    "browser test": "playwright",
    "pytest": "pytest",
    "unit test": "pytest",
    # Infra / Cloud
    "kubectl": "kubectl",
    "kubernetes": "kubectl",
    "helm": "helm",
    "terraform": "terraform",
    "ansible": "ansible",
    "docker": "docker",
    "podman": "podman",
    "aws": "aws",
    "azure": "az",
    "az": "az",
    "gcloud": "gcloud",
    # Whois / DNS recon
    "whois": "whois",
    "whois lookup": "whois",
    "whois check": "whois",
    "whois domain": "whois",
    # Directory enumeration
    "directory enumeration": "gobuster",
    "directory enum": "gobuster",
    "dir enumeration": "gobuster",
    "dir busting": "gobuster",
    # Web vulnerability scanning
    "web vulnerability": "nuclei",
    "web vulnerabilities": "nuclei",
    "vulnerability check": "nuclei",
    "web app scan": "nikto",
    "web application scan": "nikto",
    "web security scan": "nikto",
    "web security check": "nikto",
    # Network tools
    "ifconfig": "ifconfig",
    "ip addr": "ip",
    "network interface": "ifconfig",
    "traceroute": "traceroute",
    "trace route": "traceroute",
    "dig": "dig",
    "dns lookup": "dig",
    "nslookup": "nslookup",
    # System tools
    "uname": "uname",
    "system info": "uname",
    "system information": "uname",
    "uptime": "uptime",
    "disk usage": "df",
    "memory usage": "free",
    "process list": "ps",
    "running processes": "ps",
}

_SCAN_KEYWORDS = {
    "scan",
    "check",
    "probe",
    "discover",
    "detect",
    "find",
    "enumerate",
    "audit",
    "assess",
    "inspect",
    "investigate",
    "look for",
    "search for",
    "identify",
    "fingerprint",
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

_CLOUD_KEYWORDS = {
    "cloud",
    "aws",
    "azure",
    "gcp",
    "kubernetes",
    "cluster",
    "terraform",
    "ansible",
    "helm",
}

_COMPLIANCE_KEYWORDS = {
    "compliance",
    "audit",
    "policy",
    "baseline",
    "cis",
    "nist",
}

_CONFIG_KEYWORDS = {
    "configure",
    "config",
    "setup",
    "install",
    "update",
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


_INTENT_PATTERNS: dict[str, list[str]] = {
    "current_directory": [
        "pwd",
        "current directory",
        "current folder",
        "present directory",
    ],
    "list_files": ["list files", "show files", "list directory", "dir", "ls"],
    "list_processes": [
        "list processes",
        "show processes",
        "running processes",
        "ps aux",
        "ps",
    ],
    "process_tree": ["process tree", "pstree"],
    "network_connections": [
        "network connections",
        "show connections",
        "list connections",
        "active connections",
        "netstat",
    ],
    "open_ports": ["open ports", "listening ports", "ports"],
    "network_interfaces": [
        "network interfaces",
        "show interfaces",
        "list interfaces",
        "ip addr",
        "ifconfig",
        "ipconfig",
    ],
    "routing_table": ["routing table", "route table", "show routes", "routing"],
    "arp_table": ["arp table", "arp cache", "show arp"],
    "dns_lookup": ["dns lookup", "nslookup", "resolve dns", "dns query"],
    "dns_cache": ["dns cache", "dns client cache", "show dns cache", "displaydns"],
    "whoami": ["whoami", "current user", "show privileges", "my user", "who am i"],
    "environment_vars": ["environment variables", "env vars", "printenv", "show env"],
    "firewall_rules": [
        "firewall rules",
        "firewall config",
        "iptables",
        "show firewall",
    ],
    "scheduled_tasks": ["scheduled tasks", "cron jobs", "cron", "schtasks"],
    "services": ["running services", "list services", "systemctl", "show services"],
    "users": ["local users", "list users", "show users", "user accounts"],
    "groups": ["local groups", "list groups", "show groups"],
    "installed_software": [
        "installed software",
        "installed programs",
        "installed apps",
    ],
    "package_managers": ["package managers", "winget", "choco", "apt"],
    "system_info": ["system info", "system information", "os info", "uname"],
    "disk_usage": ["disk usage", "disk space", "df -h"],
    "disk_free": ["disk free"],
    "file_hash": ["file hash", "sha256sum", "checksum"],
    "find_suid": ["suid files", "privileged files", "find suid", "setuid"],
    "registry_autoruns": ["registry autoruns", "autoruns", "startup programs"],
    "host_file": ["hosts file", "cat /etc/hosts"],
    "ping": ["ping"],
    "traceroute": ["traceroute", "tracert"],
    "git_status": ["git status"],
    "git_branches": ["git branch", "git branches"],
    "docker_ps": ["docker ps", "docker containers", "running containers"],
    "docker_images": ["docker images"],
    "kubectl_get_pods": ["kubectl get pods", "kubernetes pods", "get pods"],
    "kubectl_contexts": ["kubectl contexts", "kubernetes contexts"],
    "helm_list": ["helm releases", "helm list"],
    "terraform_plan": ["terraform plan"],
    "aws_identity": ["aws identity", "aws caller identity", "aws whoami"],
    "az_account": ["az account", "azure account"],
    "gcloud_auth": ["gcloud auth", "gcp auth"],
    "ssh_connect": ["ssh connect", "ssh to"],
    "scp_copy": ["scp copy", "scp to"],
    "rsync_copy": ["rsync copy", "rsync to"],
    "python_version": ["python version"],
    "node_version": ["node version"],
    "pip_list": ["pip list", "python packages"],
    "whois_lookup": [
        "whois",
        "whois lookup",
        "whois check",
        "whois domain",
        "domain info",
        "domain registration",
    ],
    "dir_enum": [
        "directory enumeration",
        "directory enum",
        "dir enumeration",
        "dirbusting",
        "directory busting",
        "web directory scan",
        "directory brute force",
    ],
    "web_vuln_scan": [
        "web vulnerabilities",
        "web vulnerability",
        "web vulnerability check",
        "web app vulnerabilities",
        "web security check",
        "web security scan",
        "check web vulnerabilities",
        "find web vulnerabilities",
    ],
    "subdomain_enum": [
        "subdomain enumeration",
        "subdomain enum",
        "subdomain scan",
        "subdomain discovery",
        "find subdomains",
        "enumerate subdomains",
    ],
    "password_crack": [
        "password crack",
        "crack password",
        "hash crack",
        "crack hash",
        "brute force password",
    ],
    "sql_injection": [
        "sql injection",
        "sqli test",
        "sql injection test",
        "sqli scan",
        "sql vulnerability",
    ],
}


_INTENT_TOOLS: dict[str, str] = {
    "whois_lookup": "whois",
    "dir_enum": "gobuster",
    "web_vuln_scan": "nuclei",
    "subdomain_enum": "subfinder",
    "sql_injection": "sqlmap",
    "password_crack": "john",
    "dns_lookup": "dig",
    "open_ports": "nmap",
    "network_interfaces": "ifconfig",
    "system_info": "uname",
    "traceroute": "traceroute",
    "ping": "ping",
}


class RuleInterpreter:
    """Heuristic interpreter for common security command patterns.

    This component provides fast, deterministic command interpretation
    and works completely offline without any model dependencies.
    """

    def _match_custom_intent(self, text_lower: str) -> tuple[str | None, float]:
        """Match natural language command to cross-platform command intents in shell_knowledge."""
        best_intent = None
        longest_match_len = 0

        for intent, patterns in _INTENT_PATTERNS.items():
            for pat in patterns:
                # Use regex with word boundaries to ensure we don't match substrings like 'ps' in 'https'
                pattern_regex = r"\b" + re.escape(pat) + r"\b"
                if re.search(pattern_regex, text_lower):
                    if len(pat) > longest_match_len:
                        longest_match_len = len(pat)
                        best_intent = intent

        if best_intent:
            return best_intent, 0.9
        return None, 0.0

    def interpret(self, text: str) -> InterpretedTask:
        """Interpret natural language *text* into a structured :class:`InterpretedTask`."""
        text_lower = text.lower().strip()

        # 1. Check for conditional: "if <condition> then <actions> [else <actions>]"
        if text_lower.startswith("if "):
            match = re.match(r"^if\s+(.+?)\s+then\s+(.+)$", text_lower, re.DOTALL)
            if match:
                cond_str = match.group(1).strip()
                rest = match.group(2).strip()
                else_parts = re.split(r"\s+else\s+", rest, maxsplit=1)
                then_raw = else_parts[0].strip()
                else_raw = else_parts[1].strip() if len(else_parts) > 1 else None

                then_task = self.interpret(then_raw)
                then_task.flags["branch"] = "then"

                sub_tasks = [then_task]
                if else_raw:
                    else_task = self.interpret(else_raw)
                    else_task.flags["branch"] = "else"
                    sub_tasks.append(else_task)

                return InterpretedTask(
                    category=TaskCategory.WORKFLOW,
                    action="conditional",
                    flags={"condition": cond_str},
                    raw_text=text,
                    confidence=0.95,
                    sub_tasks=sub_tasks,
                )

        # 2. Check for logic chains: "&&" or "||"
        if "&&" in text_lower or "||" in text_lower:
            tokens = re.split(r"\s+(&&|\|\|)\s+", text)
            sub_tasks = []
            first_task = self.interpret(tokens[0].strip())
            sub_tasks.append(first_task)

            for idx in range(1, len(tokens), 2):
                if idx + 1 < len(tokens):
                    op = tokens[idx].strip()
                    task_text = tokens[idx + 1].strip()
                    task = self.interpret(task_text)
                    task.flags["chain_op"] = op
                    sub_tasks.append(task)

            return InterpretedTask(
                category=TaskCategory.WORKFLOW,
                action="chain",
                targets=list({t for si in sub_tasks for t in si.targets}),
                tools=list({t for si in sub_tasks for t in si.tools}),
                raw_text=text,
                confidence=min(si.confidence for si in sub_tasks) if sub_tasks else 0.0,
                sub_tasks=sub_tasks,
            )

        # 3. Check for standard multi-step workflows (contains "then", "and then", etc.)
        if self._is_workflow(text_lower):
            return self._interpret_workflow(text, text_lower)

        # 4. Single task
        return self._interpret_single(text, text_lower)

    def _is_workflow(self, text_lower: str) -> bool:
        """Detect if the text describes a multi-step workflow."""
        workflow_connectors = [
            " then ",
            " and then ",
            " after that ",
            " followed by ",
            " next ",
        ]
        return any(conn in text_lower for conn in workflow_connectors)

    def _interpret_workflow(self, raw: str, text_lower: str) -> InterpretedTask:
        """Split a multi-step instruction into sub-tasks."""
        # Split on workflow connectors
        parts = re.split(
            r"\s+(?:then|and then|after that|followed by|next|finally)\s+",
            text_lower,
        )
        sub_tasks = [self.interpret(part.strip()) for part in parts]

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
        intent, intent_conf = self._match_custom_intent(text_lower)
        if intent:
            targets = self._extract_targets(raw)
            # Map intent to tool if available
            intent_tool = _INTENT_TOOLS.get(intent)
            tools = [intent_tool] if intent_tool else self._extract_tools(text_lower)
            return InterpretedTask(
                category=TaskCategory.CUSTOM,
                action=intent,
                targets=targets,
                tools=tools,
                flags={"intent": intent},
                raw_text=raw,
                confidence=intent_conf,
            )

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

        # First check multi-word keywords via substring matching (priority order)
        for kw in _WORKFLOW_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.WORKFLOW
        for kw in _RECON_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.RECON
        for kw in _SCAN_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.SCAN
        for kw in _EXPLOIT_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.EXPLOIT
        for kw in _ANALYZE_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.ANALYZE
        for kw in _REPORT_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.REPORT
        for kw in _MONITOR_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.MONITOR
        for kw in _COMPLIANCE_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.COMPLIANCE
        for kw in _CLOUD_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.CLOUD
        for kw in _CONFIG_KEYWORDS:
            if " " in kw and kw in text_lower:
                return TaskCategory.CONFIG

        # Then check single-word keywords via set intersection
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
        if words & _COMPLIANCE_KEYWORDS:
            return TaskCategory.COMPLIANCE
        if words & _CLOUD_KEYWORDS:
            return TaskCategory.CLOUD
        if words & _CONFIG_KEYWORDS:
            return TaskCategory.CONFIG
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

    def _infer_action(
        self, text_lower: str, category: TaskCategory, tools: list[str]
    ) -> str:
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
            score += 0.45
        if targets:
            score += 0.25
        if tools:
            score += 0.2
        if flags:
            score += 0.1

        return min(score, 1.0)
