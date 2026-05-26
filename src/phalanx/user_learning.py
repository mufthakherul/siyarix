"""
User Learning — Pedagogical output engine per Chapter 10.2.

Features:
  • Educational step-by-step breakdown: "What happened" / "What it means"
  • CVE and vulnerability explanations in plain language
  • Interactive drill-down: "Would you like a detailed explanation of any step?"
  • Experience auto-detection from usage patterns
  • Milestone achievement system
  • Multi-session history with analytics
  • Preference learning and adaptation
  • Integration with XI SkillProfiler
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

logger = logging.getLogger(__name__)

_PHALANX_HOME = Path.home() / ".phalanx"
_LEARNING_DIR = _PHALANX_HOME / "learning"
_MEMORY_DIR = _PHALANX_HOME / "memory"

# ── Tool categories for diversity tracking ───────────────────────────────
_TOOL_CATEGORIES: dict[str, str] = {
    "nmap": "recon",
    "masscan": "recon",
    "whois": "recon",
    "dig": "recon",
    "nslookup": "recon",
    "theHarvester": "recon",
    "amass": "recon",
    "subfinder": "recon",
    "dnsx": "recon",
    "httpx": "recon",
    "waybackurls": "recon",
    "gau": "recon",
    "katana": "recon",
    "shodan": "recon",
    "gobuster": "web",
    "ffuf": "web",
    "nikto": "web",
    "wpscan": "web",
    "nuclei": "web",
    "sqlmap": "web",
    "zap": "web",
    "burpsuite": "web",
    "hydra": "exploit",
    "john": "exploit",
    "hashcat": "exploit",
    "msfconsole": "exploit",
    "bettercap": "exploit",
    "aircrack-ng": "wireless",
    "reaver": "wireless",
    "wifite": "wireless",
    "kismet": "wireless",
    "impacket": "exploit",
    "responder": "exploit",
    "crackmapexec": "exploit",
    "evil-winrm": "exploit",
    "bloodhound": "exploit",
    "volatility": "forensics",
    "binwalk": "forensics",
    "sleuthkit": "forensics",
    "docker": "infra",
    "kubectl": "infra",
    "terraform": "infra",
    "ansible": "infra",
}

# ── CVE educational database (curated) ───────────────────────────────────
_CVE_KNOWLEDGE: dict[str, dict] = {
    "CVE-2020-15778": {
        "description": "OpenSSH scp command injection",
        "impact": "Allows remote code execution via crafted filenames in scp",
        "affected": "OpenSSH <= 8.3p1",
        "mitigation": "Update OpenSSH or restrict scp usage",
    },
    "CVE-2021-23017": {
        "description": "nginx DNS resolver vulnerability",
        "impact": "Potential denial of service or memory disclosure",
        "affected": "nginx 0.6.18 - 1.20.0",
        "mitigation": "Upgrade nginx to 1.21.0+ or disable DNS resolver if unused",
    },
    "CVE-2021-41773": {
        "description": "Apache HTTP Server path traversal",
        "impact": "Directory traversal allowing file read outside document root",
        "affected": "Apache 2.4.49",
        "mitigation": "Upgrade to Apache 2.4.50+",
    },
    "CVE-2021-26855": {
        "description": "Exchange Server SSRF (ProxyLogon)",
        "impact": "Remote code execution via SSRF in Exchange",
        "affected": "Microsoft Exchange Server 2013/2016/2019",
        "mitigation": "Apply Microsoft security patches",
    },
    "CVE-2023-23397": {
        "description": "Microsoft Outlook elevation of privilege",
        "impact": "Attacker can trigger NTLM credential leak via calendar invite",
        "affected": "Microsoft Outlook for Windows",
        "mitigation": "Apply Microsoft patch or block TCP 445 outbound",
    },
    "MS17-010": {
        "description": "EternalBlue SMB vulnerability",
        "impact": "Remote code execution via SMBv1 -- used by WannaCry ransomware",
        "affected": "Windows 7/8/10, Server 2008/2012/2016",
        "mitigation": "Disable SMBv1 and apply MS17-010 patch",
    },
    "generic_ssh": {
        "description": "Exposed SSH service",
        "impact": "Potential brute-force or credential-stuffing attacks",
        "affected": "Any SSH server on the internet",
        "mitigation": "Use key-based auth, disable root login, change default port",
    },
    "generic_http": {
        "description": "Exposed web server",
        "impact": "Potential web application attacks, data exposure, defacement",
        "affected": "Any HTTP/HTTPS server",
        "mitigation": "Harden headers, WAF, regular security scanning",
    },
}

# ── Tool explainers for "what_happened" and "what_it_means" ──────────────
_TOOL_EXPLAINERS: dict[str, dict] = {
    "nmap": {
        "what_happened": "Nmap sent specially crafted packets to the target and analyzed the responses to determine which ports are open, what services are running, and the operating system.",
        "what_it_means": "Open ports are like unlocked doors -- each one is a potential way into the system. Services behind ports can have vulnerabilities.",
    },
    "nuclei": {
        "what_happened": "Nuclei matched the target's responses against thousands of vulnerability templates to find known security issues.",
        "what_it_means": "Nuclei found CVEs matching your target's software versions. Each match indicates a known, documented vulnerability with an assigned CVE identifier.",
    },
    "gobuster": {
        "what_happened": "Gobuster sent HTTP requests to common directory and file paths, checking which ones return a valid response instead of a 404.",
        "what_it_means": "Each discovered path is a hidden part of the web application that wasn't linked from the homepage. These often contain admin panels, backups, or configuration files.",
    },
    "nikto": {
        "what_happened": "Nikto tested the web server for over 7000 known dangerous files, outdated server software, and configuration issues.",
        "what_it_means": "Nikto findings highlight server-level weaknesses -- these aren't application bugs but infrastructure problems like default credentials or outdated software.",
    },
    "hydra": {
        "what_happened": "Hydra systematically tried thousands of username/password combinations against the target's login service to find valid credentials.",
        "what_it_means": "A successful login means the service allows weak or guessable passwords. This demonstrates why strong password policies and rate-limiting are essential.",
    },
    "sqlmap": {
        "what_happened": "SQLmap injected SQL commands into web parameters to test if the application properly sanitizes user input before database queries.",
        "what_it_means": "SQL injection allows attackers to read, modify, or delete database contents. This is one of the most critical web vulnerabilities.",
    },
    "subfinder": {
        "what_happened": "Subfinder queried dozens of passive DNS databases and certificate transparency logs to find subdomains without directly contacting the target.",
        "what_it_means": "Subdomains reveal the attack surface -- each one is a separate application or service that could have its own vulnerabilities.",
    },
    "theHarvester": {
        "what_happened": "theHarvester searched search engines, PGP key servers, and other public sources for email addresses, subdomains, and employee information.",
        "what_it_means": "Harvested emails can be used for phishing simulations or password spraying. Public data exposes organizational structure.",
    },
    "whois": {
        "what_happened": "Whois queried domain registration databases for ownership, contact, and nameserver information about the target domain.",
        "what_it_means": "Domain registration information can reveal the organization's name, address, and technical contacts -- useful for social engineering pretexts.",
    },
    "wpscan": {
        "what_happened": "WPScan checked the WordPress installation for known plugin/theme vulnerabilities, weak passwords, and configuration issues.",
        "what_it_means": "WordPress plugins are the most common attack vector -- each outdated plugin is a potential backdoor into the site.",
    },
    "ffuf": {
        "what_happened": "Ffuf sent brute-forced HTTP requests with various parameters, paths, and values to discover hidden endpoints and parameters.",
        "what_it_means": "Discovered endpoints may reveal API routes, admin panels, or debug interfaces not intended for public access.",
    },
}

_OPERATION_EXPLAINERS: dict[str, dict] = {
    "port_scan": {
        "what_happened": "The scanner sent probes to thousands of ports on the target to determine which are open and listening.",
        "what_it_means": "Each open port is a network service running on the target. Common ports like 22 (SSH), 80 (HTTP), and 443 (HTTPS) indicate standard services, while unusual ports may indicate custom applications or backdoors.",
    },
    "subdomain_enum": {
        "what_happened": "The tool searched through DNS records, certificate transparency logs, and search engine caches to find subdomains of the target domain.",
        "what_it_means": "Subdomains expand the attack surface. Development subdomains (dev., staging., admin.) often have weaker security than the main site.",
    },
    "web_scan": {
        "what_happened": "The web scanner tested the target's web server and applications against a database of known vulnerabilities and misconfigurations.",
        "what_it_means": "Web vulnerabilities typically fall into categories: injection (SQL, command), broken authentication, sensitive data exposure, and misconfiguration.",
    },
    "forensics": {
        "what_happened": "The forensic tool analyzed disk images or memory dumps for artifacts, deleted files, and evidence of compromise.",
        "what_it_means": "Forensic artifacts include deleted files, registry keys, prefetch files, event logs, and browser history -- each tells a part of the story.",
    },
    "exploit": {
        "what_happened": "The exploitation tool attempted to leverage a known vulnerability to gain unauthorized access or elevated privileges.",
        "what_it_means": "Successful exploitation means the target is vulnerable to a known attack. This must be documented and remediated immediately.",
    },
    "wireless": {
        "what_happened": "The wireless tool captured and analyzed Wi-Fi traffic to identify networks, connected devices, and security weaknesses.",
        "what_it_means": "Wireless vulnerabilities include weak encryption (WEP), WPS PIN attacks, and deauthentication attacks. WPA3 addresses many of these.",
    },
}


class ExperienceLevel:
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

    @classmethod
    def all(cls) -> list[str]:
        return [cls.NOVICE, cls.INTERMEDIATE, cls.ADVANCED, cls.EXPERT]

    @classmethod
    def auto_detect(cls, profile: UserProfile) -> str:
        score = min(profile.unique_tools * 3, 30)
        score += min(profile.category_count * 5, 20)
        score += min(profile.advanced_command_count * 5, 25)
        if profile.total_commands > 100:
            score += 15
        elif profile.total_commands > 50:
            score += 10
        elif profile.total_commands > 20:
            score += 5
        err = profile.error_rate if profile.total_commands > 0 else 0
        if err > 0.4:
            score -= 15
        elif err > 0.25:
            score -= 8
        elif err > 0.1:
            score -= 3
        score = max(0, min(100, score))
        if score >= 80:
            return cls.EXPERT
        if score >= 55:
            return cls.ADVANCED
        if score >= 30:
            return cls.INTERMEDIATE
        return cls.NOVICE


@dataclass
class SessionRecord:
    session_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    command_count: int = 0
    tools_used: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    findings_found: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    pedagogical_steps: int = 0

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "command_count": self.command_count,
            "tools_used": self.tools_used,
            "categories": self.categories,
            "findings_found": self.findings_found,
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 1),
            "pedagogical_steps": self.pedagogical_steps,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SessionRecord:
        return cls(
            **{k: v for k, v in data.items() if k in SessionRecord.__dataclass_fields__}
        )


@dataclass
class UserProfile:
    username: str = ""
    experience: str = ExperienceLevel.INTERMEDIATE
    auto_detect: bool = True
    total_commands: int = 0
    unique_tools: int = 0
    advanced_command_count: int = 0
    category_count: int = 0
    category_counts: dict[str, int] = field(default_factory=dict)
    error_rate: float = 0.0
    total_errors: int = 0
    total_findings: int = 0
    session_count: int = 0
    milestones: list[str] = field(default_factory=list)
    pedagogical_enabled: bool = False
    preferences: dict = field(
        default_factory=lambda: {
            "verbosity": "adaptive",
            "show_hints": True,
            "auto_confirm_safe": False,
            "output_format": "rich",
            "color_theme": "",
            "show_timestamps": True,
            "compact_mode": False,
        }
    )
    recent_tools: list[str] = field(default_factory=list)
    sessions: list[SessionRecord] = field(default_factory=list)
    updated_at: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "experience": self.experience,
            "auto_detect": self.auto_detect,
            "total_commands": self.total_commands,
            "unique_tools": self.unique_tools,
            "advanced_command_count": self.advanced_command_count,
            "category_count": self.category_count,
            "category_counts": self.category_counts,
            "error_rate": round(self.error_rate, 4),
            "total_errors": self.total_errors,
            "total_findings": self.total_findings,
            "session_count": self.session_count,
            "milestones": self.milestones,
            "pedagogical_enabled": self.pedagogical_enabled,
            "preferences": self.preferences,
            "recent_tools": self.recent_tools[-50:],
            "sessions": [s.to_dict() for s in self.sessions[-50:]],
            "updated_at": self.updated_at,
            "created_at": self.created_at or datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> UserProfile:
        sessions = [SessionRecord.from_dict(s) for s in data.get("sessions", [])]
        return cls(
            username=data.get("username", ""),
            experience=data.get("experience", ExperienceLevel.INTERMEDIATE),
            auto_detect=data.get("auto_detect", True),
            total_commands=data.get("total_commands", 0),
            unique_tools=data.get("unique_tools", 0),
            advanced_command_count=data.get("advanced_command_count", 0),
            category_count=data.get("category_count", 0),
            category_counts=data.get("category_counts", {}),
            error_rate=data.get("error_rate", 0.0),
            total_errors=data.get("total_errors", 0),
            total_findings=data.get("total_findings", 0),
            session_count=data.get("session_count", 0),
            milestones=data.get("milestones", []),
            pedagogical_enabled=data.get("pedagogical_enabled", False),
            preferences=data.get(
                "preferences",
                {
                    "verbosity": "adaptive",
                    "show_hints": True,
                    "auto_confirm_safe": False,
                    "output_format": "rich",
                    "color_theme": "",
                    "show_timestamps": True,
                    "compact_mode": False,
                },
            ),
            recent_tools=data.get("recent_tools", []),
            sessions=sessions,
            updated_at=data.get("updated_at", ""),
            created_at=data.get("created_at", ""),
        )


# ── Milestones ───────────────────────────────────────────────────────────
_MILESTONES = [
    {
        "id": "first_command",
        "name": "First Command",
        "cond": lambda p: p.total_commands >= 1,
    },
    {
        "id": "tool_diversity_3",
        "name": "Tool Explorer",
        "cond": lambda p: p.category_count >= 2 and p.unique_tools >= 3,
    },
    {
        "id": "ten_commands",
        "name": "Getting Started",
        "cond": lambda p: p.total_commands >= 10,
    },
    {
        "id": "all_categories",
        "name": "Tool Master",
        "cond": lambda p: p.category_count >= 4,
    },
    {
        "id": "advanced_user",
        "name": "Power User",
        "cond": lambda p: p.advanced_command_count >= 5,
    },
    {
        "id": "hundred_commands",
        "name": "Centurion",
        "cond": lambda p: p.total_commands >= 100,
    },
    {
        "id": "exploit_initiated",
        "name": "First Exploit",
        "cond": lambda p: p.category_counts.get("exploit", 0) >= 1,
    },
    {
        "id": "recon_specialist",
        "name": "Recon Specialist",
        "cond": lambda p: p.category_counts.get("recon", 0) >= 10,
    },
    {
        "id": "web_expert",
        "name": "Web Expert",
        "cond": lambda p: p.category_counts.get("web", 0) >= 10,
    },
    {
        "id": "wireless_pioneer",
        "name": "Wireless Pioneer",
        "cond": lambda p: p.category_counts.get("wireless", 0) >= 1,
    },
    {
        "id": "forensics_investigator",
        "name": "Forensics Investigator",
        "cond": lambda p: p.category_counts.get("forensics", 0) >= 1,
    },
    {
        "id": "expert_level",
        "name": "Expert Status",
        "cond": lambda p: p.experience == "expert",
    },
]


@dataclass
class PedagogicalStep:
    """A single step in the educational breakdown."""

    title: str
    command: str
    what_happened: str
    what_it_means: str
    severity: str = ""
    details: list[str] = field(default_factory=list)
    cve_id: str = ""


class PedagogicalEngine:
    """Generates step-by-step educational output (Chapter 10.2)."""

    def __init__(self, console: Any = None) -> None:
        self._console = console or Console()

    def generate_breakdown(
        self,
        steps: list[dict],
        findings: list[dict] | None = None,
    ) -> list[PedagogicalStep]:
        """Generate a pedagogical breakdown from execution steps and findings."""
        pedagogical_steps: list[PedagogicalStep] = []

        for i, step in enumerate(steps, 1):
            tool = step.get("tool", "")
            command = step.get("command", step.get("description", ""))
            output = step.get("output", "")
            step_type = step.get("step_type", "")

            title = self._generate_step_title(tool, command, step_type)
            what_happened = self._explain_what_happened(tool, command, output)
            what_it_means = self._explain_what_it_means(tool, command, output)

            details: list[str] = []
            cve_id = ""

            import re

            cves = re.findall(r"CVE-\d{4}-\d{4,}", output or "")
            for cve in cves[:3]:
                details.append(f"Detected {cve}")
                if cve in _CVE_KNOWLEDGE:
                    ck = _CVE_KNOWLEDGE[cve]
                    details.append(f"  {ck['description']}")
                    details.append(f"  Impact: {ck['impact']}")
                    details.append(f"  Mitigation: {ck['mitigation']}")
                    if not cve_id:
                        cve_id = cve

            if findings:
                step_findings = [
                    f for f in findings if f.get("tool", "").lower() == tool.lower()
                ]
                for sf in step_findings[:3]:
                    sev = sf.get("severity", "info")
                    desc = sf.get("description", sf.get("detail", ""))
                    if desc:
                        details.append(f"[{sev.upper()}] {desc}")

            severity = ""
            if findings:
                severities = [
                    f.get("severity", "")
                    for f in findings
                    if f.get("tool", "").lower() == tool.lower()
                ]
                if "critical" in severities:
                    severity = "critical"
                elif "high" in severities:
                    severity = "high"
                elif "medium" in severities:
                    severity = "medium"

            pedagogical_steps.append(
                PedagogicalStep(
                    title=title,
                    command=command,
                    what_happened=what_happened,
                    what_it_means=what_it_means,
                    severity=severity,
                    details=details,
                    cve_id=cve_id,
                )
            )

        return pedagogical_steps

    def _generate_step_title(self, tool: str, command: str, step_type: str) -> str:
        if tool:
            cat = _TOOL_CATEGORIES.get(tool.lower(), "")
            if cat == "recon":
                return f"Reconnaissance ({tool})"
            if cat == "web":
                return f"Web Application Testing ({tool})"
            if cat == "exploit":
                return f"Exploitation ({tool})"
            if cat == "wireless":
                return f"Wireless Testing ({tool})"
            if cat == "forensics":
                return f"Forensic Analysis ({tool})"
            return f"{tool.title()} Scan"
        if step_type:
            return step_type.replace("_", " ").title()
        return "Analysis Step"

    def _explain_what_happened(self, tool: str, command: str, output: str) -> str:
        tool_key = tool.lower()
        if tool_key in _TOOL_EXPLAINERS:
            return _TOOL_EXPLAINERS[tool_key]["what_happened"]
        for op_key, explainer in _OPERATION_EXPLAINERS.items():
            if op_key in command.lower():
                return explainer["what_happened"]
        if not command:
            return f"The system executed the {tool or 'requested'} operation and collected the results."
        return f"The command '{command}' was executed on the target system and produced the following output."

    def _explain_what_it_means(self, tool: str, command: str, output: str) -> str:
        tool_key = tool.lower()
        if tool_key in _TOOL_EXPLAINERS:
            return _TOOL_EXPLAINERS[tool_key]["what_it_means"]
        for op_key, explainer in _OPERATION_EXPLAINERS.items():
            if op_key in command.lower():
                return explainer["what_it_means"]
        return "Review the output carefully. Each finding represents a potential security issue that should be investigated further."

    def display_breakdown(self, steps: list[PedagogicalStep]) -> None:
        """Render the pedagogical breakdown to the console."""
        if not steps:
            return

        label = "[bold green]Phalanx[/bold green]"
        self._console.print(f"\n{label} Task complete. Educational breakdown:\n")

        for i, step in enumerate(steps, 1):
            border_style = "red" if step.severity in ("critical", "high") else "cyan"
            self._console.print(
                Rule(f"[bold]STEP {i}: {step.title}[/bold]", style=border_style)
            )

            content = (
                f"\n[bold cyan]What happened:[/bold cyan]\n  {step.what_happened}\n\n"
                f"[bold green]What it means:[/bold green]\n"
            )
            for line in step.what_it_means.split("\n"):
                content += f"  {line.strip()}\n"

            if step.details:
                content += "\n[bold yellow]Details:[/bold yellow]\n"
                for d in step.details[:5]:
                    content += f"  {d}\n"

            if step.cve_id:
                content += f"\n[bold red]CVE: {step.cve_id}[/bold red]\n"
                cve_data = _CVE_KNOWLEDGE.get(step.cve_id)
                if cve_data:
                    content += f"  Description: {cve_data['description']}\n"
                    content += f"  Impact: {cve_data['impact']}\n"
                    content += f"  Mitigation: {cve_data['mitigation']}\n"

            if step.severity:
                color = {"critical": "red", "high": "yellow"}.get(
                    step.severity, "white"
                )
                content += f"\n[{color}]Severity: {step.severity.upper()}[/{color}]\n"

            self._console.print(
                Panel(content.strip(), border_style=border_style, padding=(1, 2))
            )

        if len(steps) > 1:
            self._console.print(
                f"\n{label} Would you like a detailed explanation of any step? ", end=""
            )
            choices = "/".join(str(i) for i in range(1, len(steps) + 1))
            self._console.print(f"[bold][{choices}/n][/bold]: ", end="")
            import sys

            answer = sys.stdin.readline().strip()
            if answer.isdigit():
                idx = int(answer) - 1
                if 0 <= idx < len(steps):
                    self._display_detailed_step(steps[idx])

    def _display_detailed_step(self, step: PedagogicalStep) -> None:
        self._console.print(
            Rule(f"[bold]Deep Dive: {step.title}[/bold]", style="magenta")
        )
        content = (
            f"[bold]Command:[/bold] {step.command}\n\n"
            f"[bold cyan]What happened:[/bold cyan]\n  {step.what_happened}\n\n"
            f"[bold green]What it means:[/bold green]\n"
        )
        for line in step.what_it_means.split("\n"):
            content += f"  {line.strip()}\n"

        if step.cve_id:
            cve_data = _CVE_KNOWLEDGE.get(step.cve_id)
            if cve_data:
                content += (
                    f"\n[bold red]Vulnerability: {step.cve_id}[/bold red]\n"
                    f"  Description: {cve_data['description']}\n"
                    f"  Impact: {cve_data['impact']}\n"
                    f"  Affected: {cve_data['affected']}\n"
                    f"  Mitigation: {cve_data['mitigation']}\n"
                    f"  \n[dim]Next step: Verify with manual testing or search for PoC[/dim]\n"
                )

        self._console.print(
            Panel(
                content.strip(), title="Educational Deep Dive", border_style="magenta"
            )
        )


class UserLearning:
    """Adaptive user learning with pedagogical output (Chapter 10.2)."""

    def __init__(self, xi_skill_profiler: Any = None) -> None:
        _LEARNING_DIR.mkdir(parents=True, exist_ok=True)
        _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        self._profile_path = _LEARNING_DIR / "user_profile.json"
        self._profile = UserProfile()
        self._skill_profiler = xi_skill_profiler
        self._current_session: SessionRecord | None = None
        self._pedagogical = PedagogicalEngine()
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._profile_path.exists():
            self._profile.created_at = datetime.now(timezone.utc).isoformat()
            return
        try:
            with open(str(self._profile_path)) as f:
                data = json.load(f)
            self._profile = UserProfile.from_dict(data)
        except Exception as exc:
            logger.warning("Failed to load user profile: %s", exc)

    def _save(self) -> None:
        self._profile.updated_at = datetime.now(timezone.utc).isoformat()
        try:
            with open(str(self._profile_path), "w") as f:
                json.dump(self._profile.to_dict(), f, indent=2, default=str)
        except Exception as exc:
            logger.warning("Failed to save user profile: %s", exc)

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def profile(self) -> UserProfile:
        return self._profile

    @property
    def experience(self) -> str:
        return self._profile.experience

    @experience.setter
    def experience(self, level: str) -> None:
        if level in ExperienceLevel.all():
            self._profile.experience = level
            self._profile.auto_detect = False
            self._save()

    @property
    def pedagogical_enabled(self) -> bool:
        return self._profile.pedagogical_enabled

    def set_pedagogical(self, enabled: bool) -> None:
        self._profile.pedagogical_enabled = enabled
        self._save()
        logger.info("Pedagogical output %s", "enabled" if enabled else "disabled")

    @property
    def auto_detect_enabled(self) -> bool:
        return self._profile.auto_detect

    def enable_auto_detect(self) -> None:
        self._profile.auto_detect = True
        self._reassess()
        self._save()

    def disable_auto_detect(self) -> None:
        self._profile.auto_detect = False
        self._save()

    # ── Preferences ──────────────────────────────────────────────────────

    def set_preference(self, key: str, value: Any) -> None:
        valid = {
            "verbosity",
            "show_hints",
            "auto_confirm_safe",
            "output_format",
            "color_theme",
            "show_timestamps",
            "compact_mode",
        }
        if key not in valid:
            logger.warning("Unknown preference: %s", key)
            return
        self._profile.preferences[key] = value
        self._save()

    def get_preference(self, key: str, default: Any = None) -> Any:
        return self._profile.preferences.get(key, default)

    @property
    def preferences(self) -> dict:
        return dict(self._profile.preferences)

    # ── Session Management ───────────────────────────────────────────────

    def start_session(self, session_id: str = "") -> None:
        self._current_session = SessionRecord(
            session_id=session_id
            or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._profile.session_count += 1
        self._save()

    def end_session(self) -> SessionRecord | None:
        if not self._current_session:
            return None
        self._current_session.ended_at = datetime.now(timezone.utc).isoformat()
        self._profile.sessions.append(self._current_session)
        self._reassess()
        self._save()
        session = self._current_session
        self._current_session = None
        return session

    # ── Command Recording ────────────────────────────────────────────────

    def record_command(
        self,
        command: str,
        tool: str = "",
        success: bool = True,
        findings_count: int = 0,
    ) -> None:
        p = self._profile
        p.total_commands += 1
        if not success:
            p.total_errors += 1
        p.total_findings += findings_count

        if tool:
            p.recent_tools.append(tool)
            p.recent_tools = p.recent_tools[-50:]
            cat = _TOOL_CATEGORIES.get(tool.lower(), "other")
            p.category_counts[cat] = p.category_counts.get(cat, 0) + 1
            p.category_count = len(p.category_counts)
            unique = set(p.recent_tools)
            p.unique_tools = len(unique)

        if self._analyze_complexity(command) >= 3:
            p.advanced_command_count += 1

        if self._current_session:
            self._current_session.command_count += 1
            if tool and tool not in self._current_session.tools_used:
                self._current_session.tools_used.append(tool)
            if not success:
                self._current_session.errors += 1
            self._current_session.findings_found += findings_count
            if tool:
                cat = _TOOL_CATEGORIES.get(tool.lower(), "other")
                if cat not in self._current_session.categories:
                    self._current_session.categories.append(cat)

        if p.auto_detect and p.total_commands % 5 == 0:
            self._reassess()
        self._sync_skill_profiler(command, tool, success)
        self._check_milestones()
        self._save()

    @staticmethod
    def _analyze_complexity(command: str) -> int:
        score = 0
        parts = command.split()
        flag_count = sum(1 for p in parts if p.startswith("-"))
        score += min(flag_count, 3)
        for op in ("&&", "||", "|", ";", "|&"):
            if op in parts:
                score += 2
        if len(parts) > 10:
            score += 1
        if len(parts) > 20:
            score += 1
        for flag in ("--dry-run", "--parallel", "--persist"):
            if flag in parts:
                score += 1
        return score

    # ── Experience Assessment ────────────────────────────────────────────

    def _reassess(self) -> None:
        if not self._profile.auto_detect:
            return
        new_level = ExperienceLevel.auto_detect(self._profile)
        if new_level != self._profile.experience:
            old = self._profile.experience
            self._profile.experience = new_level
            logger.info("Experience: %s -> %s", old, new_level)

    # ── Milestones ───────────────────────────────────────────────────────

    def _check_milestones(self) -> list[dict]:
        newly = []
        for m in _MILESTONES:
            if m["id"] not in self._profile.milestones and m["cond"](self._profile):
                self._profile.milestones.append(m["id"])
                newly.append(m)
        if newly:
            self._save()
        return newly

    def get_milestones(self) -> list[dict]:
        return [
            {
                "id": m["id"],
                "name": m["name"],
                "achieved": m["id"] in self._profile.milestones,
            }
            for m in _MILESTONES
        ]

    # ── Pedagogical Output (Chapter 10.2) ────────────────────────────────

    def generate_pedagogical_output(
        self,
        steps: list[dict],
        findings: list[dict] | None = None,
    ) -> list[PedagogicalStep] | None:
        """Generate and display educational breakdown if pedagogical mode is on."""
        if not self._profile.pedagogical_enabled:
            return None
        p_steps = self._pedagogical.generate_breakdown(steps, findings)
        if p_steps:
            self._pedagogical.display_breakdown(p_steps)
            if self._current_session:
                self._current_session.pedagogical_steps += len(p_steps)
            self._save()
        return p_steps

    def should_show_explanation(self) -> bool:
        if self._profile.auto_detect:
            return self._profile.experience in (
                ExperienceLevel.NOVICE,
                ExperienceLevel.INTERMEDIATE,
            )
        return self._profile.preferences.get("show_hints", True)

    def verbosity_level(self) -> int:
        if not self._profile.auto_detect:
            return {"minimal": 0, "compact": 1, "normal": 1, "verbose": 2}.get(
                self._profile.preferences.get("verbosity", "adaptive"), 1
            )
        return {
            ExperienceLevel.NOVICE: 2,
            ExperienceLevel.INTERMEDIATE: 1,
            ExperienceLevel.ADVANCED: 1,
            ExperienceLevel.EXPERT: 0,
        }.get(self._profile.experience, 1)

    def auto_confirm_safe(self) -> bool:
        return self._profile.experience == ExperienceLevel.EXPERT

    # ── XI Integration ───────────────────────────────────────────────────

    def _sync_skill_profiler(self, command: str, tool: str, success: bool) -> None:
        if self._skill_profiler and hasattr(self._skill_profiler, "record_command"):
            try:
                self._skill_profiler.record_command(command, tool=tool, success=success)
            except Exception as exc:
                logger.debug("SkillProfiler sync: %s", exc)

    def sync_from_skill_profiler(self) -> None:
        if not self._skill_profiler:
            return
        try:
            sp = self._skill_profiler.profile
            if sp and hasattr(sp, "level"):
                self._profile.experience = sp.level
                self._save()
        except Exception as exc:
            logger.debug("SkillProfiler import: %s", exc)

    # ── Display ──────────────────────────────────────────────────────────

    def get_profile_panel(self) -> Panel:
        p = self._profile
        tree = Tree(f"[bold cyan]User: {p.username or 'anonymous'}[/bold cyan]")
        tree.add(
            f"[bold]Experience:[/bold] [magenta]{p.experience}[/magenta]"
            f"{' ([green]auto[/green])' if p.auto_detect else ' ([yellow]manual[/yellow])'}"
        )
        tree.add(
            f"[bold]Pedagogical:[/bold] {'[green]On[/green]' if p.pedagogical_enabled else '[red]Off[/red]'}"
        )
        tree.add(
            f"[bold]Commands:[/bold] {p.total_commands} | "
            f"[bold]Tools:[/bold] {p.unique_tools} | "
            f"[bold]Categories:[/bold] {p.category_count}"
        )
        tree.add(
            f"[bold]Advanced:[/bold] {p.advanced_command_count} | "
            f"[bold]Error Rate:[/bold] {p.error_rate:.1%} | "
            f"[bold]Findings:[/bold] {p.total_findings}"
        )
        tree.add(f"[bold]Sessions:[/bold] {p.session_count}")
        tree.add(
            f"[bold]Verbosity:[/bold] {self.verbosity_level()}/2 | "
            f"[bold]Explanations:[/bold] {'[green]On[/green]' if self.should_show_explanation() else '[red]Off[/red]'}"
        )
        achieved = [m for m in _MILESTONES if m["id"] in p.milestones]
        if achieved:
            mb = tree.add("[bold]Milestones:[/bold]")
            for m in achieved:
                mb.add(f"[green]{m['name']}[/green]")
        return Panel(
            tree, title="User Learning Profile", border_style="cyan", padding=(1, 2)
        )

    def get_milestones_panel(self) -> Panel:
        mstones = self.get_milestones()
        ac = sum(1 for m in mstones if m["achieved"])
        table = Table(
            title=f"Milestones ({ac}/{len(mstones)})", header_style="bold cyan"
        )
        table.add_column("Status", width=4)
        table.add_column("Name")
        table.add_column("ID", style="dim")
        for m in mstones:
            s = "[green]" if m["achieved"] else "[dim]"
            table.add_row(f"{s}[/]", f"{s}{m['name']}[/]", f"[dim]{m['id']}[/]")
        return Panel(table, title="Learning Milestones", border_style="green")

    def get_sessions_panel(self, limit: int = 10) -> Panel:
        sessions = self._profile.sessions[-limit:]
        if not sessions:
            return Panel(
                "[dim]No sessions yet.[/dim]",
                title="Session History",
                border_style="dim",
            )
        table = Table(
            title=f"Recent Sessions ({len(sessions)})", header_style="bold cyan"
        )
        table.add_column("ID", style="cyan")
        table.add_column("Cmds", justify="right")
        table.add_column("Tools")
        table.add_column("Findings", justify="right")
        table.add_column("Err", justify="right")
        table.add_column("Ped Steps", justify="right")
        table.add_column("Duration")
        for s in reversed(sessions):
            tools = ", ".join(s.tools_used[:3])
            if len(s.tools_used) > 3:
                tools += "..."
            table.add_row(
                s.session_id[:10],
                str(s.command_count),
                tools,
                str(s.findings_found),
                str(s.errors),
                str(s.pedagogical_steps),
                f"{s.duration_seconds:.0f}s" if s.duration_seconds else "-",
            )
        return Panel(table, title="Session History", border_style="cyan")

    def get_improvement_suggestions(self) -> list[str]:
        p = self._profile
        suggestions = []
        if p.unique_tools < 5:
            suggestions.append("Try more tools: nmap, whois, gobuster, nuclei, hydra")
        elif p.unique_tools < 15:
            suggestions.append("Good diversity! Try bloodhound, impacket, volatility")
        missing = [
            c
            for c in ("recon", "web", "exploit", "wireless", "forensics")
            if c not in p.category_counts
        ]
        if missing:
            suggestions.append(f"Explore: {'/'.join(missing)}")
        if p.advanced_command_count < 3 and p.total_commands > 10:
            suggestions.append("Try --dry-run, --parallel, or chain with &&")
        if p.error_rate > 0.2 and p.total_commands > 10:
            suggestions.append(
                f"Error rate {p.error_rate:.0%}. Use --dry-run to preview."
            )
        return suggestions

    def clear_history(self) -> None:
        self._profile = UserProfile()
        self._save()


__all__ = [
    "UserLearning",
    "UserProfile",
    "SessionRecord",
    "ExperienceLevel",
    "PedagogicalEngine",
    "PedagogicalStep",
]
