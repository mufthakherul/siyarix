# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline Reasoning Engine — intelligent local analysis and plan execution without LLM.

Provides:
- **Local Knowledge Query Resolution**: Queries OfflineStore and KnowledgeGraph
  to answer user questions about past scans, open ports, discovered services,
  and vulnerability findings.
- **Built-in Security Guidance & Remediation**: Comprehensive CWE, OWASP Top 10,
  and CIS hardening advice with actionable code/configuration patches.
- **Offline Heuristic Planning**: Uses NaturalLanguageParser and continuous learning
  skills to generate multi-step executable plans locally.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .models import ExecutionPlan, PlanStatus, PlanStep, PlanType
from .nlp_engine import NaturalLanguageParser
from .offline_store import OfflineStore
from .planner_autonomous import PlanValidator

logger = logging.getLogger(__name__)


@dataclass
class RemediationAdvisory:
    """Structured security remediation guidance for a specific vulnerability class."""

    vuln_class: str
    title: str
    cwe: str
    owasp: str
    severity: str
    cvss_base: float
    description: str
    remediation_steps: list[str]
    code_example: str = ""
    detection_signature: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Built-in Offline Security Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════

OFFLINE_SECURITY_KNOWLEDGE: dict[str, RemediationAdvisory] = {
    "sql_injection": RemediationAdvisory(
        vuln_class="sql_injection",
        title="SQL Injection (SQLi)",
        cwe="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        cvss_base=9.8,
        description="User input is directly concatenated into SQL queries, allowing arbitrary database query execution, data exfiltration, or administrative bypass.",
        remediation_steps=[
            "Use parameterized prepared statements with bind variables across all queries.",
            "Use modern Object-Relational Mappings (ORMs) that enforce parameterization.",
            "Enforce principle of least privilege on database user accounts.",
            "Deploy Web Application Firewall (WAF) SQLi rule sets as defense-in-depth.",
        ],
        code_example=(
            "# Vulnerable:\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n\n"
            "# Secure (Prepared Statement):\n"
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        ),
        detection_signature="regex: (?i)(\\bunion\\s+select\\b|'\\s+or\\s+'1'='1|--|/\\*\\*/)",
    ),
    "xss": RemediationAdvisory(
        vuln_class="xss",
        title="Cross-Site Scripting (XSS)",
        cwe="CWE-79: Improper Neutralization of Input During Web Page Generation",
        owasp="A03:2021-Injection",
        severity="HIGH",
        cvss_base=7.5,
        description="Unsanitized user-controlled input is reflected in HTML responses or executed in user browsers, enabling session hijacking, credential theft, or page defacement.",
        remediation_steps=[
            "Context-aware output encoding (HTML, JavaScript, CSS, URL contexts).",
            "Deploy a robust Content Security Policy (CSP): default-src 'self'; script-src 'self' 'nonce-...'.",
            "Mark all session and authentication cookies with HttpOnly and Secure flags.",
            "Sanitize any rich HTML inputs using DOMPurify or equivalent trusted sanitizers.",
        ],
        code_example=(
            "// Secure CSP Header:\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';\n\n"
            "// Cookie Security:\n"
            "Set-Cookie: session_id=abc; Secure; HttpOnly; SameSite=Strict"
        ),
        detection_signature="regex: (?i)(<script\\b[^>]*>|javascript:|onerror\\s*=|onload\\s*=)",
    ),
    "ssrf": RemediationAdvisory(
        vuln_class="ssrf",
        title="Server-Side Request Forgery (SSRF)",
        cwe="CWE-918: Server-Side Request Forgery (SSRF)",
        owasp="A10:2021-Server-Side Request Forgery",
        severity="HIGH",
        cvss_base=8.6,
        description="The web server fetches a remote resource specified by an external user without validating destination IP, allowing attackers to pivot into internal networks or cloud metadata (169.254.169.254).",
        remediation_steps=[
            "Strictly validate and whitelist allowed destination hostnames or protocols (allow only https).",
            "Block private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local (169.254.0.0/16).",
            "Disable following HTTP redirects or validate target IP post-redirect.",
            "Enforce IMDSv2 in AWS environments to prevent tokenless metadata access.",
        ],
        code_example=(
            "# AWS IMDSv2 Enforcement via CLI:\n"
            "aws ec2 modify-instance-metadata-options \\\n"
            "  --instance-id i-1234567890abcdef0 \\\n"
            "  --http-tokens required --http-endpoint enabled"
        ),
        detection_signature="url_contains: 169.254.169.254 or localhost or 127.0.0.1",
    ),
    "rce": RemediationAdvisory(
        vuln_class="rce",
        title="Remote Code Execution (RCE)",
        cwe="CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        cvss_base=9.8,
        description="Arbitrary commands are executed directly on the underlying server host OS, leading to total server compromise.",
        remediation_steps=[
            "Avoid shell execution wrappers (system(), exec(), popen(), shell=True).",
            "Use native programming language APIs instead of launching subprocess commands.",
            "If system commands are unavoidable, pass arguments as discrete array elements without shell interpolation.",
            "Apply container sandboxing (read-only rootfs, drop capabilities: cap-drop=ALL).",
        ],
        code_example=(
            "# Secure Subprocess Execution:\n"
            "import subprocess\n"
            "# Pass argv list, never shell=True:\n"
            "subprocess.run(['ping', '-c', '1', validated_host], check=True)"
        ),
        detection_signature="regex: (?i)(;\\s*cat\\s+/etc/passwd|;\\s*whoami|\\|\\s*powershell)",
    ),
    "missing_headers": RemediationAdvisory(
        vuln_class="missing_headers",
        title="Missing HTTP Security Headers",
        cwe="CWE-693: Protection Mechanism Failure",
        owasp="A05:2021-Security Misconfiguration",
        severity="LOW",
        cvss_base=4.3,
        description="The web server does not send standard defensive security headers, leaving clients exposed to clickjacking, MIME-sniffing, and downgrade attacks.",
        remediation_steps=[
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY (or Content-Security-Policy frame-ancestors 'none')",
            "Referrer-Policy: strict-origin-when-cross-origin",
            "Permissions-Policy: geolocation=(), camera=(), microphone=()",
        ],
        code_example=(
            "# Nginx configuration snippet:\n"
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;\n"
            "add_header X-Content-Type-Options 'nosniff' always;\n"
            "add_header X-Frame-Options 'DENY' always;\n"
            "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;"
        ),
        detection_signature="header_missing: Strict-Transport-Security or X-Content-Type-Options",
    ),
    "weak_tls": RemediationAdvisory(
        vuln_class="weak_tls",
        title="Weak TLS/SSL Configuration",
        cwe="CWE-326: Inadequate Encryption Strength",
        owasp="A02:2021-Cryptographic Failures",
        severity="MEDIUM",
        cvss_base=5.9,
        description="The server supports deprecated cryptographic protocols (SSLv3, TLS 1.0, TLS 1.1) or weak ciphers (RC4, 3DES, CBC mode), allowing man-in-the-middle decryption.",
        remediation_steps=[
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 exclusively.",
            "Configure modern AEAD cipher suites (ECDHE-ECDSA-AES128-GCM-SHA256, CHACHA20-POLY1305).",
            "Enable Forward Secrecy (PFS) with ECDHE key exchange.",
            "Automate certificate renewals with ACME / Let's Encrypt using 2048+ bit RSA or P-256 ECDSA keys.",
        ],
        code_example=(
            "# Nginx SSL Modern Profile:\n"
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_prefer_server_ciphers off;\n"
            "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';"
        ),
        detection_signature="scan_finding: TLS 1.0 enabled or SSLv3 enabled",
    ),
}


class OfflineReasoningEngine:
    """Enterprise offline reasoning, query resolution, and planning engine."""

    def __init__(
        self,
        offline_store: OfflineStore | None = None,
        nlp_parser: NaturalLanguageParser | None = None,
    ) -> None:
        self._store = offline_store or OfflineStore()
        self._nlp = nlp_parser or NaturalLanguageParser()

    # ── Local Query Resolution ──────────────────────────────────────────

    def resolve_query(self, query: str, target: str = "") -> str | None:
        """Attempt to resolve user questions from local database stores.

        Returns formatted markdown answer if handled, or None if the query
        is an actionable execution request that requires planning.
        """
        q_lower = query.lower().strip()

        # 1. Open Ports / Services query
        if any(
            kw in q_lower
            for kw in ("open port", "ports open", "what ports", "list ports", "show ports")
        ):
            return self._query_open_ports(target or self._extract_target(query))

        # 2. Vulnerabilities / Findings query
        if any(
            kw in q_lower
            for kw in ("vulnerabilit", "findings", "issues found", "bugs found", "cve")
        ):
            return self._query_findings(target or self._extract_target(query), q_lower)

        # 3. Target scan history / status
        if any(kw in q_lower for kw in ("status of", "history of", "scans on", "last scan")):
            return self._query_target_history(target or self._extract_target(query))

        # 4. Remediation / How to fix query
        if any(
            kw in q_lower for kw in ("how to fix", "remediation", "mitigate", "prevent", "explain")
        ):
            for key, advisory in OFFLINE_SECURITY_KNOWLEDGE.items():
                if (
                    key.replace("_", " ") in q_lower
                    or advisory.title.lower() in q_lower
                    or advisory.vuln_class in q_lower
                ):
                    return self._format_advisory(advisory)

        return None

    def _extract_target(self, text: str) -> str:
        """Extract IP or domain target from query string."""
        intent = self._nlp.parse(text)
        return intent.target or ""

    def _query_open_ports(self, target: str) -> str:
        """Retrieve and format discovered open ports for target."""
        findings = self._store.search_findings(severity="", limit=200)
        port_findings = [
            f
            for f in findings
            if (f.get("port") or 0) > 0
            and (not target or target.lower() in str(f.get("target", "")).lower())
        ]

        if not port_findings:
            tgt_label = f" for **{target}**" if target else ""
            return (
                f"[dim]No open port records found{tgt_label} in the local offline database.[/dim]\n\n"
                f"You can discover open ports by running: **`scan {target or '<target>'}`**"
            )

        # Group by port
        ports_map: dict[int, dict[str, str]] = {}
        for pf in port_findings:
            p = int(pf["port"])
            if p not in ports_map:
                ports_map[p] = {
                    "service": pf.get("service") or "unknown",
                    "technology": pf.get("technology") or "",
                    "target": pf.get("target") or target or "",
                }

        lines = [
            f"### Discovered Open Ports ({len(ports_map)} Total)",
            "",
            "| Port | Service | Technology | Target |",
            "|:----:|:--------|:-----------|:-------|",
        ]
        for port, info in sorted(ports_map.items()):
            lines.append(
                f"| `{port}` | {info['service']} | {info['technology'] or '—'} | `{info['target']}` |"
            )

        lines.append("")
        lines.append("*(Data retrieved from local OfflineStore cache)*")
        return "\n".join(lines)

    def _query_findings(self, target: str, query: str) -> str:
        """Retrieve and format vulnerability findings from local store."""
        target_clean = target.lower()
        findings = self._store.search_findings(severity="", limit=100)
        if target_clean:
            findings = [f for f in findings if target_clean in str(f.get("target", "")).lower()]

        if not findings:
            tgt_label = f" for **{target}**" if target else ""
            return (
                f"[dim]No vulnerability findings recorded{tgt_label} in the local offline database.[/dim]\n\n"
                f"To perform a local security assessment: **`vuln scan {target or '<target>'}`**"
            )

        # Filter by severity if requested
        if "critical" in query:
            findings = [f for f in findings if (f.get("severity") or "").lower() == "critical"]
        elif "high" in query:
            findings = [
                f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")
            ]

        lines = [
            f"### Vulnerability Findings ({len(findings)} Total)",
            "",
            "| Severity | Title | Target | Tool |",
            "|:--------:|:------|:-------|:-----|",
        ]
        for f in findings[:20]:
            sev = (f.get("severity") or "info").upper()
            title = f.get("title") or f.get("description") or "Finding"
            f_tgt = f.get("target") or target or ""
            tool = f.get("tool") or "scanner"
            lines.append(f"| **{sev}** | {title[:40]} | `{f_tgt}` | {tool} |")

        if len(findings) > 20:
            lines.append(f"| ... | *and {len(findings) - 20} more* | | |")

        lines.append("")
        lines.append("*(Query `/report` for full details and export)*")
        return "\n".join(lines)

    def _query_target_history(self, target: str) -> str:
        """Retrieve historical scans for a target."""
        stats = self._store.stats()
        return (
            f"### Target Intelligence: {target or 'All Assets'}\n\n"
            f"- **Total Scans Recorded**: {stats.get('total_scans', 0)}\n"
            f"- **Total Findings**: {stats.get('total_findings', 0)}\n"
            f"- **Offline Database**: Connected (`offline_store.db`)\n\n"
            f"Run **`/status`** or **`/campaign`** to inspect active operational profiles."
        )

    def _format_advisory(self, adv: RemediationAdvisory) -> str:
        """Format a structured security remediation advisory."""
        steps_md = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(adv.remediation_steps))
        lines = [
            f"## Security Advisory: {adv.title}",
            f"**Severity**: `{adv.severity}` (CVSS Base {adv.cvss_base:.1f}) | **CWE**: {adv.cwe}",
            f"**OWASP Category**: {adv.owasp}",
            "",
            "### Threat Description",
            adv.description,
            "",
            "### Actionable Remediation Guidance",
            steps_md,
        ]
        if adv.code_example:
            lines.extend(
                [
                    "",
                    "### Implementation Example",
                    "```python",
                    adv.code_example,
                    "```",
                ]
            )
        if adv.detection_signature:
            lines.extend(
                [
                    "",
                    f"**Detection Signature**: `{adv.detection_signature}`",
                ]
            )
        return "\n".join(lines)

    # ── Offline Plan Generation ─────────────────────────────────────────

    def plan_offline_instruction(
        self,
        instruction: str,
        target: str = "",
        available_tools: list[str] | None = None,
    ) -> ExecutionPlan | None:
        """Generate an executable security plan locally using offline heuristics and learned skills."""
        parsed = self._nlp.parse(instruction)
        effective_target = target or parsed.target or "127.0.0.1"

        # 1. Try Continuous Learning System skills first
        try:
            from .learning_system import get_learning_system

            cls = get_learning_system()
            skill = cls.find_high_confidence_skill(instruction, effective_target, threshold=0.70)
            if skill and skill.steps:
                anon_goal = cls._anonymize_target(instruction, effective_target)
                instantiated = cls.instantiate_skill(
                    skill, effective_target, raw_anon_goal=anon_goal
                )
                if instantiated:
                    plan_steps = [
                        PlanStep(
                            id=f"skill_step_{i:03d}",
                            description=s.get("description", f"Skill Step {i + 1}"),
                            tool=s.get("tool", ""),
                            command=s.get("command", ""),
                            args=s.get("args", {}),
                        )
                        for i, s in enumerate(instantiated)
                    ]
                    plan_steps = PlanValidator.deduplicate_steps(plan_steps)
                    return ExecutionPlan(
                        goal=instruction,
                        plan_type=PlanType.SEQUENTIAL,
                        steps=plan_steps,
                        context={"source": "cls_offline", "skill_id": skill.skill_id},
                        status=PlanStatus.ACTIVE,
                    )
        except Exception as exc:
            logger.debug("Offline CLS match failed: %s", exc)

        # 2. Template / intent-based heuristic planning
        steps: list[PlanStep] = []
        cmd_text = instruction.lower()

        if any(kw in cmd_text for kw in ("port scan", "nmap", "scan port")):
            steps.append(
                PlanStep(
                    id="step_001",
                    description=f"TCP port scan on {effective_target}",
                    tool="nmap",
                    command=f"nmap -sT -Pn -F {effective_target}",
                    args={"target": effective_target},
                )
            )
        elif any(kw in cmd_text for kw in ("dns", "subdomain", "domain enum")):
            steps.append(
                PlanStep(
                    id="step_001",
                    description=f"DNS reconnaissance on {effective_target}",
                    tool="nslookup",
                    command=f"nslookup {effective_target}",
                    args={"target": effective_target},
                )
            )
        elif any(kw in cmd_text for kw in ("web", "http", "headers")):
            steps.append(
                PlanStep(
                    id="step_001",
                    description=f"HTTP security headers check on {effective_target}",
                    tool="curl",
                    command=f"curl -s -I {effective_target}",
                    args={"target": effective_target},
                )
            )
        elif any(kw in cmd_text for kw in ("full scan", "vuln scan", "audit")):
            steps.append(
                PlanStep(
                    id="step_001",
                    description=f"Initial discovery scan on {effective_target}",
                    tool="nmap",
                    command=f"nmap -sT -Pn --top-ports 100 {effective_target}",
                    args={"target": effective_target},
                )
            )
            steps.append(
                PlanStep(
                    id="step_002",
                    description=f"HTTP banner extraction on {effective_target}",
                    tool="curl",
                    command=f"curl -s -I http://{effective_target}",
                    dependencies=["step_001"],
                    args={"target": effective_target},
                )
            )

        if not steps:
            return None

        # Sanitize and deduplicate
        sanitized_steps = [PlanValidator.validate_and_sanitize_step(s) for s in steps]
        sanitized_steps = PlanValidator.deduplicate_steps(sanitized_steps)

        return ExecutionPlan(
            goal=instruction,
            plan_type=PlanType.DAG
            if any(s.dependencies for s in sanitized_steps)
            else PlanType.SEQUENTIAL,
            steps=sanitized_steps,
            context={"source": "offline_heuristic"},
            status=PlanStatus.ACTIVE,
        )


__all__ = [
    "OfflineReasoningEngine",
    "RemediationAdvisory",
    "OFFLINE_SECURITY_KNOWLEDGE",
]
