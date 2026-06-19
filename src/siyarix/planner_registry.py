# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registry/offline planner — heuristic tool selection without LLM."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from .events import Event, EventType, emit_sync
from .nlp_engine import NaturalLanguageParser
from .models import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    PlanType,
    StepStatus,
)

_IS_WIN = os.name == "nt"

_COMMON_WORDLIST = (
    r"C:\Tools\wordlists\dirb\common.txt" if _IS_WIN else "/usr/share/wordlists/dirb/common.txt"
)
_USERNAME_WORDLIST = (
    r"C:\Tools\wordlists\usernames.txt" if _IS_WIN else "/usr/share/wordlists/usernames.txt"
)
_PASSWORD_WORDLIST = (
    r"C:\Tools\wordlists\passwords.txt" if _IS_WIN else "/usr/share/wordlists/passwords.txt"
)

logger = logging.getLogger(__name__)

TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "nmap": ["masscan", "rustscan", "naabu"],
    "masscan": ["nmap", "rustscan"],
    "gobuster": ["ffuf", "dirb", "dirsearch"],
    "ffuf": ["gobuster", "dirb", "dirsearch"],
    "whatweb": ["wappalyzer", "builtwith"],
    "nuclei": ["nikto", "wapiti", "skipfish"],
    "nikto": ["nuclei", "wapiti"],
    "hydra": ["medusa", "ncrack", "patator"],
    "subfinder": ["amass", "sublist3r", "assetfinder"],
    "amass": ["subfinder", "sublist3r"],
    "curl": ["wget", "httpie"],
    "dig": ["nslookup", "host"],
    "aircrack-ng": ["hashcat", "john"],
    "sqlmap": ["jSQL", "sqlninja"],
}


class RegistryPlanner:
    """Heuristic planner using templates, keyword index, and intent matching.

    Pure offline — no LLM dependency. Uses an inverted-index strategy for
    scalable tool lookup and template-based workflow generation.
    """

    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._nlp = NaturalLanguageParser()
        self._auto_dag_templates: set[str] = {
            "recon_full",
            "web_audit",
            "network_scan",
            "cloud_audit",
            "vuln_scan",
            "dns_recon",
            "full_audit",
            "smb_enum",
        }
        self._cron_path = "/etc/crontab" if os.name != "nt" else "C:\\Windows\\System32\\Tasks"
        self._templates: dict[str, list[dict[str, Any]]] = self._build_templates()
        self._keyword_index: dict[str, set[str]] = {}

    def _build_templates(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "recon_full": [
                {
                    "description": "Full port scan with service/OS detection and default scripts",
                    "tool": "nmap",
                    "args": {"flags": "-sV -sC -T4"},
                },
                {
                    "description": "Web technology stack fingerprinting",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Directory and file brute-force enumeration",
                    "tool": "gobuster",
                    "args": {"mode": "dir"},
                },
                {"description": "Passive subdomain enumeration", "tool": "subfinder", "args": {}},
                {
                    "description": "Aggressive subdomain discovery via brute-force",
                    "tool": "amass",
                    "args": {},
                },
                {
                    "description": "Template-based vulnerability scan",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
            ],
            "web_audit": [
                {
                    "description": "HTTP security headers and response analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {
                    "description": "Web application technology fingerprinting",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Template-based vulnerability scanning (medium+ severity)",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
                {
                    "description": "Content discovery and directory/file enumeration",
                    "tool": "ffuf",
                    "args": {"wordlist": "common.txt"},
                },
                {
                    "description": "WordPress-specific vulnerability scan",
                    "tool": "wpscan",
                    "args": {},
                },
                {"description": "Web server vulnerability scan", "tool": "nikto", "args": {}},
            ],
            "headers_check": [
                {
                    "description": "HTTP security headers analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {
                    "description": "SSL/TLS certificate inspection",
                    "tool": "openssl",
                    "args": {"flags": "s_client -connect {target}:443 -servername {target}"},
                },
            ],
            "cors_check": [
                {
                    "description": "CORS headers and preflight analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI -H 'Origin: https://evil.com'"},
                },
                {
                    "description": "Verbose CORS header extraction",
                    "tool": "curl",
                    "args": {"flags": "-s -D - -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: GET' -X OPTIONS"},
                },
            ],
            "ssl_audit": [
                {
                    "description": "SSL/TLS certificate chain validation",
                    "tool": "openssl",
                    "args": {"flags": "s_client -connect {target}:443 -servername {target}"},
                },
                {
                    "description": "SSL/TLS cipher suite enumeration",
                    "tool": "nmap",
                    "args": {"flags": "--script ssl-enum-ciphers -p 443"},
                },
                {
                    "description": "SSL/TLS certificate info via nmap",
                    "tool": "nmap",
                    "args": {"flags": "--script ssl-cert -p 443"},
                },
            ],
            "brute_force": [
                {
                    "description": "Target service discovery and version identification",
                    "tool": "nmap",
                    "args": {"flags": "-sV"},
                },
                {
                    "description": "Multi-protocol credential brute-force attack",
                    "tool": "hydra",
                    "args": {},
                },
                {
                    "description": "Offline hash cracking of captured credentials",
                    "tool": "hashcat",
                    "args": {},
                },
            ],
            "wifi_audit": [
                {
                    "description": "Wireless traffic capture and handshake collection",
                    "tool": "aircrack-ng",
                    "args": {"mode": "capture"},
                },
                {
                    "description": "WPA/WPA2 PSK handshake offline crack",
                    "tool": "aircrack-ng",
                    "args": {"mode": "crack"},
                },
            ],
            "network_scan": [
                {
                    "description": "Full TCP port sweep with high-rate discovery",
                    "tool": "nmap",
                    "args": {"flags": "-sT -T4 -p- --min-rate 1000"},
                },
                {
                    "description": "Service version detection on top 1000 ports",
                    "tool": "nmap",
                    "args": {"flags": "-sV -T4 --top-ports 1000"},
                },
                {
                    "description": "DNS record resolution and zone analysis",
                    "tool": "dig",
                    "args": {},
                },
                {
                    "description": "WHOIS registration and IP ownership lookup",
                    "tool": "whois",
                    "args": {},
                },
                {
                    "description": "Mass port scan for additional coverage",
                    "tool": "masscan",
                    "args": {"flags": "--rate 1000 --top-ports 100"},
                },
            ],
            "cloud_audit": [
                {
                    "description": "HTTP security headers and CORS policy analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {
                    "description": "Web application stack and framework detection",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Full DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME)",
                    "tool": "dig",
                    "args": {"flags": "ANY"},
                },
                {
                    "description": "SSL/TLS certificate chain and cipher suite validation",
                    "tool": "openssl",
                    "args": {"flags": "s_client -servername"},
                },
            ],
            "ad_assessment": [
                {
                    "description": "Domain controller critical port scan",
                    "tool": "nmap",
                    "args": {
                        "flags": "-sT -sV -T4 -p 53,88,135,139,389,445,464,636,3268,3269,3389"
                    },
                },
                {
                    "description": "SMB protocol version and dialect negotiation analysis",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-protocols"},
                },
                {
                    "description": "LDAP anonymous bind and root DSE information disclosure check",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 389 --script ldap-rootdse"},
                },
                {
                    "description": "Kerberos user enumeration attempt",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 88 --script krb5-enum-users"},
                },
            ],
            "linux_privesc": [
                {
                    "description": "Kernel and OS version identification",
                    "tool": "uname",
                    "args": {"flags": "-a"},
                },
                {
                    "description": "SUID and SGID binary discovery",
                    "tool": "find",
                    "args": {"flags": "/ -perm -4000 -type f 2>/dev/null"},
                },
                {
                    "description": "World-writable directory search",
                    "tool": "find",
                    "args": {"flags": "/ -writable -type d 2>/dev/null"},
                },
                {
                    "description": "Scheduled task and cron job inspection",
                    "tool": "cat",
                    "args": {"flags": self._cron_path},
                },
            ],
            "vuln_scan": [
                {
                    "description": "Template-based vulnerability scan (all severities)",
                    "tool": "nuclei",
                    "args": {"severity": "low,medium,high,critical"},
                },
                {"description": "Web server vulnerability scan", "tool": "nikto", "args": {}},
                {"description": "WordPress vulnerability scan", "tool": "wpscan", "args": {}},
                {
                    "description": "SQL injection scan",
                    "tool": "sqlmap",
                    "args": {"flags": "--batch --random-agent"},
                },
            ],
            "dns_recon": [
                {
                    "description": "DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)",
                    "tool": "dig",
                    "args": {},
                },
                {"description": "Passive subdomain discovery", "tool": "subfinder", "args": {}},
                {
                    "description": "Brute-force subdomain discovery via wordlist",
                    "tool": "amass",
                    "args": {},
                },
                {
                    "description": "WHOIS registration and domain ownership lookup",
                    "tool": "whois",
                    "args": {},
                },
            ],
            "full_audit": [
                {
                    "description": "Full port scan with service and OS detection",
                    "tool": "nmap",
                    "args": {"flags": "-sV -sC -T4"},
                },
                {
                    "description": "HTTP security headers and response analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {"description": "Web technology fingerprinting", "tool": "whatweb", "args": {}},
                {
                    "description": "Template-based vulnerability scan",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
                {
                    "description": "Directory and file enumeration",
                    "tool": "gobuster",
                    "args": {"mode": "dir"},
                },
                {"description": "DNS record enumeration", "tool": "dig", "args": {}},
                {"description": "Subdomain discovery", "tool": "subfinder", "args": {}},
                {"description": "WHOIS registration lookup", "tool": "whois", "args": {}},
            ],
            "smb_enum": [
                {
                    "description": "SMB port scan and service detection",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445"},
                },
                {
                    "description": "SMB protocol version and dialect negotiation",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-protocols"},
                },
                {
                    "description": "SMB share enumeration",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-enum-shares"},
                },
                {
                    "description": "SMB OS discovery and security check",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-os-discovery,smb-security-mode"},
                },
            ],
        }

    # ── Index builder ─────────────────────────────────────────────────────

    def build_index(self, available_tools: list[str], tool_registry: Any = None) -> None:
        self._keyword_index.clear()
        tools_metadata = []
        for name in available_tools:
            name_lower = name.lower()
            self._add_to_index(name_lower, name)
            for part in re.split(r"[-_.]+", name_lower):
                if len(part) > 1:
                    self._add_to_index(part, name)
            if tool_registry is not None:
                try:
                    tool = (
                        tool_registry.get_tool(name) if hasattr(tool_registry, "get_tool") else None
                    )
                    if tool is None and hasattr(tool_registry, "_graph"):
                        tool = tool_registry._graph.get_tool(name)
                    if tool:
                        tools_metadata.append(
                            {
                                "name": tool.name,
                                "description": getattr(tool, "description", ""),
                                "tags": getattr(tool, "tags", []),
                                "category": getattr(tool, "category", ""),
                            }
                        )
                        for tag in getattr(tool, "tags", []):
                            self._add_to_index(tag.lower(), name)
                        desc = getattr(tool, "description", "")
                        if desc and desc != name:
                            for word in desc.lower().split():
                                if len(word) > 2:
                                    self._add_to_index(word, name)
                except Exception as exc:
                    logger.warning("Failed to get tool metadata for %s: %s", name, exc)

        # Train NLP Engine
        if tools_metadata:
            self._nlp.train_tools(tools_metadata)
        templates_meta = {
            k: " ".join(step["description"] for step in v) for k, v in self._templates.items() if v
        }
        self._nlp.train_templates(templates_meta)

    def _add_to_index(self, keyword: str, tool_name: str) -> None:
        if keyword not in self._keyword_index:
            self._keyword_index[keyword] = set()
        self._keyword_index[keyword].add(tool_name)

    def _search_index(self, query: str) -> list[str]:
        words = {w for w in re.split(r"[^\w]+", query.lower()) if len(w) > 1}
        if not words:
            return []
        scores: dict[str, int] = {}
        for w in words:
            for tool_name in self._keyword_index.get(w, []):
                scores[tool_name] = scores.get(tool_name, 0) + 1
        if not scores:
            for key, names in self._keyword_index.items():
                if key in query.lower():
                    for n in names:
                        scores[n] = scores.get(n, 0) + 1
        for t in list(scores.keys()):
            t_lower = t.lower()
            if t_lower in words:
                scores[t] += 500
            else:
                for part in re.split(r"[-_.]+", t_lower):
                    if part in words and len(part) > 2:
                        scores[t] += 50
                        break
        ranked = sorted(scores, key=lambda n: -scores[n])
        return ranked

    def resolve_alternatives(
        self, template_name: str, available_tools: set[str]
    ) -> list[dict[str, Any]]:
        steps = self._templates.get(template_name, [])
        resolved = []
        for step in steps:
            tool = step["tool"]
            if not available_tools or tool in available_tools:
                resolved.append(step)
            else:
                alt_found = None
                for alt in TOOL_ALTERNATIVES.get(tool, []):
                    if alt in available_tools:
                        alt_found = alt
                        break
                if alt_found:
                    resolved.append(
                        {
                            **step,
                            "tool": alt_found,
                            "description": f"{step['description']} (via {alt_found})",
                        }
                    )
                else:
                    logger.warning("Tool %s missing and no alternative found. Keeping step for auto-install.", tool)
                    resolved.append(step)
        return resolved

    # ── Core planning ─────────────────────────────────────────────────────

    def plan(self, goal: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        """Main entry point — decompose a user goal into an execution plan."""
        return self.decompose_goal(goal, available_tools)

    def smart_plan(self, text: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        """Plan using NLP analysis for smarter intent understanding.

        Uses the trained NaturalLanguageParser to extract intent, target,
        and parameters from natural language. Falls back to decompose_goal()
        when confidence is low or no template matches.
        """
        avail_set = set(available_tools or [])
        intent = self._nlp.parse(text)

        context = {
            "nlp_template": intent.template_name or "",
            "nlp_confidence": intent.confidence,
            "nlp_target": intent.target,
            "nlp_target_type": intent.target_type,
            "nlp_parameters": intent.parameters,
        }

        if intent.template_name and intent.confidence > 0.15:
            target = intent.target or text
            overrides = {"args": intent.parameters} if intent.parameters else None
            try:
                plan = self.create_from_template(
                    intent.template_name,
                    target,
                    overrides=overrides,
                    available_tools=avail_set,
                )
                plan.context.update(context)
                return plan
            except ValueError:
                pass

        return self.decompose_goal(text, available_tools)

    def create_plan(
        self,
        goal: str,
        plan_type: PlanType = PlanType.SEQUENTIAL,
        steps: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        plan_steps = []
        if steps:
            for i, step_def in enumerate(steps):
                plan_steps.append(
                    PlanStep(
                        id=step_def.get("id", f"step_{i:03d}"),
                        description=step_def.get("description", f"Step {i + 1}"),
                        tool=step_def.get("tool", ""),
                        args=step_def.get("args", {}),
                        command=step_def.get("command"),
                        dependencies=step_def.get("dependencies", []),
                        timeout=step_def.get("timeout", 300.0),
                    )
                )
        plan = ExecutionPlan(
            goal=goal,
            plan_type=plan_type,
            steps=plan_steps,
            context=context or {},
            status=PlanStatus.ACTIVE,
        )
        self._plans[plan.id] = plan
        emit_sync(
            Event(
                type=EventType.PLAN_CREATED,
                source="planner_registry",
                data={"plan_id": plan.id, "goal": goal, "steps": len(plan_steps)},
            )
        )
        return plan

    def create_from_template(
        self,
        template_name: str,
        target: str,
        overrides: dict[str, Any] | None = None,
        available_tools: set[str] | None = None,
    ) -> ExecutionPlan:
        template = self._templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown template: {template_name}")
        if available_tools:
            template = self.resolve_alternatives(template_name, available_tools)
        url_match = re.search(r"https?://[^\s]+", target)
        host_match = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", target.lower())
        clean_target = (
            url_match.group(0) if url_match else (host_match.group(0) if host_match else target)
        )
        steps = []
        for step_def in template:
            step = {**step_def, "args": {**step_def.get("args", {}), "target": clean_target}}
            if overrides:
                # Merge overrides carefully, and apply NLP-specific overrides mapping if applicable
                override_args = overrides.get("args", {})
                tool_name = step.get("tool")
                
                # Intelligent parameter mapping to avoid passing bad args to tools
                if tool_name in ("nmap", "masscan"):
                    if "speed" in override_args:
                        step["args"]["flags"] = step["args"].get("flags", "") + f" -T{override_args['speed']} "
                    if "ports" in override_args:
                        step["args"]["flags"] = step["args"].get("flags", "") + f" -p {override_args['ports']} "
                    if "threads" in override_args:
                        step["args"]["flags"] = step["args"].get("flags", "") + f" --min-rate {override_args['threads']} "
                elif tool_name in ("ffuf", "gobuster", "hydra"):
                    if "threads" in override_args:
                        step["args"]["threads"] = override_args["threads"]
                    if "username" in override_args:
                        step["args"]["username"] = override_args["username"]
                    if "password" in override_args:
                        step["args"]["password"] = override_args["password"]
                elif tool_name == "nuclei":
                    if "threads" in override_args:
                        step["args"]["rate-limit"] = override_args["threads"]
                        
                # Merge the rest (this might overwrite some but it's okay)
                for k, v in override_args.items():
                    if k not in ("speed", "ports", "threads", "username", "password", "module"):
                        step["args"][k] = v
                
                # Cleanup spaces
                if "flags" in step["args"]:
                    step["args"]["flags"] = step["args"]["flags"].strip()
                    
            steps.append(step)
        plan_type = (
            PlanType.DAG if template_name in self._auto_dag_templates else PlanType.SEQUENTIAL
        )
        return self.create_plan(
            goal=f"{template_name} on {clean_target}",
            steps=steps,
            context={"target": clean_target, "template": template_name},
            plan_type=plan_type,
        )

    def decompose_goal(self, goal: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        # Handle multi-step intents
        intents = self._nlp.parse_multi(goal)
        if len(intents) > 1:
            all_steps = []
            is_dag = False
            last_step_ids: list[str] = []
            for intent in intents:
                sub_plan = self.decompose_goal(intent.raw_text, available_tools)
                
                # If there are previous steps, make the first steps of THIS intent depend on the last steps of the PREVIOUS intent
                if last_step_ids and sub_plan.steps:
                    for step in sub_plan.steps:
                        if not step.dependencies:
                            step.dependencies.extend(last_step_ids)
                
                all_steps.extend(sub_plan.steps)
                last_step_ids = [s.id for s in sub_plan.steps if s.is_terminal or not any(other.id in s.dependencies for other in sub_plan.steps)]
                # Fallback if the logic above returns empty
                if not last_step_ids and sub_plan.steps:
                    last_step_ids = [sub_plan.steps[-1].id]
                    
                if sub_plan.plan_type == PlanType.DAG:
                    is_dag = True
            plan_type = PlanType.DAG if is_dag else PlanType.SEQUENTIAL
            
            # Injected dependencies should make this a DAG if dependencies exist
            if any(s.dependencies for s in all_steps):
                plan_type = PlanType.DAG
                
            return self.create_plan(
                goal=goal,
                steps=[{"id": s.id, "description": s.description, "tool": s.tool, "args": s.args, "command": s.command, "dependencies": s.dependencies, "timeout": s.timeout} for s in all_steps],
                context={"target": intents[0].target if intents else ""},
                plan_type=plan_type,
            )

        goal_lower = goal.lower()
        avail_set = set(available_tools or [])

        # ── Step 0: NLP Semantic Intent Parsing ─────────────────────────
        intent = self._nlp.parse(goal)
        target = intent.target

        # If NLP engine has high confidence in a template
        if intent.template_name and intent.confidence > 1.5:
            return self.create_from_template(
                intent.template_name,
                target,
                overrides={"args": intent.parameters},
                available_tools=avail_set,
            )

        # If NLP engine has high confidence in a specific tool
        if intent.tool_name and intent.confidence > 1.5:
            actual_tool = intent.tool_name
            if actual_tool not in avail_set and available_tools:
                for alt in TOOL_ALTERNATIVES.get(actual_tool, []):
                    if alt in avail_set:
                        actual_tool = alt
                        break
            args = {"target": target}
            flags = ""

            # Apply Semantic Parameters
            if actual_tool in ("nmap", "masscan"):
                if intent.parameters.get("speed") == "fast":
                    flags += "-T4 "
                elif intent.parameters.get("speed") == "stealth":
                    flags += "-sS -T2 "
                else:
                    flags += "-sT -T4 "

                if intent.parameters.get("ports") == "all":
                    flags += "-p- "
                elif intent.parameters.get("ports"):
                    flags += f"-p {intent.parameters['ports']} "
                else:
                    flags += "--top-ports 100 "

                if intent.parameters.get("verbose"):
                    flags += "-v "
                if intent.parameters.get("timeout"):
                    flags += f"--host-timeout {intent.parameters['timeout']} "
                if intent.parameters.get("format") == "xml":
                    flags += "-oX - "

            elif actual_tool == "nuclei":
                if intent.parameters.get("severity"):
                    flags += f"-s {intent.parameters['severity']} "
                if intent.parameters.get("format") == "json":
                    flags += "-json-export "
                if intent.parameters.get("timeout"):
                    flags += f"-timeout {intent.parameters['timeout'].replace('s', '')} "

            elif actual_tool in ("ffuf", "gobuster"):
                if intent.parameters.get("timeout"):
                    flags += f"-t {intent.parameters['timeout'].replace('s', '')} "
                if intent.parameters.get("format") == "json":
                    flags += "-o result.json -of json "

            if flags:
                args["flags"] = flags.strip()

            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": f"Execute {actual_tool} on {target}",
                        "tool": actual_tool,
                        "args": args,
                    }
                ],
            )

        # ── Step 1: Match against named workflow templates ──────────────
        kw_map = [
            (("brute", "crack", "password", "credential"), "brute_force"),
            (("wifi", "wireless", "wpa"), "wifi_audit"),
            (
                ("ad ", "active directory", "domain controller", "kerberos", "ldap", "smb"),
                "ad_assessment",
            ),
            (("cloud", "aws", "s3 ", "azure", "gcp"), "cloud_audit"),
            (("privesc", "privilege escalation", "root", "suid", "linux audit"), "linux_privesc"),
            (
                ("network scan", "infrastructure", "port scan", "full scan", "open ports"),
                "network_scan",
            ),
            (("web", "website", "webapp", "web app", "cms"), "web_audit"),
            (("subdomain", "subdomain", "dns enum", "dnsrecon"), "recon_full"),
            (("vuln", "cve", "vulnerability", "exploit"), "vuln_scan"),
            (("dns recon", "dns enum", "dns record", "nameserver", "mx record"), "dns_recon"),
            (("smb", "netbios", "windows share", "cifs"), "smb_enum"),
            (("full scan", "full audit", "comprehensive scan", "thorough check"), "full_audit"),
            (("http header", "response header", "security header"), "headers_check"),
            (("cors", "cross-origin", "cross origin"), "cors_check"),
            (("ssl", "tls", "certificate", "https cert", "cipher"), "ssl_audit"),
        ]
        for keywords, template_name in kw_map:
            if any(kw in goal_lower for kw in keywords):
                return self.create_from_template(template_name, goal, available_tools=avail_set)

        # ── Step 2: Extract target ─────────────────────────────────────
        url_match = re.search(r"https?://[^\s]+", goal)
        host_match = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", goal_lower)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", goal)
        target = ""
        if url_match:
            target = url_match.group(0)
        elif host_match:
            target = host_match.group(0)
        elif ip_match:
            target = ip_match.group(0)

        # ── Step 3: Availability-weighted index search ──────────────────
        tool_match = None
        if available_tools:
            if self._keyword_index:
                candidates = self._search_index(goal)
                for c in candidates:
                    if c in avail_set:
                        pattern = r"(?<!\w)" + re.escape(c.lower()) + r"(?!\w)"
                        if re.search(pattern, goal_lower):
                            tool_match = c
                            break
            if not tool_match:
                for t in available_tools:
                    if len(t) < 3:
                        continue
                    pattern = r"(?<!\w)" + re.escape(t.lower()) + r"(?!\w)"
                    if re.search(pattern, goal_lower):
                        tool_match = t
                        break
        if tool_match:
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": f"Execute {tool_match} on {target}",
                        "tool": tool_match,
                        "args": {
                            "target": target,
                            "flags": "-sT -T4 --top-ports 100" if tool_match == "nmap" else "",
                        },
                    }
                ],
            )

        # ── Step 4: Intent-based tool selection ─────────────────────────
        if target:
            intent_map = {
                "headers": ("curl", "HTTP headers check", "-sIL"),
                "http": ("curl", "HTTP headers check", "-sIL"),
                "tech": ("whatweb", "Technology fingerprinting", ""),
                "framework": ("whatweb", "Technology fingerprinting", ""),
                "wp": ("wpscan", "WordPress vulnerability scan", ""),
                "wordpress": ("wpscan", "WordPress vulnerability scan", ""),
                "cms": ("whatweb", "CMS fingerprinting", ""),
                "vuln": ("nuclei", "Vulnerability scan", "-t http"),
                "cve": ("nuclei", "CVE scan", "-t http/cves"),
                "fuzz": ("ffuf", "Directory fuzzing", f"-w {_COMMON_WORDLIST}"),
                "directories": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "dirbust": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "endpoint": ("gobuster", "Endpoint enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "sqli": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
                "sql": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
                "xss": ("nuclei", "XSS scan", "-t http/xss"),
                "dns": ("dig", "DNS enumeration", ""),
                "nameserver": ("dig", "DNS enumeration", ""),
                "resolve": ("dig", "DNS enumeration", ""),
                "subdomain": ("subfinder", "Subdomain enumeration", ""),
                "sub": ("subfinder", "Subdomain enumeration", ""),
                "whois": ("whois", "WHOIS lookup", ""),
                "port": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "open port": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "service": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "masscan": ("masscan", "Mass port scan", "--rate 1000 --top-ports 100"),
                "recon": ("nmap", "Recon scan", "-sT -sV -T4 --top-ports 1000"),
                "scan": ("nmap", "Quick scan", "-sT -T4 --top-ports 100"),
                "explore": ("nmap", "Full scan", "-sT -sV -T4 --top-ports 1000"),
                "stealth": (
                    "nmap",
                    "Stealth scan",
                    "-sT -T2 --top-ports 100" if os.name == "nt" else "-sS -T2 --top-ports 100",
                ),
                "ssl": ("nmap", "SSL/TLS check", "--script ssl-enum-ciphers -p 443"),
                "tls": ("nmap", "SSL/TLS check", "--script ssl-enum-ciphers -p 443"),
                "smb": (
                    "nmap",
                    "SMB enumeration",
                    "--script smb-enum-shares,smb-os-discovery -p 445",
                ),
                "brute": (
                    "hydra",
                    "Brute force attack",
                    f"-L {_USERNAME_WORDLIST} -P {_PASSWORD_WORDLIST}",
                ),
                "crack": ("hashcat", "Hash cracking", ""),
                "cors": ("curl", "CORS check", "-sI -H 'Origin: https://evil.com'"),
                "certificate": ("openssl", "Certificate info", "s_client -connect {target}:443"),
                "cipher": ("nmap", "Cipher suite check", "--script ssl-enum-ciphers -p 443"),
                "header": ("curl", "Header check", "-sIL"),
                "cookie": ("curl", "Cookie analysis", "-sIL -D -"),
                "redirect": ("curl", "Redirect chain", "-sIL -o /dev/null -w '%{redirect_url}'"),
                "screenshot": ("eyewitness", "Web screenshot", ""),
                "cloud": ("curl", "Cloud metadata check", "-sI"),
                "aws": ("curl", "AWS metadata check", "-sI"),
                "azure": ("curl", "Azure metadata check", "-sI"),
                "gcp": ("curl", "GCP metadata check", "-sI"),
                "docker": ("nmap", "Docker discovery", "-sT -p 2375,2376"),
                "k8s": ("nmap", "Kubernetes discovery", "-sT -p 6443,10250,10255"),
                "api": ("curl", "API endpoint check", "-s -o /dev/null -w '%{http_code}'"),
                "waf": ("nmap", "WAF detection", "--script http-waf-detect -p 80,443"),
                "cdn": ("curl", "CDN detection", "-sI"),
                "ldap": ("nmap", "LDAP enumeration", "--script ldap-rootdse -p 389"),
                "kerberos": ("nmap", "Kerberos enumeration", "--script krb5-enum-users -p 88"),
                "ntlm": ("nmap", "NTLM info", "--script http-ntlm-info -p 80,443"),
            }
            matched_keyword = None
            for keyword in sorted(intent_map, key=len, reverse=True):
                if keyword in goal_lower:
                    matched_keyword = keyword
                    break
            if matched_keyword:
                tool, desc, flags = intent_map[matched_keyword]
                actual_tool = tool
                if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                    for alt in TOOL_ALTERNATIVES[tool]:
                        if alt in avail_set:
                            actual_tool = alt
                            break
                clean_target = (
                    target.replace("https://", "").replace("http://", "").split("/")[0]
                )
                return self.create_plan(
                        goal=goal,
                        steps=[
                            {
                                "description": desc
                                + (f" (via {actual_tool})" if actual_tool != tool else ""),
                                "tool": actual_tool,
                                "args": {"target": clean_target, "flags": flags},
                            }
                        ],
                    )

            # ── Step 5: Category-aware probe fallback ───────────────────
            probe_groups = [
                [
                    ("curl", "HTTP headers check", "-sIL"),
                    ("whatweb", "Technology fingerprinting", ""),
                    (
                        "nuclei",
                        "Quick vulnerability scan",
                        "-t http -severity low,medium,high,critical",
                    ),
                    ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                ],
                [
                    ("dig", "DNS enumeration", ""),
                    ("subfinder", "Subdomain enumeration", ""),
                    ("whois", "WHOIS lookup", ""),
                ],
                [
                    ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                    ("masscan", "Mass port scan", "--rate 1000 --top-ports 100"),
                ],
            ]
            probe_steps = []
            last_step_id = None
            for group in probe_groups:
                for tool, desc, flags in group:
                    actual_tool = tool
                    if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                        for alt in TOOL_ALTERNATIVES[tool]:
                            if alt in avail_set:
                                actual_tool = alt
                                break
                    clean_target = (
                        target.replace("https://", "").replace("http://", "").split("/")[0]
                    )
                    step_id = f"probe_{actual_tool}"
                    probe_steps.append(
                        {
                            "id": step_id,
                            "description": desc
                            + (f" (via {actual_tool})" if actual_tool != tool else ""),
                            "tool": actual_tool,
                            "args": {"target": clean_target, "flags": flags},
                            "dependencies": [last_step_id] if last_step_id else [],
                        }
                    )
                    last_step_id = step_id
            if probe_steps:
                plan_type = PlanType.DAG if len(probe_steps) > 2 else PlanType.SEQUENTIAL
                return self.create_plan(goal=goal, steps=probe_steps, plan_type=plan_type)
            return self.create_plan(goal=goal)

        goal_keywords = {
            "scan",
            "recon",
            "audit",
            "check",
            "enum",
            "analyze",
            "analyse",
            "explore",
            "map",
            "discover",
            "probe",
            "test",
            "hack",
            "pentest",
        }
        if any(kw in goal_lower.split() for kw in goal_keywords):
            return self.create_plan(
                goal=goal,
                steps=[
                    {"description": "Technology fingerprinting", "tool": "whatweb", "args": {}},
                    {
                        "description": "Port scan",
                        "tool": "nmap",
                        "args": {"flags": "-sT -T4 --top-ports 100"},
                    },
                ],
            )
        return self.create_plan(goal=goal)

    def adapt_plan(self, plan: ExecutionPlan, failed_step: PlanStep, error: str) -> ExecutionPlan:
        error_lower = error.lower()
        RECOVERY_RULES: list[tuple[str | None, str, Any]] = [
            (
                "nmap",
                "filtered",
                lambda s: s.args.update({"flags": s.args.get("flags", "") + " -Pn"}),
            ),
            (
                "nmap",
                "permission",
                lambda s: s.args.update({"flags": s.args.get("flags", "").replace("-sS", "-sT")}),
            ),
            (None, "timeout", lambda s: s.args.update({"timeout": s.timeout * 1.5})),
            (
                "gobuster|ffuf",
                "404",
                lambda s: s.args.update({"extensions": "php,html,js,txt,asp,aspx"}),
            ),
            ("hydra", "invalid user", lambda s: s.args.update({"flags": "-e nsr"})),
            ("sqlmap", "not injectable", lambda s: s.args.update({"flags": "--level=3 --risk=2"})),
        ]
        for tool_pat, err_pat, recovery_fn in RECOVERY_RULES:
            tool_match = tool_pat is None or re.search(tool_pat, failed_step.tool)
            if tool_match and err_pat in error_lower:
                if failed_step.can_retry:
                    recovery_fn(failed_step)
                    failed_step.status = StepStatus.PENDING
                    failed_step.retry_count += 1
                    return plan
        if "refused" in error_lower:
            failed_step.status = StepStatus.SKIPPED
            plan.steps.append(
                PlanStep(
                    tool="nuclei",
                    args={"target": failed_step.args.get("target", "")},
                )
            )
            return plan
        if failed_step.can_retry:
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        else:
            failed_step.status = StepStatus.FAILED
        return plan

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        return self._plans.get(plan_id)

    def list_plans(self, status: PlanStatus | None = None) -> list[ExecutionPlan]:
        plans = list(self._plans.values())
        if status:
            plans = [p for p in plans if p.status == status]
        return sorted(plans, key=lambda p: -p.created_at)

    def stats(self) -> dict[str, Any]:
        plans = list(self._plans.values())
        return {
            "total_plans": len(plans),
            "active": len([p for p in plans if p.status == PlanStatus.ACTIVE]),
            "completed": len([p for p in plans if p.status == PlanStatus.COMPLETED]),
            "templates": list(self._templates.keys()),
        }


__all__ = [
    "RegistryPlanner",
    "TOOL_ALTERNATIVES",
]
