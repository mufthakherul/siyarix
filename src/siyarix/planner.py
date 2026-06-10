# SPDX-License-Identifier: AGPL-3.0-or-later
"""Advanced planning system with goal decomposition and workflow generation."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .events import Event, EventType, emit_sync


class PlanStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCESS = "success"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"
    BLOCKED = "blocked"


class PlanType(StrEnum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DAG = "dag"
    REACT = "react"
    ADAPTIVE = "adaptive"


class StepType(StrEnum):
    TOOL_RUN = "tool_run"
    SHELL_CMD = "shell_cmd"
    ANALYSIS = "analysis"
    REPORT = "report"
    NETWORK = "network"
    WEB = "web"


@dataclass
class ExecutionStep:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    step_type: StepType = StepType.TOOL_RUN
    tool: str = ""
    args: list[str] = field(default_factory=list)
    target: str = ""
    depends_on: list[str] = field(default_factory=list)
    command: str | None = None
    description: str = ""
    timeout: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanStep:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    command: str | None = None
    status: StepStatus = StepStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 300.0
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ready(self) -> bool:
        return self.status == StepStatus.PENDING

    @property
    def can_retry(self) -> bool:
        return self.retry_count < self.max_retries

    @property
    def is_terminal(self) -> bool:
        return self.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED)


@dataclass
class StepResult:
    step_id: str = ""
    status: StepStatus = StepStatus.PENDING
    output: str = ""
    error: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    exit_code: int | None = None
    duration_ms: float = 0.0


@dataclass
class ExecutionPlan:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    goal: str = ""
    plan_type: PlanType = PlanType.SEQUENTIAL
    status: PlanStatus = PlanStatus.DRAFT
    steps: list[PlanStep] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_instruction: str = ""
    source: str = ""
    confidence: float = 1.0

    @property
    def completed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == StepStatus.COMPLETED]

    @property
    def failed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == StepStatus.FAILED]

    @property
    def pending_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status in (StepStatus.PENDING, StepStatus.READY)]

    @property
    def is_complete(self) -> bool:
        return all(s.is_terminal for s in self.steps)

    @property
    def has_failures(self) -> bool:
        return any(s.status == StepStatus.FAILED for s in self.steps)

    @property
    def progress_pct(self) -> float:
        if not self.steps:
            return 100.0
        done = len(self.completed_steps) + len(
            [s for s in self.steps if s.status == StepStatus.SKIPPED]
        )
        return (done / len(self.steps)) * 100.0

    def get_step(self, step_id: str) -> PlanStep | None:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def get_ready_steps(self) -> list[PlanStep]:
        ready = []
        for step in self.steps:
            if step.status not in (StepStatus.PENDING, StepStatus.READY):
                continue
            deps_met = True
            for dep in step.dependencies:
                dep_step = self.get_step(dep)
                if dep_step is None or dep_step.status != StepStatus.COMPLETED:
                    deps_met = False
                    break
            if deps_met:
                step.status = StepStatus.READY
                ready.append(step)
        return ready

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "type": self.plan_type.value,
            "status": self.status.value,
            "progress": self.progress_pct,
            "steps": [
                {"id": s.id, "description": s.description, "tool": s.tool, "status": s.status.value}
                for s in self.steps
            ],
        }


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


class Planner:
    """Plan decomposer with an inverted-index strategy for scalable tool lookup."""

    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._auto_dag_templates: set[str] = {
            "recon_full",
            "web_audit",
            "network_scan",
            "cloud_audit",
        }
        self._cron_path = "/etc/crontab" if os.name != "nt" else "C:\\Windows\\System32\\Tasks"
        self._templates: dict[str, list[dict[str, Any]]] = {
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
                    "description": "Full TCP SYN sweep with high-rate discovery",
                    "tool": "nmap",
                    "args": {"flags": "-sS -T4 -p- --min-rate 1000"},
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
                    "description": "Domain controller critical port scan (Kerberos, LDAP, SMB, RPC, GC)",
                    "tool": "nmap",
                    "args": {
                        "flags": "-sS -sV -T4 -p 53,88,135,139,389,445,464,636,3268,3269,3389"
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
            ],
            "linux_privesc": [
                {
                    "description": "Kernel and OS version identification for known exploit matching",
                    "tool": "uname",
                    "args": {"flags": "-a"},
                },
                {
                    "description": "SUID and SGID binary discovery for privilege escalation vectors",
                    "tool": "find",
                    "args": {"flags": "/ -perm -4000 -type f 2>/dev/null"},
                },
                {
                    "description": "World-writable directory search for dropper placements",
                    "tool": "find",
                    "args": {"flags": "/ -writable -type d 2>/dev/null"},
                },
                {
                    "description": "Scheduled task and cron job inspection for persistence",
                    "tool": "cat",
                    "args": {"flags": self._cron_path},
                },
            ],
        }
        # Inverted index: keyword → set of tool names
        self._keyword_index: dict[str, set[str]] = {}

    # ── Index builder ─────────────────────────────────────────────────────

    def build_index(self, available_tools: list[str], tool_registry: Any = None) -> None:
        """Build an inverted keyword index from available tool names & metadata.

        ``tool_registry`` is any object that provides ``.get_tool(name)``
        returning an object with ``.tags``, ``.description``, ``.category``.
        """
        self._keyword_index.clear()
        for name in available_tools:
            name_lower = name.lower()
            # Index the full name
            self._add_to_index(name_lower, name)
            # Index each word in the name (split on "-", "_", ".")
            for part in re.split(r"[-_.]+", name_lower):
                if len(part) > 1:
                    self._add_to_index(part, name)
            # Index tags and description when a registry is available
            if tool_registry is not None:
                try:
                    tool = (
                        tool_registry.get_tool(name) if hasattr(tool_registry, "get_tool") else None
                    )
                    if tool is None and hasattr(tool_registry, "_graph"):
                        tool = tool_registry._graph.get_tool(name)
                    if tool:
                        for tag in getattr(tool, "tags", []):
                            self._add_to_index(tag.lower(), name)
                        desc = getattr(tool, "description", "")
                        if desc and desc != name:
                            for word in desc.lower().split():
                                if len(word) > 2:
                                    self._add_to_index(word, name)
                except Exception:
                    pass

    def resolve_alternatives(
        self, template_name: str, available_tools: set[str]
    ) -> list[dict[str, Any]]:
        """Resolve template steps, substituting missing tools with alternatives."""
        steps = self._templates.get(template_name, [])
        resolved = []
        for step in steps:
            tool = step["tool"]
            if tool in available_tools:
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
                    resolved.append(step)
        return resolved

    def _add_to_index(self, keyword: str, tool_name: str) -> None:
        if keyword not in self._keyword_index:
            self._keyword_index[keyword] = set()
        self._keyword_index[keyword].add(tool_name)

    def _search_index(self, query: str) -> list[str]:
        """Return tool names matching the query, ranked by relevance.

        Scoring (higher = better):
          - Tool name is literally in the query        → +500  (exact charter)
          - A name-part (split on ``-_.``) is in query  → +50
          - A tag word matches                          → +10
          - A description word matches                  → +3

        Returns only tools with a positive score,
        ordered by score descending.
        """
        words = {w for w in re.split(r"[^\w]+", query.lower()) if len(w) > 1}
        if not words:
            return []

        scores: dict[str, int] = {}
        for w in words:
            for tool_name in self._keyword_index.get(w, []):
                scores[tool_name] = scores.get(tool_name, 0) + 1

        # Fallback: if no word matched, try substring match of index keys
        if not scores:
            for key, names in self._keyword_index.items():
                if key in query.lower():
                    for n in names:
                        scores[n] = scores.get(n, 0) + 1

        # Boost exact and part matches
        for t in list(scores.keys()):
            t_lower = t.lower()
            if t_lower in words:
                scores[t] += 500  # exact name matched literally
            else:
                for part in re.split(r"[-_.]+", t_lower):
                    if part in words and len(part) > 2:
                        scores[t] += 50
                        break

        ranked = sorted(scores, key=lambda n: -scores[n])
        return ranked

    # ── LLM-driven planning ─────────────────────────────────────────────

    async def llm_decompose_goal(
        self,
        goal: str,
        available_tools: list[str],
        llm_call: Any,
        tool_schemas: list[dict] | None = None,
        system_prompt: str | None = None,
        history: list[dict] | None = None,
    ) -> ExecutionPlan:
        """Use an LLM to analyse the user's goal and produce a tool plan.

        The LLM decides:
        1. Whether tools are needed at all
        2. Which tools from *available_tools* are suitable
        3. What arguments each tool should receive

        Parameters
        ----------
        llm_call:
            An async callable ``(system_prompt: str, user_prompt: str, *, history: list[dict] | None = None) → str``
            that returns the LLM's response text.
        tool_schemas:
            Optional list of tool dicts with ``name``, ``description``,
            ``tags``, ``category`` to give the LLM richer context.
        system_prompt:
            Optional external system prompt. When provided the tools list
            is appended; when omitted the old inline prompt is used.
        history:
            Optional list of ``{"role": ..., "content": ...}`` dicts from prior conversation.
        """
        # Build a compact tool list for the prompt
        if tool_schemas:
            tool_lines = []
            for t in tool_schemas:
                name = t.get("name", "")
                desc = t.get("description", "")
                tags = t.get("tags", [])
                cat = t.get("category", "")
                if name in available_tools:
                    meta = f"  - {name}"
                    if desc and desc != name:
                        meta += f": {desc}"
                    if tags:
                        meta += f" [{', '.join(tags[:5])}]"
                    if cat:
                        meta += f" ({cat})"
                    tool_lines.append(meta)
        else:
            tool_lines = [f"  - {t}" for t in available_tools]

        if system_prompt:
            full_prompt = (
                system_prompt
                + "\n\nCommands you construct will execute via `sh -c` — use proper quoting, pipes, and flags. You have full access to every binary on the system."
            )
        else:
            full_prompt = """You are a senior red-team operator and penetration testing specialist.

You have full access to every binary on this system. Construct exact shell commands.

Respond with ONLY valid JSON:
{{
  "needs_tools": true or false,
  "reasoning": "Strategic rationale",
  "steps": [
    {{
      "tool": "",
      "command": "exact shell command with all flags and arguments",
      "description": "What this does"
    }}
  ]
}}

- needs_tools=true for security operations, false for chat/explanation
- Always use the "command" field for raw shell execution"""

        user_prompt = goal

        try:
            raw = await llm_call(full_prompt, user_prompt, history=history)
            response = raw.get("content", "") if isinstance(raw, dict) else str(raw)
        except Exception as exc:
            raise RuntimeError(f"LLM planning call failed: {exc}") from exc

        # Parse JSON response
        # Strip any markdown fences the LLM might add
        cleaned = response.strip()
        if cleaned.startswith("```"):
            # Remove ```json … ``` fences
            cleaned = cleaned.split("\n", 1)[-1]
            cleaned = cleaned.rsplit("```", 1)[0]
        cleaned = cleaned.strip()
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"LLM returned invalid JSON:\n{cleaned[:500]}") from exc

        if not data.get("needs_tools"):
            return self.create_plan(
                goal=goal,
                context={"reasoning": data.get("reasoning", ""), "response": data.get("response", ""), "llm_planned": True},
            )

        steps_raw = data.get("steps", [])
        steps = []
        for i, s in enumerate(steps_raw):
            step_def: dict[str, Any] = {
                "description": s.get("description", f"LLM step {i+1}"),
                "tool": s.get("tool", ""),
                "command": s.get("command"),
                "args": s.get("args", {}),
            }
            steps.append(step_def)

        if not steps:
            # LLM said needs_tools but gave no steps — treat as chat
            return self.create_plan(
                goal=goal,
                context={"reasoning": data.get("reasoning", ""), "response": data.get("response", ""), "llm_planned": True},
            )

        return self.create_plan(
            goal=goal,
            steps=steps,
            context={"reasoning": data.get("reasoning", ""), "response": data.get("response", ""), "llm_planned": True},
        )

    # ── Existing API ──

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
                        id=f"step_{i:03d}",
                        description=step_def.get("description", f"Step {i+1}"),
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
                source="planner",
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
        import re

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
                step["args"].update(overrides.get("args", {}))
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
        goal_lower = goal.lower()
        avail_set = set(available_tools or [])
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
        ]
        for keywords, template_name in kw_map:
            if any(kw in goal_lower for kw in keywords):
                return self.create_from_template(template_name, goal, available_tools=avail_set)
        url_match = re.search(r"https?://[^\s]+", goal)
        host_match = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", goal_lower)
        target = ""
        if url_match:
            target = url_match.group(0)
        elif host_match:
            target = host_match.group(0)

        # Availability-weighted index search
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
        if target:
            # Smart fallback: pick available tools from probe set
            probe_steps = []
            for tool, desc, flags in [
                ("curl", "HTTP headers check", "-sI"),
                ("whatweb", "Technology fingerprinting", ""),
                ("dig", "DNS enumeration", ""),
                ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
            ]:
                actual_tool = tool
                if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                    for alt in TOOL_ALTERNATIVES[tool]:
                        if alt in avail_set:
                            actual_tool = alt
                            break
                if actual_tool in avail_set or not avail_set:
                    clean_target = (
                        target.replace("https://", "").replace("http://", "").split("/")[0]
                    )
                    probe_steps.append(
                        {
                            "description": desc
                            + (f" (via {actual_tool})" if actual_tool != tool else ""),
                            "tool": actual_tool,
                            "args": {"target": clean_target, "flags": flags},
                        }
                    )
            if probe_steps:
                plan_type = PlanType.DAG if len(probe_steps) > 2 else PlanType.SEQUENTIAL
                return self.create_plan(goal=goal, steps=probe_steps, plan_type=plan_type)
            return self.create_plan(goal=goal)
        # Check if the query sounds like a security/recon goal (no target given)
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
        if failed_step.tool == "nmap" and "filtered" in error.lower():
            failed_step.args["flags"] = failed_step.args.get("flags", "") + " -Pn"
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        elif failed_step.tool in ("nikto", "nuclei") and "refused" in error.lower():
            idx = plan.steps.index(failed_step)
            plan.steps.insert(
                idx + 1,
                PlanStep(
                    id=f"adapted_{idx}",
                    description="Fallback scan",
                    tool="nuclei",
                    args={"target": failed_step.args.get("target", "")},
                ),
            )
            failed_step.status = StepStatus.SKIPPED
        elif failed_step.tool in ("gobuster", "ffuf") and "404" in error:
            failed_step.args["extensions"] = "php,html,js,txt"
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        elif failed_step.can_retry:
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
