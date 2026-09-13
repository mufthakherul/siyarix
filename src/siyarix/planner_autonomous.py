# SPDX-License-Identifier: AGPL-3.0-or-later
"""Autonomous planner — LLM-only goal decomposition without local heuristic fallback.

Sends tool schemas only on the first call of a session to conserve tokens.
The LLM is responsible for verifying tool availability, installing missing
tools, and constructing correct shell commands.
"""

from __future__ import annotations

import json
import logging
import platform as _platform
import re
import sys
from typing import Any, overload

from .events import Event, EventType, emit_sync
from .models import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    PlanType,
    StepStatus,
)

logger = logging.getLogger(__name__)


class PlanValidator:
    """Enterprise-grade plan and command validator for cyber security operations.

    Validates execution steps against platform boundaries, safety policies,
    OPSEC rules, and removes duplicate redundant steps.
    """

    DANGEROUS_PATTERNS: list[str] = [
        r"\brm\s+-(?:rf?|fr?)\s+/(?:\s|$)",  # rm -rf /
        r"\bdel\s+/[sfq]\s+[Cc]:\\(?:\s|$)",  # del /s C:\
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",  # fork bomb
        r"\bdd\s+if=.*?of=/dev/[sh]d[a-z]\b",
        r"\bmkfs\b",
        r"\bformat\s+[Cc]:\b",
    ]

    @overload
    @classmethod
    def validate_and_sanitize_step(
        cls,
        step: PlanStep,
        platform_system: str | None = None,
    ) -> PlanStep: ...

    @overload
    @classmethod
    def validate_and_sanitize_step(
        cls,
        step: dict[str, Any],
        platform_system: str | None = None,
    ) -> dict[str, Any]: ...

    @classmethod
    def validate_and_sanitize_step(
        cls,
        step: PlanStep | dict[str, Any],
        platform_system: str | None = None,
    ) -> PlanStep | dict[str, Any]:
        """Validate and sanitize a plan step for safety and platform compatibility."""
        if isinstance(step, PlanStep):
            cmd = step.command
        else:
            cmd = step.get("command")

        if not cmd:
            return step

        platform_sys = (platform_system or _platform.system()).lower()
        is_windows = "win" in platform_sys

        # 1. Dangerous command guard
        for pat in cls.DANGEROUS_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                logger.warning("PlanValidator: dangerous command blocked: %s", cmd)
                blocked_msg = (
                    f"echo '[SECURITY POLICY] Command blocked by safety guard: {cmd[:40]}'"
                )
                if isinstance(step, PlanStep):
                    step.command = blocked_msg
                    step.metadata["blocked_dangerous"] = True
                else:
                    step["command"] = blocked_msg
                    step.setdefault("metadata", {})["blocked_dangerous"] = True
                return step

        # 2. Platform sanitization
        if is_windows:
            # Strip unix-only sudo
            if cmd.startswith("sudo "):
                cmd = cmd[5:]
            # Rewrite nmap -sS to -sT -Pn on Windows
            if "nmap" in cmd and "-sS" in cmd:
                cmd = cmd.replace("-sS", "-sT -Pn")
            # Rewrite which to where
            if cmd.startswith("which "):
                cmd = "where " + cmd[6:]
        else:
            # On POSIX, strip Windows type/where if accidentally emitted
            if cmd.startswith("where "):
                cmd = "which " + cmd[6:]

        # 3. OPSEC tuning: clamp overly aggressive thread limits to prevent unintended DoS
        if re.search(r"\b(gobuster|ffuf|hydra|dirsearch)\b", cmd):

            def _clamp_threads(m: re.Match[str]) -> str:
                t_val = int(m.group(2))
                if t_val > 64:
                    return "-t 64"
                return str(m.group(0))

            cmd = re.sub(r"(-t\s+)(\d+)", _clamp_threads, cmd)

        if isinstance(step, PlanStep):
            step.command = cmd
        else:
            step["command"] = cmd

        return step

    @classmethod
    def deduplicate_steps(cls, steps: list[PlanStep]) -> list[PlanStep]:
        """Remove duplicate redundant steps while preserving order."""
        seen: set[str] = set()
        deduped: list[PlanStep] = []
        for s in steps:
            cmd = (s.command or "").strip()
            key = cmd if cmd else f"{s.tool}:{json.dumps(s.args, sort_keys=True)}"
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            deduped.append(s)
        return deduped

    @classmethod
    def compute_execution_waves(cls, steps: list[PlanStep]) -> list[list[PlanStep]]:
        """Compute execution waves for parallel vs sequential execution using topological grouping."""
        if not steps:
            return []

        step_map = {s.id: s for s in steps}
        resolved: set[str] = set()
        waves: list[list[PlanStep]] = []
        remaining = list(steps)

        while remaining:
            current_wave: list[PlanStep] = []
            for s in list(remaining):
                deps = [d for d in s.dependencies if d in step_map]
                if not deps or all(d in resolved for d in deps):
                    current_wave.append(s)
                    remaining.remove(s)
            if not current_wave:
                # Cycle detected or unreachable dependencies — execute remaining sequentially
                for s in remaining:
                    waves.append([s])
                break
            waves.append(current_wave)
            for s in current_wave:
                resolved.add(s.id)

        return waves


class SemanticToolSelector:
    """Intelligently filters and prioritizes the most relevant tools for a given goal.

    Prevents token bloat, reduces local model latency, and ensures high precision.
    """

    KEYWORD_MAPPINGS: dict[str, list[str]] = {
        "web": [
            "nmap",
            "httpx",
            "nuclei",
            "whatweb",
            "ffuf",
            "gobuster",
            "curl",
            "subfinder",
            "whois",
            "dig",
            "sqlmap",
            "nikto",
        ],
        "dns": ["dig", "whois", "subfinder", "dnsrecon", "nmap", "curl"],
        "network": [
            "nmap",
            "masscan",
            "tshark",
            "netcat",
            "ping",
            "arp-scan",
            "traceroute",
            "tcpdump",
        ],
        "exploit": ["searchsploit", "metasploit", "sqlmap", "hydra", "nuclei", "cve_correlator"],
        "bruteforce": ["hydra", "john", "hashcat", "medusa", "ffuf", "gobuster"],
        "forensic": ["volatility", "strings", "binwalk", "exiftool", "gdb", "lsof", "file"],
        "cloud": ["aws", "azure", "gcloud", "scoutsuite", "prowler", "cloud_audit"],
        "ad": [
            "responder",
            "crackmapexec",
            "impacket",
            "smbmap",
            "enum4linux",
            "active_directory_inspector",
        ],
    }

    CORE_TOOLS: list[str] = ["nmap", "curl", "whois", "dig"]

    @classmethod
    def select_tools(
        cls,
        goal: str,
        tool_schemas: list[dict[str, Any]] | None = None,
        available_tools: list[str] | None = None,
        max_tools: int = 14,
    ) -> tuple[list[dict[str, Any]] | None, list[str] | None]:
        goal_lower = goal.lower()
        matched_categories: set[str] = set()

        if any(
            w in goal_lower
            for w in (
                "http",
                "https",
                "url",
                "domain",
                "web",
                "site",
                "api",
                "endpoint",
                "path",
                "graphql",
                "rest",
            )
        ):
            matched_categories.add("web")
        if any(
            w in goal_lower for w in ("dns", "record", "mx", "ns", "subdomain", "cname", "takeover")
        ):
            matched_categories.add("dns")
        if any(
            w in goal_lower
            for w in ("ip", "cidr", "subnet", "port", "network", "host", "ping", "sniff")
        ):
            matched_categories.add("network")
        if any(w in goal_lower for w in ("exploit", "vuln", "cve", "poc", "rce", "sqli", "epss")):
            matched_categories.add("exploit")
        if any(
            w in goal_lower for w in ("pass", "wordlist", "brute", "crack", "login", "auth", "hash")
        ):
            matched_categories.add("bruteforce")
        if any(
            w in goal_lower
            for w in ("memory", "dump", "process", "forensic", "pcap", "artifact", "binary")
        ):
            matched_categories.add("forensic")
        if any(
            w in goal_lower
            for w in ("cloud", "aws", "azure", "gcp", "s3", "iam", "bucket", "storage")
        ):
            matched_categories.add("cloud")
        if any(
            w in goal_lower
            for w in (
                "ad",
                "active directory",
                "kerberos",
                "ldap",
                "spn",
                "dcsync",
                "domain controller",
            )
        ):
            matched_categories.add("ad")
            matched_categories.add("network")

        priority_tool_names: list[str] = list(cls.CORE_TOOLS)
        for cat in matched_categories:
            priority_tool_names.extend(cls.KEYWORD_MAPPINGS.get(cat, []))

        if tool_schemas:
            schema_map = {t.get("name", "").lower(): t for t in tool_schemas}
            selected: list[dict[str, Any]] = []
            seen: set[str] = set()

            for p in priority_tool_names:
                p_low = p.lower()
                if p_low in schema_map and p_low not in seen:
                    selected.append(schema_map[p_low])
                    seen.add(p_low)
                if len(selected) >= max_tools:
                    break

            # Also check direct tool name matches in goal
            for t in tool_schemas:
                t_name = t.get("name", "").lower()
                if t_name and t_name in goal_lower and t_name not in seen:
                    selected.append(t)
                    seen.add(t_name)
                if len(selected) >= max_tools:
                    break

            # Also check tool category and tags matching detected categories
            if matched_categories:
                for t in tool_schemas:
                    t_name = t.get("name", "").lower()
                    if t_name in seen:
                        continue
                    t_cat = (t.get("category") or "").lower()
                    t_tags = [str(tg).lower() for tg in t.get("tags") or []]
                    if t_cat in matched_categories or any(
                        mc in t_tags for mc in matched_categories
                    ):
                        selected.append(t)
                        seen.add(t_name)
                    if len(selected) >= max_tools:
                        break

            # Fallback ONLY if no relevant tools were found at all
            if not selected:
                for t in tool_schemas:
                    t_name = t.get("name", "").lower()
                    if t_name not in seen:
                        selected.append(t)
                        seen.add(t_name)
                    if len(selected) >= max_tools:
                        break

            return selected, [t.get("name", "") for t in selected]

        if available_tools:
            avail_set = {t.lower(): t for t in available_tools}
            selected_names: list[str] = []
            seen_names: set[str] = set()

            for p in priority_tool_names:
                p_low = p.lower()
                if p_low in avail_set and p_low not in seen_names:
                    selected_names.append(avail_set[p_low])
                    seen_names.add(p_low)
                if len(selected_names) >= max_tools:
                    break

            for at in available_tools:
                at_low = at.lower()
                if at_low and at_low in goal_lower and at_low not in seen_names:
                    selected_names.append(avail_set[at_low])
                    seen_names.add(at_low)
                if len(selected_names) >= max_tools:
                    break

            # Fallback ONLY if no relevant tools were found at all
            if not selected_names:
                for at in available_tools:
                    at_low = at.lower()
                    if at_low not in seen_names:
                        selected_names.append(at)
                        seen_names.add(at_low)
                    if len(selected_names) >= max_tools:
                        break

            return None, selected_names

        return None, None

    @classmethod
    def prune_schemas(
        cls,
        tool_schemas: list[dict[str, Any]],
        goal: str,
        max_tools: int = 14,
    ) -> list[dict[str, Any]]:
        """Convenience method to prune tool schemas directly for a goal."""
        selected, _ = cls.select_tools(goal=goal, tool_schemas=tool_schemas, max_tools=max_tools)
        return selected or []


class AutonomousPlanner:
    """LLM-driven planner with session-aware token optimisation.

    On the first call of a session, the full available tool list and
    platform context is sent to the LLM. Subsequent calls send only
    the compact context to reduce token consumption.

    The LLM is instructed to verify tools are installed before use
    and to install any missing tools autonomously.
    """

    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._session_initialised: bool = False

    @property
    def session_initialised(self) -> bool:
        return self._session_initialised

    def mark_session_initialised(self) -> None:
        self._session_initialised = True

    def reset_session(self) -> None:
        self._session_initialised = False

    def _build_platform_context(self) -> str:
        _is_win = sys.platform == "win32"
        _shell_cmd = "cmd /c" if _is_win else "sh -c"
        lines = [
            f"Running on: {_platform.system()} {_platform.release()} ({_platform.machine()})",
            f"Shell: {_shell_cmd}",
        ]
        if _is_win:
            lines.extend(
                [
                    "IMPORTANT: This is a Windows system. Use Windows-compatible commands and paths.",
                    "  - nmap: use -sT (TCP connect) instead of -sS (SYN scan); omit -O (OS detection)",
                    "  - Use forward slashes or escaped backslashes in paths",
                    "  - For DNS queries, use nslookup instead of dig if dig is unavailable",
                    "  - List available tools with 'where' instead of 'which'",
                    "  - Standard security tools may need to be installed via winget/choco",
                ]
            )
        else:
            lines.extend(
                [
                    "Running on a Unix-like system (Linux/macOS). Standard Unix commands apply.",
                    "  - nmap -sS (SYN scan) requires root",
                ]
            )
        return "\n".join(lines)

    def _build_first_prompt(
        self,
        system_prompt: str | None,
        user_goal: str,
        platform_info: str,
        tool_schemas: list[dict] | None = None,
        available_tools: list[str] | None = None,
    ) -> str:
        if system_prompt:
            base = system_prompt
        else:
            base = """You are a senior red-team operator and penetration testing specialist with full access to every binary on this system. Construct exact shell commands.

Respond with ONLY valid JSON:
{
  "needs_tools": true or false,
  "reasoning": "Strategic rationale",
  "steps": [
    {
      "tool": "",
      "command": "exact shell command with all flags and arguments",
      "description": "What this does"
    }
  ]
}

- needs_tools=true for security operations, false for chat/explanation
- Always use the "command" field for raw shell execution
- Before running each command, verify the required tool is installed
- If a tool is missing, install it first (using winget, choco, apt, brew, pip, go, npm, or cargo as appropriate)
- Default to non-invasive techniques first
- Prefer accuracy over speed"""

        base += f"\n\n{platform_info}\n"

        if tool_schemas:
            lines = ["\nAvailable tools on this system:"]
            for t in tool_schemas:
                name = t.get("name", "")
                desc = t.get("description", "")
                tags = t.get("tags", [])
                cat = t.get("category", "")
                meta = f"  - {name}"
                if desc and desc != name:
                    meta += f": {desc}"
                if tags:
                    meta += f" [{', '.join(tags[:5])}]"
                if cat:
                    meta += f" ({cat})"
                lines.append(meta)
            base += "\n".join(lines)
        elif available_tools:
            lines = ["\nAvailable tools:"] + [f"  - {t}" for t in available_tools]
            base += "\n".join(lines)

        base += "\n\nUser request: " + user_goal
        return base

    def _build_subsequent_prompt(
        self,
        system_prompt: str | None,
        user_goal: str,
        platform_info: str,
        history: list[dict] | None = None,
        available_tools: list[str] | None = None,
    ) -> str:
        if system_prompt:
            base = system_prompt
        else:
            base = "Continue the previous session. Respond with ONLY valid JSON following the same structure as before."
        base += f"\n\n{platform_info}\n"
        if available_tools:
            base += "\nActive relevant tools: " + ", ".join(available_tools[:12]) + "\n"
        if history:
            recent = history[-6:] if len(history) > 6 else history
            base += "\nRecent context:\n" + "\n".join(
                f"{m.get('role', 'unknown')}: {m.get('content', '')[:200]}" for m in recent
            )
        base += "\n\nUser request: " + user_goal
        return base

    async def plan(
        self,
        goal: str,
        system_prompt: str | None = None,
        platform: str | None = None,
        llm_call: Any = None,
        tool_schemas: list[dict] | None = None,
        available_tools: list[str] | None = None,
        history: list[dict] | None = None,
        is_first_call: bool | None = None,
    ) -> ExecutionPlan:
        """Generate a plan using the LLM with semantic tool selection."""
        if llm_call is None:
            msg = "AutonomousPlanner requires an llm_call function"
            raise RuntimeError(msg)

        effective_first = (
            is_first_call if is_first_call is not None else not self._session_initialised
        )
        platform_info = platform or self._build_platform_context()

        # Semantic tool pruning to prevent token bloat
        pruned_schemas, pruned_tools = SemanticToolSelector.select_tools(
            goal,
            tool_schemas=tool_schemas,
            available_tools=available_tools,
            max_tools=14,
        )

        if effective_first:
            full_prompt = self._build_first_prompt(
                system_prompt,
                goal,
                platform_info,
                tool_schemas=pruned_schemas if pruned_schemas is not None else tool_schemas,
                available_tools=pruned_tools if pruned_tools is not None else available_tools,
            )
            logger.debug("AutonomousPlanner: first-call prompt (pruned tools)")
        else:
            full_prompt = self._build_subsequent_prompt(
                system_prompt,
                goal,
                platform_info,
                history=history,
                available_tools=pruned_tools if pruned_tools is not None else available_tools,
            )
            logger.debug("AutonomousPlanner: subsequent-call prompt (compact)")

        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": "execute_plan",
                    "description": "Execute shell commands or system operations.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "needs_tools": {"type": "boolean"},
                            "reasoning": {"type": "string"},
                            "steps": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "tool": {"type": "string"},
                                        "command": {"type": "string"},
                                        "description": {"type": "string"},
                                    },
                                    "required": ["tool", "command", "description"],
                                },
                            },
                        },
                        "required": ["needs_tools", "reasoning", "steps"],
                    },
                },
            }
        ]

        try:
            raw = await llm_call(full_prompt, goal, history=history, tools=openai_tools)
        except Exception as exc:
            raise RuntimeError(f"LLM planning call failed: {exc}") from exc

        if effective_first:
            self.mark_session_initialised()

        data = self._parse_llm_response(raw)

        if not data.get("needs_tools"):
            return self.create_plan(
                goal=goal,
                context={
                    "reasoning": data.get("reasoning", ""),
                    "response": data.get("response", ""),
                    "llm_planned": True,
                },
            )

        steps_raw = data.get("steps", [])
        steps: list[dict[str, Any]] = []
        for i, s in enumerate(steps_raw):
            if not isinstance(s, dict):
                steps.append(
                    {
                        "description": str(s) if s else f"LLM step {i + 1}",
                        "tool": "",
                        "command": str(s) if s else None,
                        "args": {},
                    }
                )
                continue
            steps.append(
                {
                    "description": s.get("description", f"LLM step {i + 1}"),
                    "tool": s.get("tool", ""),
                    "command": s.get("command"),
                    "args": s.get("args", {}),
                }
            )

        if not steps:
            return self.create_plan(
                goal=goal,
                context={
                    "reasoning": data.get("reasoning", ""),
                    "response": data.get("response", ""),
                    "llm_planned": True,
                },
            )

        return self.create_plan(
            goal=goal,
            steps=steps,
            context={
                "reasoning": data.get("reasoning", ""),
                "response": data.get("response", ""),
                "llm_planned": True,
            },
        )

    def _parse_llm_response(self, raw: Any) -> dict[str, Any]:
        from .tool_call_repair import repair_plan_payload

        parsed = repair_plan_payload(raw)
        if isinstance(parsed, dict):
            return parsed

        text = raw.get("content", "") if isinstance(raw, dict) else str(raw or "")
        return {
            "needs_tools": False,
            "reasoning": "",
            "steps": [],
            "response": text,
        }

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
                sanitized_def = PlanValidator.validate_and_sanitize_step(dict(step_def))
                deps = sanitized_def.get("dependencies") or sanitized_def.get("depends_on") or []
                plan_steps.append(
                    PlanStep(
                        id=sanitized_def.get("id", f"step_{i:03d}"),
                        description=sanitized_def.get("description", f"Step {i + 1}"),
                        tool=sanitized_def.get("tool", ""),
                        args=sanitized_def.get("args", {}),
                        command=sanitized_def.get("command"),
                        dependencies=list(deps),
                        timeout=sanitized_def.get("timeout", 300.0),
                        metadata=sanitized_def.get("metadata", {}),
                    )
                )

        # Enterprise deduplication: remove identical commands
        plan_steps = PlanValidator.deduplicate_steps(plan_steps)

        # Automatically promote to DAG if any step declares explicit dependencies
        effective_type = PlanType.DAG if any(s.dependencies for s in plan_steps) else plan_type

        plan = ExecutionPlan(
            goal=goal,
            plan_type=effective_type,
            steps=plan_steps,
            context=context or {},
            status=PlanStatus.ACTIVE,
        )
        self._plans[plan.id] = plan
        emit_sync(
            Event(
                type=EventType.PLAN_CREATED,
                source="planner_autonomous",
                data={"plan_id": plan.id, "goal": goal, "steps": len(plan_steps)},
            )
        )
        return plan

    def adapt_plan_sync(
        self, plan: ExecutionPlan, failed_step: PlanStep, error: str
    ) -> ExecutionPlan:
        """Heuristic adaptation of an autonomous plan upon step failure."""
        error_lower = error.lower()

        # 1. Nmap raw socket / privilege failure
        if any(kw in error_lower for kw in ("permission", "root", "raw socket", "pcap")):
            if failed_step.command and "nmap" in failed_step.command:
                new_cmd = failed_step.command.replace("-sS", "-sT")
                if "-Pn" not in new_cmd:
                    new_cmd += " -Pn"
                failed_step.command = new_cmd
                failed_step.status = StepStatus.PENDING
                failed_step.retry_count += 1
                return plan

        # 2. Host appears down / filtered
        if any(
            kw in error_lower for kw in ("host seems down", "filtered", "no response", "0 hosts up")
        ):
            if (
                failed_step.command
                and "nmap" in failed_step.command
                and "-Pn" not in failed_step.command
            ):
                failed_step.command += " -Pn"
                failed_step.status = StepStatus.PENDING
                failed_step.retry_count += 1
                return plan

        # 3. Rate-limiting / 429 Too Many Requests
        if any(kw in error_lower for kw in ("429", "rate limit", "too many requests")):
            if failed_step.command:
                if "-t " in failed_step.command:
                    failed_step.command = re.sub(r"-t\s+\d+", "-t 5", failed_step.command)
                else:
                    failed_step.command += " --rate-limit 10"
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
            return plan

        # 4. Command not found / Missing binary
        if any(
            kw in error_lower
            for kw in ("not found", "not recognized", "cannot find", "no such file")
        ):
            failed_step.status = StepStatus.SKIPPED
            fallback = self._resolve_fallback_step(failed_step)
            if fallback:
                idx = (
                    plan.steps.index(failed_step) if failed_step in plan.steps else len(plan.steps)
                )
                plan.steps.insert(idx + 1, fallback)
            return plan

        # 5. Generic retry with exponential backoff if retryable
        if failed_step.can_retry:
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
            failed_step.timeout *= 1.5
        else:
            failed_step.status = StepStatus.FAILED

        return plan

    def _resolve_fallback_step(self, failed_step: PlanStep) -> PlanStep | None:
        """Resolve a fallback step when a security tool is missing."""
        cmd = failed_step.command or failed_step.tool or ""
        cmd_lower = cmd.lower()
        if "dig" in cmd_lower:
            return PlanStep(
                id=f"{failed_step.id}_fb",
                description="DNS fallback via nslookup",
                tool="nslookup",
                command=re.sub(r"\bdig\b.*", "nslookup {target}", cmd),
            )
        if "nikto" in cmd_lower:
            return PlanStep(
                id=f"{failed_step.id}_fb",
                description="Web inspection fallback via curl",
                tool="curl",
                command="curl -s -I {target}",
            )
        if "gobuster" in cmd_lower or "ffuf" in cmd_lower:
            return PlanStep(
                id=f"{failed_step.id}_fb",
                description="Directory check fallback via curl common paths",
                tool="curl",
                command="curl -s -o /dev/null -w '%{http_code}' {target}/admin",
            )
        return None

    async def adapt_plan(
        self,
        plan: ExecutionPlan,
        failed_step: PlanStep,
        error: str,
        llm_call: Any = None,
    ) -> ExecutionPlan:
        """Dynamically adapt an autonomous plan, using LLM if available or rules fallback."""
        if llm_call is not None:
            try:
                prompt = (
                    f"A step in the security plan failed:\n"
                    f"Failed step: {failed_step.command or failed_step.tool}\n"
                    f"Description: {failed_step.description}\n"
                    f"Error: {error}\n\n"
                    f"Provide an alternative shell command or workaround to achieve the goal despite this error.\n"
                    f'Respond with JSON: {{"needs_tools": true, "reasoning": "...", "steps": [{{"tool": "...", "command": "...", "description": "..."}}]}}'
                )
                raw = await llm_call(
                    system="You are an expert offensive and defensive security operator solving execution failures.",
                    user=prompt,
                    stream=False,
                )
                data = self._parse_llm_response(raw)
                if data and data.get("steps"):
                    failed_step.status = StepStatus.SKIPPED
                    idx = (
                        plan.steps.index(failed_step)
                        if failed_step in plan.steps
                        else len(plan.steps)
                    )
                    for offset, s in enumerate(data["steps"], 1):
                        new_step = PlanStep(
                            id=f"{failed_step.id}_alt_{offset}",
                            description=s.get("description", f"Alternative step {offset}"),
                            tool=s.get("tool", ""),
                            command=s.get("command"),
                            args=s.get("args", {}),
                        )
                        PlanValidator.validate_and_sanitize_step(new_step)
                        plan.steps.insert(idx + offset - 1, new_step)
                    return plan
            except Exception as exc:
                logger.debug(
                    "LLM plan adaptation failed: %s; falling back to rule-based adaptation", exc
                )

        return self.adapt_plan_sync(plan, failed_step, error)

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
            "session_initialised": self._session_initialised,
        }


__all__ = [
    "AutonomousPlanner",
    "PlanValidator",
]
