# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep scan engine — multi-layered reconnaissance with OS fingerprinting,
vulnerability detection, and comprehensive reporting.

Upgrades the legacy ``--deep`` CLI flag into a full scanning methodology
that chains multiple tools and analysis passes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .exceptions import ToolExecutionError, ToolNotFoundError
from .executor import BaseExecutor
from .models import PlanStep
from .offline_store import OfflineStore
from .planner_registry import RegistryPlanner
from .registry import ToolRegistry

logger = logging.getLogger(__name__)


@dataclass
class DeepScanProfile:
    """Configuration profile for a deep scan pass."""

    name: str
    description: str
    tools: list[dict[str, Any]] = field(default_factory=list)
    timeout: int = 600
    parallel: bool = True


_DEEP_SCAN_PASSES: list[DeepScanProfile] = [
    DeepScanProfile(
        name="discovery",
        description="Host discovery and port sweep",
        tools=[
            {"tool": "ping", "args": {"flags": "-c 3"}, "timeout": 30},
            {"tool": "nmap", "args": {"flags": "-sn -T4"}, "timeout": 120},
            {"tool": "nmap", "args": {"flags": "-p- -T4 --min-rate 1000"}, "timeout": 300},
        ],
        timeout=300,
        parallel=True,
    ),
    DeepScanProfile(
        name="fingerprint",
        description="OS detection, service versioning, and default scripts",
        tools=[
            {"tool": "nmap", "args": {"flags": "-sV -O -sC -T4 --osscan-guess"}, "timeout": 300},
            {"tool": "whatweb", "args": {"flags": "-a 3"}, "timeout": 120},
        ],
        timeout=300,
        parallel=True,
    ),
    DeepScanProfile(
        name="vulnerability",
        description="Template-based vulnerability scanning",
        tools=[
            {
                "tool": "nuclei",
                "args": {"severity": "low,medium,high,critical", "flags": "-duc -nt"},
                "timeout": 600,
            },
            {"tool": "nikto", "args": {"flags": "-C all"}, "timeout": 300},
        ],
        timeout=600,
        parallel=True,
    ),
    DeepScanProfile(
        name="enumeration",
        description="Directory, subdomain, and DNS enumeration",
        tools=[
            {"tool": "gobuster", "args": {"mode": "dir", "flags": "-t 50"}, "timeout": 300},
            {"tool": "subfinder", "args": {}, "timeout": 120},
            {"tool": "dig", "args": {"flags": "ANY"}, "timeout": 60},
        ],
        timeout=300,
        parallel=True,
    ),
    DeepScanProfile(
        name="memory_forensics",
        description="Memory dump analysis for artifacts, processes, and network connections",
        tools=[
            {"tool": "volatility", "args": {"flags": "-f"}, "timeout": 300},
            {"tool": "strings", "args": {}, "timeout": 60},
            {"tool": "yara", "args": {}, "timeout": 120},
        ],
        timeout=600,
        parallel=False,
    ),
    DeepScanProfile(
        name="disk_forensics",
        description="Disk image analysis for deleted files, metadata, and hidden artifacts",
        tools=[
            {"tool": "sleuthkit", "args": {"flags": "fls"}, "timeout": 300},
            {"tool": "foremost", "args": {}, "timeout": 300},
            {"tool": "binwalk", "args": {}, "timeout": 120},
            {"tool": "exiftool", "args": {}, "timeout": 60},
        ],
        timeout=600,
        parallel=True,
    ),
    DeepScanProfile(
        name="code_review",
        description="Static code security analysis, secrets detection, and dependency auditing",
        tools=[
            {"tool": "semgrep", "args": {"flags": "--config=auto"}, "timeout": 300},
            {"tool": "bandit", "args": {"flags": "-r"}, "timeout": 120},
            {"tool": "gitleaks", "args": {"flags": "detect --no-git"}, "timeout": 120},
            {"tool": "trufflehog", "args": {}, "timeout": 120},
        ],
        timeout=600,
        parallel=True,
    ),
    DeepScanProfile(
        name="cloud_audit",
        description="Cloud infrastructure security auditing and compliance checking",
        tools=[
            {"tool": "checkov", "args": {"flags": "-d ."}, "timeout": 300},
            {
                "tool": "trivy",
                "args": {"flags": "filesystem --severity HIGH,CRITICAL"},
                "timeout": 300,
            },
            {"tool": "prowler", "args": {}, "timeout": 600},
        ],
        timeout=600,
        parallel=False,
    ),
    DeepScanProfile(
        name="container_security",
        description="Container image vulnerability scanning and SBOM generation",
        tools=[
            {"tool": "trivy", "args": {"flags": "image"}, "timeout": 300},
            {"tool": "grype", "args": {}, "timeout": 300},
            {"tool": "syft", "args": {}, "timeout": 120},
        ],
        timeout=600,
        parallel=True,
    ),
    DeepScanProfile(
        name="osint",
        description="Passive reconnaissance and open-source intelligence gathering",
        tools=[
            {"tool": "whois", "args": {}, "timeout": 30},
            {"tool": "dig", "args": {"flags": "ANY"}, "timeout": 30},
            {"tool": "shodan", "args": {}, "timeout": 60},
        ],
        timeout=300,
        parallel=True,
    ),
]


class DeepScanEngine:
    """Orchestrates multi-pass deep scans with progressive analysis.

    Features:
    - Progressive scanning (discovery → fingerprint → vulnerability → enumeration)
    - Parallel pass execution within each phase
    - Result aggregation and diffing across passes
    - Automatic offline store persistence
    - Fallback to alternative tools when primary tool is unavailable
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        executor: BaseExecutor | None = None,
        store: OfflineStore | None = None,
        planner: RegistryPlanner | None = None,
    ) -> None:
        self._registry = registry or ToolRegistry()
        self._executor = executor
        self._store = store or OfflineStore()
        self._planner = planner or RegistryPlanner()
        self._results: dict[str, list[dict[str, Any]]] = {}

    async def scan(
        self,
        target: str,
        profiles: list[str] | None = None,
        timeout: int = 600,
        persist: bool = True,
    ) -> dict[str, Any]:
        """Run a deep scan against the given target."""
        passes = [p for p in _DEEP_SCAN_PASSES if profiles is None or p.name in profiles]
        if not passes:
            passes = _DEEP_SCAN_PASSES

        all_findings: dict[str, list[dict[str, Any]]] = {}
        scan_id = f"deep_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{target.replace('.', '_').replace(':', '_')}"

        for profile in passes:
            logger.info("Deep scan pass: %s — %s", profile.name, profile.description)
            pass_findings: list[dict[str, Any]] = []
            tasks = []

            for tool_def in profile.tools:
                tool_name = tool_def["tool"]
                tool_args = tool_def.get("args", {})
                tool_timeout = tool_def.get("timeout", profile.timeout)
                step = PlanStep(
                    tool=tool_name,
                    args={**tool_args, "target": target},
                    timeout=tool_timeout,
                )
                tasks.append(self._execute_tool(step, profile.name))

            if profile.parallel and len(tasks) > 1:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, dict) and res.get("status") != "error":
                        pass_findings.extend(res.get("findings", []))
                    elif isinstance(res, BaseException):
                        logger.debug("Deep scan pass %s task failed: %s", profile.name, res)
            else:
                for task in tasks:
                    res = await task
                    if isinstance(res, dict) and res.get("status") != "error":
                        pass_findings.extend(res.get("findings", []))

            all_findings[profile.name] = pass_findings
            self._results[profile.name] = pass_findings

            if persist:
                try:
                    self._store.save_scan(
                        f"{target}/{profile.name}",
                        pass_findings,
                        mode="deep_scan",
                        plan_id=scan_id,
                    )
                except Exception as exc:
                    logger.warning("Failed to persist deep scan pass %s: %s", profile.name, exc)

        return self._aggregate(target, all_findings, scan_id)

    async def _execute_tool(self, step: PlanStep, pass_name: str) -> dict[str, Any]:
        if self._executor:
            try:
                result = await self._registry.execute(step.tool, **step.args)
                return {"status": "completed", "findings": self._wrap_result(result, step.tool)}
            except Exception as exc:
                return {"status": "error", "error": str(exc), "tool": step.tool}

        try:
            result = await self._registry.execute(step.tool, **step.args)
            return {"status": "completed", "findings": self._wrap_result(result, step.tool)}
        except ToolNotFoundError:
            alt_result = await self._try_alternatives(step)
            if alt_result.get("status") != "error":
                return alt_result
            return {
                "status": "error",
                "error": f"Tool {step.tool} not available",
                "tool": step.tool,
            }
        except ToolExecutionError as e:
            return {"status": "error", "error": str(e), "tool": step.tool}

    async def _try_alternatives(self, step: PlanStep) -> dict[str, Any]:
        from .planner_registry import TOOL_ALTERNATIVES

        alt_tools = TOOL_ALTERNATIVES.get(step.tool, [])
        for alt in alt_tools:
            try:
                result = await self._registry.execute(alt, **step.args)
                if result.get("status") != "error":
                    return {"status": "completed", "findings": self._wrap_result(result, alt)}
            except (ToolNotFoundError, ToolExecutionError):
                continue
        return {"status": "error", "error": f"No alternatives succeeded for {step.tool}"}

    def _wrap_result(self, result: Any, tool: str) -> list[dict[str, Any]]:
        if isinstance(result, dict):
            raw = result.get("raw_output", result.get("stdout", ""))
            if raw:
                from .parsers import ParserRegistry

                parser_reg = ParserRegistry()
                parser_reg.discover()
                return parser_reg.parse(tool, str(raw))
            return [{"tool": tool, "detail": str(result.get("summary", ""))}]
        return [{"tool": tool, "detail": str(result)}]

    def _aggregate(
        self, target: str, all_findings: dict[str, list[dict[str, Any]]], scan_id: str
    ) -> dict[str, Any]:
        combined: list[dict[str, Any]] = []
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        tool_counts: dict[str, int] = {}

        for pass_name, findings in all_findings.items():
            for f in findings:
                combined.append(f)
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                tool = f.get("tool", "unknown")
                tool_counts[tool] = tool_counts.get(tool, 0) + 1

        risk_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 7
            + severity_counts["medium"] * 4
            + severity_counts["low"] * 1
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": "deep_scan",
            "passes_completed": list(all_findings.keys()),
            "total_findings": len(combined),
            "severity_summary": severity_counts,
            "tools_used": list(tool_counts.keys()),
            "risk_score": risk_score,
            "all_findings": combined,
            "findings_by_pass": all_findings,
        }

    def get_results(self, pass_name: str | None = None) -> dict[str, list[dict[str, Any]]]:
        if pass_name:
            return {pass_name: self._results.get(pass_name, [])}
        return dict(self._results)


__all__ = [
    "DeepScanEngine",
    "DeepScanProfile",
]
