# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mixins for AgentCore to separate execution and graph logic."""

from __future__ import annotations

import logging
import time
from typing import Any

from ..planner import ExecutionPlan, PlanStatus, StepStatus, PlanStep
from ..events import Event, EventType

logger = logging.getLogger(__name__)


class ExecutionMixin:
    """Execution capabilities for AgentCore."""

    async def _execute_registry(
        self, goal: Any, plan: ExecutionPlan | None, start: float, result: Any
    ) -> Any:
        from ..core import AgentStatus

        try:
            tool_names = [t.name for t in self._registry.list_tools()]
            if plan is None:
                plan = self._planner_registry.plan(goal.description, tool_names)
            result.plan = plan

            step_progress: dict[str, str] = {}

            def on_step(s: PlanStep) -> None:
                step_id = s.id
                old_status = step_progress.get(step_id, "pending")
                if old_status != s.status.value:
                    step_progress[step_id] = s.status.value
                    from ..events import emit_sync

                    emit_sync(
                        Event(
                            type=EventType.PLAN_STEP_START
                            if s.status.value == "running"
                            else EventType.PLAN_STEP_COMPLETE,
                            source="core.registry",
                            data={"step_id": step_id, "tool": s.tool, "status": s.status.value},
                        )
                    )
                    if self._progress_callback:
                        self._progress_callback(s, step_progress)

            self._executor_registry.set_progress_callback(on_step)
            await self._validator.validate_plan(plan.steps)
            self._metrics.record_plan_generation(successful=True, used_model=False)

            if hasattr(plan, "plan_type") and getattr(plan.plan_type, "value", None) == "dag":
                plan = await self._executor_registry.execute_workflow(plan)
            else:
                plan = await self._executor_registry.execute_plan(plan)
            result.success = plan.status == PlanStatus.COMPLETED

            result.summary = self._generate_summary(plan)
            result.findings = self._extract_findings(plan)
        except Exception as e:
            result.success = False
            result.summary = f"Registry agent failed: {e}"
            logger.debug("Registry agent execution failed", exc_info=True)
        result.duration_ms = (time.time() - start) * 1000
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        self._history.append(result)

        self._metrics.record_scan(
            duration=result.duration_ms / 1000.0,
            successful=result.success,
            findings_count=len(result.findings),
        )
        await self._store.save_scan_async(
            target=goal.target or goal.description,
            findings=result.findings,
            mode=self._mode.value,
            plan_id=plan.id if plan else "",
        )
        return result

    async def _execute_autonomous(
        self, goal: Any, plan: ExecutionPlan | None, start: float, result: Any
    ) -> Any:
        from ..core import AgentStatus

        try:
            await self._check_budget()
            if plan is None:
                from ..config import SettingsStore

                _settings = SettingsStore()
                _preferred = _settings.get("model_provider") or None
                provider, model = self._providers.select_provider(preferred=_preferred)

                async def llm_call(
                    system_prompt: str, user_prompt: str, *, history: Any = None, **kwargs: Any
                ) -> Any:
                    return await self._providers.complete(
                        provider, "", system_prompt, user_prompt, history=history, **kwargs
                    )

                tool_schemas = [
                    {
                        "name": t.name,
                        "description": t.description,
                        "tags": t.tags,
                        "category": getattr(t.category, "value", str(t.category)),
                    }
                    for t in self._registry.list_tools()
                ]

                context_history = self._context.get_history()

                plan = await self._planner_autonomous.plan(
                    goal.description,
                    llm_call=llm_call,
                    tool_schemas=tool_schemas,
                    available_tools=[t.name for t in self._registry.list_tools()],
                    history=context_history,
                    is_first_call=True,
                )
            result.plan = plan
            self._context.add_history(f"Goal: {goal.description}", "user")
            await self._validator.validate_plan(plan.steps)
            self._metrics.record_plan_generation(successful=True, used_model=True)
            plan = await self._executor_autonomous.execute_plan(plan, live_display=False)

            if plan.has_failures:
                for step in plan.failed_steps:
                    recovery = await self._validator.plan_recovery(
                        step, step.result.get("error", "")
                    )
                    from ..validators import RecoveryAction

                    if recovery.action == RecoveryAction.RETRY and recovery.modified_step:
                        idx = plan.steps.index(step)
                        plan.steps[idx] = recovery.modified_step
                        plan = await self._executor_autonomous.execute_plan(
                            plan, live_display=False
                        )
                        break

            result.success = plan.status == PlanStatus.COMPLETED
            result.summary = self._generate_summary(plan)
            result.findings = self._extract_findings(plan)
        except Exception as e:
            result.success = False
            result.summary = f"Autonomous agent failed: {e}"
            logger.exception("Autonomous agent execution failed")
        result.duration_ms = (time.time() - start) * 1000
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        self._history.append(result)

        self._metrics.record_scan(
            duration=result.duration_ms / 1000.0,
            successful=result.success,
            findings_count=len(result.findings),
        )
        await self._store.save_scan_async(
            target=goal.target or goal.description,
            findings=result.findings,
            mode=self._mode.value,
            plan_id=plan.id if plan else "",
        )
        return result

    async def _execute_hybrid(
        self, goal: Any, plan: ExecutionPlan | None, start: float, result: Any
    ) -> Any:
        auto_result = await self._execute_autonomous(
            goal, plan, start, result.__class__(goal=goal.description)
        )
        if auto_result.success:
            return auto_result

        logger.info("Autonomous execution failed, falling back to registry mode")

        completed_step_tools = {
            s.tool
            for s in (auto_result.plan.steps if auto_result.plan else [])
            if s.status == StepStatus.COMPLETED and s.tool
        }

        fallback_goal = goal.description
        if auto_result.plan and auto_result.plan.has_failures:
            failure_reasons = []
            for s in auto_result.plan.failed_steps:
                err = s.result.get("error", "Unknown error") if s.result else "Unknown error"
                failure_reasons.append(f"{s.tool or 'shell'} failed: {err}")
            if failure_reasons:
                fallback_goal += (
                    f" (Previous autonomous failures to avoid: {'; '.join(failure_reasons)})"
                )

        registry_plan = self._planner_registry.plan(
            fallback_goal, [t.name for t in self._registry.list_tools()]
        )
        for step in registry_plan.steps:
            if step.tool in completed_step_tools:
                step.status = StepStatus.SKIPPED

        return await self._execute_registry(
            goal, registry_plan, start, result.__class__(goal=fallback_goal)
        )

    async def _execute_interactive(
        self, goal: Any, plan: ExecutionPlan | None, start: float, result: Any
    ) -> Any:
        from ..core import AgentStatus

        try:
            if plan is None:
                plan = self._planner_registry.plan(
                    goal.description, [t.name for t in self._registry.list_tools()]
                )
            result.plan = plan

            print("\n--- Plan Preview ---")
            for step in plan.steps:
                print(f"[{step.id}] {step.tool}: {step.description}")
            print("--------------------\n")

            approval = input("Approve plan? [y/N]: ").strip().lower()
            if approval != "y":
                result.success = False
                result.summary = "Plan rejected by user."
                return result

            plan = await self._executor_registry.execute_plan(plan)
            result.success = plan.status == PlanStatus.COMPLETED
            result.summary = self._generate_summary(plan)
            result.findings = self._extract_findings(plan)
        except Exception as e:
            result.success = False
            result.summary = f"Interactive agent failed: {e}"
            logger.exception("Interactive agent execution failed")
        result.duration_ms = (time.time() - start) * 1000
        self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
        self._history.append(result)

        self._metrics.record_scan(
            duration=result.duration_ms / 1000.0,
            successful=result.success,
            findings_count=len(result.findings),
        )
        await self._store.save_scan_async(
            target=goal.target or goal.description,
            findings=result.findings,
            mode=self._mode.value,
            plan_id=plan.id if plan else "",
        )
        return result


class GraphMixin:
    """Knowledge graph operations for AgentCore."""

    def _extract_findings(self, plan: ExecutionPlan) -> list[dict[str, Any]]:
        import hashlib

        def _make_finding_hash(finding: dict) -> str:
            key_parts = [
                finding.get("target", ""),
                finding.get("port", ""),
                finding.get("cve", finding.get("title", "")),
                finding.get("severity", ""),
            ]
            return hashlib.md5(
                "|".join(str(p).lower() for p in key_parts).encode(), usedforsecurity=False
            ).hexdigest()

        findings = []
        seen_keys: set[str] = set()
        for step in plan.steps:
            if not (step.status == StepStatus.COMPLETED and step.result):
                continue
            parsed = step.result.get("findings")
            if parsed and isinstance(parsed, list):
                for f in parsed:
                    dedup_key = _make_finding_hash(f)
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append(f)
                        self._ingest_finding_to_graph(f, discovered_by=step.tool)
            output = step.result.get("output", "")
            if output and not parsed:
                f_dict = {
                    "tool": step.tool,
                    "description": step.description,
                    "output_preview": output[:500],
                    "severity": "info",
                }
                findings.append(f_dict)
                self._ingest_finding_to_graph(f_dict, discovered_by=step.tool)
        return findings

    def _ingest_finding_to_graph(self, finding: dict[str, Any], discovered_by: str) -> None:
        from ..knowledge_graph import NodeType, EdgeType

        target = finding.get("target", "")
        host_node = None
        if target:
            host_node = self._knowledge_graph.add_node(
                NodeType.HOST,
                label=target,
                discovered_by=discovered_by,
                ip=finding.get("ip", ""),
                hostname=finding.get("hostname", ""),
            )
        if finding.get("cve") or finding.get("severity"):
            vuln_node = self._knowledge_graph.add_node(
                NodeType.VULNERABILITY,
                label=finding.get("cve", finding.get("title", finding.get("description", "vuln"))),
                severity=finding.get("severity", ""),
                cve=finding.get("cve", ""),
                discovered_by=discovered_by,
            )
            if host_node:
                self._knowledge_graph.add_edge(
                    host_node.node_id, vuln_node.node_id, EdgeType.HAS_VULN
                )
