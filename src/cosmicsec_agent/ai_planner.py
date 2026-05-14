"""AI-powered task planner — converts natural language to structured execution plans.

This is the **dynamic** component of the hybrid engine. It uses an LLM provider
(OpenAI, Ollama, or CosmicSec cloud) to interpret arbitrary user instructions
and produce a structured execution plan that the hybrid engine can run.

When no AI provider is available, it falls back to the local intent parser
(static/rule-based) automatically.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from .intent_parser import IntentCategory, LocalIntentParser, ParsedIntent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Execution Plan data model
# ---------------------------------------------------------------------------

class StepType(StrEnum):
    """Type of execution step in a plan."""

    TOOL_RUN = "tool_run"  # Run a registered security tool
    SHELL_CMD = "shell_cmd"  # Run an arbitrary (safe) shell command
    AI_ANALYSIS = "ai_analysis"  # AI-driven analysis of results
    CONDITIONAL = "conditional"  # Conditional step based on previous output
    PARALLEL_GROUP = "parallel_group"  # Group of steps to run in parallel
    REPORT = "report"  # Generate a report
    NOTIFY = "notify"  # Send notification

@dataclass
class ExecutionStep:
    """A single step in an execution plan."""

    id: str
    step_type: StepType
    tool: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    target: str | None = None
    depends_on: list[str] = field(default_factory=list)
    condition: str | None = None
    timeout: int = 300
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "step_type": self.step_type.value,
            "tool": self.tool,
            "command": self.command,
            "args": self.args,
            "target": self.target,
            "depends_on": self.depends_on,
            "condition": self.condition,
            "timeout": self.timeout,
            "description": self.description,
            "metadata": self.metadata,
        }

@dataclass
class ExecutionPlan:
    """A structured plan of steps to execute for a user request."""

    steps: list[ExecutionStep] = field(default_factory=list)
    source: str = "static"  # "static" | "dynamic" | "hybrid"
    confidence: float = 0.0
    raw_intent: str = ""
    parsed_intent: ParsedIntent | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [s.to_dict() for s in self.steps],
            "source": self.source,
            "confidence": self.confidence,
            "raw_intent": self.raw_intent,
            "parsed_intent": self.parsed_intent.to_dict() if self.parsed_intent else None,
        }

# ---------------------------------------------------------------------------
# LLM Provider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for LLM providers used by the AI planner."""

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Send a planning prompt to the LLM and return structured plan JSON."""
        ...

# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------

class OpenAIProvider:
    """LLM provider using OpenAI API (GPT-4o, etc.)."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o") -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._model = model

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via OpenAI chat completion."""
        try:
            import openai
        except ImportError:
            logger.warning("openai package not installed; AI planning unavailable")
            return {}

        if not self._api_key:
            return {}

        system_prompt = _build_system_prompt(context)

        client = openai.AsyncOpenAI(api_key=self._api_key)
        try:
            response = await client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=2048,
            )
            content = response.choices[0].message.content or "{}"
            return json.loads(content)
        except Exception as exc:
            logger.warning("OpenAI planning failed: %s", exc)
            return {}

# ---------------------------------------------------------------------------
# Ollama Provider (local LLM)
# ---------------------------------------------------------------------------

class OllamaProvider:
    """LLM provider using local Ollama instance."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    @property
    def available(self) -> bool:
        """Check if Ollama is reachable (synchronous quick check)."""
        try:
            import httpx

            resp = httpx.get(f"{self._base_url}/api/tags", timeout=2.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via Ollama."""
        try:
            import httpx
        except ImportError:
            return {}

        system_prompt = _build_system_prompt(context)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{self._base_url}/api/chat",
                    json={
                        "model": self._model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt},
                        ],
                        "format": "json",
                        "stream": False,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("message", {}).get("content", "{}")
                    return json.loads(content)
        except Exception as exc:
            logger.warning("Ollama planning failed: %s", exc)

        return {}

# ---------------------------------------------------------------------------
# CosmicSec Cloud Provider
# ---------------------------------------------------------------------------

class CloudProvider:
    """LLM provider using CosmicSec cloud AI service."""

    def __init__(self, server_url: str = "", api_key: str = "") -> None:
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key

    @property
    def available(self) -> bool:
        return bool(self._server_url and self._api_key)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via CosmicSec cloud AI."""
        if not self.available:
            return {}

        try:
            import httpx
        except ImportError:
            return {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._server_url}/api/ai/plan",
                    json={"prompt": prompt, "context": context},
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception as exc:
            logger.warning("Cloud AI planning failed: %s", exc)

        return {}

# ---------------------------------------------------------------------------
# System prompt builder
# ---------------------------------------------------------------------------

def _build_system_prompt(context: dict[str, Any]) -> str:
    """Build the system prompt for AI planning with tool context."""
    available_tools = context.get("available_tools", [])
    tool_list = "\n".join(f"  - {t['name']}: {', '.join(t.get('capabilities', []))}" for t in available_tools)

    return f"""You are CosmicSec Helix AI, an expert cybersecurity task planner.

Your job is to convert natural language security instructions into a structured
JSON execution plan. You have access to the following locally installed security tools:

{tool_list or "  (no tools discovered yet)"}

IMPORTANT RULES:
1. Only suggest tools from the available list above, or common system commands.
2. Never suggest destructive commands (rm -rf, format, etc.).
3. For each step, specify: id, step_type, tool/command, args, target, description.
4. step_type must be one of: tool_run, shell_cmd, ai_analysis, conditional,
   parallel_group, report, notify.
5. Order steps logically — reconnaissance before exploitation, scanning before analysis.
6. If a step depends on a previous step, specify depends_on with the step id(s).
7. Always include a timeout (seconds) for each step.

Respond with ONLY a JSON object in this format:
{{
  "steps": [
    {{
      "id": "step_1",
      "step_type": "tool_run",
      "tool": "nmap",
      "command": null,
      "args": ["-sV", "-sC"],
      "target": "192.168.1.1",
      "depends_on": [],
      "condition": null,
      "timeout": 300,
      "description": "Port scan with service detection"
    }}
  ],
  "confidence": 0.9,
  "reasoning": "Brief explanation of the plan"
}}"""

# ---------------------------------------------------------------------------
# AI Task Planner — the main orchestrator
# ---------------------------------------------------------------------------

class AITaskPlanner:
    """Converts natural language instructions into executable plans.

    Uses AI providers when available, falls back to local intent parsing.
    This is the brain of the hybrid execution engine.
    """

    def __init__(
        self,
        providers: list[LLMProvider] | None = None,
    ) -> None:
        self._providers = providers or []
        self._local_parser = LocalIntentParser()

    def add_provider(self, provider: LLMProvider) -> None:
        """Register an LLM provider for dynamic planning."""
        self._providers.append(provider)

    async def plan(
        self,
        instruction: str,
        context: dict[str, Any] | None = None,
        force_mode: str | None = None,
        **kwargs: Any,
    ) -> ExecutionPlan:
        """Create an execution plan from a natural language instruction.

        Parameters
        ----------
        instruction:
            Natural language command from the user.
        context:
            Runtime context (available tools, scan history, etc.).
        force_mode:
            If "static", skip AI. If "dynamic", skip local parser.
            If None or "hybrid", try AI first then fall back to local.
        **kwargs:
            Additional parameters merged into context.
        """
        ctx = context or {}
        if kwargs:
            ctx.update(kwargs)

        # --- Static-only mode ---
        if force_mode == "static":
            return self._plan_from_intent(instruction)

        # --- Dynamic-only mode ---
        if force_mode == "dynamic":
            plan = await self._plan_from_ai(instruction, ctx)
            if plan and plan.steps:
                return plan
            # Even in dynamic mode, don't leave user with nothing
            logger.warning("Dynamic planning failed; no AI providers available")
            return ExecutionPlan(
                raw_intent=instruction,
                source="dynamic",
                confidence=0.0,
            )

        # --- Hybrid mode (default) ---
        # 1) Try local parser first for quick classification
        local_intent = self._local_parser.parse(instruction)

        # 2) If local parser is highly confident, use static plan
        if local_intent.confidence >= 0.8:
            static_plan = self._build_plan_from_intent(local_intent, instruction)
            static_plan.source = "hybrid-static"
            return static_plan

        # 3) Try AI planning for complex/ambiguous instructions
        ai_plan = await self._plan_from_ai(instruction, ctx)
        if ai_plan and ai_plan.steps:
            ai_plan.source = "hybrid-dynamic"
            ai_plan.parsed_intent = local_intent
            return ai_plan

        # 4) Fall back to static plan from whatever the local parser got
        fallback_plan = self._build_plan_from_intent(local_intent, instruction)
        fallback_plan.source = "hybrid-fallback"
        return fallback_plan

    async def interpret(self, instruction: str, target: str | None = None) -> str:
        """Briefly interpret a command and return a summary string."""
        plan = await self.plan(instruction, context={"targets": [target] if target else []})
        if not plan.steps:
            return f"Unknown intent for: {instruction}"

        steps_desc = [s.description or (s.tool or s.command or "step") for s in plan.steps]
        return f"Plan: {' -> '.join(steps_desc)}"

    def _plan_from_intent(self, instruction: str) -> ExecutionPlan:
        """Create a plan purely from the local intent parser (static mode)."""
        intent = self._local_parser.parse(instruction)
        return self._build_plan_from_intent(intent, instruction)

    async def _plan_from_ai(self, instruction: str, context: dict[str, Any]) -> ExecutionPlan | None:
        """Try each AI provider in order; return the first successful plan."""
        for provider in self._providers:
            if hasattr(provider, "available") and not provider.available:
                continue
            try:
                raw = await provider.plan(instruction, context)
                if raw and raw.get("steps"):
                    return self._parse_ai_response(raw, instruction)
            except Exception as exc:
                logger.warning("AI provider %s failed: %s", type(provider).__name__, exc)

        return None

    def _parse_ai_response(self, raw: dict[str, Any], instruction: str) -> ExecutionPlan:
        """Parse the raw AI JSON response into an ExecutionPlan."""
        steps: list[ExecutionStep] = []
        for s in raw.get("steps", []):
            step_type_str = s.get("step_type", "shell_cmd")
            try:
                step_type = StepType(step_type_str)
            except ValueError:
                step_type = StepType.SHELL_CMD

            steps.append(
                ExecutionStep(
                    id=s.get("id", f"step_{len(steps) + 1}"),
                    step_type=step_type,
                    tool=s.get("tool"),
                    command=s.get("command"),
                    args=s.get("args", []),
                    target=s.get("target"),
                    depends_on=s.get("depends_on", []),
                    condition=s.get("condition"),
                    timeout=s.get("timeout", 300),
                    description=s.get("description", ""),
                    metadata=s.get("metadata", {}),
                )
            )

        return ExecutionPlan(
            steps=steps,
            source="dynamic",
            confidence=raw.get("confidence", 0.5),
            raw_intent=instruction,
        )

    def _build_plan_from_intent(self, intent: ParsedIntent, instruction: str) -> ExecutionPlan:
        """Convert a ParsedIntent into an ExecutionPlan with concrete steps."""
        steps: list[ExecutionStep] = []
        step_counter = 0

        # Handle multi-step workflows
        if intent.sub_intents:
            prev_ids: list[str] = []
            for sub in intent.sub_intents:
                sub_steps = self._intent_to_steps(sub, step_counter, prev_ids)
                steps.extend(sub_steps)
                prev_ids = [s.id for s in sub_steps]
                step_counter += len(sub_steps)
        else:
            steps = self._intent_to_steps(intent, 0, [])

        return ExecutionPlan(
            steps=steps,
            source="static",
            confidence=intent.confidence,
            raw_intent=instruction,
            parsed_intent=intent,
        )

    def _intent_to_steps(self, intent: ParsedIntent, offset: int, depends_on: list[str]) -> list[ExecutionStep]:
        """Convert a single intent into execution steps."""
        steps: list[ExecutionStep] = []
        targets = intent.targets or [""]
        primary_target = targets[0] if targets else None

        if intent.category in (IntentCategory.SCAN, IntentCategory.RECON):
            if intent.tools:
                for i, tool in enumerate(intent.tools):
                    step_id = f"step_{offset + i + 1}"
                    steps.append(
                        ExecutionStep(
                            id=step_id,
                            step_type=StepType.TOOL_RUN,
                            tool=tool,
                            target=primary_target,
                            depends_on=depends_on if i == 0 else [],
                            timeout=intent.flags.get("timeout", 300),
                            description=f"Run {tool} scan",
                        )
                    )
            elif intent.flags.get("all_tools"):
                steps.append(
                    ExecutionStep(
                        id=f"step_{offset + 1}",
                        step_type=StepType.TOOL_RUN,
                        tool="__all__",
                        target=primary_target,
                        depends_on=depends_on,
                        timeout=intent.flags.get("timeout", 600),
                        description="Run all available tools",
                    )
                )
            else:
                # Default: nmap for unknown scan
                steps.append(
                    ExecutionStep(
                        id=f"step_{offset + 1}",
                        step_type=StepType.TOOL_RUN,
                        tool="nmap",
                        target=primary_target,
                        depends_on=depends_on,
                        timeout=300,
                        description="Default: port scan with nmap",
                    )
                )

        elif intent.category == IntentCategory.ANALYZE:
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.AI_ANALYSIS,
                    description="AI-powered analysis of findings",
                    depends_on=depends_on,
                )
            )

        elif intent.category == IntentCategory.REPORT:
            fmt = intent.flags.get("output_format", "html")
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.REPORT,
                    description=f"Generate {fmt} report",
                    depends_on=depends_on,
                    metadata={"format": fmt},
                )
            )

        elif intent.category == IntentCategory.CUSTOM:
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.SHELL_CMD,
                    command=intent.raw_text,
                    description="Custom command execution",
                    depends_on=depends_on,
                )
            )

        else:
            # Unknown — create a placeholder
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.SHELL_CMD,
                    description=f"Execute: {intent.raw_text}",
                    depends_on=depends_on,
                )
            )

        return steps

# Instantiate the global planner singleton
ai_planner = AITaskPlanner()
