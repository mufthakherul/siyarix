# SPDX-License-Identifier: AGPL-3.0-or-later

"""Task planner — converts natural language instructions into execution plans.

Uses language models (OpenAI, Gemini, Anthropic, Ollama, etc.) to interpret
complex instructions and produce structured plans. Falls back to a local
heuristic-based interpreter when no model provider is available.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from .interpreter import InterpretedTask, RuleInterpreter, TaskCategory
from .providers import CircuitBreaker, registry as _provider_registry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Execution Plan data model
# ---------------------------------------------------------------------------


class StepType(StrEnum):
    """Type of execution step in a plan."""

    TOOL_RUN = "tool_run"  # Run a registered security tool
    SHELL_CMD = "shell_cmd"  # Run an arbitrary (safe) shell command
    ANALYSIS = "analysis"  # Model-driven analysis of results
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

    def __repr__(self) -> str:
        return (
            f"ExecutionStep(id={self.id!r}, type={self.step_type.value!r}, "
            f"tool={self.tool!r}, target={self.target!r})"
        )


@dataclass
class ExecutionPlan:
    """A structured plan of steps to execute for a user request."""

    steps: list[ExecutionStep] = field(default_factory=list)
    source: str = "registry"  # "registry" | "autonomous" | "integrated"
    confidence: float = 0.0
    reasoning: str = ""  # Model reasoning/chain-of-thought behind the plan
    raw_instruction: str = ""
    interpreted_task: InterpretedTask | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [s.to_dict() for s in self.steps],
            "source": self.source,
            "confidence": self.confidence,
            "raw_instruction": self.raw_instruction,
            "interpreted_task": (
                self.interpreted_task.to_dict() if self.interpreted_task else None
            ),
        }

    def __repr__(self) -> str:
        return (
            f"ExecutionPlan(steps={len(self.steps)}, source={self.source!r}, "
            f"confidence={self.confidence:.2f})"
        )


# ---------------------------------------------------------------------------
# Model Provider protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ModelProvider(Protocol):
    """Protocol for model providers used by the task planner."""

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Send a planning prompt to the model and return structured plan JSON."""
        ...


# ---------------------------------------------------------------------------
# OpenAI Model Provider
# ---------------------------------------------------------------------------


class OpenAIModel:
    """Model provider using OpenAI API (GPT-4o, etc.)."""

    def __init__(
        self, api_key: str | None = None, model: str = "gpt-4o", base_url: str | None = None
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._model = model
        self._base_url = base_url

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via OpenAI chat completion."""
        try:
            import openai
        except ImportError:
            logger.warning(
                "openai package not installed; autonomous planning unavailable"
            )
            return {}

        if not self._api_key:
            return {}

        system_prompt = _build_system_prompt(context)

        client = openai.AsyncOpenAI(api_key=self._api_key, base_url=self._base_url) if self._base_url else openai.AsyncOpenAI(api_key=self._api_key)
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


class GeminiModel:
    """Model provider using Google Gemini."""

    def __init__(
        self, api_key: str | None = None, model: str = "gemini-1.5-pro"
    ) -> None:
        self._api_key = (
            api_key
            or os.environ.get("GEMINI_API_KEY", "")
            or os.environ.get("GOOGLE_API_KEY", "")
        )
        self._model = model

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via Gemini."""
        try:
            import google.generativeai as genai
        except ImportError:
            logger.warning(
                "google-generativeai package not installed; Gemini unavailable"
            )
            return {}

        if not self._api_key:
            return {}

        system_prompt = _build_system_prompt(context)

        def _generate() -> str:
            genai.configure(
                api_key=self._api_key
            )  # pyright: ignore[reportPrivateImportUsage]
            model = genai.GenerativeModel(
                self._model
            )  # pyright: ignore[reportPrivateImportUsage]
            response = model.generate_content(
                [system_prompt, prompt],
                generation_config={"temperature": 0.1, "max_output_tokens": 2048},
            )
            text = getattr(response, "text", "") or "{}"
            return text

        try:
            content = await asyncio.to_thread(_generate)
            return json.loads(content)
        except Exception as exc:
            logger.warning("Gemini planning failed: %s", exc)
            return {}


# ---------------------------------------------------------------------------
# Ollama Model Provider (local) — lazy availability check (no blocking startup)
# ---------------------------------------------------------------------------


class OllamaModel:
    """Model provider using local Ollama instance.

    Availability is checked lazily (only when planning is requested) to avoid
    blocking the CLI startup with a synchronous HTTP call.
    """

    _CACHE_TTL: float = 30.0  # seconds

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._available: bool | None = None  # None = not yet checked
        self._cache_expiry: float = 0.0

    @property
    def available(self) -> bool:
        """Return cached availability with TTL."""
        if self._available is not None and time.monotonic() < self._cache_expiry:
            return self._available
        return True  # optimistic — actual check in plan()

    async def _check_available(self) -> bool:
        """Async availability check — run this lazily before planning."""
        now = time.monotonic()
        # Respect existing cache
        if self._available is not None and now < self._cache_expiry:
            return bool(self._available)
        try:
            import httpx

            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                self._available = resp.status_code == 200
        except Exception as exc:
            logger.debug("Ollama check failed: %s", exc)
            self._available = False
        self._cache_expiry = time.monotonic() + self._CACHE_TTL
        return bool(self._available)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via Ollama."""
        try:
            import httpx
        except ImportError:
            return {}

        # Lazy availability check
        if self._available is None:
            ok = await self._check_available()
            if not ok:
                return {}
        elif not self._available:
            if time.monotonic() < self._cache_expiry:
                return {}
            ok = await self._check_available()
            if not ok:
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
            self._available = False

        return {}


# ---------------------------------------------------------------------------
# Cloud Model Provider
# ---------------------------------------------------------------------------


class CloudModel:
    """Model provider using cloud service."""

    def __init__(self, server_url: str = "", api_key: str = "") -> None:
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key

    @property
    def available(self) -> bool:
        return bool(self._server_url and self._api_key)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        """Generate an execution plan via cloud service."""
        if not self.available:
            return {}

        try:
            import httpx
        except ImportError:
            return {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._server_url}/api/planner/plan",
                    json={"prompt": prompt, "context": context},
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception as exc:
            logger.warning("Cloud planning failed: %s", exc)

        return {}


# ---------------------------------------------------------------------------
# Base for OpenAI-compatible HTTP API providers
# ---------------------------------------------------------------------------


class _OpenAICompatibleModel:
    """Base for OpenAI-compatible chat completion providers (Groq, Together, LM Studio, Custom)."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str = "",
        model: str = "",
        timeout: float = 60.0,
        name: str = "provider",
        lazy_check: bool = False,
        require_api_key: bool = True,
        require_model: bool = True,
        json_mode: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._name = name
        self._lazy_check = lazy_check
        self._require_api_key = require_api_key
        self._require_model = require_model
        self._json_mode = json_mode
        if lazy_check:
            self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._lazy_check:
            return True
        if self._require_api_key:
            return bool(self._api_key)
        return bool(self._base_url)

    async def _check_available(self) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._base_url}/v1/models")
                self._available = resp.status_code == 200
        except Exception:
            self._available = False
        return bool(self._available)

    async def plan(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        try:
            import httpx
        except ImportError:
            return {}

        if self._lazy_check:
            if self._available is None:
                ok = await self._check_available()
                if not ok:
                    return {}
            elif not self._available:
                return {}
        elif self._require_api_key and not self._api_key:
            return {}
        elif not self._require_api_key and not self._base_url:
            return {}

        system_prompt = _build_system_prompt(context)
        try:
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                payload: dict[str, Any] = {
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 2048,
                }
                if self._json_mode:
                    payload["response_format"] = {"type": "json_object"}
                if self._require_model:
                    payload["model"] = self._model or "default"
                elif self._model:
                    payload["model"] = self._model

                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = (
                        data.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", "{}")
                    )
                    return json.loads(content)
        except Exception as exc:
            logger.warning("%s planning failed: %s", self._name, exc)
            if self._lazy_check:
                self._available = False
        return {}


# ---------------------------------------------------------------------------
# Groq Model Provider
# ---------------------------------------------------------------------------


class GroqModel(_OpenAICompatibleModel):
    """Model provider using Groq API (fast inference)."""

    def __init__(
        self, api_key: str | None = None, model: str = "llama3-70b-8192"
    ) -> None:
        super().__init__(
            base_url="https://api.groq.com/openai/v1",
            api_key=api_key or os.environ.get("GROQ_API_KEY", ""),
            model=model,
            name="Groq",
        )


# ---------------------------------------------------------------------------
# Together AI Model Provider
# ---------------------------------------------------------------------------


class TogetherModel(_OpenAICompatibleModel):
    """Model provider using Together AI API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "mistralai/Mixtral-8x7B-Instruct-v0.1",
    ) -> None:
        super().__init__(
            base_url="https://api.together.xyz/v1",
            api_key=api_key or os.environ.get("TOGETHER_API_KEY", ""),
            model=model,
            name="Together",
        )


# ---------------------------------------------------------------------------
# LM Studio Model Provider (Local)
# ---------------------------------------------------------------------------


class LMStudioModel(_OpenAICompatibleModel):
    """Model provider using local LM Studio instance (OpenAI-compatible API)."""

    def __init__(
        self, base_url: str = "http://localhost:1234", model: str = ""
    ) -> None:
        super().__init__(
            base_url=base_url,
            api_key="",
            model=model or "local-model",
            timeout=120.0,
            name="LMStudio",
            lazy_check=True,
            require_api_key=False,
        )

    @property
    def available(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Custom Model Provider (User-defined)
# ---------------------------------------------------------------------------


class CustomModel(_OpenAICompatibleModel):
    """Model provider for user-defined custom API endpoints."""

    def __init__(
        self, server_url: str = "", api_key: str = "", model: str = ""
    ) -> None:
        super().__init__(
            base_url=server_url,
            api_key=api_key,
            model=model,
            name="Custom",
            require_api_key=False,
            require_model=False,
            json_mode=False,
        )


# ---------------------------------------------------------------------------
# System prompt builder — specialized for cybersecurity
# ---------------------------------------------------------------------------


def _build_system_prompt(context: dict[str, Any]) -> str:
    """Build the system prompt for task planning with tool context."""
    available_tools = context.get("available_tools", [])
    tool_list = "\n".join(
        f"  - {t['name']} ({t.get('category', '?')}): {', '.join(t.get('capabilities', []))}"
        for t in available_tools
    )
    platform = context.get("platform", "unknown")

    return f"""You are Siyarix — an expert autonomous cybersecurity agent and task planner.
Platform: {platform}

You convert natural language security instructions into structured JSON execution plans.
You have access to the following locally installed security tools:

{tool_list or "  (no tools discovered yet — suggest common system commands)"}

CYBERSECURITY EXPERTISE:
- You understand penetration testing methodologies (PTES, OWASP, NIST)
- You know MITRE ATT&CK tactics, techniques, and procedures (TTPs)
- You understand CVE scoring (CVSS v3), EPSS, and exploit maturity
- You can suggest both offensive (red team) and defensive (blue team) steps
- You understand network protocols (TCP/IP, DNS, HTTP/S, SMB, RDP, SSH)
- You know Windows (CMD, PowerShell, Registry, AD) and Linux (bash, proc, sysfs) internals
- You understand cloud environments (AWS, Azure, GCP) attack surfaces

IMPORTANT RULES:
1. Only suggest tools from the available list above, or safe system commands.
2. Never suggest destructive, irreversible, or illegal commands.
3. Respect scope — do not suggest scanning targets not mentioned.
4. For each step, specify: id, step_type, tool/command, args, target, description.
5. step_type must be one of: tool_run, shell_cmd, analysis, conditional, parallel_group, report, notify.
6. Order steps logically (recon → scan → analyze → report).
7. If a step depends on a previous step, set depends_on with the step id(s).
8. Always include a timeout (seconds) for each step.
9. Prefer parallel steps where safe and independent.

Respond with ONLY a JSON object:
{{
  "steps": [
    {{
      "id": "step_1",
      "step_type": "tool_run",
      "tool": "nmap",
      "command": null,
      "args": ["-sV", "-sC", "--open"],
      "target": "192.168.1.1",
      "depends_on": [],
      "condition": null,
      "timeout": 300,
      "description": "Port scan with service/version detection"
    }}
  ],
  "confidence": 0.9,
  "reasoning": "Brief explanation of the plan approach"
}}"""


# ---------------------------------------------------------------------------
# Task Planner — the main orchestrator
# ---------------------------------------------------------------------------


class TaskPlanner:
    """Converts natural language instructions into executable plans.

    Uses model providers when available, falls back to heuristic interpretation.
    """

    def __init__(
        self,
        providers: list[ModelProvider] | None = None,
    ) -> None:
        self._providers = providers or []
        self._interpreter = RuleInterpreter()
        # Circuit breakers per provider type
        self._circuit_breakers: dict[str, CircuitBreaker] = {
            "OpenAIModel": CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name="OpenAI"
            ),
            "GeminiModel": CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name="Gemini"
            ),
            "OllamaModel": CircuitBreaker(
                failure_threshold=2, reset_timeout=30.0, name="Ollama"
            ),
            "CloudModel": CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name="Cloud"
            ),
            "GroqModel": CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name="Groq"
            ),
            "TogetherModel": CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name="Together"
            ),
            "LMStudioModel": CircuitBreaker(
                failure_threshold=2, reset_timeout=30.0, name="LMStudio"
            ),
            "CustomModel": CircuitBreaker(
                failure_threshold=3, reset_timeout=60.0, name="Custom"
            ),
        }

    def add_provider(self, provider: ModelProvider) -> None:
        """Register a model provider for dynamic planning."""
        self._providers.append(provider)

    def set_providers(self, providers: list[ModelProvider]) -> None:
        """Replace all providers (useful for hot-swapping)."""
        self._providers = list(providers)

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
            If "static", skip autonomous models. If "autonomous", skip interpreter.
            If None or "integrated", try models first then fall back to interpreter.
        **kwargs:
            Additional parameters merged into context.
        """
        ctx = context or {}
        if kwargs:
            ctx.update(kwargs)

        # --- Static-only mode ---
        if force_mode == "static":
            return self._plan_from_interpretation(instruction)

        # --- Autonomous-only mode ---
        if force_mode == "autonomous":
            plan = await self._plan_from_model(instruction, ctx)
            if plan and plan.steps:
                return plan
            logger.warning("Autonomous planning failed; no model providers available")
            return ExecutionPlan(
                raw_instruction=instruction,
                source="autonomous",
                confidence=0.0,
            )

        # --- Integrated mode (default) ---
        # 1) Try interpreter first for quick classification
        interpreted_task = self._interpreter.interpret(instruction)

        # 2) If interpreter is highly confident, use static plan
        if interpreted_task.confidence >= 0.8:
            static_plan = self._build_plan_from_task(interpreted_task, instruction)
            static_plan.source = "integrated-registry"
            return static_plan

        # 3) Try model planning for complex/ambiguous instructions
        model_plan = await self._plan_from_model(instruction, ctx)
        if model_plan and model_plan.steps:
            model_plan.source = "integrated-autonomous"
            model_plan.interpreted_task = interpreted_task
            return model_plan

        # 4) Fall back to static plan from whatever the interpreter got
        fallback_plan = self._build_plan_from_task(interpreted_task, instruction)
        fallback_plan.source = "integrated-fallback"
        return fallback_plan

    async def interpret(self, instruction: str, target: str | None = None) -> str:
        """Briefly interpret a command and return a summary string."""
        plan = await self.plan(
            instruction, context={"targets": [target] if target else []}
        )
        if not plan.steps:
            return f"Unknown instruction: {instruction}"

        steps_desc = [
            s.description or (s.tool or s.command or "step") for s in plan.steps
        ]
        return f"Plan: {' -> '.join(steps_desc)}"

    async def replan(
        self,
        instruction: str,
        context: dict[str, Any],
        trigger_step: ExecutionStep,
        trigger_reason: str,
    ) -> ExecutionPlan | None:
        """Adaptive re-planning entrypoint for execution feedback loops."""
        replan_prompt = (
            f"Objective: {instruction}\n"
            f"Trigger: step '{trigger_step.id}' with reason '{trigger_reason}'.\n"
            "Generate only the next minimal corrective steps."
        )
        model_plan = await self._plan_from_model(replan_prompt, context)
        if model_plan and model_plan.steps:
            model_plan.source = "adaptive-replan"
            return model_plan

        fallback_steps: list[ExecutionStep] = []
        if trigger_reason == "step_failed" and trigger_step.tool == "nikto":
            fallback_steps.append(
                ExecutionStep(
                    id=f"{trigger_step.id}_adaptive_nuclei",
                    step_type=StepType.TOOL_RUN,
                    tool="nuclei",
                    target=trigger_step.target,
                    description=f"Adaptive fallback: nuclei after {trigger_step.id} failure",
                )
            )
        elif trigger_reason == "zero_findings" and trigger_step.tool == "nmap":
            fallback_steps.append(
                ExecutionStep(
                    id=f"{trigger_step.id}_adaptive_nuclei",
                    step_type=StepType.TOOL_RUN,
                    tool="nuclei",
                    target=trigger_step.target,
                    description=f"Adaptive follow-up: nuclei after zero findings from {trigger_step.id}",
                )
            )
        elif trigger_reason == "zero_findings" and trigger_step.tool == "gobuster":
            fallback_steps.append(
                ExecutionStep(
                    id=f"{trigger_step.id}_adaptive_nikto",
                    step_type=StepType.TOOL_RUN,
                    tool="nikto",
                    target=trigger_step.target,
                    description=f"Adaptive follow-up: nikto after zero findings from {trigger_step.id}",
                )
            )

        if not fallback_steps:
            return None
        return ExecutionPlan(
            steps=fallback_steps,
            source="adaptive-replan-fallback",
            confidence=0.6,
            raw_instruction=instruction,
        )

    def _plan_from_interpretation(self, instruction: str) -> ExecutionPlan:
        """Create a plan purely from the heuristic interpreter."""
        task = self._interpreter.interpret(instruction)
        return self._build_plan_from_task(task, instruction)

    async def _plan_from_model(
        self, instruction: str, context: dict[str, Any]
    ) -> ExecutionPlan | None:
        """Try each model provider in order; return the first successful plan.

        Uses a circuit breaker per provider to avoid hammering failing endpoints.
        """
        tried_any = False

        # Phase 1 — try configured providers in order
        for provider in self._providers:
            if not getattr(provider, "available", True):
                continue

            # Check circuit breaker
            provider_name = type(provider).__name__
            breaker = self._circuit_breakers.get(provider_name)
            if breaker and not breaker.is_available:
                logger.debug("Circuit breaker OPEN for %s — skipping", provider_name)
                continue

            tried_any = True
            logger.info("Trying provider %s ...", provider_name)
            try:
                raw = await provider.plan(instruction, context)
                if raw and raw.get("steps"):
                    if breaker:
                        breaker.record_success()
                    _provider_registry.record_success(provider_name)
                    return self._parse_model_response(raw, instruction)
            except Exception:
                logger.warning("Provider %s failed, trying next ...", provider_name)
                if breaker:
                    breaker.record_failure()
                _provider_registry.record_failure(provider_name)

        # Phase 2 — try providers from global registry that weren't already tried
        for reg_name in _provider_registry.list_providers():
            try:
                reg_prov = _provider_registry.get(reg_name)
            except KeyError:
                continue
            if not isinstance(reg_prov, type):
                continue  # skip instances, already in self._providers
            if any(type(p).__name__ == reg_prov.__name__ for p in self._providers):
                continue  # already tried as a configured provider

            provider_name = reg_prov.__name__
            breaker = self._circuit_breakers.get(provider_name)
            if breaker and not breaker.is_available:
                continue

            # Build a minimal instance (no config — just check availability)
            try:
                prov_instance = reg_prov()
            except Exception:
                continue
            if not getattr(prov_instance, "available", True):
                continue

            tried_any = True
            logger.info("Trying fallback provider %s from registry ...", provider_name)
            try:
                raw = await prov_instance.plan(instruction, context)
                if raw and raw.get("steps"):
                    if breaker:
                        breaker.record_success()
                    return self._parse_model_response(raw, instruction)
            except Exception:
                logger.warning("Provider %s failed, trying next ...", provider_name)
                if breaker:
                    breaker.record_failure()

        if not tried_any:
            logger.warning("No model providers available for planning")
        else:
            logger.info("All model providers exhausted — falling back to interpreter")

        return None

    def _parse_model_response(
        self, raw: dict[str, Any], instruction: str
    ) -> ExecutionPlan:
        """Parse the raw model JSON response into an ExecutionPlan.

        This method is intentionally lenient — it handles:
        • Missing or mis-typed fields gracefully
        • Markdown code-fenced JSON in string values
        • Unknown step_type values (falls back to SHELL_CMD)
        • args as string or list
        """
        steps: list[ExecutionStep] = []
        raw_steps = raw.get("steps", [])

        # If raw_steps is a string (model wrapped JSON in a string), try parsing
        if isinstance(raw_steps, str):
            try:
                raw_steps = json.loads(raw_steps)
            except (json.JSONDecodeError, TypeError):
                raw_steps = []

        for s in raw_steps:
            if not isinstance(s, dict):
                continue

            step_type_str = s.get("step_type", "shell_cmd")
            try:
                if step_type_str == "ai_analysis":
                    step_type = StepType.ANALYSIS
                else:
                    step_type = StepType(step_type_str)
            except ValueError:
                step_type = StepType.SHELL_CMD

            # Handle args as string or list
            raw_args = s.get("args", [])
            if isinstance(raw_args, str):
                args = raw_args.split()
            elif isinstance(raw_args, list):
                args = [str(a) for a in raw_args]
            else:
                args = []

            # Handle depends_on as string or list
            raw_deps = s.get("depends_on", [])
            if isinstance(raw_deps, str):
                depends_on = [raw_deps] if raw_deps else []
            elif isinstance(raw_deps, list):
                depends_on = [str(d) for d in raw_deps]
            else:
                depends_on = []

            # Coerce timeout
            try:
                timeout = int(s.get("timeout", 300))
            except (TypeError, ValueError):
                timeout = 300

            steps.append(
                ExecutionStep(
                    id=s.get("id", f"step_{len(steps) + 1}"),
                    step_type=step_type,
                    tool=s.get("tool"),
                    command=s.get("command"),
                    args=args,
                    target=s.get("target"),
                    depends_on=depends_on,
                    condition=s.get("condition"),
                    timeout=timeout,
                    description=s.get("description", ""),
                    metadata=s.get("metadata") or {},
                )
            )

        # Coerce confidence
        try:
            confidence = float(raw.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5

        reasoning = raw.get("reasoning", "") or raw.get("chain_of_thought", "")
        if isinstance(reasoning, list):
            reasoning = "\n".join(str(r) for r in reasoning)

        return ExecutionPlan(
            steps=steps,
            source="autonomous",
            confidence=confidence,
            reasoning=reasoning,
            raw_instruction=instruction,
        )

    def _build_plan_from_task(
        self, task: InterpretedTask, instruction: str
    ) -> ExecutionPlan:
        """Convert an InterpretedTask into an ExecutionPlan with concrete steps."""
        steps: list[ExecutionStep] = []
        step_counter = 0

        # Handle workflows, conditionals, and chains
        if task.action == "conditional":
            then_sub = next(
                (s for s in task.sub_tasks if s.flags.get("branch") == "then"), None
            )
            else_sub = next(
                (s for s in task.sub_tasks if s.flags.get("branch") == "else"), None
            )
            cond_str = task.flags.get("condition")

            if then_sub:
                then_steps = self._task_to_steps(then_sub, step_counter, [])
                for s in then_steps:
                    s.condition = cond_str
                steps.extend(then_steps)
                step_counter += len(then_steps)

            if else_sub:
                else_steps = self._task_to_steps(else_sub, step_counter, [])
                for s in else_steps:
                    s.condition = f"not ({cond_str})"
                steps.extend(else_steps)
                step_counter += len(else_steps)

        elif task.action == "chain":
            prev_ids: list[str] = []
            for i, sub in enumerate(task.sub_tasks):
                sub_steps = self._task_to_steps(sub, step_counter, prev_ids)
                if i > 0 and sub_steps and prev_ids:
                    op = sub.flags.get("chain_op", "&&")
                    prev_id = prev_ids[-1]
                    if op == "&&":
                        sub_steps[0].condition = f"{prev_id}.success"
                    elif op == "||":
                        sub_steps[0].condition = f"{prev_id}.failed"
                steps.extend(sub_steps)
                prev_ids = [s.id for s in sub_steps]
                step_counter += len(sub_steps)

        elif task.sub_tasks:
            prev_ids = []
            for sub in task.sub_tasks:
                sub_steps = self._task_to_steps(sub, step_counter, prev_ids)
                steps.extend(sub_steps)
                prev_ids = [s.id for s in sub_steps]
                step_counter += len(sub_steps)
        else:
            steps = self._task_to_steps(task, 0, [])

        return ExecutionPlan(
            steps=steps,
            source="registry",
            confidence=task.confidence,
            raw_instruction=instruction,
            interpreted_task=task,
        )

    def _task_to_steps(
        self, task: InterpretedTask, offset: int, depends_on: list[str]
    ) -> list[ExecutionStep]:
        """Convert a single task into execution steps."""
        steps: list[ExecutionStep] = []
        targets = task.targets or [""]
        primary_target = targets[0] if targets else None

        if task.category in (TaskCategory.SCAN, TaskCategory.RECON):
            if task.tools:
                for i, tool in enumerate(task.tools):
                    step_id = f"step_{offset + i + 1}"
                    steps.append(
                        ExecutionStep(
                            id=step_id,
                            step_type=StepType.TOOL_RUN,
                            tool=tool,
                            target=primary_target,
                            depends_on=depends_on if i == 0 else [],
                            timeout=task.flags.get("timeout", 300),
                            description=f"Run {tool} scan",
                        )
                    )
            elif task.flags.get("all_tools"):
                steps.append(
                    ExecutionStep(
                        id=f"step_{offset + 1}",
                        step_type=StepType.TOOL_RUN,
                        tool="__all__",
                        target=primary_target,
                        depends_on=depends_on,
                        timeout=task.flags.get("timeout", 600),
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

        elif task.category == TaskCategory.ANALYZE:
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.ANALYSIS,
                    description="Analysis of findings",
                    depends_on=depends_on,
                )
            )

        elif task.category == TaskCategory.REPORT:
            fmt = task.flags.get("output_format", "html")
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.REPORT,
                    description=f"Generate {fmt} report",
                    depends_on=depends_on,
                    metadata={"format": fmt},
                )
            )

        elif task.category == TaskCategory.CUSTOM:
            intent = task.flags.get("intent")
            if intent:
                import importlib

                if importlib.util.find_spec("siyarix.shell_knowledge"):
                    from . import shell_knowledge as _shell_knowledge  # type: ignore[attr-defined]

                    kwargs: dict[str, str] = {}
                    if primary_target:
                        kwargs["target"] = primary_target
                        kwargs["file"] = primary_target
                    cmd = _shell_knowledge.render_intent(intent, **kwargs)
                    desc = _shell_knowledge.INTENT_METADATA.get(intent, {}).get(
                        "description", f"Execute {intent}"
                    )
                else:
                    cmd = ""
                    desc = ""
                steps.append(
                    ExecutionStep(
                        id=f"step_{offset + 1}",
                        step_type=StepType.SHELL_CMD,
                        command=cmd,
                        description=desc,
                        depends_on=depends_on,
                    )
                )
            else:
                steps.append(
                    ExecutionStep(
                        id=f"step_{offset + 1}",
                        step_type=StepType.SHELL_CMD,
                        command=task.raw_text,
                        description="Custom command execution",
                        depends_on=depends_on,
                    )
                )

        else:
            # Unknown — create a placeholder shell step
            steps.append(
                ExecutionStep(
                    id=f"step_{offset + 1}",
                    step_type=StepType.SHELL_CMD,
                    description=f"Execute: {task.raw_text}",
                    depends_on=depends_on,
                )
            )

        return steps


# Instantiate the global planner singleton — providers are added lazily by the engine
planner = TaskPlanner()
