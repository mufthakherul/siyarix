from __future__ import annotations
from .platform_utils import build_platform_context
import asyncio
import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.panel import Panel

from ..exceptions import LLMProviderError
from .session import ChatSession
from .console import console

if TYPE_CHECKING:
    from ..config import SettingsStore
    from ..providers.state import ProviderStateManager
    from ..providers.usage import UsageTracker

logger = logging.getLogger(__name__)


class LLMEngineMixin:
    if TYPE_CHECKING:
        _session: ChatSession
        _settings: SettingsStore
        _mode: str
        _provider_state: ProviderStateManager
        _usage_tracker: UsageTracker
        _print_assistant: Any
        _llm_calls: int
        SYSTEM_REFRESH_INTERVAL: int
        _stream_assistant_response: Any
        _get_conversation_history: Any
        _print_plan: Any
        _print_results: Any
        _tool_cache: list[Any] | None

    async def _handle_natural_language(self, user_input: str) -> None:
        """Process a natural language instruction."""
        self._session.add_message("user", user_input)

        # Inject target context if set and not already in input
        instruction = user_input
        if self._session.target and self._session.target not in instruction:
            instruction = f"{instruction} on {self._session.target}"

        await self._execute_instruction(
            instruction, target=self._session.target or "", show_plan=True
        )

    async def _execute_instruction(
        self,
        instruction: str,
        target: str = "",
        show_plan: bool = False,
    ) -> None:
        """Execute an instruction — AgentCore for LLM modes, engine for registry modes."""
        from ..registry import ToolRegistry

        # ── Route by mode ──
        if self._mode in ("registry", "offline"):
            pass  # skip agent, go straight to registry engine below
        elif self._mode == "autonomous":
            ok = await self._execute_agent(instruction, target, require_llm=True)
            if ok:
                return
            # Autonomous: agent failed → show error, stop
            console.print(
                "[red]Autonomous mode requires an LLM provider. "
                "Use /config set model_provider <name> and set the corresponding API key.[/red]"
            )
            return
        else:  # integrated
            ok = await self._execute_agent(instruction, target, require_llm=False)
            if ok:
                return
            # Integrated: agent failed → fall through to registry
            console.print("[yellow]⚠ Falling back to offline registry mode[/yellow]")

        # ── Registry / integrated fallback: traditional plan → execute pipeline ──
        from ..compat import ExecutionEngine, ExecutionMode

        try:
            exec_mode = ExecutionMode(self._mode)
        except ValueError:
            exec_mode = ExecutionMode.INTEGRATED

        # Build platform context for the planner
        platform_ctx = build_platform_context()

        # Lazy engine build
        engine_config: dict[str, Any] = {
            "openai_api_key": self._resolve_api_key("openai", "OPENAI_API_KEY") or "",
            "gemini_api_key": self._resolve_api_key("gemini", "GEMINI_API_KEY") or "",
            "ollama_url": os.environ.get("SIYARIX_OLLAMA_URL", "http://localhost:11434"),
            "model_provider": self._settings.get("model_provider"),
            "gemini_model": self._settings.get("gemini_model"),
        }

        reg = ToolRegistry()
        from ..session_log import session_logger

        engine = ExecutionEngine(
            mode=exec_mode,
            registry=reg,
            config=engine_config,
            session_logger=session_logger,
        )
        self._engine_kill_switch = getattr(engine, "_kill_switch", None)

        # Build full context with conversation history
        ctx = engine._build_context()
        ctx["platform"] = platform_ctx["platform"]
        ctx["shell"] = platform_ctx["shell"]
        ctx["conversation_history"] = self._session.get_context_summary()
        if target:
            ctx["target"] = target

        # Planning phase with spinner
        plan = None
        with console.status("[bold green]Planning...[/bold green]", spinner="dots"):
            plan = await engine.plan(instruction)

        if plan is None or not plan.steps:
            # Registry/offline mode: local response only (no LLM)
            if self._mode in ("registry", "offline"):
                response = self._generate_text_response(instruction) or ""
                if not response:
                    response = self._build_offline_fallback_response(instruction)
                self._print_assistant(response)
            else:
                prov_name, api_key = self._resolve_provider()
                if prov_name and api_key:
                    compact = self._should_use_compact()
                    sys_prompt = self._build_system_prompt(compact=compact)
                    response = await asyncio.wait_for(
                        self._stream_assistant_response(
                            sys_prompt,
                            instruction,
                            prov_name,
                            api_key,
                            history=self._get_conversation_history(),
                        ),
                        timeout=120.0,
                    )
                    self._llm_calls += 1
                else:
                    response = self._generate_text_response(instruction) or ""
            if response:
                self._session.add_message("assistant", response or "")
            return

        # Show plan if requested
        if show_plan and len(plan.steps) > 1:
            if self._mode in ("registry", "offline"):
                from ..response import ResponseGenerator

                ResponseGenerator().render_plan(plan.steps)
            else:
                self._print_plan(plan)

        # Multi-model ensemble voting (available providers > 1)
        try:
            from .stubs import MultiModelEnsemble, VotingStrategy

            ensemble = MultiModelEnsemble()
            registered_count = 0
            for p in getattr(getattr(engine, "_planner", None), "_providers", []):
                name = type(p).__name__.lower().replace("model", "")
                if getattr(p, "available", False) and hasattr(p, "plan"):
                    ensemble.register_provider(name, p)
                    registered_count += 1
            if registered_count > 1:
                ensemble_result = await ensemble.plan(
                    instruction,
                    _voting_strategy=VotingStrategy.WEIGHTED,
                )
                if ensemble_result.selection_reason and registered_count > 1:
                    console.print(
                        Panel(
                            f"[bold]Ensemble:[/bold] {ensemble_result.selection_reason}\n"
                            f"[dim]Providers:[/dim] {', '.join(r.model_name for r in ensemble_result.responses) if hasattr(ensemble_result, 'responses') and ensemble_result.responses else str(registered_count)}  "
                            f"[dim]Consensus:[/dim] {ensemble_result.consensus_level:.0%}  "
                            f"[dim]Hallucination risk:[/dim] {ensemble_result.hallucination_risk:.0%}",
                            title="[bold cyan]🔮 Multi-Model Ensemble[/bold cyan]",
                            border_style="cyan",
                        )
                    )
        except ModuleNotFoundError:
            pass
        except Exception as exc:
            logger.debug("Ensemble integration skipped: %s", exc)

        # Auto-queue plan for retry if in offline mode and plan has steps but execution may fail
        if self._mode in ("registry", "offline") and plan.steps:
            try:
                from ..offline_queue import OfflineCommandQueue
                queue = OfflineCommandQueue()
                queue.enqueue(
                    instruction=instruction,
                    target=self._session.target or target,
                    mode=self._mode,
                    max_attempts=2,
                )
            except Exception:
                pass

        # Adversarial plan review
        try:
            from .stubs import AdversarialTester, AdversarialSeverity

            tester = AdversarialTester()
            plan_lines = [
                f"{getattr(s, 'tool', '') or ''} {' '.join(str(a) for a in getattr(s, 'args', []))} {getattr(s, 'target', '') or ''}".strip() or getattr(s, 'command', '') or ""
                for s in plan.steps
            ]
            findings = tester.review_plan(plan_lines)
            critical = [f for f in findings if f.severity == AdversarialSeverity.CRITICAL]
            high = [f for f in findings if f.severity == AdversarialSeverity.HIGH]
            if findings:
                console.print(
                    Panel(
                        "\n".join(
                            f"[{'red' if f.severity in ('critical', 'high') else 'yellow'}]"
                            f"{'🔴' if f.severity == 'critical' else '⚠'} "
                            f"[{f.severity.upper()}] {f.message}[/]\n"
                            f"  [dim]Suggestion: {f.suggestion}[/dim]"
                            for f in findings[:5]
                        )
                        + (
                            f"\n  [dim]... and {len(findings) - 5} more[/dim]"
                            if len(findings) > 5
                            else ""
                        ),
                        title=f"[bold {'red' if critical else 'yellow'}]🔍 Adversarial Review ({len(findings)} findings)"
                        f"{' — ' + str(len(critical)) + ' critical' if critical else ''}"
                        f"{' — ' + str(len(high)) + ' high' if high else ''}[/bold {'red' if critical else 'yellow'}]",
                        border_style="red" if critical else "yellow",
                    )
                )
        except ModuleNotFoundError:
            pass
        except Exception as exc:
            logger.debug("Adversarial review skipped: %s", exc)

        # Execute with live output — pass plan so it's not discarded
        t0 = time.monotonic()
        total_steps = len(plan.steps) if plan else 0
        console.print(
            f"[bold]Executing {total_steps} step{'s' if total_steps != 1 else ''}...[/bold]"
        )

        def _offline_progress(step: Any, step_progress: dict[str, str]) -> None:
            _status = step.status.value if hasattr(step.status, "value") else str(step.status)
            if _status in ("running", "completed", "failed"):
                done = sum(1 for v in step_progress.values() if v in ("completed", "failed"))
                icon = "✓" if _status == "completed" else ("✗" if _status == "failed" else "▶")
                console.print(
                    f"  {icon} [{_status}] {step.tool or step.description or step.id}"
                    f"  [dim]({done}/{total_steps})[/dim]"
                )

        try:
            result = await engine.execute(
                instruction, plan=plan, interactive=False,
                progress_callback=_offline_progress,
            )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            logger.error("Execution failed: %s", exc, exc_info=True)
            error_msg = str(exc)
            if self._mode in ("registry", "offline"):
                self._print_assistant(
                    f"**Execution Error:** {error_msg}\n\n"
                    "This command has been queued for retry. "
                    "You can check queue status with `/queue status`."
                )
            else:
                console.print(f"[red]Execution failed: {error_msg}[/red]")
            return
        elapsed = time.monotonic() - t0

        try:
            from ..offline_store import OfflineStore

            store = OfflineStore()
            target = self._session.target or ""
            store.save_scan(target or instruction, result.all_findings, mode=self._mode)
            if plan and plan.id:
                step_dicts = [
                    {
                        "tool": getattr(s, "tool", ""),
                        "status": s.status.value if s.status is not None else "unknown",
                        "description": getattr(s, "description", ""),
                    }
                    for s in plan.steps
                ]
                store.save_plan(plan.id, plan.goal, step_dicts, mode=self._mode)
        except Exception as exc:
            logger.debug("Failed to persist to offline store: %s", exc)

        # Print results — match autonomous mode output format
        if self._mode in ("registry", "offline"):
            from ..models import StepStatus
            from rich.panel import Panel as _RichPanel

            # Per-step full output panels (matches autonomous agent loop)
            for r in result.step_results:
                output = (r.output or "").strip()
                error = (r.error or "").strip()
                success = r.status == StepStatus.COMPLETED
                display_lines = (
                    output.split("\n") if output
                    else (error.split("\n") if error else ["(no output)"])
                )
                icon = "✓" if success else "✗"
                border = "green" if success else "red"
                truncated = []
                for line in display_lines[-200:]:
                    if len(line) > 500:
                        truncated.append(line[:500] + "...")
                    else:
                        truncated.append(line)
                console.print(
                    _RichPanel(
                        "\n".join(truncated),
                        title=f"{icon} {r.step_id}",
                        border_style=border,
                    )
                )

            # Bottom stats line (matches autonomous agent loop)
            persona_name = self._settings.get("persona") or "auto"
            stats_parts = [
                f"Time: {elapsed:.1f}s",
                f"Mode: {self._mode}",
                f"Persona: {persona_name}",
            ]
            console.print("[dim]" + " | ".join(stats_parts) + "[/dim]")

            # ── CLS: read-only skill lookup for learning insights ──────────
            try:
                from ..learning_system import get_learning_system
                _cls = get_learning_system()
                _real_target = self._session.target or target
                _matched_skill = _cls.query_skill(instruction, _real_target, min_confidence=0.30)
                if _matched_skill:
                    _insight = _cls.generate_offline_summary(instruction, result, _matched_skill)
                    if _insight:
                        console.print(
                            Panel(
                                _insight,
                                title="[bold cyan]📚 Learning Insights[/bold cyan]",
                                border_style="cyan",
                                padding=(0, 1),
                            )
                        )
            except Exception as _exc:
                logger.debug("CLS offline query failed: %s", _exc)
        else:
            self._print_results(result, elapsed)

        # Store findings in session context so split pane can render them!
        self._session.context["findings"] = result.all_findings

        timeline = []
        for step_res in result.step_results:
            from siyarix.models import StepStatus

            status_emoji = "🟢" if step_res.status == StepStatus.COMPLETED else "🔴"
            timeline.append(
                {
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "event": f"{status_emoji} Step {step_res.step_id}: {step_res.status.value.upper()}",
                }
            )
        for f in result.all_findings:
            timeline.append(
                {
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "event": f"🔴 [VULN] {f.get('type', 'Finding')}: {f.get('detail', f.get('description', ''))}",
                }
            )
        self._session.context["timeline_events"] = timeline

        # Add assistant summary to session
        summary = f"Executed {len(result.step_results)} steps in {elapsed:.1f}s. "
        summary += f"Found {len(result.all_findings)} findings. "
        summary += "Success." if result.success else "Some steps failed."
        self._session.add_message("assistant", summary, findings=len(result.all_findings))

    def _generate_text_response(self, user_input: str) -> str | None:
        """Return a text response for non-tool queries, or ``None`` to let the pipeline proceed."""
        lowered = user_input.strip().lower()
        greetings = {
            "hello", "hi", "hey", "sup", "what's up", "help",
            "good morning", "good evening", "good afternoon",
            "howdy", "yo", "greetings", "hey there",
        }
        if lowered in greetings or lowered.startswith(("hello ", "hi ", "hey ", "howdy ")):
            return self._build_greeting_response()

        # Farewell responses
        if lowered in ("bye", "goodbye", "see you", "see ya", "cya", "farewell"):
            return (
                "Goodbye! Stay curious, stay ethical.\n\n"
                "Type **`/exit`** to quit or just keep exploring."
            )

        # How are you / status questions
        if any(q in lowered for q in ("how are you", "how's it going", "what can you do", "what are you")):
            return (
                "I'm **Siyarix** — your cybersecurity intelligence system, operating in "
                f"**{self._mode}** mode. "
                "I can help with reconnaissance, vulnerability detection, network scanning, "
                "web auditing, and more.\n\n"
                "In **offline mode**, I use built-in heuristic planning without an LLM. "
                "Just describe what you want to accomplish, and I'll build a plan.\n\n"
                "**Examples:**\n"
                "- `scan example.com`\n"
                "- `enumerate subdomains of target.com`\n"
                "- `port scan 10.0.0.1`\n"
                "- `check for vulns on https://app.local`\n"
                "- `dns recon on example.com`\n\n"
                "Type **`/help`** for all commands."
            )

        # Thank you
        if lowered in ("thanks", "thank you", "ty", "thx", "appreciate it"):
            return "You're welcome! Let me know if you need anything else."

        # Source / version queries
        if lowered in ("version", "what version", "source", "github"):
            from .. import __version__
            return (
                f"**Siyarix** version **{__version__}**\n\n"
                "Source code: https://github.com/mufthakherul/siyarix\n"
                "Contributing: https://github.com/mufthakherul/siyarix/blob/main/CONTRIBUTING.md"
            )

        return None

    def _build_offline_fallback_response(self, instruction: str) -> str:
        lowered = instruction.lower()

        suggestions = []
        if any(kw in lowered for kw in ("ping", "icmp", "reachable")):
            suggestions.append("  • **`ping example.com`** — ICMP ping connectivity test")
        if any(kw in lowered for kw in ("scan", "port", "nmap")):
            suggestions.append("  • **`scan example.com`** — full port scan")
        if any(kw in lowered for kw in ("web", "http", "website", "site")):
            suggestions.append("  • **`check http headers on example.com`** — web audit")
        if any(kw in lowered for kw in ("dns", "domain", "subdomain", "nameserver")):
            suggestions.append("  • **`dns recon on example.com`** — DNS enumeration")
        if any(kw in lowered for kw in ("vuln", "cve", "vulnerability", "exploit")):
            suggestions.append("  • **`vuln scan on example.com`** — vulnerability scan")
        if any(kw in lowered for kw in ("ssl", "tls", "certificate", "cipher")):
            suggestions.append("  • **`ssl check on example.com`** — TLS audit")
        if any(kw in lowered for kw in ("brute", "crack", "password", "hydra")):
            suggestions.append("  • **`brute force ssh on target`** — credential testing")
        if any(kw in lowered for kw in ("smb", "windows", "netbios")):
            suggestions.append("  • **`smb enum on 10.0.0.1`** — SMB enumeration")
        if any(kw in lowered for kw in ("cloud", "aws", "azure", "gcp")):
            suggestions.append("  • **`cloud audit on example.com`** — cloud assessment")
        if any(kw in lowered for kw in ("wifi", "wireless", "wpa")):
            suggestions.append("  • **`wifi audit`** — wireless assessment")
        if any(kw in lowered for kw in ("headers", "http", "security headers")):
            suggestions.append("  • **`headers on example.com`** — HTTP security headers")
        if any(kw in lowered for kw in ("cors", "cross")):
            suggestions.append("  • **`cors check on example.com`** — CORS policy")

        if suggestions:
            return (
                "I couldn't build a complete plan from your request. "
                "Based on what you described, here are some suggestions:\n\n"
                + "\n".join(suggestions[:5])
                + "\n\nType **`/help`** to see all available commands."
            )

        # Last resort — show a small generic help with common patterns
        return (
            "I didn't recognize that as a security task I can handle in offline mode. "
            "Try one of these patterns:\n\n"
            "  • **`scan <target>`** — full reconnaissance\n"
            "  • **`port scan <target>`** — TCP port scan\n"
            "  • **`web audit <url>`** — web application audit\n"
            "  • **`dns recon <domain>`** — DNS enumeration\n"
            "  • **`vuln scan <target>`** — vulnerability scan\n\n"
            "Type **`/help`** for all commands, or switch to **integrated** mode "
            "with `/mode integrated` for LLM-powered interpretation."
        )

    def _build_greeting_response(self) -> str:
        import getpass
        from datetime import datetime

        username = getpass.getuser()
        hour = datetime.now().hour
        if 5 <= hour < 12:
            tod = "morning"
        elif 12 <= hour < 13:
            tod = "noon"
        elif 13 <= hour < 17:
            tod = "afternoon"
        elif 17 <= hour < 21:
            tod = "evening"
        else:
            tod = "night"

        time_of_day = {
            "morning": "morning",
            "noon": "noon",
            "afternoon": "afternoon",
            "evening": "evening",
            "night": "night",
        }.get(tod, "day")

        website_url = "https://siyarix.github.io"

        return (
            f"Hello, {username}. Good {time_of_day}.\n\n"
            "I'm Siyarix — an open-source, AI-powered CLI assistant focused on cybersecurity. "
            "I am currently under active development.\n\n"
            "My principal creator is Mufthakherul, but as an open-source project, "
            "maybe many developers from around the world contribute to building and improving me. "
            "I am genuinely grateful to every contributor who helps shape Siyarix "
            "and keeps it relevant in the modern era.\n\n"
            "If you would like to contribute, please visit my repository:\n"
            f"{website_url}\n\n"
            "Useful commands:\n\n"
            "  help\n"
            "  /help\n"
            "  --help\n\n"
            "For complete documentation:\n"
            f"{website_url}\n\n"
            "Note: This is a pre-written offline response."
        )

    def _should_use_compact(self) -> bool:
        """Indicate whether to send the compact system prompt."""
        return self._llm_calls > 0 and bool(self._llm_calls % self.SYSTEM_REFRESH_INTERVAL)

    def _build_system_prompt(self, compact: bool = False) -> str:
        """Build the system prompt for the LLM.

        When *compact* is True, return a short reminder instead of the full prompt
        to save context window tokens (first call and every N calls use full).

        Appends any user-configured *additional_system_message* and workspace
        context files (AGENTS.md, SOUL.md) when present.
        """
        from ..personas import build_persona_prompt, get_persona
        from .prompts import (
            COMPACT_NEUTRAL,
            COMPACT_PROMPT,
            NEUTRAL_SYSTEM_PROMPT,
            SIYARIX_SYSTEM_PROMPT,
        )

        persona_name = self._settings.get("persona") or "auto"

        if compact:
            if persona_name == "none":
                prompt = COMPACT_NEUTRAL
            else:
                p = get_persona(persona_name)  # noqa: F811
                label = p["label"] if p else "default"
                prompt = f"## Active Persona: {label}\n{COMPACT_PROMPT}"
        elif persona_name == "none":
            prompt = NEUTRAL_SYSTEM_PROMPT
        else:
            preamble = build_persona_prompt(persona_name)
            if preamble:
                prompt = preamble + "\n\n" + SIYARIX_SYSTEM_PROMPT
            else:
                prompt = SIYARIX_SYSTEM_PROMPT

        # ── User custom instructions ──────────────────────────────────────
        extra = self._settings.get("additional_system_message", "").strip()
        if extra:
            prompt += "\n\n## Custom Instructions\n" + extra

        # ── Workspace context files (AGENTS.md / SOUL.md) ─────────────────
        for filename in ("AGENTS.md", "SOUL.md"):
            ctx_file = Path.cwd() / filename
            if ctx_file.exists():
                try:
                    content = ctx_file.read_text(encoding="utf-8").strip()
                    if content:
                        label = filename.replace(".md", "")
                        prompt += f"\n\n## {label}\n{content}"
                except OSError:
                    logger.warning(
                        "Failed to read workspace context file %s", filename, exc_info=True
                    )

        # ── Environment info (OS + shell) ──────────────────────────
        is_win = sys.platform == "win32"
        os_name = "Windows" if is_win else ("macOS" if sys.platform == "darwin" else "Linux")
        shell_var = os.environ.get("SHELL", "")
        if is_win:
            ps_parent = os.environ.get("PSModulePath", "")
            shell = "PowerShell" if ps_parent else "cmd.exe"
        elif shell_var:
            shell = shell_var.split("/")[-1] or shell_var
        else:
            shell = "sh"
        prompt += f"\n\n## Execution Environment\n- OS: {os_name}\n- Shell: {shell}\n- Commands you construct run directly on this shell — use correct quoting, path separators, and syntax for the target platform."

        return prompt

    async def _execute_agent(
        self, instruction: str, target: str = "", require_llm: bool = False
    ) -> bool:
        """Agent loop: LLM-first planning → parallel execution → LLM synthesis.

        When *require_llm* is True (autonomous mode), the method returns False
        if no LLM is available — no heuristic fallback.
        """
        from ..core import AgentCore, AgentMode

        # ── Resolve provider ─────────────────────────────────────────────
        provider_name, api_key = self._resolve_provider()
        if not provider_name:
            if require_llm:
                console.print("[red]✗ No LLM provider configured for autonomous mode[/red]")
                return False
            if self._mode == "integrated":
                return False  # fall through to clean offline pipeline
            console.print("[yellow]⚠ No LLM provider configured — using local planner[/yellow]")
            provider_name = "none"

        instruction_with_target = instruction
        if target and target not in instruction:
            instruction_with_target = f"{instruction} on {target}"

        chat_mode = self._mode
        if chat_mode == "integrated":
            agent_mode = AgentMode.HYBRID
        elif chat_mode == "autonomous":
            agent_mode = AgentMode.AUTONOMOUS
        elif chat_mode in ("registry", "offline"):
            agent_mode = AgentMode.REGISTRY
        else:
            agent_mode = AgentMode.AUTONOMOUS
        agent = AgentCore(mode=agent_mode)
        with console.status("[bold green]Initializing...[/bold green]", spinner="dots"):
            await agent.initialize()

        all_tools = agent._registry.list_tools()
        tool_names = [t.name for t in all_tools]
        tool_dicts = [
            {
                "name": t.name,
                "description": t.description,
                "tags": t.tags,
                "category": (t.category.value if hasattr(t.category, "value") else str(t.category)),
            }
            for t in all_tools
        ]

        # ── Decision maker ───────────────────────────────────────────────
        total_start = time.time()
        llm_plan: Any = None
        llm_reasoning: str | None = None
        llm_connected = False
        llm_model = provider_name if provider_name else "none"
        total_input_tokens = 0
        total_output_tokens = 0
        llm_call_fn = None

        # Auto-start local provider if not running
        if provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
            if not self._check_local_provider_running(provider_name):
                console.print(f"[dim]{provider_name} not running — attempting to start...[/dim]")
                started = self._ensure_local_provider_running(provider_name)
                if not started:
                    console.print(f"[yellow]⚠ Could not start {provider_name}[/yellow]")
            else:
                # Check model availability and discover+enrich provider models
                from ..provider_utils import ensure_model_pulled, discover_provider_models
                from ..providers import ProviderManager, ModelInfo

                base_url = self._settings.get(f"{provider_name}_url") or os.getenv(
                    f"SIYARIX_{provider_name.upper()}_URL", ""
                )
                settings_key = f"{provider_name}_model"
                configured = self._settings.get(settings_key) or ""

                if configured:
                    pulled = ensure_model_pulled(provider_name, configured, base_url, console)
                    if not pulled:
                        console.print(
                            f"[yellow]⚠ Model '{configured}' not available for {provider_name}[/yellow]"
                        )

                # Enrich provider profile with discovered models
                try:
                    pm = ProviderManager.get_instance()
                    profile = pm.get_profile(provider_name)
                    if profile:
                        discovered = discover_provider_models(provider_name, base_url, enrich=True)
                        if discovered:
                            profile.models = [
                                ModelInfo(
                                    name=m["name"],
                                    supports_vision=m.get("supports_vision", False),
                                    supports_tools=m.get("supports_tools", True),
                                    context_window=m.get("context_window", 128000),
                                )
                                for m in discovered
                            ]
                except Exception:
                    logger.warning(
                        "Failed to discover provider models for %s", provider_name, exc_info=True
                    )

        # Build call function for the provider.
        # No separate health ping — check reachability via model listing,
        # then proceed directly to the real chat request.
        if api_key or provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
            raw_llm_call = self._make_llm_call(provider_name, api_key or "")

            # Wrap it to capture token counts from non-streaming responses
            async def llm_call_fn(system_prompt: str, user_prompt: str, **kwargs: Any) -> Any:
                result = await asyncio.wait_for(
                    raw_llm_call(system_prompt, user_prompt, **kwargs),
                    timeout=120.0,
                )
                if not kwargs.get("stream") and isinstance(result, dict):
                    nonlocal total_input_tokens
                    nonlocal total_output_tokens
                    inp = result.get("input_tokens", 0)
                    out = result.get("output_tokens", 0)
                    total_input_tokens += inp
                    total_output_tokens += out
                    if inp or out:
                        self._usage_tracker.record_call(
                            provider=provider_name or "unknown",
                            model=result.get("model", "unknown"),
                            input_tokens=inp,
                            output_tokens=out,
                        )
                return result

            if provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
                if self._check_local_provider_running(provider_name):
                    llm_connected = True
                elif require_llm:
                    console.print(f"[red]✗ {provider_name} not reachable for autonomous mode[/red]")
                    return False
                else:
                    console.print(
                        f"[yellow]⚠ {provider_name} not reachable — falling back[/yellow]"
                    )
            else:
                # Quick connectivity probe before committing to a 120s LLM call
                try:
                    from .openai_compat import PROVIDER_CONFIG
                    import httpx
                    base_url = PROVIDER_CONFIG.get(provider_name, ("", "", ""))[0]
                    if base_url:
                        async with httpx.AsyncClient(timeout=5) as _client:
                            await _client.get(base_url.rstrip("/v1"))
                        llm_connected = True
                    else:
                        llm_connected = True
                except Exception:
                    llm_connected = False

        if not llm_connected:
            if require_llm:
                console.print("[red]✗ No working LLM provider for autonomous mode[/red]")
                return False
            if self._mode == "integrated" and provider_name not in ("none",):
                self._mode = "offline"
                self._session.mode = "offline"
                self._settings.set("model_provider", "registry")
                console.print(
                    "[yellow]⚠ All providers unreachable — switched to offline mode[/yellow]"
                )
                return False  # fall through to clean offline pipeline
            else:
                _label = provider_name if provider_name and provider_name != "none" else "provider"
                console.print(
                    f"[yellow]⚠ {_label} not reachable — using local planner[/yellow]"
                )

        # ── Planning ─────────────────────────────────────────────────────
        all_outputs: list[str] = []
        if llm_connected:
            # ── CLS high-confidence skill pre-execution (integrated mode) ──
            # If a skill with ≥ 90% confidence matches, execute its cached steps first
            # then feed all outputs to the LLM as rich base context — saving one LLM call.
            _real_target = target or self._session.target or ""
            try:
                if self._mode == "integrated":
                    from ..learning_system import get_learning_system
                    _cls = get_learning_system()
                    _hi_skill = _cls.find_high_confidence_skill(
                        instruction_with_target, _real_target, threshold=0.80
                    )
                    if _hi_skill:
                        console.print(
                            f"[bold cyan]📚 Learning:[/bold cyan] Replaying skill "
                            f"'[cyan]{_hi_skill.intent_pattern[:55]}[/cyan]' "
                            f"([green]{_hi_skill.confidence:.0%}[/green] confidence)\u2026"
                        )
                        _raw_anon = _cls._anonymize_target(instruction_with_target, _real_target)
                        _prerun_steps = _cls.instantiate_skill(_hi_skill, _real_target, raw_anon_goal=_raw_anon)
                        if _prerun_steps:
                            from ..models import ExecutionPlan as _EP, PlanType, PlanStep
                            _prerun_plan = _EP(
                                goal=instruction_with_target,
                                steps=[
                                    PlanStep(
                                        id=f"cls_pre_{_i:03d}",
                                        description=_s.get("description", f"Step {_i+1}"),
                                        tool=_s.get("tool", ""),
                                        command=_s.get("command", ""),
                                        args=_s.get("args", {}),
                                    )
                                    for _i, _s in enumerate(_prerun_steps)
                                ],
                                plan_type=PlanType.SEQUENTIAL,
                                context={"source": "cls_prerun"},
                            )
                            _saved_cr = agent.executor_autonomous.command_review
                            agent.executor_autonomous.command_review = False
                            try:
                                _prerun_executed = await agent.executor_autonomous.execute_plan(
                                    _prerun_plan, live_display=True
                                )
                            finally:
                                agent.executor_autonomous.command_review = _saved_cr
                            console.print()
                            _prerun_outputs: list[str] = []
                            for _ps in _prerun_executed.steps:
                                _pr = _ps.result or {}
                                _pout = (_pr.get("output") or "").strip()[:2000]
                                _plabel = f"$ {_ps.command}" if _ps.command else _ps.tool
                                _prerun_outputs.append(f"• {_plabel}:\n{_pout}\n")
                            all_outputs.insert(
                                0,
                                f"[Learned skill pre-execution: '{_hi_skill.intent_pattern[:60]}', "
                                f"confidence {_hi_skill.confidence:.0%}]\n"
                                + "\n".join(_prerun_outputs)
                                + "\nThese results were produced automatically from a cached skill. "
                                "If additional investigation is needed, proceed. Otherwise summarise.",
                            )
            except Exception as _exc:
                logger.debug("CLS pre-run failed: %s", _exc)

            with console.status("[bold cyan]LLM analysing request...[/bold cyan]", spinner="dots"):
                try:
                    self._llm_calls += 1
                    compact = self._should_use_compact()
                    plan_sys_prompt = self._build_system_prompt(compact=compact)
                    if all_outputs:
                        _goal_with_context = (
                            f"Original request: {instruction_with_target}\n\n"
                            f"Pre-executed from cached skill, results so far:\n\n"
                            f"{''.join(all_outputs)}\n\n"
                            f"Analyse these results. If the original request is already satisfied, "
                            f"provide a concise final response (set needs_tools=false). "
                            f"If more investigation is needed, plan the remaining steps."
                        )
                    else:
                        _goal_with_context = instruction_with_target
                    plan_result = await agent.planner_autonomous.plan(
                        _goal_with_context,
                        system_prompt=plan_sys_prompt,
                        llm_call=llm_call_fn,
                        tool_schemas=tool_dicts,
                        available_tools=tool_names,
                        history=self._get_conversation_history(),
                        is_first_call=(self._llm_calls <= 1),
                    )
                    llm_plan = plan_result
                    llm_reasoning = (
                        plan_result.context.get("reasoning", "")
                        if isinstance(plan_result.context, dict)
                        else ""
                    )
                    self._provider_state.record_success(provider_name or "")
                except Exception as exc:
                    import sys
                    sys.stdout.write("\033[2K\r\n")
                    sys.stdout.flush()
                    console.print(
                        f"[yellow]⚠ {provider_name} failed ({exc}) — using local planner[/yellow]"
                    )
                    llm_connected = False
                    llm_call_fn = None  # type: ignore[assignment]
                    if self._mode == "integrated" and provider_name not in ("none",):
                        self._mode = "offline"
                        self._session.mode = "offline"
                        self._settings.set("model_provider", "registry")
                        console.print(
                            "[yellow]⚠ Switched to offline mode[/yellow]"
                        )
                else:
                    import sys
                    sys.stdout.write("\033[2K\r\n")
                    sys.stdout.flush()

        if not llm_plan:
            llm_plan = agent.planner_registry.plan(
                goal=instruction_with_target,
                available_tools=tool_names,
            )

        # ── No tools needed ──────────────────────────────────────────────
        if not llm_plan.steps:
            response = llm_plan.context.get("response", "") if llm_plan else ""
            if response:
                self._print_assistant(response)
            elif llm_connected and llm_call_fn is not None:
                compact = self._should_use_compact()
                sys_prompt = self._build_system_prompt(compact=compact)
                response = await self._stream_assistant_response(
                    sys_prompt,
                    instruction,
                    provider_name,
                    api_key,
                    history=self._get_conversation_history(),
                )
                self._llm_calls += 1
            else:
                greeting = self._generate_text_response(instruction)
                response = (
                    greeting
                    or llm_reasoning
                    or "I understood your request but no tools were needed."
                )
                self._print_assistant(response)
            self._session.add_message("assistant", response)
            duration = time.time() - total_start
            persona_name = self._settings.get("persona") or "auto"
            console.print(
                f"[dim]Time: {duration:.1f}s | Mode: {self._mode} | "
                f"Persona: {persona_name} | "
                f"LLM: {'connected' if llm_connected else 'offline'}[/dim]"
            )
            return True

        # ── Multi-wave execution loop ─────────────────────────────────────
        max_waves = self._settings.get("max_waves") or 12
        plan: Any = llm_plan
        last_executed_plan: Any = None

        for wave in range(max_waves):
            if not plan or not plan.steps:
                break

            # Skip hallucinated or placeholder tool names
            tool_labels = []
            for s in plan.steps:
                if s.command:
                    tool_labels.append(f"[bold]$ {s.command}[/bold]")
                elif s.tool and s.tool not in ("execute_plan", "_", ""):
                    tool_labels.append(f"[bold]{s.tool}[/bold]")
            if not wave:
                console.print(f"[cyan]→ Executing:[/cyan] {', '.join(tool_labels)}")
            else:
                console.print(f"[cyan]→ Wave {wave + 1}:[/cyan] {', '.join(tool_labels)}")

            # Execute via AutonomousExecutor with live display
            from rich.panel import Panel as RichPanel

            agent.executor_autonomous.command_review = self._settings.get("command_review", True)
            plan = await agent.executor_autonomous.execute_plan(plan, live_display=True)
            last_executed_plan = plan

            if plan.status.name == "CANCELLED":
                console.print("[yellow]⚠ Command cancelled by user[/yellow]")
                return True

            # Separate Live display output from summary panels
            console.print()

            # Show summary for this wave
            for s in plan.steps:
                result = s.result or {}
                out = (result.get("output") or "").strip()
                err = (result.get("error") or "").strip()
                success = result.get("status") == "success"
                label = f"$ {s.command}" if s.command else s.tool
                display_lines = (
                    out.split("\n") if out else (err.split("\n") if err else ["(no output)"])
                )
                icon = "✓" if success else "✗"
                border = "green" if success else "red"
                if not display_lines:
                    display_lines = ["(no output)"] if success else ["Command failed"]
                truncated = []
                for line in display_lines[-200:]:
                    if len(line) > 500:
                        truncated.append(line[:500] + "...")
                    else:
                        truncated.append(line)
                console.print(
                    RichPanel(
                        "\n".join(truncated),
                        title=f"{icon} {label}",
                        border_style=border,
                    )
                )

            # Store outputs for next wave context
            for s in plan.steps:
                result = s.result or {}
                output = (result.get("output") or "").strip()[:2000]
                cmd_label = f"$ {s.command}" if s.command else s.tool
                all_outputs.append(f"• {cmd_label} ({s.description}):\n{output}\n")

            # Ask LLM whether processing is complete or another iteration is needed
            if llm_connected and llm_call_fn is not None:
                wave_goal = (
                    f"Original request: {instruction_with_target}\n\n"
                    f"Completed execution wave {wave + 1}. Results so far:\n\n"
                    f"{''.join(all_outputs)}\n\n"
                    "Analyse these results. Decide: is the original request now fully satisfied?\n"
                    "- If YES → set needs_tools=false and provide a concise final response.\n"
                    "- If NO and only 1-2 more commands would complete it → set needs_tools=true.\n"
                    "- If NO and many more commands are needed → set needs_tools=false and "
                    "summarise what was found so far instead of continuing indefinitely.\n"
                    "Prefer stopping early with a good summary over endless waves of probing."
                )
                with console.status(
                    "[bold cyan]LLM analysing wave results...[/bold cyan]",
                    spinner="dots",
                ):
                    try:
                        self._llm_calls += 1
                        compact = self._should_use_compact()
                        wave_sys_prompt = self._build_system_prompt(compact=compact)
                        plan = await agent.planner_autonomous.plan(
                            wave_goal,
                            system_prompt=wave_sys_prompt,
                            llm_call=llm_call_fn,
                            tool_schemas=tool_dicts,
                            available_tools=tool_names,
                            history=self._get_conversation_history(),
                            is_first_call=False,
                        )
                        llm_model = provider_name or "none"
                    except asyncio.TimeoutError:
                        plan = None
                import sys
                sys.stdout.write("\033[2K\r\n")
                sys.stdout.flush()
                if plan is None:
                    console.print("[yellow]⚠ LLM analysis timed out — moving on[/yellow]")
                elif plan.steps:
                    console.print(
                        f"[cyan]→ LLM decided more work needed — wave {wave + 2}[/cyan]"
                    )
                else:
                    # Done — show final response
                    ctx = plan.context or {}
                    summary = (ctx.get("response") or ctx.get("reasoning", "")) or "Done."
                    self._session.add_message("assistant", summary)
                    self._print_assistant(summary)
            else:
                plan = None

        # ── Bottom stats line ────────────────────────────────────────────
        total_duration = time.time() - total_start

        # ── CLS: observe and learn from the completed LLM action sequence ──
        if llm_connected:
            try:
                from ..learning_system import get_learning_system
                _cls_real_target = target or self._session.target or ""
                _cls_result = last_executed_plan or plan  # use the plan that was actually executed
                _learned_skill = get_learning_system().observe_llm_action(
                    goal=instruction_with_target,
                    plan=llm_plan,
                    result=_cls_result,
                    target=_cls_real_target,
                    wave_count=wave + 1,
                    duration_ms=total_duration * 1000,
                )
                if _learned_skill:
                    logger.debug(
                        "CLS: LLM action learned — skill '%s' confidence=%.2f",
                        _learned_skill.intent_pattern[:50],
                        _learned_skill.confidence,
                    )
                    _has_param_accum = (
                        getattr(_learned_skill, 'param_values', None) and
                        any(len(v) >= 3 for v in _learned_skill.param_values.values())
                    )
                    if _learned_skill.universal_schema == "{}" and "{param_" in _learned_skill.intent_pattern:
                        if _learned_skill.confidence >= 0.80 or _has_param_accum:
                            asyncio.create_task(self._compile_universal_skill(_learned_skill, llm_call_fn))
            except Exception as _exc:
                logger.debug("CLS LLM observation failed: %s", _exc)

        persona_name = self._settings.get("persona") or "none"
        stats_parts = [
            f"Time: {total_duration:.1f}s",
            f"Mode: {self._mode}",
            f"Persona: {persona_name}",
        ]
        if llm_connected:
            stats_parts.append(f"Model: {llm_model}")
            stats_parts.append(f"Tokens: {total_input_tokens}↑ {total_output_tokens}↓")
        console.print("[dim]" + " | ".join(stats_parts) + "[/dim]")

        return True

    async def _compile_universal_skill(self, skill: Any, llm_call_fn: Any) -> None:
        """Background task to compile a high-confidence parameterized skill into a Universal Skill using the LLM."""
        from rich.console import Console
        _console = Console()
        _console.print(f"[bold magenta]\u26a1 Background Task:[/bold magenta] Compiling universal skill for '{skill.intent_pattern[:40]}...'")
        try:
            steps_text = []
            for i, s in enumerate(skill.steps):
                steps_text.append(f"Step {i+1}: Tool={s.tool}, Command={s.command_template}, Desc={s.description}")
            steps_str = "\n".join(steps_text)

            param_values_str = json.dumps(skill.param_values, indent=2) if getattr(skill, 'param_values', None) else "{}"

            prompt = (
                "You are an AI compiler for a Continuous Learning System.\n"
                "The system has identified a reusable workflow pattern with variable parameters ({param_0}, etc).\n"
                "Your task is to analyze the pattern and provide a universal schema explaining these parameters.\n\n"
                f"Intent Pattern: {skill.intent_pattern}\n"
                f"Steps:\n{steps_str}\n\n"
                f"Observed parameter values across executions:\n{param_values_str}\n\n"
                "Use the observed values to infer each parameter's name, type, and possible range/format.\n"
                "For example, if values are numbers, set type='integer'; if URLs/IPs, set type='string'.\n\n"
                "Output ONLY a valid JSON object with the following structure:\n"
                "{\n"
                '  "parameters": {\n'
                '    "{param_0}": { "name": "human_readable_name", "description": "what this parameter does", "type": "string|integer" }\n'
                "  },\n"
                '  "refined_intent": "optional slightly cleaned up intent pattern",\n'
                '  "refined_steps": [ { "tool": "...", "command_template": "...", "description": "..." } ]\n'
                "}\n"
                "Ensure that {target} and {param_N} placeholders remain in the refined templates."
            )

            # Use the provider's direct completion
            response = await llm_call_fn(
                system="You are an expert systems engineer and schema designer.",
                user=prompt,
                stream=False
            )

            if isinstance(response, dict) and "content" in response:
                content = response["content"]
            elif isinstance(response, str):
                content = response
            else:
                content = str(response)

            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                schema_json = json.loads(match.group(0))
                # Store original steps as backup
                from dataclasses import asdict
                skill.backup_json = json.dumps([asdict(s) for s in skill.steps])
                skill.universal_schema = json.dumps(schema_json.get("parameters", {}))

                # Apply refinements if provided
                if schema_json.get("refined_intent"):
                    skill.intent_pattern = schema_json["refined_intent"]

                if schema_json.get("refined_steps"):
                    from ..learning_system import LearnedStep
                    new_steps = []
                    for s in schema_json["refined_steps"]:
                        new_steps.append(LearnedStep(
                            tool=s.get("tool", ""),
                            command_template=s.get("command_template", ""),
                            description=s.get("description", "")
                        ))
                    skill.steps = new_steps

                from ..learning_system import get_learning_system
                get_learning_system()._save_skill(skill)
                _console.print("[bold green]✓ Universal skill compiled successfully![/bold green]")

        except Exception as e:
            _console.print(f"[dim yellow]⚠ Universal skill compilation failed: {e}[/dim yellow]")

    def _make_llm_call(self, provider_name: str, api_key: str) -> Any:
        """Return an async callable (system, user, *, stream=False, history=None) -> dict | AsyncGenerator.

        Uses the unified OpenAI-compatible adapter for all OpenAI API providers
        (openai, openrouter, gemini, deepseek, xai, perplexity, groq, together,
        azure, cerebras, fireworks, zai, minimax, moonshot, nvidia, opencode-zen,
        huggingface, llamacpp, vllm, localai) and native SDK for Anthropic.

        When stream=True, call with await fn(system, user, stream=True, history=history)
        which returns an async generator yielding content tokens.
        history is a list of {"role": ..., "content": ...} dicts from prior conversation.
        """
        from .openai_compat import make_openai_adapter, PROVIDER_CONFIG

        # -- Anthropic (native SDK) ---------------------------------------------
        if provider_name == "anthropic":
            try:
                from anthropic import AsyncAnthropic
            except ImportError:
                raise LLMProviderError(
                    "anthropic package not installed. Run: pip install anthropic"
                )

            anthropic_client = AsyncAnthropic(api_key=api_key)
            from ..providers import ProviderManager

            model = ProviderManager.get_instance().resolve_model_id(
                "anthropic",
                self._settings.get("anthropic_model") or "claude-sonnet-4-6",
            )

            async def call_anthropic(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        hist_msgs = [m for m in (history or []) if m.get("role") != "system"]
                        msgs = hist_msgs + [{"role": "user", "content": user_prompt}]
                        async with anthropic_client.messages.stream(
                            model=model,
                            system=system_prompt,
                            messages=msgs,  # type: ignore[arg-type]
                            max_tokens=2000,
                            temperature=0.3,
                        ) as stream_ctx:
                            async for text in stream_ctx.text_stream:
                                yield text

                    return _gen()  # type: ignore[no-any-return]
                hist_msgs = [m for m in (history or []) if m.get("role") != "system"]
                msgs = hist_msgs + [{"role": "user", "content": user_prompt}]
                msg = await anthropic_client.messages.create(
                    model=model,
                    system=system_prompt,
                    messages=msgs,  # type: ignore[arg-type]
                    max_tokens=2000,
                    temperature=0.3,
                )
                content_block = msg.content[0] if msg.content else None
                return {
                    "content": getattr(content_block, "text", ""),
                    "model": msg.model or model,
                    "input_tokens": msg.usage.input_tokens if msg.usage else 0,
                    "output_tokens": msg.usage.output_tokens if msg.usage else 0,
                }

            return call_anthropic

        # -- All other providers use the unified OpenAI-compatible adapter --------
        if provider_name not in PROVIDER_CONFIG:
            raise LLMProviderError(f"Unsupported provider: {provider_name}")

        from ..providers import ProviderManager

        return make_openai_adapter(
            provider=provider_name,
            api_key=api_key,
            settings=self._settings,
            provider_manager=ProviderManager.get_instance(),
        )

    def _llm_available(self) -> bool:
        """Check if an LLM provider is configured and available."""
        provider = (self._settings.get("model_provider") or "gemini").lower().strip()

        from ..providers import ProviderManager

        pm = ProviderManager.get_instance()
        profile = pm.get_profile(provider)

        if provider == "cloud":
            return bool(os.getenv("SIYARIX_SERVER_URL"))
        if provider == "custom":
            return bool(os.getenv("CUSTOM_API_KEY"))
        if provider == "opencode-zen":
            return bool(os.getenv("OPENCODE_API_KEY"))
        if provider in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
            return self._check_local_provider_running(provider)
        if profile and profile.api_key_env:
            return bool(self._resolve_api_key(provider, profile.api_key_env))
        return False

    @staticmethod
    def _check_local_provider_running(provider_name: str) -> bool:
        """Check if a local provider is running via its health endpoint.

        Uses generic provider_utils for all providers.
        """
        from ..provider_utils import check_provider_health

        return check_provider_health(provider_name)

    @staticmethod
    def _ensure_local_provider_running(provider_name: str) -> bool:
        """Try to auto-start a local provider if it's not already running.

        Uses provider_utils defaults for binary names and URLs.
        """
        from ..provider_utils import check_provider_health, PROVIDER_DEFAULTS

        cfg = PROVIDER_DEFAULTS.get(provider_name)
        if not cfg:
            return False

        base_url = cfg["url"]
        health_path = cfg["health_endpoint"]

        start_configs = {
            "ollama": ("ollama", ["serve"]),
            "lmstudio": ("lmstudio", ["--server"]),
            "llamacpp": (
                "llama-server",
                [
                    "--port",
                    "18080",
                    "--host",
                    "127.0.0.1",
                ],
            ),
        }
        info = start_configs.get(provider_name)
        if not info:
            return False
        binary, args = info

        # For llama.cpp, try to discover a valid model GGUF before starting
        if provider_name == "llamacpp":
            models_dir = Path.home() / ".siyarix" / "models"
            if models_dir.is_dir():
                ggufs = sorted(
                    models_dir.glob("*.gguf"), key=lambda p: p.stat().st_mtime, reverse=True
                )
                # Validate GGUF magic bytes (first 4 bytes must be "GGUF")
                valid_model = None
                for g in ggufs:
                    try:
                        header = g.read_bytes()[:4]
                        if header == b"GGUF":
                            valid_model = str(g)
                            break
                        logger.warning("Skipping invalid GGUF (bad magic): %s", g.name)
                        g.rename(g.with_suffix(".gguf.invalid"))
                    except OSError:
                        continue
                if valid_model:
                    args = [*args, "--model", valid_model]
                    logger.info("llama-server model: %s", valid_model)
                else:
                    logger.warning("No valid GGUF model found in %s", models_dir)

        binary_path = shutil.which(binary)
        if not binary_path:
            # Check ~/.siyarix/bin as fallback (onboarding installs there)
            siyarix_bin = Path.home() / ".siyarix" / "bin"
            siyarix_binary = siyarix_bin / binary
            if os.name == "nt":
                siyarix_binary = siyarix_bin / f"{binary}.exe"
            if siyarix_binary.exists():
                binary_path = str(siyarix_binary)
                # One-time promotion of shared libs from stale subdirectories
                for d in siyarix_bin.iterdir():
                    if d.is_dir() and d.name.startswith("llama-"):
                        for lib in d.glob("*.so*"):
                            dest = siyarix_bin / lib.name
                            if not dest.exists():
                                shutil.copy2(lib, dest)
        if check_provider_health(provider_name):
            return True
        try:
            import subprocess

            if os.name == "nt":
                subprocess.Popen(
                    [binary, *args],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    [binary, *args],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            import time

            for _ in range(15):
                time.sleep(2)
                try:
                    from ..provider_utils import safe_http_get_raw

                    r = safe_http_get_raw(f"{base_url}{health_path}", timeout=3)
                    if r is not None:
                        logger.info("%s started successfully", binary)
                        return True
                except Exception:
                    logger.warning(
                        "%s health check failed (attempt %d/15)", binary, _ + 1, exc_info=True
                    )
            logger.warning("%s started but not responding within 30s", binary)
            return False
        except Exception as exc:
            logger.warning("Failed to auto-start %s: %s", binary, exc)
            return False

    @staticmethod
    def _resolve_api_key(provider: str, env_var: str) -> str | None:
        """Resolve an API key from credential store → environment."""
        from ..providers import resolve_api_key

        return resolve_api_key(provider, env_var)

    def _resolve_provider(self) -> tuple[str | None, str | None]:
        """Return ``(provider_name, api_key)`` for the active provider.

        When ``model_provider`` is set to a specific name, use that.
        When ``"auto"``, returns the first available cloud provider (with a real
        API key).  Only falls back to local providers (ollama, lmstudio, etc.)
        if no cloud provider has a key configured.
        """
        configured = self._settings.get("model_provider") or "openrouter"
        if configured == "registry":
            return (None, None)

        if configured != "auto":
            from ..providers import ProviderManager
            pm = ProviderManager.get_instance()
            profile = pm.get_profile(configured)
            env_var = profile.api_key_env if profile else ""
            key = self._resolve_api_key(configured, env_var)
            if not key and profile and not profile.api_key_env:
                key = "local"
            if configured == "ollama":
                try:
                    from ..providers.ollama_utils import ensure_ollama_running
                    ensure_ollama_running()
                except Exception:
                    pass
            return (configured, key or None)

        all_candidates = self._resolve_candidates()
        for _candidate_name, _candidate_key in all_candidates:
            if not _candidate_key or _candidate_key == "local":
                continue
            return (_candidate_name, _candidate_key)
        if all_candidates:
            return all_candidates[0]
        return (None, None)

    def _resolve_candidates(self) -> list[tuple[str, str]]:
        """Return all candidate ``(provider_name, api_key)`` tuples for auto mode,
        sorted by cost tier (cloud first, local last).  Local providers are only
        included when no cloud provider has a valid API key.
        """
        from ..providers import ProviderManager
        pm = ProviderManager.get_instance()

        cloud: list[tuple[int, str, str]] = []
        local: list[tuple[int, str, str]] = []

        for prov_name in pm.list_providers():
            if prov_name == "registry":
                continue
            if self._provider_state.is_disabled(prov_name):
                continue
            profile = pm.get_profile(prov_name)
            if not profile:
                continue

            if not profile.api_key_env:
                local.append((profile.cost_tier.sort_key, prov_name, "local"))
                continue

            key = self._resolve_api_key(prov_name, profile.api_key_env)
            if key:
                cloud.append((profile.cost_tier.sort_key, prov_name, key))

        def _sort_key(c: tuple) -> tuple:
            prof = pm.get_profile(c[1])
            return (c[0], -(prof.priority if prof else 0))

        local.sort(key=_sort_key)
        cloud.sort(key=_sort_key)

        # Cloud providers first (valid API key), local providers last
        result = [(p, k) for _, p, k in cloud] + [(p, k) for _, p, k in local]
        return result or []
