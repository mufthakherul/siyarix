from __future__ import annotations
from .platform_utils import build_platform_context
import asyncio
import logging
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.panel import Panel

from .session import ChatMessage, ChatSession
from .console import console

if TYPE_CHECKING:
    from ..config import SettingsStore
    from ..providers.state import ProviderStateManager

logger = logging.getLogger(__name__)

class LLMEngineMixin:
    if TYPE_CHECKING:
        _session: ChatSession
        _settings: SettingsStore
        _mode: str
        _provider_state: ProviderStateManager
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
        # Add user message to history
        self._session.add_message("user", user_input)

        # Inject target context if set and not already in input
        instruction = user_input
        if self._session.target and self._session.target not in instruction:
            instruction = f"{instruction} on {self._session.target}"

        await self._execute_instruction(instruction, show_plan=True)


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

        if not plan.steps:
            # Registry/offline mode: local response only (no LLM)
            if self._mode in ("registry", "offline"):
                response = self._generate_text_response(instruction) or ""
                if response:
                    self._print_assistant(response)
            else:
                prov_name, api_key = self._resolve_provider()
                if prov_name and api_key:
                    compact = self._should_use_compact()
                    sys_prompt = self._build_system_prompt(compact=compact)
                    response = await self._stream_assistant_response(
                        sys_prompt,
                        instruction,
                        prov_name,
                        api_key,
                        history=self._get_conversation_history(),
                    )
                    self._llm_calls += 1
                else:
                    response = self._generate_text_response(instruction) or ""
            if response:
                self._session.add_message("assistant", response or "")
            return

        # Show plan if requested
        if show_plan and len(plan.steps) > 1:
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
                    voting_strategy=VotingStrategy.WEIGHTED,
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

        # Adversarial plan review
        try:
            from .stubs import AdversarialTester, AdversarialSeverity

            tester = AdversarialTester()
            plan_lines = [
                f"{s.tool or ''} {' '.join(s.args)} {s.target or ''}".strip() or s.command or ""
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

        # Execute with live output
        t0 = time.monotonic()
        result = await engine.execute(instruction, interactive=False)
        elapsed = time.monotonic() - t0

        # Save to offline store
        try:
            from ..offline_store import OfflineStore

            store = OfflineStore()
            target = self._session.target or ""
            store.save_scan(target or instruction, result.all_findings, mode=self._mode)
            if plan and plan.id:
                step_dicts = [
                    {
                        "tool": s.tool,
                        "status": s.status.value,
                        "description": s.description,
                    }
                    for s in plan.steps
                ]
                store.save_plan(plan.id, plan.goal, step_dicts, mode=self._mode)
        except Exception as exc:
            logger.debug("Failed to persist to offline store: %s", exc)

        # Print results
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
            "hello",
            "hi",
            "hey",
            "sup",
            "what's up",
            "help",
            "good morning",
            "good evening",
            "good afternoon",
        }
        if lowered in greetings or lowered.startswith(("hello ", "hi ", "hey ")):
            import getpass
            from datetime import datetime, timezone

            username = getpass.getuser()
            hour = datetime.now(timezone.utc).hour
            if hour < 12:
                tod = "morning"
            elif hour < 17:
                tod = "afternoon"
            elif hour < 21:
                tod = "evening"
            else:
                tod = "night"
            return (
                f"Good **{tod}**, **{username}**.\n\n"
                "I'm **Siyarix** — your cybersecurity intelligence system. "
                "I'm here to help with any security task, whether offensive, defensive, "
                "investigative, or advisory.\n\n"
                "**Areas of expertise:**\n"
                "- Reconnaissance and attack surface mapping — ports, services, subdomains, technologies\n"
                "- Vulnerability detection — web, network, cloud, Active Directory, wireless\n"
                "- Defensive analysis — detection engineering, log analysis, hardening, IR\n"
                "- Cloud security assessment — IAM, storage, containers, serverless\n"
                "- Threat intelligence — TTP mapping, IoC analysis, adversary profiling\n"
                "- Forensics and incident response — timeline reconstruction, artefact analysis\n"
                "- Governance and compliance — framework assessment, policy review, risk analysis\n\n"
                "I am an ongoing under-development project, and my knowledge base is improving "
                "day by day. I am built and sustained by community of security "
                "researchers, developers, and practitioners from around the world. Every "
                "contribution, bug report, feature suggestion, and pull request helps me "
                "serve you better. I am deeply grateful to everyone who has helped shape "
                "my project.\n\n"
                "If you'd like to join them, contributions and issue reports are always welcome:\n"
                "- Repo: https://github.com/mufthakherul/siyarix\n"
                "- Contributing: https://github.com/mufthakherul/siyarix/blob/main/CONTRIBUTING.md\n\n"
                "For maximum capability, connect an **LLM provider** — OpenRouter, OpenAI, Gemini, "
                "Anthropic, Groq, Together, or Ollama (local). "
                "Without one, I use built-in heuristic planning.\n\n"
                "Just tell me what you'd like to accomplish — I'll handle the rest.\n"
                "Type **`/help`** for all commands."
            )
        return None


    def _should_use_compact(self) -> bool:
        """Return True if we should send the compact (reminder) system prompt."""
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
                    pass

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

        # ── Resolve provider with auto fallback ──────────────────────────
        provider_name, api_key = self._resolve_provider()
        if not provider_name:
            if require_llm:
                console.print("[red]✗ No LLM provider configured for autonomous mode[/red]")
                return False
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
                        console.print(f"[yellow]⚠ Model '{configured}' not available for {provider_name}[/yellow]")

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
                    pass

        # Build call function for the provider.
        # OpenClaw pattern: no separate ping — check reachability via
        # model listing, then proceed directly to the real chat request.
        if api_key or provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
            llm_call_fn = self._make_llm_call(provider_name, api_key or "")
            if provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
                if self._check_local_provider_running(provider_name):
                    llm_connected = True
                elif require_llm:
                    console.print(f"[red]✗ {provider_name} not reachable for autonomous mode[/red]")
                    return False
                else:
                    console.print(f"[yellow]⚠ {provider_name} not reachable — falling back[/yellow]")
            else:
                llm_connected = True

        if not llm_connected:
            if require_llm:
                console.print("[red]✗ No working LLM provider for autonomous mode[/red]")
                return False

        # ── Planning ─────────────────────────────────────────────────────
        if llm_connected:
            with console.status("[bold cyan]LLM analysing request...[/bold cyan]", spinner="dots"):
                try:
                    self._llm_calls += 1
                    compact = self._should_use_compact()
                    plan_sys_prompt = self._build_system_prompt(compact=compact)
                    plan_result = await agent.planner_autonomous.plan(
                        instruction_with_target,
                        system_prompt=plan_sys_prompt,
                        llm_call=llm_call_fn,
                        tool_schemas=tool_dicts,
                        available_tools=tool_names,
                        history=self._get_conversation_history(),
                        is_first_call=(self._llm_calls <= 1),
                    )
                    llm_plan = plan_result
                    llm_reasoning = plan_result.context.get("reasoning", "") if isinstance(plan_result.context, dict) else ""
                    self._provider_state.record_success(provider_name or "")
                except (asyncio.TimeoutError, RuntimeError, ValueError, AttributeError) as exc:
                    console.print(
                        f"[yellow]⚠ LLM planning failed ({exc}) — using local planner[/yellow]"
                    )

        if not llm_plan:
            if require_llm:
                # LLM connected but planning format failed (model didn't return
                # valid JSON).  Stream the response directly instead of aborting.
                llm_plan = agent.planner_autonomous.create_plan(goal=instruction_with_target, context={})
            else:
                with console.status("[bold green]Planning...[/bold green]", spinner="dots"):
                    llm_plan = agent.planner_registry.plan(instruction_with_target, tool_names)

        # ── No tools needed ──────────────────────────────────────────────
        if not llm_plan.steps:
            response = llm_plan.context.get("response", "") if llm_plan else ""
            if response:
                self._print_assistant(response)
            elif llm_connected and llm_call_fn:
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
        all_outputs: list[str] = []
        plan: Any = llm_plan

        for wave in range(max_waves):
            if not plan or not plan.steps:
                break

            # Announce — skip hallucinated / placeholder tool names
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

            # Execute all steps in parallel with a single live display
            from ..subprocess_utils import get_platform_shell_cmd, safe_run_async_stream

            @dataclass
            class _CmdState:
                label: str
                lines: list[str] = field(default_factory=list)
                exit_code: int | None = None
                done: bool = False

            cmd_states: list[_CmdState] = []
            for s in plan.steps:
                if s.command:
                    cmd_states.append(_CmdState(label=f"$ {s.command}"))
                elif s.tool and s.tool not in ("execute_plan", "_", ""):
                    cmd_states.append(_CmdState(label=s.tool))

            async def _exec_one(step: Any, state: _CmdState) -> tuple[Any, dict]:
                if not step.command:
                    result = await agent._registry.execute(step.tool, **step.args)
                    if not isinstance(result, dict):
                        result = {"status": "error" if isinstance(result, Exception) else "success", "output": str(result)}
                    state.exit_code = 0 if result.get("status") == "success" else 1
                    out = (result.get("output") or "").strip()
                    err = (result.get("error") or "").strip()
                    if out:
                        state.lines.extend(out.split("\n"))
                    if err:
                        state.lines.extend(err.split("\n"))
                    state.done = True
                    return step, result

                cmd_timeout = self._settings.get("agent_timeout") or 1740
                exec_result = await safe_run_async_stream(
                    get_platform_shell_cmd(step.command),
                    timeout=cmd_timeout,
                    validate=False,
                    on_stdout=lambda line: state.lines.append(line),
                    on_stderr=lambda line: state.lines.append(line),
                )
                state.exit_code = exec_result.exit_code
                state.done = True
                return step, {
                    "status": "success" if not exec_result.exit_code else "error",
                    "output": exec_result.stdout,
                    "error": exec_result.stderr,
                    "exit_code": exec_result.exit_code,
                }

            # Pre-review all shell commands before starting Live display
            from ..shell_review import review_and_confirm

            command_review = self._settings.get("command_review", True)
            for s in plan.steps:
                if not s.command:
                    continue
                if not command_review:
                    break
                reviewed = review_and_confirm(s.command, "raw", "Raw shell command from LLM plan")
                if reviewed is None:
                    console.print("[yellow]⚠ Command cancelled by user[/yellow]")
                    return True
                s.command = reviewed

            exec_tasks = [_exec_one(s, st) for s, st in zip(plan.steps, cmd_states)]
            exec_task = asyncio.ensure_future(asyncio.gather(*exec_tasks))

            from rich.live import Live
            from rich.panel import Panel as RichPanel

            # Suppress CPR warning on terminals that don't support it
            _old_term = os.environ.get("TERM")
            os.environ["TERM"] = "xterm-256color"

            if cmd_states:
                focus_idx = 0
                done_set = False
                wave_start = time.time()
                with Live(console=console, refresh_per_second=10, screen=False) as live:
                    while not done_set:
                        await asyncio.sleep(0.1)
                        if cmd_states[focus_idx].done:
                            unfinished = [i for i, st in enumerate(cmd_states) if not st.done]
                            if unfinished:
                                focus_idx = unfinished[0]
                            else:
                                done_set = True

                        st = cmd_states[focus_idx]
                        elapsed = time.time() - wave_start
                        icon = "·" if st.exit_code is None else ("✓" if not st.exit_code else "✗")
                        border = (
                            "cyan"
                            if st.exit_code is None
                            else ("green" if not st.exit_code else "red")
                        )

                        # Show last 200 lines or "Running..." with elapsed time
                        if st.lines:
                            panel_content = "\n".join(st.lines[-200:])
                        elif st.exit_code is None:
                            panel_content = f"Running... ({elapsed:.1f}s)"
                        else:
                            panel_content = "(no output)"

                        live.update(
                            RichPanel(
                                panel_content,
                                title=f"{icon} {st.label}",
                                subtitle=f"Elapsed: {elapsed:.1f}s" if st.exit_code is None else None,
                                border_style=border,
                            )
                        )

            raw_results = await exec_task

            # Restore original TERM
            if _old_term is not None:
                os.environ["TERM"] = _old_term
            else:
                os.environ.pop("TERM", None)

            # Separate Live display output from summary panels
            console.print()

            # Show summary for this wave
            for (step, result), st in zip(raw_results, cmd_states):
                out = (result.get("output") or "").strip()
                err = (result.get("error") or "").strip()
                display_lines = out.split("\n") if out else (err.split("\n") if err else st.lines)
                icon = "✓" if not st.exit_code else "✗"
                border = "green" if not st.exit_code else "red"
                if not display_lines:
                    display_lines = ["(no output)"] if not st.exit_code else [f"Command failed (exit {st.exit_code})"]
                truncated = []
                for line in display_lines[-200:]:
                    if len(line) > 500:
                        truncated.append(line[:500] + "...")
                    else:
                        truncated.append(line)
                console.print(
                    RichPanel(
                        "\n".join(truncated),
                        title=f"{icon} {st.label}",
                        border_style=border,
                    )
                )

            # Store outputs for next wave context
            for step, result in raw_results:
                output = (result.get("output") or "").strip()[:2000]
                cmd_label = f"$ {step.command}" if step.command else step.tool
                all_outputs.append(f"• {cmd_label} ({step.description}):\n{output}\n")

            # Ask LLM: are we done, or need another wave?
            if llm_connected and llm_call_fn:
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
                        if plan.steps:
                            console.print(
                                f"[cyan]→ LLM decided more work needed — wave {wave + 2}[/cyan]"
                            )
                        else:
                            # Done — show final response
                            ctx = plan.context or {}
                            summary = (ctx.get("response") or ctx.get("reasoning", "")) or "Done."
                            self._session.add_message("assistant", summary)
                            self._print_assistant(summary)
                    except asyncio.TimeoutError:
                        console.print("[yellow]⚠ LLM analysis timed out — moving on[/yellow]")
                        plan = None
            else:
                plan = None

        # ── Bottom stats line ────────────────────────────────────────────
        total_duration = time.time() - total_start
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


    def _make_llm_call(self, provider_name: str, api_key: str) -> Any:
        """Return an async callable (system, user, *, stream=False, history=None) -> dict | AsyncGenerator.

        Uses the unified OpenAI-compatible adapter for all OpenAI API providers
        (openai, openrouter, gemini, deepseek, xai, perplexity, groq, together,
        azure, cerebras, fireworks, zai, minimax, moonshot, nvidia, opencode-go,
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
                raise ValueError("anthropic package not installed. Run: pip install anthropic")

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

                    return _gen()
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
            raise ValueError(f"Unsupported provider: {provider_name}")

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
        if provider == "opencode":
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
            "llamacpp": ("llama-server", [
                "--port", "18080",
                "--host", "127.0.0.1",
            ]),
        }
        info = start_configs.get(provider_name)
        if not info:
            return False
        binary, args = info

        # For llama.cpp, try to discover a valid model GGUF before starting
        if provider_name == "llamacpp":
            models_dir = Path.home() / ".siyarix" / "models"
            if models_dir.is_dir():
                ggufs = sorted(models_dir.glob("*.gguf"), key=lambda p: p.stat().st_mtime, reverse=True)
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
                    pass
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
        When ``"auto"``, scan known providers sorted by cost (cheapest first),
        skipping any that are disabled or in cooldown (persisted across restarts).

        Local providers (ollama, lmstudio, llamacpp, vllm, localai) that don't
        need a real API key get the placeholder ``"local"`` so callers can
        distinguish ``"no key needed"`` from ``"no provider found"``.

        The special ``"registry"`` provider represents offline mode and
        returns ``(None, None)`` to signal no LLM is available.
        """
        from ..providers import ProviderManager

        pm = ProviderManager.get_instance()

        configured = self._settings.get("model_provider") or "openrouter"
        if configured == "registry":
            return (None, None)

        if configured != "auto":
            profile = pm.get_profile(configured)
            env_var = profile.api_key_env if profile else ""
            key = self._resolve_api_key(configured, env_var)
            if not key and profile and not profile.api_key_env:
                key = "local"
            return (configured, key or None)

        candidates: list[tuple[int, str, str]] = []

        for prov_name in pm.list_providers():
            if prov_name == "registry":
                continue

            if self._provider_state.is_disabled(prov_name):
                continue

            profile = pm.get_profile(prov_name)
            if not profile:
                continue

            if not profile.api_key_env:
                candidates.append((profile.cost_tier.sort_key, prov_name, "local"))
                continue

            key = self._resolve_api_key(prov_name, profile.api_key_env)
            if key:
                candidates.append((profile.cost_tier.sort_key, prov_name, key))

        def _sort_key(c: tuple) -> tuple:
            prof = pm.get_profile(c[1])
            return (c[0], -(prof.priority if prof else 0))

        candidates.sort(key=_sort_key)
        for _, name, key in candidates:
            return (name, key or None)

        return (None, None)


