from __future__ import annotations
import asyncio
import json
import logging
import os
import sys
import time
import warnings
from collections import deque
from pathlib import Path
from typing import Any
from ..config import get_config_dir

from .session import ChatMessage as ChatMessage, ChatSession as ChatSession
from .ui import (
    SmartAutocomplete as SmartAutocomplete,
    CommandPalette as CommandPalette,
    SplitPane as SplitPane,
    ConfigPanel as ConfigPanel,
)
from ..config import SettingsStore


RICH_AVAILABLE = False
try:
    from rich.columns import Columns
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    Columns = None
    Console = None
    Markdown = None
    Panel = None
    Prompt = None
    Rule = None
    Syntax = None
    Table = None
    Text = None

logger = logging.getLogger(__name__)

PTK_AVAILABLE = False
try:
    from prompt_toolkit import prompt as ptk_prompt
    from prompt_toolkit.key_binding import KeyBindings
    PTK_AVAILABLE = True
except Exception:
    ptk_prompt = None
    KeyBindings = None

from .platform_utils import detect_shell, get_shell_platform, build_platform_context
from .handlers import CommandHandlersMixin
from .engine import LLMEngineMixin

from .console import console

class SiyarixChat(CommandHandlersMixin, LLMEngineMixin):
    """Interactive REPL for Siyarix — the cybersecurity AI assistant."""

    _SESSIONS_DIR: Path = Path()

    MAX_CONTEXT_MESSAGES = 300  # memory bound to prevent unbounded growth

    MAX_MESSAGE_CHARS = 50000  # per-message content limit

    SYSTEM_REFRESH_INTERVAL = 15  # re-send full system prompt every N calls


    def __init__(
        self,
        mode: str = "integrated",
        target: str = "",
        session_id: str | None = None,
        resume: bool = False,
    ) -> None:
        self._mode = mode
        from ..config import get_config_dir
        self._SESSIONS_DIR = get_config_dir() / "sessions"
        self._platform_ctx = build_platform_context()
        self._shell = detect_shell()
        self._settings = SettingsStore()
        self._session = self._init_session(session_id, target, resume)
        self._command_history: deque[str] = deque(maxlen=1000)
        self._running = True
        self._engine_kill_switch = None
        self._split_pane_enabled = False
        self._split_pane_type = "attack_map"
        self._esc_press_count = 0
        self._esc_press_time = 0.0
        self._esc_window = 2.0
        self._disabled_providers: set[str] = set()
        self._provider_failure_counts: dict[str, int] = {}
        self._provider_last_fail_time: dict[str, float] = {}
        self._provider_cooldown_secs = 30.0
        self._llm_calls = 0
        from ..providers import UsageTracker, ProviderStateManager

        state_dir = str(get_config_dir())
        self._provider_state = ProviderStateManager(
            path=os.path.join(state_dir, "provider_state.json")
        )
        self._usage_tracker = UsageTracker(path=os.path.join(state_dir, "usage.json"))
        from ..output import OutputEngine

        self._output = OutputEngine()
        self._con = self._output.console
        self._validate_provider_config_on_startup()


    def _validate_provider_config_on_startup(self) -> None:
        """Check configured provider has valid API key / SDK / endpoint at startup."""
        from ..providers import ProviderManager

        provider = (self._settings.get("model_provider") or "gemini").lower().strip()
        if provider == "auto":
            return  # auto mode checks at runtime
        pm = ProviderManager.get_instance()
        profile = pm.get_profile(provider)
        if not profile:
            logger.warning("Unknown model_provider in settings: %s", provider)
            return
        if not profile.api_key_env:
            return  # local provider

        key = self._resolve_api_key(provider, profile.api_key_env or "")
        if not key:
            logger.warning(
                "Provider '%s' configured but %s is not set in environment",
                provider,
                profile.api_key_env,
            )
            console.print(
                f"[yellow]⚠ Provider '{provider}' configured but {profile.api_key_env} is not set.[/yellow]"
            )

        if profile.sdk_dependency:
            try:
                __import__(profile.sdk_dependency)
            except ImportError:
                logger.warning(
                    "Provider '%s' SDK '%s' not installed",
                    provider,
                    profile.sdk_dependency,
                )
                console.print(
                    f"[yellow]⚠ Provider '{provider}' requires SDK: pip install {profile.sdk_dependency}[/yellow]"
                )


    def _init_session(self, session_id: str | None, target: str, resume: bool) -> ChatSession:
        """Initialize or resume a chat session."""
        import uuid

        self._SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        if resume and session_id:
            path = self._SESSIONS_DIR / f"{session_id}.json"
            if path.exists():
                session = ChatSession.load(path)
                console.print(f"[dim]Resumed session {session.session_id[:8]}[/dim]")
                return session

            # Try legacy SessionKernel format
            try:
                from ..compat import SessionKernel

                legacy = SessionKernel().load(session_id)
                if legacy:
                    session = ChatSession(
                        session_id=legacy.session_id,
                        target=legacy.scope or target,
                        mode=self._mode,
                    )
                    for op in legacy.operations:
                        session.add_message("user", op.instruction)
                        artifacts = ", ".join(op.artifacts) if op.artifacts else "—"
                        status = f"{op.state} (retries: {op.retries})"
                        session.add_message(
                            "assistant",
                            f"Operation {op.operation_id} [{status}]\nArtifacts: {artifacts}",
                        )
                    session.save(self._SESSIONS_DIR / f"{session.session_id}.json")
                    console.print(f"[dim]Restored legacy session {session.session_id[:8]}[/dim]")
                    return session
            except Exception:
                pass

        # New session
        sid = session_id or uuid.uuid4().hex
        session = ChatSession(session_id=sid, target=target, mode=self._mode)
        return session


    def run(self) -> None:
        """Start the interactive REPL loop."""
        self._print_welcome()
        asyncio.run(self._repl_loop())


    async def _repl_loop(self) -> None:
        """Main async REPL loop."""
        while self._running:
            try:
                if self._split_pane_enabled:
                    self._render_split_pane_layout()
                user_input = await self._prompt_async()
                if not user_input:
                    if self._esc_press_count > 0:
                        now = time.time()
                        if now - self._esc_press_time < self._esc_window:
                            self._esc_press_count += 1
                            if self._esc_press_count >= 2:
                                console.print("[bold yellow]Exiting...[/bold yellow]")
                                self._running = False
                                break
                        else:
                            self._esc_press_count = 1
                            self._esc_press_time = now
                        if self._engine_kill_switch:
                            self._engine_kill_switch.trigger()
                            console.print(
                                "[dim]Current task cancelled. Press ESC again to exit.[/dim]"
                            )
                        else:
                            console.print("[dim]No active task. Press ESC again to exit.[/dim]")
                        continue
                    continue

                self._esc_press_count = 0
                self._command_history.append(user_input)

                if user_input == "?" or user_input.lower() == "help":
                    self._cmd_help("")
                    continue

                if user_input.startswith("/"):
                    await self._handle_slash(user_input)
                else:
                    await self._handle_natural_language(user_input)

            except KeyboardInterrupt:
                self._esc_press_count += 1
                if self._esc_press_count >= 2:
                    console.print("[bold yellow]Exiting...[/bold yellow]")
                    self._running = False
                else:
                    if self._engine_kill_switch:
                        self._engine_kill_switch.trigger()
                    console.print("[dim]Task cancelled. Press Ctrl+C again to exit.[/dim]")
            except EOFError:
                self._running = False
            except Exception as exc:
                console.print(f"[red]Error: {exc}[/red]")

        self._print_goodbye()


    async def _prompt_async(self) -> str:
        """Display the input prompt and read a line."""

        if not sys.stdin.isatty():
            try:
                return input().strip()
            except (EOFError, KeyboardInterrupt):
                return ""

        esc_bindings = self._make_esc_bindings() if PTK_AVAILABLE else None
        prompt_label = Text.assemble(
            ("❯ ", "bold cyan"), ("Type your message or @path/to/file", "dim")
        )

        if self._split_pane_enabled:
            if PTK_AVAILABLE:
                try:
                    from prompt_toolkit import PromptSession
                    session = PromptSession()
                    return (await session.prompt_async(
                        "❯ ",
                        key_bindings=esc_bindings,
                        completer=SmartAutocomplete(self._session),
                    )).strip()
                except KeyboardInterrupt:
                    raise
                except Exception:
                    return Prompt.ask(prompt_label, default="").strip()
            else:
                return Prompt.ask(prompt_label, default="").strip()

        # Show compact status line above prompt
        target_str = f" ({self._session.target})" if self._session.target else ""
        mode_color = {
            "registry": "yellow",
            "autonomous": "magenta",
            "integrated": "cyan",
        }.get(self._mode, "cyan")
        theme = self._settings.get("color_theme") or "cyber-noir"
        provider = self._settings.get("model_provider") or "auto"
        status = Text.assemble(
            (f"{provider}", "bold cyan"),
            (f" · {theme}", "dim white"),
            (f" · {self._mode}", mode_color),
            (f"{target_str}", "dim") if target_str else ("", "dim"),
            ("  ", "dim"),
            ("? for shortcuts · /help for all commands", "dim"),
        )
        console.print(status)

        if PTK_AVAILABLE:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    from prompt_toolkit import PromptSession
                    session = PromptSession()
                    answer = (await session.prompt_async(
                        "❯ ",
                        key_bindings=esc_bindings,
                        completer=SmartAutocomplete(self._session),
                    )).strip()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.debug("prompt_toolkit failed: %s", exc)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    answer = Prompt.ask(prompt_label, default="").strip()
        else:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                answer = Prompt.ask(prompt_label, default="").strip()
        return answer


    def _make_esc_bindings(self) -> Any:
        """Create prompt_toolkit key bindings for ESC detection."""
        from prompt_toolkit.keys import Keys

        kb = KeyBindings()

        @kb.add(Keys.Escape)
        def _on_esc(event: Any) -> None:
            now = time.time()
            if now - self._esc_press_time < self._esc_window:
                self._esc_press_count += 1
                if self._esc_press_count >= 2:
                    self._running = False
                    event.app.exit()
                    return
            else:
                self._esc_press_count = 1
                self._esc_press_time = now
            event.app.current_buffer.text = ""
            event.app.current_buffer.validate_and_handle()

        return kb


    def _render_split_pane_layout(self, left_content: Any = None) -> None:
        """Render the terminal using side-by-side SplitPane layout."""
        if not left_content:
            # Build a nice scroll of recent conversation/messages
            left_text = Text()
            if not self._session.messages:
                left_text.append("Welcome to Siyarix Cyber Command.\n", style="bold cyan")
                left_text.append("Mode: ")
                left_text.append(f"{self._mode}\n", style="bold green")
                left_text.append("\nReady for input. Type your instruction below.\n\n")
                left_text.append("Examples:\n")
                left_text.append("  • scan 127.0.0.1\n", style="yellow")
                left_text.append("  • enumerate subdomains of siyarix.local\n", style="yellow")
            else:
                for msg in self._session.last_n(6):
                    role_color = "cyan" if msg.role == "user" else "green"
                    label = "You" if msg.role == "user" else "Siyarix"
                    left_text.append(f"[{label}]\n", style=f"bold {role_color}")
                    left_text.append(f"{msg.content}\n\n", style="white")
            left_content = left_text

        # Get findings from session context if available
        findings = self._session.context.get("findings", [])
        # Get timeline events if available
        timeline_events = self._session.context.get("timeline_events", [])

        # Instantiate SplitPane and display
        pane = SplitPane(theme=self._settings.get("color_theme") or "dark-neon")
        layout = pane.generate_layout(
            left_renderable=left_content,
            right_type=self._split_pane_type,
            session_meta=self._session,
            findings=findings,
            timeline_events=timeline_events,
        )
        console.print(layout)


    def _print_welcome(self) -> None:
        """Print the welcome banner with system status overview."""
        from ..branding import resolve_version

        ver = resolve_version()
        provider_status = self._gather_provider_status()
        shell_info = get_shell_platform()
        theme = self._settings.get("color_theme")
        provider = self._settings.get("model_provider")

        scans_count = 0
        findings_count = 0
        try:
            from ..offline_store import OfflineStore

            store = OfflineStore()
            stats = store.stats()
            scans_count = stats.get("total_scans", 0)
            findings_count = stats.get("total_findings", 0)
        except ModuleNotFoundError:
            pass
        except Exception as exc:
            logger.debug("Failed to read offline store stats: %s", exc)

        # Live tool & command counts
        tool_count = 0
        try:
            from ..registry import ToolRegistry

            reg = ToolRegistry()
            reg.scan_path()
            tool_count = len(reg.list_tools())
        except Exception:
            pass

        command_count = sum(1 for m in self._session.messages if m.role == "user")

        console.print(
            Panel(
                f"[bold cyan]Siyarix[/bold cyan] [green]v{ver}[/green] — [bold]AI Cybersecurity Agent[/bold]\n"
                f"[dim]Terminal copilot for security work — plan, inspect, execute from one shell.[/dim]",
                title="[bold]⚡ Siyarix Command Center[/bold]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        console.print(
            Columns(
                [
                    Panel(
                        f"[bold]Platform:[/bold] {shell_info}\n"
                        f"[bold]Theme:[/bold] {theme}\n"
                        f"[bold]Provider:[/bold] {provider}\n"
                        f"[bold]Session:[/bold] {self._session.session_id[:8]}",
                        title="Session",
                        border_style="green",
                        padding=(1, 2),
                    ),
                    Panel(
                        f"[bold]Scans:[/bold] {scans_count}\n"
                        f"[bold]Findings:[/bold] {findings_count}\n"
                        f"[bold]Tools:[/bold] {tool_count}\n"
                        f"[bold]Commands:[/bold] {command_count}\n"
                        f"[bold]Hotkeys:[/bold] /help · /exit",
                        title="System",
                        border_style="blue",
                        padding=(1, 2),
                    ),
                    Panel(
                        "[bold]/help[/bold] — command reference\n"
                        "[bold]/scan <tgt>[/bold] — run a scan\n"
                        "[bold]/run <cmd>[/bold] — natural language\n"
                        "[bold]/key set[/bold] — API key management\n"
                        "[bold]/theme[/bold] — switch appearance\n"
                        f"[bold]Mode:[/bold] {self._gather_mode_label(provider_status)}",
                        title="Quick Actions",
                        border_style="magenta",
                        padding=(1, 2),
                    ),
                    Panel(
                        "\n".join(
                            f"[bold]{k.capitalize()}:[/bold] {v[0]}"
                            for k, v in sorted(provider_status.items())
                        ),
                        title="Runtime",
                        border_style="yellow",
                        padding=(1, 2),
                    ),
                ],
                equal=True,
                expand=True,
            )
        )
        console.print(
            Panel(
                "[bold cyan]Type natural language[/bold cyan] to plan work, or use slash commands.\n"
                "[dim]Examples:[/dim] [green]scan 10.0.0.5[/green]  [green]enumerate example.com[/green]  [green]/theme appearance[/green]",
                title="Getting Started",
                border_style="bright_black",
                padding=(1, 2),
            )
        )


    def _gather_provider_status(self) -> dict[str, tuple[str, str]]:
        """Return a concise status map for supported providers.

        Map keys -> (icon, reason)
        """
        from ..providers import ProviderManager

        pm = ProviderManager.get_instance()
        status: dict[str, tuple[str, str]] = {}

        for prov_name in pm.list_providers():
            profile = pm.get_profile(prov_name)
            if not profile:
                continue

            # Check SDK dependency
            pkg_ok = True
            if profile.sdk_dependency:
                try:
                    __import__(profile.sdk_dependency)
                except Exception:
                    pkg_ok = False

            # Check key
            key = self._resolve_api_key(prov_name, profile.api_key_env or "")

            if profile.api_key_env and not pkg_ok:
                status[prov_name] = ("✗", f"pkg missing ({profile.sdk_dependency})")
            elif profile.api_key_env and not key:
                status[prov_name] = ("⚠", "key missing")
            elif profile.api_key_env and key:
                status[prov_name] = ("✓", "configured")
            else:
                # local providers (no api_key_env)
                status[prov_name] = ("⚠", "available (local)")

        return status


    def _gather_mode_label(self, provider_status: dict[str, tuple[str, str]]) -> str:
        """Build a human-readable mode label showing LLM connectivity state."""
        has_llm = any(
            icon == "✓" and label == "configured" for icon, label in provider_status.values()
        )
        mode_display = self._mode.capitalize()
        if has_llm:
            return f"{mode_display} (LLM online)"
        if self._mode == "registry":
            return "Registry (offline)"
        if self._mode == "autonomous":
            return "Autonomous (LLM needed)"
        return f"{mode_display} (local fallback)"


    def _print_assistant(self, message: str) -> None:
        if self._con is not None:
            from rich.markdown import Markdown
            from rich.panel import Panel

            self._con.print(
                Panel(
                    Markdown(message),
                    title="[bold green]\u25c6 Siyarix[/bold green]",
                    border_style="green",
                    padding=(0, 2),
                )
            )
        else:
            self._output._raw_print(f"\u25c6 Siyarix: {message}")


    @staticmethod
    def _strip_json_wrapper(text: str) -> str:
        """If text is JSON with a 'response' field, extract just the response text."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[-1]
            cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict) and "response" in data:
                return data["response"]
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return text


    def _get_conversation_history(self, max_messages: int = 50) -> list[dict]:
        """Extract recent conversation history from the session for LLM context."""
        msgs = self._session.messages
        if not msgs:
            return []
        recent = msgs[-max_messages:] if len(msgs) > max_messages else msgs
        return [
            {
                "role": m.role,
                "content": m.content[-4000:] if len(m.content) > 4000 else m.content,
            }
            for m in recent
        ]


    async def _stream_assistant_response(
        self,
        system_prompt: str,
        user_prompt: str,
        provider_name: str | None = None,
        api_key: str | None = None,
        history: list[dict] | None = None,
    ) -> str:
        """Stream an LLM response token-by-token with a live updating display.

        Returns the clean response text (JSON wrapper stripped if present).
        """
        from rich.live import Live
        from rich.markdown import Markdown
        from rich.panel import Panel

        if not provider_name or not api_key:
            prov_name, api_key = self._resolve_provider()
            if not prov_name or not api_key:
                console.print("[yellow]⚠ No LLM provider available for streaming[/yellow]")
                return ""
            provider_name = prov_name

        llm_fn = self._make_llm_call(provider_name, api_key)
        gen = await llm_fn(system_prompt, user_prompt, stream=True, history=history)
        full_text = ""
        md = Markdown("")
        panel = Panel(
            md,
            title="[bold green]◆ Siyarix[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
        with Live(panel, refresh_per_second=12, transient=False) as live:
            async for token in gen:
                full_text += token
                display_text = self._strip_json_wrapper(full_text)
                md = Markdown(display_text)
                panel = Panel(
                    md,
                    title="[bold green]◆ Siyarix[/bold green]",
                    border_style="green",
                    padding=(0, 2),
                )
                live.update(panel)
        console.print()
        return self._strip_json_wrapper(full_text)


    def _print_plan(self, plan: "Any") -> None:  # ExecutionPlan
        rows = []
        for i, step in enumerate(plan.steps, 1):
            target = step.args.get("target", "") if isinstance(step.args, dict) else ""
            rows.append(
                {
                    "#": str(i),
                    "Tool": step.tool or "—",
                    "Target": target or "—",
                    "Description": step.description[:50],
                }
            )
        self._output.print_table(rows, title="Execution Plan")


    def _print_results(self, result: "Any", elapsed: float) -> None:  # EngineResult
        from ..planner import StepStatus
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        success_count = sum(1 for r in result.step_results if r.status == StepStatus.SUCCESS)
        failed_count = len(result.step_results) - success_count

        # Step timeline panel
        step_lines = []
        for r in result.step_results:
            icon = "✓" if r.status == StepStatus.SUCCESS else "✗"
            style = "green" if r.status == StepStatus.SUCCESS else "red"
            tool = getattr(r, "tool", getattr(r, "step_id", "?"))
            detail = (r.output or "")[:80].replace("\n", " ") if r.output else ""
            step_lines.append(f"  [{style}]{icon} [bold]{tool}[/bold][/] [dim]{detail}[/dim]")

        if step_lines:
            console.print(
                Panel(
                    "\n".join(step_lines),
                    title="[bold]Step Results[/bold]",
                    border_style="blue",
                    padding=(1, 2),
                )
            )

        # Findings table grouped by severity
        if result.all_findings:
            sev_groups: dict[str, list[dict]] = {}
            for f in result.all_findings:
                sev = f.get("severity", "info")
                sev_groups.setdefault(sev, []).append(f)

            sev_order = ["critical", "high", "medium", "low", "info"]
            for sev in sev_order:
                if sev not in sev_groups:
                    continue
                items = sev_groups[sev][:15]
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}.get(sev, "blue")
                sev_table = Table(
                    title=f"{sev.upper()} Findings ({len(items)})",
                    header_style=sev_color,
                    border_style=sev_color,
                    box=None,
                )
                sev_table.add_column("Tool", style="cyan")
                sev_table.add_column("Detail", style="white")
                for f in items:
                    tool = f.get("tool", f.get("type", "?"))
                    desc = str(f.get("detail", f.get("description", f.get("title", ""))))[:100]
                    sev_table.add_row(tool, desc)
                console.print(sev_table)

            if len(result.all_findings) > 20:
                remaining = len(result.all_findings) - sum(
                    len(v) for v in sev_groups.values() if len(v) > 15
                )
                if remaining > 0:
                    console.print(f"  [dim]… and {remaining} more findings[/dim]")

        # Executive summary bar
        summary_panels = []
        summary_panels.append(
            Panel(
                f"[bold]{'✓' if result.success else '✗'} {'Success' if result.success else 'Partial'}[/bold]\n[dim]Status[/dim]",
                border_style="green" if result.success else "red",
                padding=(1, 2),
            )
        )
        summary_panels.append(
            Panel(
                f"[bold]{success_count}/{len(result.step_results)}[/bold]\n[dim]Steps[/dim]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        summary_panels.append(
            Panel(
                f"[bold]{len(result.all_findings)}[/bold]\n[dim]Findings[/dim]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        summary_panels.append(
            Panel(
                f"[bold]{elapsed:.1f}s[/bold]\n[dim]Duration[/dim]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        if failed_count:
            summary_panels.append(
                Panel(
                    f"[bold red]{failed_count}[/bold red]\n[dim]Failed[/dim]",
                    border_style="red",
                    padding=(1, 2),
                )
            )

        console.print(Columns(summary_panels, equal=False, padding=(0, 1)))


    def _print_goodbye(self) -> None:
        self._session.save(self._SESSIONS_DIR / f"{self._session.session_id}.json")
        self._output.print_info(f"Session saved: {self._session.session_id[:8]}")
        self._output.print_info(f"Resume with: siyarix --session {self._session.session_id}")
        self._output.print_info("Settings persist in config/.env — stay curious, stay ethical.")




def start_chat(
    mode: str = "integrated",
    target: str = "",
    session_id: str | None = None,
    resume: bool = False,
) -> None:
    """Launch the Siyarix interactive chat REPL."""
    chat = SiyarixChat(mode=mode, target=target, session_id=session_id, resume=resume)
    chat.run()

