from __future__ import annotations
import asyncio
import atexit
import json
import logging
import sys
import time
import warnings
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from ..config import get_config_dir

from .._platform import (
    is_windows as _plat_is_windows,
    has_signal as _plat_has_signal,
    has_termios as _plat_has_termios,
)

if _plat_has_signal():
    import signal as _signal
else:
    _signal = None  # type: ignore

from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.columns import Columns
from rich.table import Table
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory

from .session import ChatSession
from .ui import SmartAutocomplete, SplitPane, render_welcome_banner
from ..config import SettingsStore
from .platform_utils import detect_shell, get_shell_platform, build_platform_context
from .commands import command_history
from .handlers import CommandHandlersMixin
from .engine import LLMEngineMixin
from .console import console, panel_response, mode_border
from .prompts import (
    mode_color, make_prompt_top, make_prompt_bottom,
)

logger = logging.getLogger(__name__)


def _restore_tty() -> None:
    """Restore TTY to cooked mode if put in raw mode by prompt_toolkit."""
    if not _plat_has_termios():
        return
    try:
        import termios as _termios_mod
        fd = sys.stdin.fileno()
        attrs = _termios_mod.tcgetattr(fd)
        if attrs[3] & (_termios_mod.ECHO | _termios_mod.ICANON) == 0:
            attrs[3] |= _termios_mod.ECHO | _termios_mod.ICANON
            _termios_mod.tcsetattr(fd, _termios_mod.TCSANOW, attrs)
    except Exception:
        pass


atexit.register(_restore_tty)

# Restore TTY on SIGTERM/SIGHUP too (not on Windows)
def _signal_restore_tty(*_: Any) -> None:
    _restore_tty()

if _signal is not None:
    for _sig_name in ("SIGTERM", "SIGHUP", "SIGQUIT"):
        _sig = getattr(_signal, _sig_name, None)
        if _sig is not None:
            try:
                _signal.signal(_sig, _signal_restore_tty)
            except Exception:
                pass


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
        self._SESSIONS_DIR = get_config_dir() / "sessions"
        self._platform_ctx = build_platform_context()
        self._shell = detect_shell()
        self._settings = SettingsStore()
        self._session = self._init_session(session_id, target, resume)
        self._command_history: deque[str] = deque(maxlen=1000)
        self._running = True
        self._engine_kill_switch = None
        self._pt_session: PromptSession[Any] | None = None
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
        self._tool_cache: list[Any] | None = None
        from ..providers import UsageTracker, ProviderStateManager

        state_dir = get_config_dir()
        self._provider_state = ProviderStateManager(
            path=str(state_dir / "provider_state.json")
        )
        self._usage_tracker = UsageTracker(path=str(state_dir / "usage.json"))
        from ..output import OutputEngine

        self._output = OutputEngine()
        self._con = self._output.console

        self._validate_provider_config_on_startup()
        # Reset provider from "registry" to "auto" if mode requires an LLM
        if self._mode not in ("offline", "integrated"):
            prov = (self._settings.get("model_provider") or "auto").lower().strip()
            if prov == "registry":
                self._settings.set("model_provider", "auto")
        self._connectivity_monitor: Any = None

    @property
    def connectivity_monitor(self) -> Any:
        if self._connectivity_monitor is None:
            from ..connectivity import SmartModeController
            self._connectivity_monitor = SmartModeController(
                get_current_mode=lambda: self._mode,
                set_mode=self._set_mode_internal,
            )
        return self._connectivity_monitor

    def _set_mode_internal(self, new_mode: str) -> None:
        """Internal mode setter used by the connectivity monitor."""
        self._mode = new_mode
        self._session.mode = new_mode
        if new_mode == "offline":
            self._settings.set("model_provider", "registry")

    def _ui_flush(self) -> None:
        pass

    def _validate_provider_config_on_startup(self) -> None:
        """Check configured provider has valid API key / SDK / endpoint at startup."""
        from ..providers import ProviderManager, resolve_api_key

        provider = (self._settings.get("model_provider") or "gemini").lower().strip()
        if provider == "auto":
            return
        pm = ProviderManager.get_instance()
        profile = pm.get_profile(provider)
        if not profile:
            logger.warning("Unknown model_provider in settings: %s", provider)
            return
        if not profile.api_key_env:
            return

        key = resolve_api_key(provider, profile.api_key_env or "")
        if not key:
            msg = f"Provider '{provider}' configured but {profile.api_key_env} is not set."
            logger.warning(msg)
            console.print(f"[yellow]⚠ {msg}[/yellow]")

        if profile.sdk_dependency:
            try:
                # Validate the module name is a known SDK dependency
                _SAFE_SDKS = {"openai", "anthropic", "google-genai", "mistralai", "cohere", "together"}
                if profile.sdk_dependency not in _SAFE_SDKS:
                    logger.warning("Unknown SDK dependency '%s' for provider '%s'", profile.sdk_dependency, provider)
                __import__(profile.sdk_dependency)
            except ImportError:
                msg = f"Provider '{provider}' requires SDK: pip install {profile.sdk_dependency}"
                logger.warning(msg)
                console.print(f"[yellow]⚠ {msg}[/yellow]")

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
                logger.warning("Failed to restore legacy session", exc_info=True)

        # New session
        sid = session_id or uuid.uuid4().hex
        session = ChatSession(session_id=sid, target=target, mode=self._mode)
        return session

    def run(self) -> None:
        """Start the interactive REPL loop."""
        self._print_welcome()

        # Install SIGTSTP handler to restore terminal before Ctrl+Z suspend
        _orig_tstp: Any = None
        if _signal is not None and hasattr(_signal, "SIGTSTP"):

            def _tstp_handler(signum: int, frame: Any) -> None:
                try:
                    console.print()
                except Exception:
                    pass
                if _plat_has_termios():
                    try:
                        import termios as _termios

                        _termios.tcsetattr(
                            sys.stdin.fileno(), _termios.TCSANOW,
                            _termios.tcgetattr(sys.stdin.fileno()),
                        )
                    except Exception:
                        pass
                if _orig_tstp:
                    _orig_tstp(signum, frame)

            _orig_tstp = _signal.getsignal(_signal.SIGTSTP)
            _signal.signal(_signal.SIGTSTP, _tstp_handler)

        # Start connectivity monitor background check
        async def _run_all() -> None:
            try:
                await self.connectivity_monitor.start()
            except Exception:
                logger.debug("Connectivity monitor not available", exc_info=True)
            try:
                await self._repl_loop()
            finally:
                if _orig_tstp:
                    _signal.signal(_signal.SIGTSTP, _orig_tstp)
                try:
                    await self.connectivity_monitor.stop()
                except Exception:
                    pass

        try:
            asyncio.run(_run_all())
        except KeyboardInterrupt:
            self._running = False
            console.print("\n[bold yellow]Exited by user.[/bold yellow]")

    async def _ui_flusher_task(self) -> None:
        while self._running:
            self._ui_flush()
            await asyncio.sleep(0.05)

    async def _repl_loop(self) -> None:
        """Main async REPL loop."""
        self._flusher = asyncio.create_task(self._ui_flusher_task())
        while self._running:
            try:
                self._ui_flush()
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

                # Record in global command history for autocomplete ranking
                command_history.record(user_input)

                # Check for piping
                if "|" in user_input and not user_input.startswith("/"):
                    pipe_parts = self._check_for_piping(user_input)
                    if pipe_parts != user_input:
                        console.print(
                            "[dim]Piping detected. Processing as sequential commands...[/dim]"
                        )
                        parts = [p.strip() for p in user_input.split("|") if p.strip()]
                        for i, part in enumerate(parts):
                            console.print(
                                f"[cyan]Step {i + 1}/{len(parts)}:[/cyan] {part[:80]}"
                            )
                            if part.startswith("/"):
                                await self._handle_slash(part)
                            else:
                                await self._handle_natural_language(part)
                        continue

                if user_input == "?" or user_input.lower() == "help":
                    self._cmd_help("")
                    continue

                if user_input.startswith("/"):
                    # Check aliases
                    cmd_name = user_input.split()[0].lower()
                    aliases = self._load_aliases() if hasattr(self, "_load_aliases") else {}
                    if cmd_name.lstrip("/") in aliases:
                        resolved = aliases[cmd_name.lstrip("/")]
                        remaining = user_input[len(cmd_name):].strip()
                        full_cmd = f"{resolved} {remaining}" if remaining else resolved
                        console.print(f"[dim]Alias: /{cmd_name.lstrip('/')} -> {full_cmd}[/dim]")
                        await self._handle_slash(f"/{full_cmd}" if not full_cmd.startswith("/") else full_cmd)
                    else:
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

    def _terminal_supports_raw(self) -> bool:
        """Check if the terminal supports raw mode (required by prompt_toolkit)."""
        if not _plat_has_termios() or _plat_is_windows():
            return False
        try:
            import termios as _termios_mod

            fd = sys.stdin.fileno()
            attrs = _termios_mod.tcgetattr(fd)
            _termios_mod.tcsetattr(fd, _termios_mod.TCSANOW, attrs)
            return True
        except Exception:
            return False

    def _check_for_piping(self, user_input: str) -> str | None:
        """Check if input contains pipe and handle multi-command piping.
        Returns the processed input or None if piping was handled."""
        if "|" not in user_input:
            return user_input

        # Split on | but not inside quotes
        parts = []
        current = ""
        in_single = False
        in_double = False
        for ch in user_input:
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "|" and not in_single and not in_double:
                parts.append(current.strip())
                current = ""
                continue
            current += ch
        if current.strip():
            parts.append(current.strip())

        if len(parts) <= 1:
            return user_input

        return user_input

    async def _prompt_async(self) -> str:
        """Display the professional input prompt and read a line."""
        if not sys.stdin.isatty():
            try:
                return input().strip()
            except (EOFError, KeyboardInterrupt):
                return ""

        esc_bindings = self._make_full_bindings()

        # Gather status information
        theme = self._settings.get("color_theme") or "cyber-noir"
        provider = self._settings.get("model_provider") or "auto"
        persona = self._settings.get("persona") or ""
        session_id = self._session.session_id[:8] if self._session.session_id else ""
        msg_count = len(self._session.messages)
        uptime_delta = datetime.now(timezone.utc) - self._session.created_at
        uptime_secs = uptime_delta.total_seconds()

        # If terminal doesn't support raw mode, skip prompt_toolkit
        if not self._terminal_supports_raw():
            top_bar = make_prompt_top(self._mode, provider, session_id, msg_count, uptime_secs, theme, persona)
            input_hint = make_prompt_bottom(show_hint=True)
            console.print(top_bar)
            try:
                return Prompt.ask(input_hint, default="").strip()
            except (EOFError, KeyboardInterrupt):
                return ""

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                from prompt_toolkit.patch_stdout import patch_stdout

                if self._pt_session is None:
                    self._pt_session = PromptSession(
                        multiline=True,
                        vi_mode=False,
                    )

                top_bar = make_prompt_top(self._mode, provider, session_id, msg_count, uptime_secs, theme, persona)
                console.print(top_bar)

                pt_prompt = HTML(
                    '<style fg="ansicyan"><b>╰─➜ </b></style>'
                )

                with patch_stdout():
                    _result = await self._pt_session.prompt_async(
                        pt_prompt,
                        key_bindings=esc_bindings,
                        completer=SmartAutocomplete(self._session),
                    )
                    if _result is None:
                        raise KeyboardInterrupt
                    answer = _result.strip()
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            import traceback

            console.print(f"[red]prompt_toolkit failed: {exc}[/red]")
            console.print(traceback.format_exc())
            logger.debug("prompt_toolkit failed: %s", exc)
            top_bar = make_prompt_top(self._mode, provider, session_id, msg_count, uptime_secs, theme, persona)
            console.print(top_bar)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                answer = Prompt.ask("╰─➜ ", default="").strip()
        return answer

    def _make_full_bindings(self) -> Any:
        """Create comprehensive prompt_toolkit key bindings with
        Ctrl shortcuts and multi-line support."""
        from prompt_toolkit.keys import Keys

        kb = KeyBindings()
        self._multiline = self._settings.get("multiline", False)

        # ═══════════ Navigation ═══════════

        # Up / Ctrl+P - previous history entry
        @kb.add(Keys.Up)
        @kb.add(Keys.ControlP)
        def _on_up(event: Any) -> None:
            buf = event.app.current_buffer
            buf.history_backward()

        # Down / Ctrl+N - next history entry
        @kb.add(Keys.Down)
        @kb.add(Keys.ControlN)
        def _on_down(event: Any) -> None:
            buf = event.app.current_buffer
            buf.history_forward()

        # Ctrl+R - reverse history search
        @kb.add(Keys.ControlR)
        def _on_ctrlr(event: Any) -> None:
            event.app.current_buffer.start_reverse_history_search()

        # Home / Ctrl+A - beginning of line
        @kb.add(Keys.Home)
        @kb.add(Keys.ControlA)
        def _on_home(event: Any) -> None:
            buf = event.app.current_buffer
            buf.cursor_position = 0

        # End / Ctrl+E - end of line
        @kb.add(Keys.End)
        @kb.add(Keys.ControlE)
        def _on_end(event: Any) -> None:
            buf = event.app.current_buffer
            buf.cursor_position = len(buf.text)

        # Left / Ctrl+B - backward char
        @kb.add(Keys.Left)
        @kb.add(Keys.ControlB)
        def _on_left(event: Any) -> None:
            buf = event.app.current_buffer
            buf.cursor_left()

        # Right / Ctrl+F - forward char
        @kb.add(Keys.Right)
        @kb.add(Keys.ControlF)
        def _on_right(event: Any) -> None:
            buf = event.app.current_buffer
            buf.cursor_right()

        # Delete / Ctrl+D - delete forward char (or exit if buffer empty)
        @kb.add(Keys.Delete)
        @kb.add(Keys.ControlD)
        def _on_delete(event: Any) -> None:
            buf = event.app.current_buffer
            if buf.text:
                pos = buf.cursor_position
                buf.text = buf.text[:pos] + buf.text[pos + 1:]
            else:
                self._running = False
                event.app.exit()

        # Backspace - delete backward char
        @kb.add(Keys.Backspace)
        def _on_backspace(event: Any) -> None:
            buf = event.app.current_buffer
            pos = buf.cursor_position
            if pos > 0:
                buf.text = buf.text[:pos - 1] + buf.text[pos:]
                buf.cursor_position = pos - 1

        # ═══════════ Editing ═══════════

        # Ctrl+U - delete to start
        @kb.add(Keys.ControlU)
        def _on_ctrlu(event: Any) -> None:
            buf = event.app.current_buffer
            buf.text = buf.text[buf.cursor_position:]
            buf.cursor_position = 0

        # Ctrl+K - delete to end
        @kb.add(Keys.ControlK)
        def _on_ctrlk(event: Any) -> None:
            buf = event.app.current_buffer
            pos = buf.cursor_position
            buf.text = buf.text[:pos]

        # Ctrl+W / Alt+Backspace - delete word backward
        @kb.add(Keys.ControlW)
        @kb.add(Keys.Escape, Keys.Backspace)
        def _on_ctrlw(event: Any) -> None:
            buf = event.app.current_buffer
            text = buf.text[:buf.cursor_position]
            space = text.rstrip().rfind(" ")
            if space >= 0:
                new_pos = space + 1
            else:
                new_pos = 0
            buf.text = buf.text[:new_pos] + buf.text[buf.cursor_position:]
            buf.cursor_position = new_pos

        # Ctrl+Left - jump word left
        @kb.add(Keys.ControlLeft)
        def _on_ctrl_left(event: Any) -> None:
            buf = event.app.current_buffer
            pos = buf.cursor_position
            text = buf.text[:pos].rstrip()
            if not text:
                return
            space = text.rfind(" ")
            if space >= 0:
                buf.cursor_position = space + 1
            else:
                buf.cursor_position = 0

        # Ctrl+Right - jump word right
        @kb.add(Keys.ControlRight)
        def _on_ctrl_right(event: Any) -> None:
            buf = event.app.current_buffer
            text = buf.text
            pos = buf.cursor_position
            rest = text[pos:].lstrip()
            if not rest:
                return
            space = rest.find(" ")
            if space >= 0:
                buf.cursor_position = pos + len(text[pos:]) - len(rest) + space + 1
            else:
                buf.cursor_position = len(text)

        # ═══════════ Submit / newline ═══════════

        # Alt+Enter / Escape+Enter - submit (multiline) / newline (single-line)
        @kb.add(Keys.Escape, Keys.Enter)
        def _on_alt_enter(event: Any) -> None:
            if self._multiline:
                event.app.current_buffer.validate_and_handle()
            else:
                event.app.current_buffer.insert_text("\n")

        # Ctrl+J / Ctrl+M / Enter - newline (multiline) / submit (single-line)
        @kb.add(Keys.ControlJ)
        @kb.add(Keys.ControlM)
        def _on_enter(event: Any) -> None:
            if self._multiline:
                event.app.current_buffer.insert_text("\n")
            else:
                event.app.current_buffer.validate_and_handle()

        # ═══════════ Special actions ═══════════

        # ESC - cancel/exit detection
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

        # Ctrl+C - cancel/exit
        @kb.add(Keys.ControlC)
        def _on_ctrlc(event: Any) -> None:
            self._esc_press_count += 1
            if self._esc_press_count >= 2:
                self._running = False
                event.app.exit()
            else:
                if self._engine_kill_switch:
                    self._engine_kill_switch.trigger()
                buf = event.app.current_buffer
                if buf.text:
                    buf.text = ""
                else:
                    console.print("[dim]Press Ctrl+C again to exit.[/dim]")

        # Ctrl+L - clear screen
        @kb.add(Keys.ControlL)
        def _on_ctrll(event: Any) -> None:
            console.clear()
            event.app.current_buffer.text = ""

        # F1 - show keyboard shortcuts
        @kb.add(Keys.F1)
        def _on_f1(event: Any) -> None:
            self._print_keyboard_shortcuts()

        # Ctrl+\ - toggle multiline mode
        @kb.add(Keys.ControlBackslash)
        def _on_toggle_multiline(event: Any) -> None:
            self._multiline = not self._multiline
            self._settings.set("multiline", self._multiline)
            if self._multiline:
                console.print("[cyan]Multiline: ON — Enter=newline, Alt+Enter=submit[/cyan]")
            else:
                console.print("[cyan]Multiline: OFF — Enter=submit, Alt+Enter=newline[/cyan]")

        # F2 - New session (like /new)
        @kb.add(Keys.F2)
        def _on_f2_new(event: Any) -> None:
            if hasattr(self, '_cmd_new'):
                self._cmd_new("")

        # F3 - Clear chat (like /clear)
        @kb.add(Keys.F3)
        def _on_f3_clear(event: Any) -> None:
            if hasattr(self, '_cmd_clear'):
                self._cmd_clear("")

        # F4 - Toggle command review (like /review)
        @kb.add(Keys.F4)
        def _on_f4_review(event: Any) -> None:
            current = self._settings.get("command_review", True)
            new_val = not current
            self._settings.set("command_review", new_val)
            status = "on" if new_val else "off"
            console.print(f"[cyan]Command review toggled [bold]{status}[/bold][/cyan]")

        return kb

    def _print_keyboard_shortcuts(self) -> None:
        from prompt_toolkit import print_formatted_text as pt_print
        from prompt_toolkit.formatted_text import HTML as PTHTML
        ml_status = "ON" if self._multiline else "OFF"
        lines = [
            ('', '\n'),
            ('bold cyan', 'Keyboard Shortcuts'),
            ('', '\n' + '─' * 56 + '\n'),
            ('cyan', '↑/↓            '), ('', 'History navigation\n'),
            ('cyan', 'Ctrl+P / Ctrl+N'), ('', 'History previous / next\n'),
            ('cyan', 'Ctrl+R         '), ('', 'Reverse history search\n'),
            ('', '\n'),
            ('bold cyan', 'Navigation'),
            ('', '\n'),
            ('cyan', '←/→            '), ('', 'Move cursor left / right\n'),
            ('cyan', 'Ctrl+B / Ctrl+F'), ('', 'Move cursor left / right\n'),
            ('cyan', 'Ctrl+A / Home  '), ('', 'Go to beginning of line\n'),
            ('cyan', 'Ctrl+E / End   '), ('', 'Go to end of line\n'),
            ('cyan', 'Ctrl+← / Ctrl+→'), ('', 'Jump word left / right\n'),
            ('', '\n'),
            ('bold cyan', 'Editing'),
            ('', '\n'),
            ('cyan', 'Backspace      '), ('', 'Delete character before cursor\n'),
            ('cyan', 'Delete / Ctrl+D'), ('', 'Delete character after cursor\n'),
            ('cyan', 'Ctrl+U         '), ('', 'Delete to start of line\n'),
            ('cyan', 'Ctrl+K         '), ('', 'Delete to end of line\n'),
            ('cyan', 'Ctrl+W / Alt+⌫ '), ('', 'Delete word backward\n'),
            ('', '\n'),
            ('bold cyan', 'Input'),
            ('', '\n'),
            ('cyan', 'Tab            '), ('', 'Autocomplete / Suggest\n'),
            ('cyan', 'Enter          '), ('', f'Submit (newline if Multiline={ml_status})\n'),
            ('cyan', 'Alt+Enter      '), ('', f'Newline (submit if Multiline={ml_status})\n'),
            ('', '\n'),
            ('bold cyan', 'Actions'),
            ('', '\n'),
            ('cyan', 'F1             '), ('', 'Keyboard shortcuts\n'),
            ('cyan', 'F2             '), ('', 'New session\n'),
            ('cyan', 'F3             '), ('', 'Clear chat\n'),
            ('cyan', 'F4             '), ('', 'Toggle command review\n'),
            ('cyan', 'Ctrl+\\        '), ('', 'Toggle multiline mode\n'),
            ('cyan', 'Ctrl+L         '), ('', 'Clear screen\n'),
            ('', '\n'),
            ('bold cyan', 'Exit / Cancel'),
            ('', '\n'),
            ('cyan', 'Esc            '), ('', 'Cancel input / Double Esc to exit\n'),
            ('cyan', 'Ctrl+C         '), ('', 'Cancel task / Double Ctrl+C to exit\n'),
        ]
        html_parts = []
        for style, text in lines:
            if style == 'bold cyan':
                html_parts.append(f'<b><style fg="ansicyan">{text}</style></b>')
            elif style == 'cyan':
                html_parts.append(f'<style fg="ansicyan">{text}</style>')
            else:
                html_parts.append(text)
        pt_print(PTHTML(''.join(html_parts)))

    def _render_split_pane_layout(self, left_content: Any = None) -> None:
        """Render the terminal using side-by-side SplitPane layout."""
        if not left_content:
            # Build a scrollable view of recent conversation messages
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
        """Print the welcome banner with system status overview using a premium layout."""
        console.print()

        provider_status = self._gather_provider_status()
        shell_info = get_shell_platform()
        theme = self._settings.get("color_theme") or "cyber-noir"
        provider = self._settings.get("model_provider") or "auto"
        persona = self._settings.get("persona") or "auto"

        scans_count = 0
        findings_count = 0
        try:
            from ..offline_store import OfflineStore
            store = OfflineStore()
            stats = store.stats()
            scans_count = stats.get("total_scans", 0)
            findings_count = stats.get("total_findings", 0)
        except Exception:
            logger.warning("Failed to load offline store stats for welcome banner", exc_info=True)

        tool_count = 0
        try:
            from ..registry import ToolRegistry
            reg = ToolRegistry()
            reg.scan_path()
            tool_count = len(reg.list_tools())
        except Exception:
            logger.warning("Failed to load tool registry for welcome banner", exc_info=True)

        command_count = sum(1 for m in self._session.messages if m.role == "user")
        msg_count = len(self._session.messages)

        layout = render_welcome_banner(
            mode=self._mode,
            provider=provider,
            persona=persona,
            theme=theme,
            session_id=self._session.session_id or "",
            shell_info=shell_info,
            scans_count=scans_count,
            findings_count=findings_count,
            tool_count=tool_count,
            llm_calls=self._llm_calls,
            command_count=command_count,
            msg_count=msg_count,
            provider_status=provider_status,
        )
        console.print(layout)

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
                    _SAFE_SDKS = {"openai", "anthropic", "google-genai", "mistralai", "cohere", "together"}
                    if profile.sdk_dependency in _SAFE_SDKS or "." not in profile.sdk_dependency:
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
        if self._mode in ("offline", "registry"):
            return "Offline (registry, no LLM)"
        if has_llm:
            return f"{mode_display} (LLM online)"
        if self._mode == "autonomous":
            return "Autonomous (LLM needed)"
        return f"{mode_display} (local fallback)"

    def _print_assistant(self, message: str) -> None:
        display = self._strip_json_wrapper(message)
        if self._con is not None:
            syntax_theme = self._settings.get("syntax_theme") or "monokai"
            self._con.print(
                panel_response(
                    display,
                    mode=self._mode,
                    title="\u25c6 Siyarix",
                    syntax_theme=syntax_theme,
                )
            )
        else:
            console.print(f"\u25c6 Siyarix: {display}")

    @staticmethod
    def _strip_json_wrapper(text: str) -> str:
        """If text is JSON with a 'response' field, extract just the response text."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n", 1)
            cleaned = lines[-1] if len(lines) > 1 else ""
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
            if isinstance(data, dict) and "response" in data:
                return data["response"]
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        import re

        match = re.search(r'\{\s*"response"\s*:\s*"(.*)', cleaned, re.DOTALL | re.IGNORECASE)
        if match:
            extracted = match.group(1)
            if extracted.endswith('"}'):
                extracted = extracted[:-2]
            elif extracted.endswith('"'):
                extracted = extracted[:-1]
            elif extracted.endswith('"\n}'):
                extracted = extracted[:-3]

            extracted = extracted.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
            return extracted

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
        if not provider_name or not api_key:
            prov_name, api_key = self._resolve_provider()
            if not prov_name or not api_key:
                console.print("[yellow]⚠ No LLM provider available for streaming[/yellow]")
                return ""
            provider_name = prov_name

        llm_fn = self._make_llm_call(provider_name, api_key)
        gen = await llm_fn(system_prompt, user_prompt, stream=True, history=history)
        full_text = ""
        syntax_theme = self._settings.get("syntax_theme") or "monokai"

        from rich.live import Live
        from rich.panel import Panel

        border = mode_border(self._mode)
        md = Markdown("", code_theme=syntax_theme)
        panel = Panel(
            md, title=f"[bold {border}]◆ Siyarix[/bold {border}]",
            border_style=border, padding=(0, 2)
        )

        with Live(panel, console=console, refresh_per_second=15, transient=False) as live:
            async for token in gen:
                full_text += token
                display_text = self._strip_json_wrapper(full_text)
                md = Markdown(display_text, code_theme=syntax_theme)
                live.update(
                    Panel(
                        md,
                        title=f"[bold {border}]◆ Siyarix[/bold {border}]",
                        border_style=border,
                        padding=(0, 2),
                    )
                )

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

        success_count = sum(1 for r in result.step_results if r.status == StepStatus.COMPLETED)
        failed_count = len(result.step_results) - success_count

        step_lines = []
        for r in result.step_results:
            icon = "✓" if r.status == StepStatus.COMPLETED else "✗"
            style = "green" if r.status == StepStatus.COMPLETED else "red"
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
                sev_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "green",
                    "info": "blue",
                }.get(sev, "blue")
                from rich.table import Table

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
        from ..branding import resolve_version
        from rich.panel import Panel
        ver = resolve_version()
        auto_save = self._settings.get("auto_save_session", False)
        if auto_save:
            self._session.save(self._SESSIONS_DIR / f"{self._session.session_id}.json")
            saved_msg = f"[green]✓[/green] Session saved: [cyan]{self._session.session_id[:8]}[/cyan]\n"
            resume_msg = f"[green]✓[/green] Resume with: [cyan]siyarix --session {self._session.session_id}[/cyan]\n"
        else:
            saved_msg = ""
            resume_msg = ""
        console.print(Panel(
            f"[bold cyan]Siyarix v{ver}[/bold cyan]\n\n"
            f"{saved_msg}"
            f"{resume_msg}"
            f"[green]✓[/green] Settings persist in config/.env\n\n"
            f"[dim]Stay curious. Stay ethical.[/dim]",
            title="[bold]Session Summary[/bold]",
            border_style="cyan",
        ))


def start_chat(
    mode: str = "integrated",
    target: str = "",
    session_id: str | None = None,
    resume: bool = False,
) -> None:
    """Launch the Siyarix interactive chat REPL."""
    chat = SiyarixChat(mode=mode, target=target, session_id=session_id, resume=resume)
    chat.run()
