# SPDX-License-Identifier: AGPL-3.0-or-later

"""Chat UI components — SplitPane, ConfigPanel, SmartAutocomplete, CommandPalette."""

from __future__ import annotations

from typing import Any

from prompt_toolkit.completion import Completer, Completion, PathCompleter

from ..output import output as _output_engine

class SmartAutocomplete(Completer):
    """Context-aware autocomplete for the chat REPL."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._path_completer = PathCompleter()
        self._commands = [
            "/help", "/exit", "/clear", "/new", "/history", "/search",
            "/tools", "/platform", "/status", "/session", "/uptime",
            "/env", "/intents", "/shells", "/run", "/save", "/config",
            "/key", "/mode", "/model", "/provider", "/theme", "/target",
            "/version", "/context", "/log", "/diff", "/mcp", "/agent",
            "/review", "/persona", "/report", "/split",
            "/batch", "/opsec", "/siem",
            "/performance", "/cache", "/campaign",
            "/kb", "/ticket", "/retest", "/stealth",
            "/audit", "/palette", "/savecmd", "/cmds", "/cmd",
        ]

    def get_completions(self, document: Any, complete_event: Any) -> Any:
        text = document.text_before_cursor
        
        # Command completion
        if text.startswith("/"):
            word_before_cursor = document.get_word_before_cursor()
            prefix = text.split()[-1] if text.split() else ""
            if " " not in text:
                for cmd in self._commands:
                    if cmd.startswith(prefix):
                        yield Completion(cmd, start_position=-len(prefix))
            return

        # Path completion if text contains @ or looks like a path
        word = document.get_word_before_cursor(WORD=True)
        if word.startswith("@"):
            document_copy = document.clone()
            document_copy.text = document.text.replace("@", "")
            document_copy.cursor_position -= 1
            for completion in self._path_completer.get_completions(document_copy, complete_event):
                yield completion
        elif "/" in word or "\\" in word or word.startswith("."):
            for completion in self._path_completer.get_completions(document, complete_event):
                yield completion


class CommandPalette:
    """Interactive fuzzy command palette for quick command selection."""

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id

    async def show_async(self, console: Any) -> str | None:
        from prompt_toolkit.shortcuts import radiolist_dialog
        from .commands import HELP_CATEGORIES

        all_cmds: list[tuple[str, str]] = []
        for _cat, cmds in HELP_CATEGORIES:
            for cmd, desc in cmds.items():
                all_cmds.append((cmd, f"{cmd:<15} {desc}"))

        if not all_cmds:
            return None

        result = await radiolist_dialog(
            title="Command Palette",
            text="Select a command to execute:",
            values=all_cmds,
        ).run_async()

        return result


class SplitPane:
    """Terminal split-pane layout renderer for side-by-side views."""

    def __init__(self, theme: str = "dark-neon") -> None:
        self._theme = theme

    def generate_layout(
        self,
        left_renderable: Any = None,
        right_type: str = "",
        session_meta: Any = None,
        findings: list[Any] | None = None,
        timeline_events: list[Any] | None = None,
    ) -> str:
        from rich.panel import Panel
        from rich.text import Text

        right_content = Text()
        if right_type == "timeline":
            right_content.append("─ Timeline ─\n", style="bold cyan")
            events = timeline_events or []
            for evt in events[-10:]:
                if isinstance(evt, dict):
                    right_content.append(f"  {evt.get('time', '?')} {evt.get('event', '?')}\n")
                else:
                    right_content.append(f"  {evt}\n")
            if not events:
                right_content.append("  No events yet\n", style="dim")
        elif right_type == "metrics":
            right_content.append("─ Metrics ─\n", style="bold cyan")
            if session_meta and hasattr(session_meta, "messages"):
                right_content.append(f"  Messages: {len(session_meta.messages)}\n")
            right_content.append(f"  Findings: {len(findings or [])}\n")
        elif right_type == "cheatsheet":
            right_content.append("─ Quick Reference ─\n", style="bold cyan")
            right_content.append("  /help    — Show commands\n")
            right_content.append("  /run     — Execute command\n")
            right_content.append("  /status  — Session status\n")
            right_content.append("  /tools   — List tools\n")
            right_content.append("  /exit    — Exit chat\n")
        elif right_type == "attack_map":
            right_content.append("─ Attack Surface ─\n", style="bold cyan")
            sev_counts: dict[str, int] = {}
            for f in (findings or []):
                sev = f.get("severity", "info") if isinstance(f, dict) else "info"
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            for sev, count in sorted(sev_counts.items()):
                right_content.append(f"  {sev}: {count}\n")
            if not sev_counts:
                right_content.append("  No findings\n", style="dim")
        else:
            right_content.append("─ Session Info ─\n", style="bold cyan")
            if session_meta and hasattr(session_meta, "session_id"):
                right_content.append(f"  ID: {session_meta.session_id[:8]}\n")
                right_content.append(f"  Target: {session_meta.target or 'none'}\n")
                right_content.append(f"  Mode: {session_meta.mode}\n")

        left_panel = Panel(left_renderable or Text("No content"), title="Chat", border_style="cyan", width=60)
        right_panel = Panel(right_content, title=right_type or "Info", border_style="dim", width=40)

        from rich.columns import Columns
        layout = Columns([left_panel, right_panel], expand=True)
        from io import StringIO
        from rich.console import Console as RichConsole
        buf = StringIO()
        tmp = RichConsole(file=buf, width=120, force_terminal=True)
        tmp.print(layout)
        return buf.getvalue()


class ConfigPanel:
    @staticmethod
    def run() -> None:
        from ..config import SettingsStore

        s = SettingsStore()
        keys = [
            "color_theme",
            "model_provider",
            "gemini_model",
            "openai_model",
            "anthropic_model",
            "openrouter_model",
            "ollama_model",
            "ollama_url",
            "log_level",
        ]
        _output_engine.print_info("Configuration")
        for k in keys:
            v = s.get(k)
            if v is not None:
                _output_engine.print_info(f"  {k}: {v}")
            else:
                _output_engine.print_info(f"  {k}: (not set)")
        _output_engine.print_info("Use /model, /theme, /mode, /key to change settings.")

    @staticmethod
    def _section_tools() -> None:
        try:
            from ..registry import ToolRegistry

            reg = ToolRegistry()
            count = reg.discover_from_path()
            tools = reg.list_tools()
            if tools:
                engine = _output_engine
                engine.print_info(f"Discovered {count} security tools")
                for t in sorted(tools, key=lambda x: x.category)[:20]:
                    engine.print_info(f"  {t.name} ({t.category}) v{t.version[:20]}")
                if len(tools) > 20:
                    engine.print_info(f"  ... and {len(tools) - 20} more")
            else:
                _output_engine.print_warning("No tools found on PATH.")
        except Exception as exc:
            _output_engine.print_error(f"Tool discovery error: {exc}")
