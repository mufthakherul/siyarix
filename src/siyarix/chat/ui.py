# SPDX-License-Identifier: AGPL-3.0-or-later

"""Chat UI components — SmartAutocomplete, SplitPane, ConfigPanel, WelcomeBanner.

Provides context-aware autocomplete with fuzzy matching, recency ranking,
category headers, and per-command argument suggestions with type info.
"""

from __future__ import annotations

import difflib
import time
from typing import Any, Generator

from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.console import Console as RichConsole, Group

from ..output import output as _output_engine
from ..branding import resolve_version
from .commands import CommandRegistry

# ═══════════════════════════════════════════════════════════════════════════
# SmartAutocomplete — professional multi-tier completer
# ═══════════════════════════════════════════════════════════════════════════

_ARG_META: dict[str, str] = {
    "mode": "execution mode",
    "format": "output format",
    "toggle": "on/off/status",
    "rating": "1-5 or text rating",
    "language": "ISO language code",
    "tool": "security tool name",
    "model": "AI model name",
    "provider": "LLM provider name",
    "target": "IP/hostname/URL",
    "session_id": "session identifier",
    "category": "tool category",
    "intent": "cross-platform command intent",
    "profile_name": "saved command profile",
    "persona": "AI persona name",
    "theme": "UI color theme name",
    "number": "integer value",
    "text": "free-form text",
    "config_action": "show / set / get / list / tools",
    "log_action": "list / show / export",
    "alias_action": "list / set / remove",
    "split_type": "timeline / metrics / cheatsheet / attack_map / off",
    "section": "docs section name",
    "topic": "tutorial topic",
    "socket_action": "connect / status / disconnect",
    "playbook_action": "list / show / run",
    "plugins_action": "list / status",
    "siem_action": "connect / status / disconnect",
    "detail": "show detailed breakdown",
    "command_text": "command string to save",
    "stealth_action": "status / on / off / level",
    "audit_action": "export / status / verify",
    "queue_action": "status / list / retry / clear / flush",
    "cache_action": "status / clear / invalidate",
    "perf_action": "status / tune / configure",
    "campaign_action": "list / create / status",
    "ticket_action": "create / list",
    "retest_action": "schedule / status",
    "opsec_action": "isolate / burn / status / disable",
    "agent_action": "run / status",
    "intel_action": "lookup / status",
    "kb_action": "search / list",
    "skills_action": "stats / list / show / edit / remove / add / export",
}


class SmartAutocomplete(Completer):
    """Context-aware autocomplete with fuzzy matching, recency ranking,
    category headers, type annotations, and per-command argument suggestions."""

    _ARG_COMMANDS: dict[str, str] = {
        "/run": "tool",
        "/model": "model",
        "/provider": "provider",
        "/key": "provider",
        "/target": "target",
        "/mode": "mode",
        "/persona": "persona",
        "/theme": "theme",
        "/search": "text",
        "/history": "number",
        "/scan": "target",
        "/load": "session_id",
        "/fork": "number",
        "/diff": "session_id",
        "/batch": "file",
        "/playbook": "playbook_action",
        "/export": "format",
        "/report": "format",
        "/config": "config_action",
        "/log": "log_action",
        "/alias": "alias_action",
        "/learn": "toggle",
        "/feedback": "rating",
        "/language": "language",
        "/stealth": "stealth_action",
        "/audit": "audit_action",
        "/queue": "queue_action",
        "/cache": "cache_action",
        "/performance": "perf_action",
        "/campaign": "campaign_action",
        "/ticket": "ticket_action",
        "/retest": "retest_action",
        "/opsec": "opsec_action",
        "/agent": "agent_action",
        "/intel": "intel_action",
        "/kb": "kb_action",
        "/skills": "skills_action",
        "/docs": "section",
        "/tutorial": "topic",
        "/benchmark": "provider",
        "/split": "split_type",
        "/socket": "socket_action",
        "/save": "session_id",
        "/cmd": "profile_name",
        "/tools": "category",
        "/translate": "intent",
        "/savecmd": "command_text",
        "/siem": "siem_action",
        "/stats": "detail",
        "/plugins": "plugins_action",
        "/review": "toggle",
        "/help": "text",
        "/h": "text",
        "/?": "text",
    }

    _STATIC_ARG_CHOICES: dict[str, list[str]] = {
        "mode": [
            "autonomous",
            "integrated",
            "offline",
            "stealth",
            "verbose",
            "quiet",
            "interactive",
            "batch",
            "expert",
            "beginner",
            "redteam",
            "blueteam",
            "compliance",
            "audit",
        ],
        "format": ["json", "md", "markdown", "html", "pdf", "txt"],
        "toggle": ["on", "off", "status"],
        "rating": ["1", "2", "3", "4", "5", "good", "bad", "excellent", "poor"],
        "language": ["en", "fr", "de", "es", "it", "pt", "ru", "zh", "ja", "ko", "ar"],
        "stealth_action": ["status", "on", "off", "level"],
        "audit_action": ["export", "status", "verify"],
        "queue_action": ["status", "list", "retry", "clear", "flush"],
        "cache_action": ["status", "clear", "invalidate"],
        "perf_action": ["status", "tune", "configure"],
        "campaign_action": ["list", "create", "status"],
        "ticket_action": ["create", "list"],
        "retest_action": ["schedule", "status"],
        "opsec_action": ["isolate", "burn", "status", "disable"],
        "agent_action": ["run", "status"],
        "intel_action": ["lookup", "status"],
        "kb_action": ["search", "list"],
        "skills_action": ["stats", "list", "show", "edit", "remove", "add", "export"],
        "config_action": ["show", "set", "get", "list", "tools"],
        "log_action": ["list", "show", "export"],
        "alias_action": ["list", "set", "remove"],
        "split_type": ["timeline", "metrics", "cheatsheet", "attack_map", "off", "disable"],
        "section": [
            "getting-started",
            "commands",
            "configuration",
            "providers",
            "plugins",
            "playbooks",
            "api",
            "troubleshooting",
        ],
        "topic": [
            "basics",
            "scanning",
            "recon",
            "exploitation",
            "reporting",
            "playbooks",
            "aliases",
            "learning",
        ],
        "socket_action": ["connect", "status", "disconnect"],
        "playbook_action": ["list", "show", "run"],
        "plugins_action": ["list", "status"],
        "siem_action": ["connect", "status", "disconnect"],
        "detail": ["detail"],
        "command_text": [],
        "number": [],
        "text": [],
        "target": [],
        "theme": [],
        "persona": [],
        "session_id": [],
        "profile_name": [],
        "category": [],
        "intent": [],
        "provider": [],
        "model": [],
        "tool": [],
    }

    def __init__(self, session: Any = None) -> None:
        self._session = session
        self._path_completer = PathCompleter()
        self._tool_cache: list[str] = []
        self._model_cache: list[str] = []
        self._provider_cache: list[str] = []
        self._session_cache: list[str] = []
        self._last_cache_refresh = 0.0

    def _refresh_caches(self) -> None:
        now = time.time()
        if now - self._last_cache_refresh < 30.0:
            return
        self._last_cache_refresh = now
        self._tool_cache.clear()
        self._model_cache.clear()
        self._provider_cache.clear()
        self._session_cache.clear()
        try:
            from ..registry import ToolRegistry

            reg = ToolRegistry()
            tools = reg.list_tools()
            self._tool_cache = [t.name for t in tools]
        except Exception:
            self._tool_cache = []
        try:
            from ..providers import ProviderManager

            mgr = ProviderManager.get_instance()
            for prov in mgr.list_providers():
                models = mgr.get_models(prov)
                self._model_cache.extend(models)
                self._provider_cache.append(prov)
        except Exception:
            self._model_cache = []

    def _complete_arg(self, arg_type: str, prefix: str) -> Generator[Completion, None, None]:
        self._refresh_caches()

        meta = _ARG_META.get(arg_type, arg_type)

        static = self._STATIC_ARG_CHOICES.get(arg_type)
        if static:
            for choice in static:
                if not prefix or choice.startswith(prefix):
                    yield Completion(
                        choice,
                        start_position=-len(prefix),
                        display_meta=f"[{meta}]",
                        style="white",
                    )

        if arg_type == "tool":
            for name in self._tool_cache:
                if name.startswith(prefix):
                    yield Completion(name, start_position=-len(prefix), display_meta=f"[{meta}]")
        elif arg_type == "model":
            for name in self._model_cache:
                if name.startswith(prefix):
                    yield Completion(name, start_position=-len(prefix), display_meta=f"[{meta}]")
        elif arg_type == "provider":
            for prov in self._provider_cache:
                if prov.startswith(prefix):
                    yield Completion(prov, start_position=-len(prefix), display_meta=f"[{meta}]")
        elif arg_type == "persona":
            try:
                from ..personas import list_personas

                for p in list_personas():
                    name = p.get("name", "")
                    label = p.get("label", "")
                    if name.startswith(prefix):
                        yield Completion(
                            name, start_position=-len(prefix), display_meta=f"[{meta}] {label}"
                        )
                for extra in ("auto", "universal", "none"):
                    if extra.startswith(prefix):
                        yield Completion(
                            extra, start_position=-len(prefix), display_meta=f"[{meta}]"
                        )
            except Exception:
                pass
        elif arg_type == "session_id":
            try:
                from ..config import get_config_dir

                sessions_dir = get_config_dir() / "sessions"
                if sessions_dir.exists():
                    for sf in sorted(
                        sessions_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
                    )[:20]:
                        sid = sf.stem
                        if sid.startswith(prefix):
                            yield Completion(
                                sid, start_position=-len(prefix), display_meta=f"[{meta}]"
                            )
            except Exception:
                pass
        elif arg_type == "category":
            try:
                from ..tool_models import ToolCategory

                for cat in ToolCategory:
                    if cat.value.startswith(prefix):
                        yield Completion(
                            cat.value, start_position=-len(prefix), display_meta=f"[{meta}]"
                        )
            except Exception:
                pass
        elif arg_type == "intent":
            try:
                from .platform_utils import CROSS_PLATFORM_COMMANDS

                for intent in sorted(CROSS_PLATFORM_COMMANDS.keys()):
                    if intent.startswith(prefix):
                        yield Completion(
                            intent, start_position=-len(prefix), display_meta=f"[{meta}]"
                        )
            except Exception:
                pass
        elif arg_type == "profile_name":
            try:
                from .commands import CommandProfileStore

                store = CommandProfileStore()
                for profile in store.list_profiles():
                    if profile.name.startswith(prefix):
                        yield Completion(
                            profile.name, start_position=-len(prefix), display_meta=f"[{meta}]"
                        )
            except Exception:
                pass

    def get_completions(self, document: Any, complete_event: Any) -> Any:
        text = document.text_before_cursor

        if text.startswith("/"):
            parts = text.split()
            cmd = parts[0] if parts else ""

            if len(parts) <= 1:
                prefix = cmd.lstrip("/")
                current_mode = (
                    getattr(self._session, "mode", "integrated") if self._session else "integrated"
                )
                commands = CommandRegistry.visible_commands_for_mode(current_mode)
                seen = set()

                # Track category groups for ordering
                cat_order: dict[str, int] = {}
                for i, info in enumerate(commands):
                    cat = info.category.value
                    if cat not in cat_order:
                        cat_order[cat] = len(cat_order)

                for info in commands:
                    primary = info.name.lstrip("/")
                    names = [primary] + [a.lstrip("/") for a in info.aliases]
                    best_name = None
                    best_ratio = 0.0
                    for name in names:
                        if name in seen:
                            continue
                        if name.startswith(prefix):
                            best_name = name
                            best_ratio = 1.0
                            break
                        ratio = difflib.SequenceMatcher(None, prefix, name).ratio()
                        if ratio > best_ratio and ratio > 0.5:
                            best_ratio = ratio
                            best_name = name
                    if best_name and best_name not in seen:
                        seen.add(best_name)
                        meta = f"[{info.category.value}] {info.description[:60]}"
                        fuzzy_flag = " ~" if best_ratio < 1.0 else ""
                        yield Completion(
                            info.name,
                            start_position=-len(prefix) - 1,
                            display_meta=f"{fuzzy_flag} {meta}",
                            style="bold ansibrightcyan" if best_ratio >= 1.0 else "white",
                        )
                return

            arg_type = self._ARG_COMMANDS.get(cmd)
            if arg_type:
                prefix = parts[-1]
                yield from self._complete_arg(arg_type, prefix)
            return

        word = document.get_word_before_cursor(WORD=True)
        if word.startswith("@"):
            adjusted = document.text.replace("@", "", 1)
            pos = max(0, document.cursor_position - 1)
            document_copy = Document(text=adjusted, cursor_position=pos)
            for completion in self._path_completer.get_completions(document_copy, complete_event):
                yield completion
        elif "/" in word or "\\" in word or word.startswith("."):
            for completion in self._path_completer.get_completions(document, complete_event):
                yield completion


# ═══════════════════════════════════════════════════════════════════════════
# WelcomeBanner — premium Rich Layout welcome screen
# ═══════════════════════════════════════════════════════════════════════════


def render_welcome_banner(
    mode: str,
    provider: str,
    persona: str,
    theme: str,
    session_id: str,
    shell_info: str,
    scans_count: int = 0,
    findings_count: int = 0,
    tool_count: int = 0,
    llm_calls: int = 0,
    command_count: int = 0,
    msg_count: int = 0,
    provider_status: dict[str, tuple[str, str]] | None = None,
) -> Group:
    """Render a professional welcome banner using Rich Layout."""

    ver = resolve_version()

    # ── Header: brand + version + tagline ──
    mode_color_map = {
        "redteam": "red",
        "blueteam": "blue",
        "stealth": "red",
        "offline": "yellow",
        "autonomous": "magenta",
    }
    accent = mode_color_map.get(mode, "cyan")

    header_text = Text.assemble(
        (" █▓▒░ ", f"bold {accent}"),
        ("SIYARIX ORCHESTRATOR ", "bold white"),
        (f"v{ver} ", "bold green"),
        ("░▒▓█ ", f"bold {accent}"),
        ("\n", ""),
        ("CLI-Based AI-Native Cyber Operations Platform", "dim italic white"),
    )

    header_panel = Align.center(
        Panel(
            Align.center(header_text, vertical="middle"),
            border_style=accent,
            padding=(0, 2),
            width=68,
        )
    )

    # ── Middle: stats panels ──

    session_panel = Panel(
        f"[bold #00ffcc]Platform:[/bold #00ffcc] [white]{shell_info}[/white]\n"
        f"[bold #00ffcc]Mode:[/bold #00ffcc] [white]{mode}[/white]\n"
        f"[bold #00ffcc]Provider:[/bold #00ffcc] [white]{provider}[/white]\n"
        f"[bold #00ffcc]Persona:[/bold #00ffcc] [white]{persona}[/white]\n"
        f"[bold #00ffcc]Theme:[/bold #00ffcc] [white]{theme}[/white]\n"
        f"[bold #00ffcc]Session:[/bold #00ffcc] [white]{session_id[:8]}[/white]",
        title="[bold]Session[/bold]",
        border_style=accent,
    )

    telemetry_panel = Panel(
        f"[bold #ff00ff]Scans:[/bold #ff00ff] [white]{scans_count}[/white]\n"
        f"[bold #ff00ff]Findings:[/bold #ff00ff] [white]{findings_count}[/white]\n"
        f"[bold #ff00ff]Tools:[/bold #ff00ff] [white]{tool_count}[/white]\n"
        f"[bold #ff00ff]Commands:[/bold #ff00ff] [white]{command_count}[/white]\n"
        f"[bold #ff00ff]Messages:[/bold #ff00ff] [white]{msg_count}[/white]\n"
        f"[bold #ff00ff]LLM Calls:[/bold #ff00ff] [white]{llm_calls}[/white]",
        title="[bold]Telemetry[/bold]",
        border_style="magenta",
    )

    top_cmds = CommandRegistry.top_commands(8)
    quick_lines_text = ""
    for c in top_cmds[:6]:
        name_display = c.usage if c.usage else c.name
        quick_lines_text += (
            f"[bold white]{name_display}[/bold white]  [dim]— {c.description[:40]}[/dim]\n"
        )
    if not quick_lines_text:
        quick_lines_text = (
            "[bold white]/help[/bold white]  [dim]— all commands[/dim]\n"
            "[bold white]/scan <tgt>[/bold white]  [dim]— scan target[/dim]\n"
            "[bold white]/model <name>[/bold white]  [dim]— switch LLM[/dim]\n"
            "[bold white]/mode <mode>[/bold white]  [dim]— switch mode[/dim]\n"
        )

    quick_panel = Panel(
        quick_lines_text.strip(),
        title="[bold]Quick Actions[/bold]",
        border_style="green",
    )

    if provider_status:
        parts = []
        for name in sorted(provider_status, key=lambda n: (provider_status[n][0] != "✓", n)):
            icon, reason = provider_status[name]
            if icon == "✓":
                parts.append(f"[bold green]✓[/bold green] {name} [dim]({reason})[/dim]")
            elif icon == "⚠":
                parts.append(f"[bold yellow]⚠[/bold yellow] {name} [dim]({reason})[/dim]")
            elif icon == "✗":
                parts.append(f"[dim bright_black]✗[/dim bright_black] {name} [dim]({reason})[/dim]")
        runtime_txt = "\n".join(parts) if parts else "[dim]No providers configured[/dim]"
    else:
        runtime_txt = "[dim]No providers configured[/dim]"

    llm_panel = Panel(runtime_txt, title="[bold]LLM Status[/bold]", border_style="yellow")

    stats_row = Columns([session_panel, telemetry_panel, quick_panel, llm_panel], expand=True)

    # ── Footer: tips ──
    mode_tips = {
        "redteam": "[red]Red Team mode — offensive operations. Tab for autocomplete | /help | /scan <target> | /stealth for evasion[/red]",
        "blueteam": "[blue]Blue Team mode — defensive posture. Tab for autocomplete | /help | /audit for compliance | /review on for safety[/blue]",
        "stealth": "[red]Stealth mode active — /stealth status to check | /opsec for operational security controls[/red]",
        "offline": "[yellow]Offline mode — no LLM needed. /queue for queued commands | /scan <target> for local scans[/yellow]",
        "autonomous": "[magenta]Autonomous mode — AI-driven operations. /model to configure LLM | /agent run <goal> for sub-agents[/magenta]",
    }
    tip = mode_tips.get(mode, "[dim]Press Tab for autocomplete | ? or /help for all commands[/dim]")

    footer_content = Text.assemble(
        ("Type natural language ", "bold cyan"),
        ("to plan work, or use slash commands.\n", "white"),
        ("  Examples: ", "dim"),
        ("scan 10.0.0.5", "green"),
        ("  ", ""),
        ("enumerate example.com", "green"),
        ("  ", ""),
        ("/theme cyber-noir", "green"),
        ("\n", ""),
        (tip, "white"),
    )

    footer_panel = Panel(
        footer_content,
        title="[bold bright_black]Tip[/bold bright_black]",
        border_style="bright_black",
    )

    return Group(header_panel, stats_row, footer_panel)


# ═══════════════════════════════════════════════════════════════════════════
# SplitPane — terminal split-pane layout renderer
# ═══════════════════════════════════════════════════════════════════════════


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
        from rich.panel import Panel as RichPanel
        from rich.text import Text as RichText

        right_content = RichText()
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
            for f in findings or []:
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

        left_panel = RichPanel(
            left_renderable or RichText("No content"),
            title="Chat",
            border_style="cyan",
            width=60,
        )
        right_panel = RichPanel(
            right_content,
            title=right_type or "Info",
            border_style="dim",
            width=40,
        )

        layout = Columns([left_panel, right_panel], expand=True)
        buf = __import__("io").StringIO()
        tmp = RichConsole(file=buf, width=120, force_terminal=True)
        tmp.print(layout)
        return str(buf.getvalue())


# ═══════════════════════════════════════════════════════════════════════════
# ConfigPanel — static configuration display
# ═══════════════════════════════════════════════════════════════════════════


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
                    engine.print_info(f"  {t.name} ({t.category})")
                if len(tools) > 20:
                    engine.print_info(f"  ... and {len(tools) - 20} more")
            else:
                _output_engine.print_warning("No tools found on PATH.")
        except Exception as exc:
            _output_engine.print_error(f"Tool discovery error: {exc}")


__all__ = [
    "SmartAutocomplete",
    "render_welcome_banner",
    "SplitPane",
    "ConfigPanel",
]
