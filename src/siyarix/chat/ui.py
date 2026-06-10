# SPDX-License-Identifier: AGPL-3.0-or-later

"""Chat UI components — SplitPane, ConfigPanel, SmartAutocomplete, CommandPalette."""

from __future__ import annotations

from typing import Any

from ..output import output as _output_engine


class SmartAutocomplete:
    def __init__(self, session: Any) -> None:
        pass

    def get_completions(self, document: Any, complete_event: Any) -> list[Any]:
        return []


class CommandPalette:
    def __init__(self, session_id: str) -> None:
        pass

    def show(self, console: Any) -> str | None:
        return None


class SplitPane:
    def __init__(self, theme: str = "dark-neon") -> None:
        pass

    def generate_layout(
        self,
        left_renderable: Any = None,
        right_type: str = "",
        session_meta: Any = None,
        findings: list[Any] | None = None,
        timeline_events: list[Any] | None = None,
    ) -> str:
        return ""


class ConfigPanel:
    @staticmethod
    def run() -> None:
        from ..config import SettingsStore

        s = SettingsStore()
        keys = [
            "color_theme", "model_provider", "gemini_model", "openai_model",
            "anthropic_model", "openrouter_model", "ollama_model", "ollama_url", "log_level",
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
