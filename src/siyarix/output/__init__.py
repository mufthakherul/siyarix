# SPDX-License-Identifier: AGPL-3.0-or-later

"""Premium Output Engine — Rich tables, panels, progress, colors, exports.

Features:
  • Multiple output formats: table, json, yaml, csv, html, xml
  • Rich console with themes, colors, animations
  • Live dashboards with sparklines
  • Export to file with formatting
  • Progress bars with ETA, transfer speeds
  • Interactive prompts & confirmations
  • Syntax highlighting for code output
  • Gradient banners & premium panels
"""

from __future__ import annotations

import csv
import io
import getpass as _getpass
import json
import logging
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

YAML_AVAILABLE = False
_yaml: Any = None
try:
    import yaml as _yaml  # type: ignore[import-untyped,no-redef]

    YAML_AVAILABLE = True
except ImportError:
    pass

yaml = _yaml

Console: Any = None
BarColumn: Any = None
Progress: Any = None
SpinnerColumn: Any = None
TaskProgressColumn: Any = None
TextColumn: Any = None
TimeRemainingColumn: Any = None
TransferSpeedColumn: Any = None
Confirm: Any = None
Prompt: Any = None
Syntax: Any = None
Table: Any = None

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"
    HTML = "html"
    XML = "xml"
    RAW = "raw"
    QUIET = "quiet"


class OutputTheme(StrEnum):
    """Output theme names — delegates to branding module for actual style data."""

    CYBER_NOIR = "cyber-noir"
    MATRIX = "matrix"
    BLOODMOON = "bloodmoon"
    ARCTIC = "arctic"
    GOLDENROD = "goldenrod"
    ECLIPSE = "eclipse"
    SYNTHWAVE = "synthwave"
    DARK = "cyber-noir"
    LIGHT = "arctic"
    NEON = "synthwave"
    MINIMAL = "eclipse"
    DEFAULT = "cyber-noir"


def _load_branding_themes() -> dict[str, dict[str, str]]:
    """Load theme data from the canonical branding module."""
    from ..branding import _SEVERITY_STYLES

    return dict(_SEVERITY_STYLES)


THEMES = _load_branding_themes()


class OutputEngine:
    """Premium output engine"""

    def __init__(self, theme: str = "default", output_format: str = "table") -> None:
        try:
            theme_key = OutputTheme(theme)
        except Exception:
            theme_key = OutputTheme.DEFAULT
        self.theme = THEMES.get(theme_key, THEMES[OutputTheme.DEFAULT])
        self.format = OutputFormat(output_format)
        self.console: Any = Console() if RICH_AVAILABLE else None

    def print_banner(self, title: str, subtitle: str = "", style: str = "primary") -> None:
        if RICH_AVAILABLE and self.console is not None:
            from ..branding import print_banner as _print_branding_banner

            _print_branding_banner(
                console=self.console,
                theme=list(THEMES.keys())[0] if THEMES else "default",
                subtitle=title,
            )
        else:
            self._raw_print(f"\n{'=' * 30}")
            self._raw_print(f"  {title}")
            if subtitle:
                self._raw_print(f"  {subtitle}")
            self._raw_print(f"{'=' * 30}\n")

    def print_table(
        self, data: list[dict], title: str = "", columns: list[str] | None = None
    ) -> None:
        if not data:
            self.print_warning("No data to display")
            return
        if not columns:
            columns = list(data[0].keys())
        if RICH_AVAILABLE and self.format == OutputFormat.TABLE:
            table = Table(
                title=title,
                show_header=True,
                header_style=f"bold {self.theme['primary']}",
            )
            for col in columns:
                table.add_column(col.replace("_", " ").title(), style=self.theme["info"])
            for row in data:
                table.add_row(*[str(row.get(col, "")) for col in columns])
            if self.console is not None:
                self.console.print(table)
        else:
            for row in data:
                self._raw_print("\t".join(str(row.get(col, "")) for col in columns))

    def print_json(self, data: Any) -> None:
        if RICH_AVAILABLE and self.format == OutputFormat.JSON:
            json_str = json.dumps(data, indent=2)
            syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
            if self.console is not None:
                self.console.print(syntax)
        else:
            self._raw_print(json.dumps(data, indent=2))

    def print_yaml(self, data: Any) -> None:
        if not YAML_AVAILABLE:
            self.print_error("PyYAML not installed. Install with: pip install pyyaml")
            return
        if RICH_AVAILABLE:
            yaml_str = yaml.dump(data, default_flow_style=False)
            syntax = Syntax(yaml_str, "yaml", theme="monokai")
            if self.console is not None:
                self.console.print(syntax)
        else:
            self._raw_print(yaml.dump(data, default_flow_style=False))

    def print_csv(self, data: list[dict]) -> None:
        if not data:
            return
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        if RICH_AVAILABLE:
            syntax = Syntax(output.getvalue(), "csv", theme="monokai")
            if self.console is not None:
                self.console.print(syntax)
            else:
                self._raw_print(output.getvalue())
        else:
            self._raw_print(output.getvalue())

    def print_success(self, message: str) -> None:
        if RICH_AVAILABLE and self.console is not None:
            self.console.print(f"[{self.theme['success']}]✓ {message}[/{self.theme['success']}]")
        else:
            self._raw_print(f"✓ {message}")

    def print_error(self, message: str) -> None:
        if RICH_AVAILABLE and self.console is not None:
            error_style = self.theme.get("error", self.theme.get("critical", "red"))
            self.console.print(f"[{error_style}]✗ {message}[/{error_style}]")
        else:
            self._raw_print(f"✗ Error: {message}")

    def print_warning(self, message: str) -> None:
        if RICH_AVAILABLE and self.console is not None:
            warning_style = self.theme.get("warning", self.theme.get("medium", "yellow"))
            self.console.print(f"[{warning_style}]⚠ {message}[/{warning_style}]")
        else:
            self._raw_print(f"⚠ Warning: {message}")

    def print_info(self, message: str) -> None:
        if RICH_AVAILABLE and self.console is not None:
            self.console.print(f"[{self.theme['info']}]ℹ {message}[/{self.theme['info']}]")
        else:
            self._raw_print(f"ℹ {message}")

    def print_progress(
        self,
        items: list,
        process_fn: Callable[[Any], Any],
        description: str = "Processing",
    ) -> None:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn(f"[progress.description]{description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                TransferSpeedColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task(description, total=len(items))
                for item in items:
                    process_fn(item)
                    progress.advance(task)
        else:
            for i, item in enumerate(items, 1):
                self._raw_print(f"{description} ({i}/{len(items)})...")
                process_fn(item)

    def prompt_confirm(self, message: str, default: bool = False) -> bool:
        if RICH_AVAILABLE:
            return Confirm.ask(message, default=default)
        response = input(f"{message} (y/n) [{'Y' if default else 'n'}]: ").strip().lower()
        if not response:
            return default
        return response in ("y", "yes")

    def prompt_input(self, message: str, default: str = "", password: bool = False) -> str:
        if RICH_AVAILABLE and self.console is not None:
            return Prompt.ask(message, default=default, password=password)
        if password:
            return _getpass.getpass(f"{message}: ")
        return input(f"{message} [{default}]: ").strip() or default

    def _export_data(self, data: list[dict]) -> None:
        if self.format == OutputFormat.JSON:
            self.print_json(data)
        elif self.format == OutputFormat.YAML:
            self.print_yaml(data)
        elif self.format == OutputFormat.CSV:
            self.print_csv(data)
        elif self.format == OutputFormat.HTML:
            self._export_html(data)
        elif self.format == OutputFormat.XML:
            self._export_xml(data)
        else:
            self._raw_print(str(data))

    def _export_html(self, data: list[dict]) -> None:
        if not data:
            return
        html = "<table border='1'>\n<thead><tr>\n"
        for col in data[0]:
            html += f"  <th>{col}</th>\n"
        html += "</tr></thead>\n<tbody>\n"
        for row in data:
            html += "<tr>\n"
            for col in data[0]:
                html += f"  <td>{row.get(col, '')}</td>\n"
            html += "</tr>\n"
        html += "</tbody>\n</table>"
        if RICH_AVAILABLE and self.console is not None:
            self.console.print(html)
        else:
            self._raw_print(html)

    def _export_xml(self, data: list[dict]) -> None:
        xml = "<?xml version='1.0' encoding='UTF-8'?>\n<data>\n"
        for i, row in enumerate(data):
            xml += f"  <item id='{i}'>\n"
            for key, value in row.items():
                xml += f"    <{key}>{value}</{key}>\n"
            xml += "  </item>\n"
        xml += "</data>"
        if RICH_AVAILABLE and self.console is not None:
            self.console.print(xml)
        else:
            self._raw_print(xml)

    def export_to_file(self, data: Any, filepath: str) -> None:
        path = Path(filepath)
        suffix = path.suffix.lstrip(".")
        try:
            fmt = OutputFormat(suffix)
        except ValueError:
            fmt = OutputFormat.RAW
        if fmt == OutputFormat.JSON:
            path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        elif fmt == OutputFormat.YAML and YAML_AVAILABLE:
            path.write_text(yaml.dump(data), encoding='utf-8')
        elif fmt == OutputFormat.CSV and isinstance(data, list):
            with path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        else:
            path.write_text(str(data), encoding='utf-8')
        if RICH_AVAILABLE:
            self.print_success(f"Exported to {filepath}")
        else:
            self._raw_print(f"Exported to {filepath}")

    def _raw_print(self, text: str) -> None:
        if self.console is not None:
            try:
                self.console.print(text)
                return
            except Exception:
                logger.exception("Console print failed in OutputEngine")
        print(text)


output = OutputEngine()

_formatter_args: dict[str, object] = {"no_color": False, "verbose": 0}


class OutputFormatter:
    def __init__(self, fmt: str = "table", no_color: bool = False, verbose: int = 0):
        self.fmt = fmt
        self.no_color = no_color
        self.verbose = verbose
        self.engine = OutputEngine(output_format=fmt)

    def json(self, data: Any) -> None:
        self.engine.print_json(data)

    def csv(self, data: list[dict]) -> None:
        self.engine.print_csv(data)

    def yaml(self, data: Any) -> None:
        self.engine.print_yaml(data)

    def quiet(self, data: dict, key: str | None = None) -> None:
        if key and key in data:
            if self.engine.console is not None:
                self.engine.console.print(data[key])
            else:
                self._raw_print(str(data[key]))

    def _raw_print(self, text: str) -> None:
        console = self.engine.console
        if console is not None:
            try:
                console.print(text)
                return
            except Exception as exc:
                logger.exception("Console print failed: %s", exc)
        print(text)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_AUTH_ERROR = 2


def get_formatter(format: str = "table") -> OutputFormatter:
    no_color = bool(_formatter_args.get("no_color", False))
    try:
        verbose = int(str(_formatter_args.get("verbose", 0)))
    except Exception:
        verbose = 0
    return OutputFormatter(fmt=format, no_color=no_color, verbose=verbose)


def set_formatter(
    formatter: OutputFormatter | str, no_color: bool = False, verbose: int = 0
) -> None:
    global output, _formatter_args
    _formatter_args = {"no_color": no_color, "verbose": verbose}
    if isinstance(formatter, str):
        formatter = get_formatter(formatter)
    output = OutputEngine(output_format=formatter.fmt)


__all__ = [
    "EXIT_OK",
    "EXIT_ERROR",
    "EXIT_AUTH_ERROR",
    "OutputFormatter",
    "OutputFormat",
    "OutputTheme",
    "THEMES",
    "OutputEngine",
    "output",
    "get_formatter",
    "set_formatter",
]
