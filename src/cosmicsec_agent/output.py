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
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from rich.align import Align
    from rich.color import Color
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
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
    from rich.rule import Rule
    from rich.style import Style
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

class OutputFormat(StrEnum):
    """Output formats"""

    TABLE = "table"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"
    HTML = "html"
    XML = "xml"
    RAW = "raw"
    QUIET = "quiet"

class OutputTheme(StrEnum):
    """Output themes"""

    DEFAULT = "default"
    DARK = "dark"
    LIGHT = "light"
    NEON = "neon"
    MINIMAL = "minimal"

# Premium color schemes
THEMES = {
    OutputTheme.DEFAULT: {
        "primary": "cyan",
        "secondary": "magenta",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "info": "blue",
        "muted": "bright_black",
    },
    OutputTheme.DARK: {
        "primary": "bright_cyan",
        "secondary": "bright_magenta",
        "success": "bright_green",
        "warning": "bright_yellow",
        "error": "bright_red",
        "info": "bright_blue",
        "muted": "bright_black",
    },
    OutputTheme.NEON: {
        "primary": "rgb(0,255,255)",
        "secondary": "rgb(255,0,255)",
        "success": "rgb(0,255,0)",
        "warning": "rgb(255,255,0)",
        "error": "rgb(255,0,0)",
        "info": "rgb(0,100,255)",
        "muted": "rgb(100,100,100)",
    },
    OutputTheme.MINIMAL: {
        "primary": "white",
        "secondary": "white",
        "success": "white",
        "warning": "white",
        "error": "white",
        "info": "white",
        "muted": "bright_black",
    },
}

class OutputEngine:
    """Premium output engine"""

    def __init__(self, theme: str = "default", output_format: str = "table"):
        self.theme = THEMES.get(OutputTheme(theme), THEMES[OutputTheme.DEFAULT])
        self.format = OutputFormat(output_format)
        self.console = Console() if RICH_AVAILABLE else None

    def print_banner(self, title: str, subtitle: str = "", style: str = "primary"):
        """Print premium gradient banner"""
        if RICH_AVAILABLE:
            banner_text = Text()
            banner_text.append(title, style=self.theme[style])
            if subtitle:
                banner_text.append(f"\n{subtitle}", style=self.theme["muted"])
            panel = Panel(
                Align.center(banner_text),
                border_style=self.theme[style],
                padding=(1, 4),
            )
            self.console.print(panel)
        else:
            print(f"\n{'='*30}")
            print(f"  {title}")
            if subtitle:
                print(f"  {subtitle}")
            print(f"{'='*30}\n")

    def print_table(self, data: list[dict], title: str = "", columns: list[str] | None = None):
        """Print rich table"""
        if not data:
            self.print_warning("No data to display")
            return

        if not columns:
            columns = list(data[0].keys())

        if RICH_AVAILABLE and self.format == OutputFormat.TABLE:
            table = Table(title=title, show_header=True, header_style=f"bold {self.theme['primary']}")
            for col in columns:
                table.add_column(col.replace("_", " ").title(), style=self.theme["info"])
            for row in data:
                table.add_row(*[str(row.get(col, "")) for col in columns])
            self.console.print(table)
        else:
            self._export_data(data)

    def print_json(self, data: Any):
        """Print JSON with syntax highlighting"""
        if RICH_AVAILABLE and self.format == OutputFormat.JSON:
            json_str = json.dumps(data, indent=2)
            syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
            self.console.print(syntax)
        else:
            print(json.dumps(data, indent=2))

    def print_yaml(self, data: Any):
        """Print YAML"""
        if not YAML_AVAILABLE:
            self.print_error("PyYAML not installed. Install with: pip install pyyaml")
            return
        if RICH_AVAILABLE:
            yaml_str = yaml.dump(data, default_flow_style=False)
            syntax = Syntax(yaml_str, "yaml", theme="monokai")
            self.console.print(syntax)
        else:
            print(yaml.dump(data, default_flow_style=False))

    def print_csv(self, data: list[dict]):
        """Print CSV"""
        if not data:
            return
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        if RICH_AVAILABLE:
            syntax = Syntax(output.getvalue(), "csv", theme="monokai")
            self.console.print(syntax)
        else:
            print(output.getvalue())

    def print_success(self, message: str):
        """Print success message"""
        if RICH_AVAILABLE:
            self.console.print(f"[{self.theme['success']}]✓ {message}[/{self.theme['success']}]")
        else:
            print(f"✓ {message}")

    def print_error(self, message: str):
        """Print error message"""
        if RICH_AVAILABLE:
            self.console.print(f"[{self.theme['error']}]✗ {message}[/{self.theme['error']}]")
        else:
            print(f"✗ Error: {message}")

    def print_warning(self, message: str):
        """Print warning message"""
        if RICH_AVAILABLE:
            self.console.print(f"[{self.theme['warning']}]⚠ {message}[/{self.theme['warning']}]")
        else:
            print(f"⚠ Warning: {message}")

    def print_info(self, message: str):
        """Print info message"""
        if RICH_AVAILABLE:
            self.console.print(f"[{self.theme['info']}]ℹ {message}[/{self.theme['info']}]")
        else:
            print(f"ℹ {message}")

    def print_progress(self, items: list, process_fn: callable, description: str = "Processing"):
        """Print progress bar"""
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
                print(f"{description} ({i}/{len(items)})...")
                process_fn(item)

    def prompt_confirm(self, message: str, default: bool = False) -> bool:
        """Prompt for confirmation"""
        if RICH_AVAILABLE:
            return Confirm.ask(message, default=default)
        else:
            response = input(f"{message} (y/n) [{'Y' if default else 'n'}]: ").strip().lower()
            if not response:
                return default
            return response in ("y", "yes")

    def prompt_input(self, message: str, default: str = "", password: bool = False) -> str:
        """Prompt for input"""
        if RICH_AVAILABLE:
            return Prompt.ask(message, default=default, password=password)
        else:
            if password:
                import getpass

                return getpass.getpass(f"{message}: ")
            else:
                return input(f"{message} [{default}]: ").strip() or default

    def _export_data(self, data: list[dict]):
        """Export data based on format"""
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
            self.print_table(data)

    def _export_html(self, data: list[dict]):
        """Export as HTML table"""
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
        print(html)

    def _export_xml(self, data: list[dict]):
        """Export as XML"""
        xml = "<?xml version='1.0' encoding='UTF-8'?>\n<data>\n"
        for i, row in enumerate(data):
            xml += f"  <item id='{i}'>\n"
            for key, value in row.items():
                xml += f"    <{key}>{value}</{key}>\n"
            xml += "  </item>\n"
        xml += "</data>"
        print(xml)

    def export_to_file(self, data: Any, filepath: str):
        """Export data to file"""
        path = Path(filepath)
        format = OutputFormat(path.suffix.lstrip("."))

        if format == OutputFormat.JSON:
            path.write_text(json.dumps(data, indent=2))
        elif format == OutputFormat.YAML and YAML_AVAILABLE:
            path.write_text(yaml.dump(data))
        elif format == OutputFormat.CSV and isinstance(data, list):
            with path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        else:
            path.write_text(str(data))

        if RICH_AVAILABLE:
            self.print_success(f"Exported to {filepath}")
        else:
            print(f"Exported to {filepath}")

# Global output engine instance
output = OutputEngine()

_formatter_args = {"no_color": False, "verbose": 0}

class OutputFormatter:
    def __init__(self, fmt: str = "table", no_color: bool = False, verbose: int = 0):
        self.fmt = fmt
        self.no_color = no_color
        self.verbose = verbose
        self.engine = OutputEngine(output_format=fmt)

    def json(self, data):
        self.engine.print_json(data)

    def csv(self, data):
        self.engine.print_csv(data)

    def yaml(self, data):
        self.engine.print_yaml(data)

    def quiet(self, data, key=None):
        if key and key in data:
            print(data[key])

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_AUTH_ERROR = 2

def get_formatter(format: str = "table") -> OutputFormatter:
    return OutputFormatter(fmt=format, **_formatter_args)


def set_formatter(formatter: OutputFormatter | str, no_color: bool = False, verbose: int = 0):
    global output, _formatter_args
    _formatter_args = {"no_color": no_color, "verbose": verbose}
    if isinstance(formatter, str):
        formatter = get_formatter(formatter)
    output = OutputEngine(output_format=formatter.fmt)
