"""
Coder Bridge -- AI code generation and review facilitator.

Wraps an LLM provider for generating, reviewing, and explaining code
as described in Chapter 9.2.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class CodeReview:
    file_path: str
    issues: list[dict] = field(default_factory=list)
    score: int = 0

    def to_panel(self) -> Panel:
        text = f"[bold]File:[/bold] {self.file_path}\n"
        text += f"[bold]Score:[/bold] {self.score}/10\n"
        if self.issues:
            text += "\n[bold]Issues:[/bold]\n"
            for i, issue in enumerate(self.issues[:10], 1):
                severity = issue.get("severity", "info")
                color = {
                    "critical": "red",
                    "high": "yellow",
                    "medium": "orange1",
                    "low": "cyan",
                }.get(severity, "white")
                text += f"  {i}. [{color}][{severity.upper()}][/{color}] {issue.get('message', '')}\n"
        return Panel(text, title="Code Review", border_style="green")


class CoderBridge:
    """Lightweight code generation and review bridge."""

    def __init__(self, provider=None):
        self._provider = provider

    async def generate(self, prompt: str, language: str = "python") -> str:
        """Generate code from a natural language prompt."""
        full_prompt = f"Generate {language} code for: {prompt}\nONLY output the code, no explanation."
        if self._provider:
            return await self._provider.generate(full_prompt)
        console.print("[yellow]No provider configured for code generation.[/yellow]")
        return ""

    async def review(self, file_path: str, code: str) -> CodeReview:
        """Review code and return issues."""
        review = CodeReview(file_path=file_path)
        # Basic static analysis
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if "TODO" in stripped or "FIXME" in stripped:
                review.issues.append(
                    {"severity": "low", "message": f"Line {i}: Contains TODO/FIXME"}
                )
            if "password" in stripped.lower() and "=" in stripped:
                review.issues.append(
                    {
                        "severity": "high",
                        "message": f"Line {i}: Possible hardcoded credential",
                    }
                )
            if "eval(" in stripped or "exec(" in stripped:
                review.issues.append(
                    {
                        "severity": "critical",
                        "message": f"Line {i}: Use of eval/exec is dangerous",
                    }
                )
            if len(stripped) > 120:
                review.issues.append(
                    {
                        "severity": "medium",
                        "message": f"Line {i}: Line too long ({len(stripped)} > 120 chars)",
                    }
                )

        review.score = max(0, 10 - len(review.issues))
        return review


__all__ = ["CoderBridge", "CodeReview"]
