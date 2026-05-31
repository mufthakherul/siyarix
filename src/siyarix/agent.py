# SPDX-License-Identifier: AGPL-3.0-or-later

"""Agent loop — LLM-driven tool calling conversation.

In autonomous/LLM mode, the agent replaces the traditional
plan → execute pipeline with a direct tool-calling loop:

  1. LLM receives user request + tool definitions
  2. LLM responds with either a tool call or final answer
  3. If tool call → execute → show raw output → feed back to LLM → goto 2
  4. LLM summarises results and returns final response

This enables the LLM to use any tool on the device, check results,
and decide on next steps — just like a human operator.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Any

from siyarix.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

_TOOL_CALL_RE = r'\{_\s*"tool"\s*:\s*"([^"]+)"\s*,.+?\}'

_SYSTEM_PROMPT = textwrap.dedent("""\
You are Siyarix, an AI cybersecurity assistant running on the user's local machine.
You have direct access to the following security tools installed on this system:

{tool_descriptions}

## Tool calling format
When you need to run a tool, output a JSON object with **tool**, **target**, and optional **flags**.
The JSON MUST be on its own line and contain **no other text on that line**.

✅ Correct examples:
  {{"tool": "nmap", "target": "example.com", "flags": "-sV"}}
  {{"tool": "whois", "target": "example.com"}}
  {{"tool": "nuclei", "target": "10.0.0.1", "flags": "-severity high"}}

❌ Wrong (tool name inside text, not JSON):
  I'll run nmap on example.com.

After the tool runs, its output will be shown to you.
Analyse the output and either call another tool or give your final answer.
Always wait for tool output before drawing conclusions.

## Rules
- Run ONE tool at a time. Wait for its output before deciding the next step.
- After each tool call, review the output carefully before proceeding.
- When output looks incomplete or unexpected, call the tool again with different flags.
- If a tool is not installed, the system will tell you. Suggest alternatives if available.
- When done, provide a clear summary of findings.
- Be concise. Prefer precision over verbosity.
- Never ask the user to run commands manually — you have the tools.
- Never make up results. Only report what you actually observe from tool output.
- You can use multiple tools in sequence — each builds on the previous.
""")


@dataclass
class ToolCallResult:
    """Result of a tool call in the agent loop."""

    name: str
    args: dict[str, str]
    exit_code: int
    raw_stdout: str
    raw_stderr: str
    tool_path: str | None
    installed: bool = True


@dataclass
class AgentResult:
    """Final result from an agent loop run."""

    content: str
    iterations: int
    tools_called: list[str] = field(default_factory=list)
    cancelled: bool = False


class ConsolePrinter:
    """Minimal console abstraction for agent output."""

    def __init__(self, rich_console: Any = None) -> None:
        self._rich = rich_console

    def print(self, text: str, style: str = "") -> None:
        if self._rich:
            self._rich.print(text)
        else:
            clean = text.replace("[red]", "").replace("[/red]", "")
            clean = clean.replace("[green]", "").replace("[/green]", "")
            clean = clean.replace("[dim]", "").replace("[/dim]", "")
            clean = clean.replace("[bold]", "").replace("[/bold]", "")
            clean = clean.replace("[yellow]", "").replace("[/yellow]", "")
            print(clean)

    def raw(self, text: str) -> None:
        if self._rich:
            self._rich.print(text)
        else:
            print(text)


def _build_tool_descriptions(registry: ToolRegistry) -> str:
    """Build a formatted list of available tools for the system prompt."""
    tools = registry.discover(fast=True)
    if not tools:
        return "  No security tools detected on PATH."
    lines: list[str] = []
    for t in sorted(tools, key=lambda x: x.category):
        caps = ", ".join(t.capabilities[:5]) if t.capabilities else "general"
        extra = " [installed]" if t.path else ""
        lines.append(f"  • {t.name} ({t.category}): {t.description}{extra}")
        if caps:
            lines.append(f"    Capabilities: {caps}")
    return "\n".join(lines)


def _extract_tool_call(text: str) -> dict | None:
    """Extract a tool call JSON from the LLM response text.

    Supports two formats:
      1. {"tool": "nmap", "target": "...", "flags": "..."}  (standard JSON)
      2. {"_tool": "nmap", "target": "...", "flags": "..."}  (underscore-prefixed key)

    Scans the text for JSON objects whose keys contain ``tool``.
    """

    # Find all candidate JSON objects via balanced-brace scanning
    candidates: list[str] = []
    i = 0
    while i < len(text):
        brace = text.find("{", i)
        if brace == -1:
            break
        depth = 0
        for j in range(brace, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[brace : j + 1])
                    i = j + 1
                    break
        else:
            i = brace + 1

    for candidate in candidates:
        if "tool" not in candidate.lower():
            continue
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        tool_key = obj.get("_tool") or obj.get("tool")
        if tool_key:
            return obj

    return None


def _clean_tool_output(text: str, max_chars: int = 15000) -> str:
    """Truncate tool output to prevent token overflow."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n\n... [truncated at {max_chars} chars]"


def _should_block_command(cmd: list[str]) -> bool:
    """Block dangerous commands that could harm the system."""
    dangerous = {
        "rm", "dd", "mkfs", "format", "del", "rd",
        "shutdown", "reboot", "init", "halt", "poweroff",
        "chmod", "chown", "passwd", "useradd", "userdel",
        "mount", "umount", "fdisk", "parted",
    }
    if cmd and cmd[0] in dangerous:
        return True
    # Also block if any part contains injection characters
    for part in cmd:
        if any(ch in part for ch in [";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\x00"]):
            return True
    return False


class ToolRunner:
    """Execute tools safely and return their output."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    async def run(self, tool_name: str, args: dict[str, str]) -> ToolCallResult:
        """Look up *tool_name* in the registry and run it with *args*."""
        tool_name = tool_name.lower()
        tools = self._registry.discover(fast=True)
        tool_info = None
        for t in tools:
            if t.name.lower() == tool_name or t.binary.lower() == tool_name:
                tool_info = t
                break

        if not tool_info:
            binary_path = shutil.which(tool_name)
            if binary_path:
                tool_path = binary_path
            else:
                return ToolCallResult(
                    name=tool_name,
                    args=args,
                    exit_code=-1,
                    raw_stdout="",
                    raw_stderr=f"Tool '{tool_name}' is not installed on this system.",
                    tool_path=None,
                    installed=False,
                )
        else:
            tool_path = tool_info.path

        if not tool_path:
            return ToolCallResult(
                name=tool_name,
                args=args,
                exit_code=-1,
                raw_stdout="",
                raw_stderr=f"Tool '{tool_name}' not found on PATH.",
                tool_path=None,
                installed=False,
            )

        target = args.get("target", "")
        flags = args.get("flags", "")

        cmd: list[str] = [tool_path]
        if flags:
            cmd.extend(flags.split())
        if target:
            cmd.append(target)

        if _should_block_command(cmd):
            return ToolCallResult(
                name=tool_name,
                args=args,
                exit_code=-1,
                raw_stdout="",
                raw_stderr=f"Command '{' '.join(cmd)}' is blocked for safety.",
                tool_path=tool_path,
            )

        logger.debug("Agent running: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _timeout = args.get("timeout", 120)
                if not isinstance(_timeout, (int, float)):
                    _timeout = 120
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=float(_timeout)
                )
            except asyncio.TimeoutError:
                proc.kill()
                return ToolCallResult(
                    name=tool_name,
                    args=args,
                    exit_code=-1,
                    raw_stdout="",
                    raw_stderr=f"Tool '{tool_name}' timed out after {args.get('timeout', 120)}s.",
                    tool_path=tool_path,
                )

            return ToolCallResult(
                name=tool_name,
                args=args,
                exit_code=proc.returncode or 0,
                raw_stdout=stdout.decode("utf-8", errors="replace"),
                raw_stderr=stderr.decode("utf-8", errors="replace"),
                tool_path=tool_path,
            )
        except FileNotFoundError:
            return ToolCallResult(
                name=tool_name,
                args=args,
                exit_code=-1,
                raw_stdout="",
                raw_stderr=f"Tool '{tool_name}' not found at {tool_path}.",
                tool_path=tool_path,
                installed=False,
            )
        except Exception as exc:
            logger.exception("Tool execution failed: %s", exc)
            return ToolCallResult(
                name=tool_name,
                args=args,
                exit_code=-1,
                raw_stdout="",
                raw_stderr=str(exc),
                tool_path=tool_path,
            )


class AgentLoop:
    """Interactive agent loop that lets the LLM call tools directly.

    Usage::

        loop = AgentLoop(model_provider, tool_registry, console)
        result = await loop.run("scan google.com")
        print(result.content)
    """

    def __init__(
        self,
        model: Any,
        registry: ToolRegistry,
        console: Any = None,
        max_iterations: int = 20,
    ) -> None:
        self._model = model
        self._registry = registry
        self._console = ConsolePrinter(console) if console else ConsolePrinter()
        self._runner = ToolRunner(registry)
        self._max_iterations = max_iterations
        self._messages: list[dict[str, Any]] = []
        self._tools_called: list[str] = []

    async def run(self, instruction: str) -> AgentResult:
        """Run the agent loop with *instruction* as the user's request."""
        tool_desc = _build_tool_descriptions(self._registry)
        system = _SYSTEM_PROMPT.format(tool_descriptions=tool_desc)

        self._messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": instruction},
        ]

        for iteration in range(self._max_iterations):
            response = await self._call_llm()
            if response is None:
                return AgentResult(
                    content="LLM call failed. Check your API key and model configuration.",
                    iterations=iteration + 1,
                    tools_called=list(self._tools_called),
                )

            content = response.get("content", "")
            tool_call = _extract_tool_call(content)

            if tool_call:
                tool_name = tool_call.get("_tool") or tool_call.get("tool", "")
                if not tool_name:
                    self._console.raw(content)
                    return AgentResult(
                        content=content,
                        iterations=iteration + 1,
                        tools_called=list(self._tools_called),
                    )

                self._tools_called.append(tool_name)
                run_result = await self._runner.run(tool_name, tool_call)

                # Show raw output
                combined = run_result.raw_stdout or run_result.raw_stderr or ""
                if not run_result.installed:
                    self._console.print(
                        f"[yellow]⚠ Tool '{tool_name}' is not installed.[/yellow]"
                    )
                    self._console.print(f"[dim]{run_result.raw_stderr}[/dim]")
                    install = await self._prompt_install(tool_name)
                    if install:
                        self._console.print(f"[green]Retrying {tool_name}...[/green]")
                        self._messages.append({
                            "role": "tool",
                            "content": f"Tool '{tool_name}' was just installed. Retrying now.",
                            "tool_call_id": f"tool_{iteration}",
                        })
                        continue
                    else:
                        self._messages.append({
                            "role": "tool",
                            "content": f"Tool '{tool_name}' is not installed. User declined installation. Suggest an alternative approach or explain what information you need.",
                            "tool_call_id": f"tool_{iteration}",
                        })
                        continue
                else:
                    border = f"── {tool_name} output (exit: {run_result.exit_code}) ──"
                    self._console.print(f"\n[dim]{'─' * (len(border))}[/dim]")
                    self._console.print(f"[dim]{border}[/dim]")
                    self._console.raw(
                        combined[:2000] + ("\n[dim]... (output truncated)[/dim]" if len(combined) > 2000 else "")
                    )
                    self._console.print(f"[dim]{'─' * (len(border))}[/dim]\n")

                # Feed output back to LLM
                tool_content = _clean_tool_output(
                    f"Tool '{tool_name}' completed with exit code {run_result.exit_code}.\n\n"
                    f"STDOUT:\n{run_result.raw_stdout}\n"
                    f"STDERR:\n{run_result.raw_stderr}"
                )
                self._messages.append({
                    "role": "assistant",
                    "content": content,
                })
                self._messages.append({
                    "role": "tool",
                    "content": tool_content,
                    "tool_call_id": f"tool_{iteration}",
                })
            else:
                # No tool call detected — check if content mentions running a tool
                _tool_keywords = ["run ", "execute ", "scan ", "use ", "nmap", "whois", "nuclei", "gobuster", "dnsx", "httpx", "subfinder", "amass"]
                _mentions_tool = any(kw in content.lower() for kw in _tool_keywords)

                if _mentions_tool and iteration < self._max_iterations - 1:
                    # LLM seems to want to run a tool but format was wrong — hint and retry
                    hint = (
                        "[System]: I noticed you mentioned running a tool but didn't use the required JSON format. "
                        "To call a tool, output EXACTLY on its own line:\n"
                        "  {\"tool\": \"<name>\", \"target\": \"<target>\", \"flags\": \"<optional>\"}\n"
                        "For example: {\"tool\": \"nmap\", \"target\": \"example.com\"}\n"
                        "Please try again with the correct format."
                    )
                    self._messages.append({"role": "assistant", "content": content})
                    self._messages.append({"role": "tool", "content": hint, "tool_call_id": f"hint_{iteration}"})
                    continue

                # No tool call — this is the final answer
                self._console.raw(content)
                return AgentResult(
                    content=content,
                    iterations=iteration + 1,
                    tools_called=list(self._tools_called),
                )

        self._console.print("[yellow]⚠ Agent reached max iterations.[/yellow]")
        return AgentResult(
            content="Reached maximum number of tool calls. Please refine your request.",
            iterations=self._max_iterations,
            tools_called=list(self._tools_called),
        )

    async def _call_llm(self) -> dict[str, Any] | None:
        """Call the LLM and return the response dict with 'content' key."""
        try:
            if hasattr(self._model, "chat"):
                return await self._model.chat(self._messages)
            if hasattr(self._model, "plan"):
                plan_result = await self._model.plan(
                    self._messages[-1]["content"],
                    {"tool_descriptions": _build_tool_descriptions(self._registry)},
                )
                return {"content": json.dumps(plan_result, indent=2)}
            logger.warning("Model provider has no chat() or plan() method")
            return None
        except Exception as exc:
            logger.warning("LLM call failed in agent loop: %s", exc)
            return None

    async def _prompt_install(self, tool_name: str) -> bool:
        """Ask the user if they want to install *tool_name*."""
        try:
            msg = f"Tool '{tool_name}' is not installed. Install now? (y/N): "
            if not sys.stdin.isatty():
                return False
            answer = input(msg).strip().lower()
            if answer == "y":
                await self._install_tool(tool_name)
                return True
            return False
        except (EOFError, KeyboardInterrupt):
            return False

    async def _install_tool(self, tool_name: str) -> bool:
        """Attempt to install *tool_name* using the system package manager."""
        self._console.print(f"[yellow]Attempting to install '{tool_name}'...[/yellow]")
        self._console.print("[dim]Supported: apt, pip, brew, npm, go[/dim]")

        installers = [
            (["apt", "install", "-y", tool_name], "apt"),
            (["pip3", "install", tool_name], "pip"),
            (["pip", "install", tool_name], "pip"),
            (["brew", "install", tool_name], "brew"),
            (["npm", "install", "-g", tool_name], "npm"),
            (["go", "install", f"github.com/{tool_name}"], "go"),
        ]
        for cmd, pkg_mgr in installers:
            if shutil.which(cmd[0]):
                try:
                    self._console.print(f"[dim]Trying {pkg_mgr}: {' '.join(cmd)}[/dim]")
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                    if proc.returncode == 0:
                        self._console.print(f"[green]✓ {tool_name} installed via {pkg_mgr}[/green]")
                        return True
                    logger.debug("Install via %s failed: %s", pkg_mgr, stderr.decode(errors="replace")[:200])
                except (OSError, asyncio.TimeoutError):
                    continue
        self._console.print(f"[red]✗ Could not install '{tool_name}' automatically.[/red]")
        return False
