# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generate LLM-compatible tool/function schemas from discovered tools.

Converts locally discovered tools into OpenAI-compatible
``tools`` parameter definitions for function/tool calling,
enabling the LLM to call tools directly.
"""

from __future__ import annotations

import shlex
import subprocess  # nosec B404
from typing import Any


def build_tool_schemas(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build OpenAI-compatible tool definitions for LLM function calling.

    Each discovered tool becomes a function the LLM can call via
    ``run_tool`` with the tool name as an enum constraint.

    Returns
    -------
    list[dict]
        A list of tool definitions suitable for the ``tools`` parameter
        in OpenAI-compatible chat completion APIs.
    """
    tool_names = sorted({t["name"] for t in tools})
    return [
        {
            "type": "function",
            "function": {
                "name": "run_tool",
                "description": (
                    "Run a security tool or system command on a target. "
                    "Use this for ANY command execution: nmap, curl, dig, "
                    "whois, nuclei, gobuster, etc."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "Name of the tool to execute",
                            "enum": tool_names if tool_names else ["(none discovered)"],
                        },
                        "args": {
                            "type": "string",
                            "description": (
                                "Command-line arguments. Include the target "
                                "or domain here (e.g. '-sV scanme.nmap.org')"
                            ),
                        },
                        "description": {
                            "type": "string",
                            "description": (
                                "Brief note explaining why this tool is "
                                "being run and what you expect to learn"
                            ),
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Maximum execution time in seconds",
                            "default": 120,
                        },
                    },
                    "required": ["tool", "args"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_command",
                "description": (
                    "Run an arbitrary shell command (not a registered tool). "
                    "Use for system operations like curl, dig, ping, etc. "
                    "that aren't in the tool list."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Full shell command to execute",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Maximum execution time in seconds",
                            "default": 60,
                        },
                    },
                    "required": ["command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read the contents of a file on the local system",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the file",
                        },
                        "max_lines": {
                            "type": "integer",
                            "description": "Maximum number of lines to read",
                            "default": 200,
                        },
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "final_answer",
                "description": (
                    "Present the final answer to the user. Call this when "
                    "you have gathered enough information and are ready to "
                    "respond with a complete analysis."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "answer": {
                            "type": "string",
                            "description": "Your complete response to the user",
                        },
                        "findings": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of findings or vulnerabilities discovered",
                        },
                    },
                    "required": ["answer"],
                },
            },
        },
    ]


def run_tool_sync(tool: str, args: str, timeout: int = 120) -> str:
    """Execute a tool synchronously and return its output.

    Parameters
    ----------
    tool:
        The name of the tool (binary).
    args:
        Command-line arguments as a string.
    timeout:
        Maximum execution time in seconds.

    Returns
    -------
    str
        Combined stdout + stderr output, truncated to 100_000 chars.
    """
    import shutil

    binary = shutil.which(tool)
    if binary is None:
        return f"Error: tool '{tool}' not found on PATH. It is not installed."

    cmd = [binary] + shlex.split(args)
    try:
        result = subprocess.run(  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if not output.strip():
            return f"OK (no output, exit code {result.returncode})"
        if len(output) > 100_000:
            output = output[:100_000] + "\n... (truncated)"
        return output
    except subprocess.TimeoutExpired:
        return f"Error: tool '{tool}' timed out after {timeout}s"
    except FileNotFoundError:
        return f"Error: tool '{tool}' not found"
    except PermissionError:
        return f"Error: permission denied running '{tool}'"
    except OSError as exc:
        return f"Error running '{tool}': {exc}"


def run_command_sync(command: str, timeout: int = 60) -> str:
    """Run an arbitrary shell command synchronously.

    Parameters
    ----------
    command:
        The full command string to execute.
    timeout:
        Maximum execution time in seconds.

    Returns
    -------
    str
        Combined output, truncated to 100_000 chars.
    """
    import shlex

    parts = shlex.split(command)
    if not parts:
        return "Error: empty command"

    binary = parts[0]
    found = False
    for d in __import__("os").environ.get("PATH", "").split(__import__("os").pathsep):
        p = __import__("os").path.join(d, binary)
        if __import__("os").path.isfile(p) and __import__("os").access(p, __import__("os").X_OK):
            found = True
            break

    if not found:
        return f"Error: '{binary}' not found on PATH"

    try:
        result = subprocess.run(  # nosec B603
            parts,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if not output.strip():
            return f"OK (exit code {result.returncode})"
        if len(output) > 100_000:
            output = output[:100_000] + "\n... (truncated)"
        return output
    except subprocess.TimeoutExpired:
        return f"Error: command timed out after {timeout}s"
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return f"Error: {exc}"


def read_file_sync(path: str, max_lines: int = 200) -> str:
    """Read a file and return its contents."""
    import os as _os

    if not _os.path.isfile(path):
        return f"Error: file not found: {path}"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines: list[str] = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    lines.append(f"... (truncated at {max_lines} lines)")
                    break
                lines.append(line)
            return "".join(lines)
    except PermissionError:
        return f"Error: permission denied reading: {path}"
    except OSError as exc:
        return f"Error reading file: {exc}"
