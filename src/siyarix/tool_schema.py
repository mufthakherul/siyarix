# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generate LLM-compatible tool/function schemas from discovered tools.

Converts locally discovered tools into OpenAI-compatible
``tools`` parameter definitions for function/tool calling,
enabling the LLM to call tools directly.

For large tool sets (>200) the ``build_tool_schemas_ranked`` variant
selects only the *top-k* most relevant tools for a given user query,
avoiding prompt bloat and API enum limits.
"""

from __future__ import annotations

import re
import shlex
import subprocess  # nosec B404
from typing import Any

# ── Tool ranking for top-k retrieval ───────────────────────────────────

_KEYWORD_CACHE: dict[str, set[str]] = {}
_TOOL_METADATA_CACHE: dict[str, dict[str, Any]] = {}


def index_tool_metadata(tools: list[dict[str, Any]]) -> None:
    """Pre-compute keyword index for all tools.

    Call once when tools change; the index is reused by
    ``rank_tools_for_query`` for O(|query|) lookup.
    """
    _KEYWORD_CACHE.clear()
    _TOOL_METADATA_CACHE.clear()
    for t in tools:
        name: str = t.get("name", "")
        if not name:
            continue
        _TOOL_METADATA_CACHE[name] = t
        words = set()
        # Name parts
        name_lower = name.lower()
        words.add(name_lower)
        words.update(re.split(r"[-_.]+", name_lower))
        # Tags
        for tag in t.get("tags", []):
            words.add(tag.lower())
        # Description
        desc = t.get("description", "")
        if desc and desc != name:
            words.update(w for w in desc.lower().split() if len(w) > 2)
        # Category
        cat = t.get("category", "")
        if cat:
            words.add(cat.lower())
        for w in words:
            if len(w) > 1:
                _KEYWORD_CACHE.setdefault(w, set()).add(name)


def rank_tools_for_query(
    query: str, tools: list[dict[str, Any]], top_k: int = 30
) -> list[dict[str, Any]]:
    """Return the *top-k* tools most relevant to ``query``.

    Scoring is based on how many query words appear in the tool's
    name, tags, description, and category.  Tools with no match are
    excluded unless *fewer than* ``top_k`` tools have a positive score.
    """
    if not _KEYWORD_CACHE:
        index_tool_metadata(tools)

    query_words = {w for w in re.split(r"[^\w]+", query.lower()) if len(w) > 1}
    if not query_words:
        return tools[:top_k]

    scores: dict[str, int] = {}
    for w in query_words:
        for name in _KEYWORD_CACHE.get(w, []):
            scores[name] = scores.get(name, 0) + 1
    # Substring fallback for multi-word compounds
    if not scores:
        for key, names in _KEYWORD_CACHE.items():
            if key in query.lower():
                for n in names:
                    scores[n] = scores.get(n, 0) + 1

    ranked = sorted(scores, key=lambda n: -scores[n])
    # Map back to full dicts, preserving the original order for equal scores
    name_map = {t.get("name", ""): t for t in tools if t.get("name", "") in scores}
    result = [name_map[n] for n in ranked if n in name_map]
    # Pad with remaining tools if score > 0 produced fewer than top_k
    if len(result) < top_k:
        seen = {r.get("name") for r in result}
        result.extend(t for t in tools if t.get("name") not in seen)
    return result[:top_k]


# ── Schema builders ────────────────────────────────────────────────────


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


def build_tool_schemas_ranked(
    query: str,
    tools: list[dict[str, Any]],
    top_k: int = 30,
) -> list[dict[str, Any]]:
    """Build LLM tool schemas using *only the top-k* tools relevant to *query*.

    For large tool sets (100s–10000s) the full-schema ``build_tool_schemas``
    is impractical because the ``enum`` would exceed token limits.  This
    variant ranks tools by keyword relevance and injects only the most
    relevant ones into the ``run_tool`` function definition.
    """
    relevant = rank_tools_for_query(query, tools, top_k=top_k)
    return _build_schemas_from_tool_list(relevant)


def _build_schemas_from_tool_list(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Internal: produce the ``run_tool`` + helpers schema for a concrete tool list."""
    tool_names = sorted({t["name"] for t in tools})
    return [
        {
            "type": "function",
            "function": {
                "name": "run_tool",
                "description": (
                    "Run a security tool or system command on a target. "
                    "Use this for ANY command execution."
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
                "description": "Run an arbitrary shell command (not a registered tool).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Full shell command to execute"},
                        "timeout": {"type": "integer", "description": "Max seconds", "default": 60},
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
                        "path": {"type": "string", "description": "Absolute path to the file"},
                        "max_lines": {"type": "integer", "description": "Max lines to read", "default": 200},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "final_answer",
                "description": "Present the final answer to the user.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "answer": {"type": "string", "description": "Your complete response"},
                        "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
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

    # Security: block dangerous commands
    _dangerous_bins = {
        "rm", "dd", "mkfs", "format", "del", "rd",
        "shutdown", "reboot", "init", "halt", "poweroff",
        "chmod", "chown", "passwd", "useradd", "userdel",
        "mount", "umount", "fdisk", "parted",
    }
    if binary in _dangerous_bins:
        return f"Error: command '{binary}' is blocked for safety"

    # Security: block injection characters
    for part in parts:
        if any(ch in part for ch in [";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\x00"]):
            return "Error: command contains blocked characters"

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


# Sensitive paths that must never be read via LLM tool calls
_SENSITIVE_PATHS: set[str] = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/master.passwd",
}

_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "/etc/pki", "/etc/ssl/private",
)


def read_file_sync(path: str, max_lines: int = 200) -> str:
    """Read a file and return its contents.

    Security: blocks access to sensitive system files and paths.
    """
    import os as _os

    if not _os.path.isfile(path):
        return f"Error: file not found: {path}"

    # Security: block sensitive paths
    resolved = _os.path.realpath(path)
    if resolved in _SENSITIVE_PATHS:
        return "Error: access denied — sensitive system file"
    for prefix in _SENSITIVE_PREFIXES:
        if resolved.startswith(prefix):
            return "Error: access denied — sensitive path"
    # Block home directory sensitive files
    home = _os.path.expanduser("~")
    sensitive_home = (
        ".ssh/id_", ".ssh/id_rsa", ".ssh/id_ed25519",
        ".gnupg/", ".siyarix/.vault_key", ".aws/credentials",
        ".env",
    )
    for sh in sensitive_home:
        if resolved.startswith(_os.path.join(home, sh.rstrip("/"))):
            return "Error: access denied — sensitive credential file"

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
