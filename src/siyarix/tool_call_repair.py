"""Tool call repair — parse plain-text tool calls from model output.

Handles bracket syntax [tool_name]{args} and XML-ish syntax <function=name>
to reconstruct structured tool calls from models that output plain text.
"""

from __future__ import annotations

import json
import re
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────

MAX_PAYLOAD_LENGTH = 262144

BRACKET_TOOL_RE = re.compile(
    r"\[TOOL_[\w-]+\]|\[tool(?::[\w-]+)?\]|\[([\w-]+)\](?:\s*\n|\s+)(\{)", re.IGNORECASE | re.DOTALL
)
FUNCTION_CALL_RE = re.compile(
    r"(?:function|tool|action)_call:\s*\n*\s*\{", re.IGNORECASE | re.DOTALL
)
XML_TOOL_RE = re.compile(r"<function=(\w+)>(.*?)</function>", re.DOTALL)

CLOSING_MARKERS = [
    "[END_TOOL_REQUEST]",
    "[/tool]",
    "[/function]",
    "<|call|>",
]

# ── Parsing ────────────────────────────────────────────────────────────


def find_json_object_end(text: str, start: int) -> int:
    """Find the closing brace of a JSON object starting at *start*.
    Handles nested braces and strings with braces.
    """
    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if not depth:
                return i + 1

    return -1


def parse_bracket_tool_calls(text: str) -> list[dict[str, Any]]:
    """Parse bracket-syntax tool calls: [tool_name]\n{...args...}"""
    calls: list[dict[str, Any]] = []

    for match in BRACKET_TOOL_RE.finditer(text):
        tool_name = match.group(1) or "unknown"
        args_start = match.start(2) if match.group(2) else match.end()

        json_end = find_json_object_end(text, args_start)
        if json_end == -1:
            continue

        args_text = text[args_start:json_end]
        if len(args_text) > MAX_PAYLOAD_LENGTH:
            continue

        try:
            args = json.loads(args_text)
        except json.JSONDecodeError:
            args = {"raw": args_text}

        if not isinstance(args, dict):
            args = {"value": args}

        calls.append({"name": tool_name, "args": args})

    return calls


def parse_xml_tool_calls(text: str) -> list[dict[str, Any]]:
    """Parse XML-ish tool calls: <function=name>\n<parameter=name>value</parameter>...</function>"""
    calls: list[dict[str, Any]] = []

    for match in XML_TOOL_RE.finditer(text):
        tool_name = match.group(1)
        body = match.group(2).strip()

        if len(body) > MAX_PAYLOAD_LENGTH:
            continue

        # Try JSON first
        if body.startswith("{"):
            try:
                args = json.loads(body)
                if isinstance(args, dict):
                    calls.append({"name": tool_name, "args": args})
                    continue
            except json.JSONDecodeError:
                pass

        # Try XML parameter format: <parameter=name>value</parameter>
        param_re = re.compile(r"<parameter=(\w+)>(.*?)</parameter>", re.DOTALL)
        params = {}
        for param_match in param_re.finditer(body):
            key = param_match.group(1)
            val = param_match.group(2).strip()
            params[key] = val

        if params:
            calls.append({"name": tool_name, "args": params})
        else:
            calls.append({"name": tool_name, "args": {"input": body}})

    return calls


# ── Main API ───────────────────────────────────────────────────────────


def parse_plain_text_tool_calls(text: str) -> list[dict[str, Any]]:
    """Parse all supported plain-text tool call syntaxes from text.

    Returns list of {name, args} dicts.
    """
    calls = parse_bracket_tool_calls(text)
    if not calls:
        calls = parse_xml_tool_calls(text)
    return calls


def _find_bracket_spans(text: str) -> list[tuple[int, int]]:
    """Find (start, end) spans of complete bracket tool calls."""
    spans: list[tuple[int, int]] = []
    for match in BRACKET_TOOL_RE.finditer(text):
        json_start = match.start(2) if match.group(2) else match.end()
        json_end = find_json_object_end(text, json_start)
        if json_end == -1:
            spans.append((match.start(), json_start))
        else:
            spans.append((match.start(), json_end))
    return spans


def strip_tool_call_blocks(text: str) -> str:
    """Strip tool call blocks from text, preserving non-tool text."""
    spans = _find_bracket_spans(text)
    for xml_match in XML_TOOL_RE.finditer(text):
        spans.append((xml_match.start(), xml_match.end()))

    if spans:
        spans.sort()
        chunks: list[str] = []
        pos = 0
        for start, end in spans:
            if start > pos:
                chunks.append(text[pos:start])
            pos = max(pos, end)
        chunks.append(text[pos:])
        text = "".join(chunks)

    # Remove closing markers
    for marker in CLOSING_MARKERS:
        text = text.replace(marker, "")

    # Clean up whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def has_plain_text_tool_calls(text: str) -> bool:
    """Check if text contains plain-text tool calls."""
    if BRACKET_TOOL_RE.search(text):
        return True
    if XML_TOOL_RE.search(text):
        return True
    if FUNCTION_CALL_RE.search(text):
        return True
    for marker in CLOSING_MARKERS:
        if marker in text:
            return True
    return False


def promote_to_native_tool_calls(
    text: str,
    allowed_tools: list[str] | None = None,
    fuzzy: bool = True,
) -> tuple[str, list[dict[str, Any]]]:
    """Promote plain-text tool calls to native format.

    Returns (cleaned_text, native_tool_calls) where native_tool_calls is
    a list of {name, args} suitable for execution.
    """
    calls = parse_plain_text_tool_calls(text)
    if not calls:
        return text, []

    if allowed_tools:
        filtered: list[dict[str, Any]] = []
        for call in calls:
            call_name = call["name"]
            if fuzzy:
                match = _fuzzy_match_tool_name(call_name, allowed_tools)
                if match:
                    call["name"] = match
                    filtered.append(call)
            elif call_name in allowed_tools:
                filtered.append(call)
        calls = filtered

    cleaned = strip_tool_call_blocks(text)
    return cleaned, calls


# ── Internals ──────────────────────────────────────────────────────────


def _fuzzy_match_tool_name(name: str, allowed: list[str]) -> str | None:
    """Fuzzy-match a tool name against allowed names.

    Prioritizes: exact match > case-insensitive > substring > edit distance 1.
    """
    name_lower = name.lower()
    if name in allowed:
        return name

    for a in allowed:
        if a.lower() == name_lower:
            return a

    for a in allowed:
        if a.lower() in name_lower or name_lower in a.lower():
            return a

    # Levenshtein distance ≤ 2 (covers typos and adjacent transpositions)
    for a in allowed:
        a_lower = a.lower()
        if abs(len(a_lower) - len(name_lower)) > 2:
            continue
        if _levenshtein_distance(a_lower, name_lower) <= 2:
            return a

    return None


def _levenshtein_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def repair_json(text: str) -> dict[str, Any] | None:
    """Robustly parse and repair malformed JSON emitted by LLMs."""
    if not text:
        return None
    cleaned = text.strip()
    # Strip markdown code fence
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    # Fast path
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, ValueError):
        pass

    # Extract JSON object substring between first { and matching last }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = cleaned[first_brace : last_brace + 1]
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, ValueError):
            # Attempt surgical regex repairs:
            # 1. Remove trailing commas before } or ]
            repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
            # 2. Convert single-quoted string keys to double-quoted keys: {'foo': -> {"foo":
            repaired = re.sub(r"([{,]\s*)'([^']+)'\s*:", r'\1"\2":', repaired)
            # 3. Convert single-quoted values to double quotes where safe
            repaired = re.sub(r":\s*'([^']*)'(\s*[,}])", r': "\1"\2', repaired)
            try:
                data = json.loads(repaired)
                if isinstance(data, dict):
                    return data
            except (json.JSONDecodeError, ValueError):
                pass

    return None


def parse_markdown_code_blocks(text: str) -> list[dict[str, Any]]:
    """Extract shell commands from markdown code fences."""
    blocks = re.findall(
        r"```(?:bash|sh|zsh|cmd|powershell|)\s*\n(.*?)\n```",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    steps: list[dict[str, Any]] = []
    for block in blocks:
        for line in block.splitlines():
            cmd = line.strip()
            # Ignore comments and empty lines
            if cmd and not cmd.startswith("#") and not cmd.startswith("rem "):
                steps.append(
                    {
                        "tool": "sh",
                        "command": cmd,
                        "description": f"Execute: {cmd[:40]}",
                        "args": {},
                    }
                )
    return steps


def repair_plan_payload(raw: Any) -> dict[str, Any] | None:
    """Extract and repair structured plan payload from any raw model output."""
    # 1. Direct dict from function calling or pre-parsed
    if isinstance(raw, dict):
        tool_calls = raw.get("tool_calls")
        if tool_calls and len(tool_calls) > 0:
            tc0 = tool_calls[0]
            func = getattr(tc0, "function", None)
            func_args = getattr(func, "arguments", None) if func else None
            if func_args is None and isinstance(tc0, dict):
                func_args = tc0.get("function", {}).get("arguments")
            if isinstance(func_args, str):
                parsed = repair_json(func_args)
                if parsed:
                    return parsed
            elif isinstance(func_args, dict):
                return func_args

        if "needs_tools" in raw or "steps" in raw:
            return raw

        if "tasks" in raw and isinstance(raw["tasks"], list):
            return {
                "needs_tools": True,
                "reasoning": raw.get("reasoning", "Tasks from model"),
                "steps": raw["tasks"],
                "response": str(raw),
            }

    text = raw.get("content", "") if isinstance(raw, dict) else str(raw or "")
    if not text:
        return None

    # 2. Try JSON extraction & repair
    json_data = repair_json(text)
    if json_data and ("needs_tools" in json_data or "steps" in json_data):
        return json_data

    # 3. Try YAML parsing if available
    try:
        import yaml  # type: ignore[import-untyped]

        cleaned_fence = re.sub(r"^```(?:yaml)?\s*", "", text.strip(), flags=re.IGNORECASE)
        cleaned_fence = re.sub(r"\s*```$", "", cleaned_fence).strip()
        y_data = yaml.safe_load(cleaned_fence)
        if isinstance(y_data, dict) and ("needs_tools" in y_data or "steps" in y_data):
            return y_data
    except Exception:
        pass

    # 4. Try bracket and XML tool parsing
    native_text, plain_calls = promote_to_native_tool_calls(text)
    if plain_calls:
        steps = []
        for call in plain_calls:
            tool_name = call.get("name", "")
            args = call.get("args", {})
            cmd = args.get("command") or args.get("cmd") or ""
            steps.append(
                {
                    "tool": tool_name,
                    "command": cmd or None,
                    "description": f"Call {tool_name}",
                    "args": args,
                }
            )
        return {
            "needs_tools": True,
            "reasoning": "Extracted plain-text tool calls",
            "steps": steps,
            "response": native_text,
        }

    # 5. Try markdown code blocks
    code_steps = parse_markdown_code_blocks(text)
    if code_steps:
        return {
            "needs_tools": True,
            "reasoning": "Extracted commands from code fences",
            "steps": code_steps,
            "response": text,
        }

    # 6. Try bracket shorthand commands: [nmap -sS target]
    bracket_cmds = re.findall(r"\[([a-zA-Z0-9_\-\./]+(?:\s+[^\]\n]+)?)\]", text)
    if bracket_cmds:
        b_steps = []
        for b_cmd in bracket_cmds:
            b_cmd = b_cmd.strip()
            if (
                not b_cmd
                or b_cmd.lower().startswith("tool")
                or b_cmd.lower().startswith("end_tool")
            ):
                continue
            parts = b_cmd.split(None, 1)
            tool_name = parts[0]
            b_steps.append(
                {
                    "tool": tool_name,
                    "command": b_cmd,
                    "description": f"Execute: {b_cmd[:40]}",
                    "args": {"command": b_cmd},
                }
            )
        if b_steps:
            return {
                "needs_tools": True,
                "reasoning": "Extracted bracket commands",
                "steps": b_steps,
                "response": text,
            }

    return None


__all__ = [
    "MAX_PAYLOAD_LENGTH",
    "BRACKET_TOOL_RE",
    "XML_TOOL_RE",
    "FUNCTION_CALL_RE",
    "CLOSING_MARKERS",
    "find_json_object_end",
    "parse_bracket_tool_calls",
    "parse_xml_tool_calls",
    "parse_plain_text_tool_calls",
    "strip_tool_call_blocks",
    "has_plain_text_tool_calls",
    "promote_to_native_tool_calls",
    "repair_json",
    "parse_markdown_code_blocks",
    "repair_plan_payload",
]
