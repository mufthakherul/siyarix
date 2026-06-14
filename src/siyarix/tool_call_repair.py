"""Tool call repair — parse plain-text tool calls from model output.

OpenClaw pattern: packages/tool-call-repair/
Handles bracket syntax [tool_name]\n{args} and XML-ish syntax <function=name>.
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
    # Find all spans to remove (bracket + XML tool calls)
    spans = _find_bracket_spans(text)
    for xml_match in XML_TOOL_RE.finditer(text):
        spans.append((xml_match.start(), xml_match.end()))

    # Merge overlapping spans and remove them
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

__all__ = [
    "MAX_PAYLOAD_LENGTH",
    "BRACKET_TOOL_RE",
    "XML_TOOL_RE",
    "CLOSING_MARKERS",
    "find_json_object_end",
    "parse_bracket_tool_calls",
    "parse_xml_tool_calls",
    "parse_plain_text_tool_calls",
    "strip_tool_call_blocks",
    "has_plain_text_tool_calls",
    "promote_to_native_tool_calls",
]
