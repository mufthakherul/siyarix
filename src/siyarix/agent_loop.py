# SPDX-License-Identifier: AGPL-3.0-or-later

"""Agentic tool-calling loop for autonomous planning and execution.

Instead of the old plan → parse → execute pipeline, this module
implements a ReAct-style loop where the LLM calls tools directly
via OpenAI-compatible function/tool calling, receives results, and
iterates until it produces a final answer.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .tool_schema import (
    build_tool_schemas,
    read_file_sync,
    run_command_sync,
    run_tool_sync,
)

logger = logging.getLogger(__name__)

# Maximum number of tool-calling iterations before we bail out
_MAX_ITERATIONS = 20


async def agentic_plan(
    provider: Any,
    instruction: str,
    context: dict[str, Any],
    system_prompt: str,
) -> tuple[list[dict[str, Any]], str, list[str]]:
    """Run the tool-calling agent loop and return results.

    Parameters
    ----------
    provider:
        A model provider instance that supports ``chat_with_tools()``.
    instruction:
        The user's natural language instruction.
    context:
        Runtime context with ``available_tools`` list.
    system_prompt:
        The system prompt for the LLM.

    Returns
    -------
    tuple[list[dict[str, Any]], str, list[str]]
        ``(tool_calls_log, final_answer, findings)`` where:
        - ``tool_calls_log`` is a list of every tool invocation and result
        - ``final_answer`` is the LLM's final textual answer
        - ``findings`` is a list of discovered findings
    """
    tool_defs = build_tool_schemas(context.get("available_tools", []))
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": instruction},
    ]

    tool_log: list[dict[str, Any]] = []
    findings: list[str] = []

    for turn in range(_MAX_ITERATIONS):
        response = await provider.chat_with_tools(
            messages=messages,
            tools=tool_defs,
        )

        msg = response.get("message", {})
        content = msg.get("content", "")
        tool_calls = msg.get("tool_calls", [])

        if not tool_calls:
            # LLM is done — extract final answer
            final = content or ""
            if not final:
                # Check if assistant message already has the answer
                pass
            return tool_log, final, findings

        for tc in tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "")
            raw_args = func.get("arguments", "{}")
            tool_call_id = tc.get("id", f"call_{turn}_{len(tool_log)}")

            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {"args": raw_args}

            log_entry = {
                "turn": turn,
                "tool_call_id": tool_call_id,
                "function": name,
                "arguments": args,
            }

            if name == "run_tool":
                result = run_tool_sync(
                    args.get("tool", ""),
                    args.get("args", ""),
                    timeout=int(args.get("timeout", 120)),
                )
                log_entry["result"] = result
            elif name == "run_command":
                result = run_command_sync(
                    args.get("command", ""),
                    timeout=int(args.get("timeout", 60)),
                )
                log_entry["result"] = result
            elif name == "read_file":
                result = read_file_sync(
                    args.get("path", ""),
                    max_lines=int(args.get("max_lines", 200)),
                )
                log_entry["result"] = result
            elif name == "final_answer":
                findings = args.get("findings", [])
                final = args.get("answer", "")
                return tool_log, final, findings
            else:
                result = f"Error: unknown function '{name}'"

            log_entry["result"] = result
            tool_log.append(log_entry)

            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": tool_call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)},
                        }
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": str(result)[:50_000],
                }
            )

    # If we exhausted iterations without a final_answer, return the last content
    last_content = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            last_content = m["content"]
            break
    logger.warning("Agent loop reached max iterations (%d)", _MAX_ITERATIONS)
    return tool_log, last_content or "Max iterations reached without final answer.", findings
