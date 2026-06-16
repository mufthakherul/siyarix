"""Tool availability evaluation — determine if tools are available before execution.

OpenClaw pattern: src/tools/availability.ts
Evaluates availability signals (always, auth, config, env, context) and
Boolean expressions (allOf, anyOf) to determine if a tool can run.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Callable


# ── Types ──────────────────────────────────────────────────────────────


@dataclass
class ToolAvailabilityContext:
    """Context for evaluating tool availability."""

    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    config: dict[str, Any] = field(default_factory=dict)
    installed_tools: dict[str, str] = field(default_factory=dict)
    provider_auth: dict[str, bool] = field(default_factory=dict)


ToolAvailabilitySignal = dict[str, Any] | str | list[Any] | bool


@dataclass
class ToolAvailabilityDiagnostic:
    """Result of a single availability check."""

    signal: str
    passed: bool
    detail: str = ""


@dataclass
class ToolAvailabilityResult:
    """Result of evaluating tool availability."""

    available: bool
    diagnostics: list[ToolAvailabilityDiagnostic] = field(default_factory=list)


# ── Signals ────────────────────────────────────────────────────────────


def _eval_always(expr: dict[str, Any], ctx: ToolAvailabilityContext) -> ToolAvailabilityDiagnostic:
    return ToolAvailabilityDiagnostic(signal="always", passed=True, detail="always available")


def _eval_auth(expr: dict[str, Any], ctx: ToolAvailabilityContext) -> ToolAvailabilityDiagnostic:
    provider = expr.get("provider", "")
    if not provider:
        return ToolAvailabilityDiagnostic(
            signal="auth", passed=False, detail="no provider specified"
        )
    authed = ctx.provider_auth.get(provider, False)
    detail = f"provider '{provider}' {'is' if authed else 'is not'} authenticated"
    return ToolAvailabilityDiagnostic(signal="auth", passed=authed, detail=detail)


def _eval_config(expr: dict[str, Any], ctx: ToolAvailabilityContext) -> ToolAvailabilityDiagnostic:
    key = expr.get("key", "")
    expected = expr.get("value")
    actual = ctx.config.get(key)
    if expected is not None:
        matched = actual == expected
        detail = f"config '{key}' = {actual!r} (expected {expected!r})"
        return ToolAvailabilityDiagnostic(signal="config", passed=matched, detail=detail)
    present = actual is not None and actual != ""
    detail = f"config '{key}' is {'set' if present else 'not set'}"
    return ToolAvailabilityDiagnostic(signal="config", passed=present, detail=detail)


def _eval_env(expr: dict[str, Any], ctx: ToolAvailabilityContext) -> ToolAvailabilityDiagnostic:
    var = expr.get("var", "")
    expected = expr.get("value")
    actual = ctx.env.get(var, "")
    if expected is not None:
        matched = actual == expected
        detail = f"env '{var}' = {actual!r} (expected {expected!r})"
        return ToolAvailabilityDiagnostic(signal="env", passed=matched, detail=detail)
    present = bool(actual)
    detail = f"env '{var}' is {'set' if present else 'not set'}"
    return ToolAvailabilityDiagnostic(signal="env", passed=present, detail=detail)


def _eval_installed(
    expr: dict[str, Any], ctx: ToolAvailabilityContext
) -> ToolAvailabilityDiagnostic:
    name = expr.get("name", "")
    if not name:
        return ToolAvailabilityDiagnostic(
            signal="installed", passed=False, detail="no tool name specified"
        )
    installed = name in ctx.installed_tools or shutil.which(name) is not None
    detail = f"tool '{name}' is {'installed' if installed else 'not installed'}"
    return ToolAvailabilityDiagnostic(signal="installed", passed=installed, detail=detail)


# ── Expression evaluators ──────────────────────────────────────────────


def _eval_all_of(expr: list[Any], ctx: ToolAvailabilityContext) -> ToolAvailabilityResult:
    results = [evaluate_availability(e, ctx) for e in expr]
    passed = all(r.available for r in results)
    diags: list[ToolAvailabilityDiagnostic] = []
    for r in results:
        diags.extend(r.diagnostics)
    return ToolAvailabilityResult(available=passed, diagnostics=diags)


def _eval_any_of(expr: list[Any], ctx: ToolAvailabilityContext) -> ToolAvailabilityResult:
    results = [evaluate_availability(e, ctx) for e in expr]
    passed = any(r.available for r in results)
    diags: list[ToolAvailabilityDiagnostic] = []
    for r in results:
        diags.extend(r.diagnostics)
    return ToolAvailabilityResult(available=passed, diagnostics=diags)


# ── Signal registry ────────────────────────────────────────────────────


_SIGNAL_HANDLERS: dict[
    str, Callable[[dict[str, Any], ToolAvailabilityContext], ToolAvailabilityDiagnostic]
] = {
    "always": _eval_always,
    "auth": _eval_auth,
    "config": _eval_config,
    "env": _eval_env,
    "installed": _eval_installed,
}


def register_signal(
    name: str,
    handler: Callable[[dict[str, Any], ToolAvailabilityContext], ToolAvailabilityDiagnostic],
) -> None:
    """Register a custom availability signal handler."""
    _SIGNAL_HANDLERS[name] = handler


# ── Main evaluation function ───────────────────────────────────────────


def evaluate_availability(
    expression: ToolAvailabilitySignal,
    ctx: ToolAvailabilityContext | None = None,
) -> ToolAvailabilityResult:
    """Evaluate a tool availability expression.

    Supports:
    - ``True`` / ``False`` — literal
    - ``{"always": True}`` — always available
    - ``{"auth": {"provider": "openai"}}`` — check provider auth
    - ``{"config": {"key": "feature_x"}}`` — check config value
    - ``{"env": {"var": "API_KEY"}}`` — check env var
    - ``{"installed": {"name": "nmap"}}`` — check tool installed
    - ``{"allOf": [...]}`` — all sub-expressions must pass
    - ``{"anyOf": [...]}`` — any sub-expression must pass
    """
    if ctx is None:
        ctx = ToolAvailabilityContext()

    if isinstance(expression, bool):
        return ToolAvailabilityResult(available=expression)

    if isinstance(expression, str):
        return evaluate_availability({"installed": {"name": expression}}, ctx)

    if not isinstance(expression, dict):
        return ToolAvailabilityResult(available=True)

    if "allOf" in expression:
        items = expression["allOf"]
        return _eval_all_of(items if isinstance(items, list) else [items], ctx)

    if "anyOf" in expression:
        items = expression["anyOf"]
        return _eval_any_of(items if isinstance(items, list) else [items], ctx)

    for signal_name, handler in _SIGNAL_HANDLERS.items():
        if signal_name in expression:
            sig_expr = expression[signal_name]
            if isinstance(sig_expr, bool):
                return ToolAvailabilityResult(
                    available=sig_expr,
                    diagnostics=[
                        ToolAvailabilityDiagnostic(
                            signal=signal_name,
                            passed=sig_expr,
                            detail=f"{signal_name}={sig_expr}",
                        )
                    ],
                )
            if isinstance(sig_expr, dict):
                diag = handler(sig_expr, ctx)
                return ToolAvailabilityResult(
                    available=diag.passed,
                    diagnostics=[diag],
                )

    return ToolAvailabilityResult(available=True)


def check_tool_available(
    tool_name: str,
    ctx: ToolAvailabilityContext | None = None,
) -> tuple[bool, list[ToolAvailabilityDiagnostic]]:
    """Convenience: check if *tool_name* is installed and usable."""
    expr = {"installed": {"name": tool_name}}
    result = evaluate_availability(expr, ctx)
    return result.available, result.diagnostics


__all__ = [
    "ToolAvailabilityContext",
    "ToolAvailabilityDiagnostic",
    "ToolAvailabilityResult",
    "register_signal",
    "evaluate_availability",
    "check_tool_available",
]
