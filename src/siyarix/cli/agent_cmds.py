# SPDX-License-Identifier: AGPL-3.0-or-later
"""Discover / run / agent CLI commands (extracted from the CLI god-module — ARCH-01)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.prompt import Prompt

from siyarix.async_utils import run_async
from siyarix.branding import print_banner
from siyarix.config import SettingsStore
from siyarix.exceptions import ValidationError
from siyarix.validators import validate_target

logger = logging.getLogger(__name__)

# Bound at register time from the CLI god-module.
_console: Console | None = None
_get_engine: Callable[..., Any] | None = None
_make_deep_scan_engine: Callable[[], Any] | None = None
_display_findings: Callable[[list[Any]], None] | None = None
_intent_router: Any = None
_session_kernel: Any = None
_ci_mode: bool = False
_active_theme: str = "default"


def _c() -> Console:
    assert _console is not None
    return _console


def discover(
    target: str = typer.Argument(help="Target network or host"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep discovery (OS, services, vulns)"),
    export: str = typer.Option("", "--export", "-e", help="Export to file (JSON/YAML)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
) -> None:
    """Discover assets, services, and vulnerabilities on a target.

    Examples:
      siyarix discover 192.168.1.0/24
      siyarix discover example.com --deep
      siyarix discover 10.0.0.0/8 --export results.json
    """
    assert _get_engine is not None and _make_deep_scan_engine is not None
    if not no_banner and not _ci_mode:
        print_banner(_c(), _active_theme)

    try:
        validate_target(target)
    except ValidationError as exc:
        _c().print(f"[red]Invalid target '{target}': {exc}[/red]")
        raise typer.Exit(1)

    if deep:
        engine = _make_deep_scan_engine()
        result = run_async(engine.scan(target, persist=True))

        if export:
            import json

            Path(export).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
            _c().print(f"[dim]Deep scan results exported to {export}[/dim]")

        severity_counts = result.get("severity_summary", {})
        _c().print(f"\n[bold cyan]Deep discovery complete for {target}[/bold cyan]")
        _c().print(f"  Total findings: {result.get('total_findings', 0)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count:
                _c().print(f"    {sev}: {count}")
        return

    instruction = f"scan and discover all services on {target}"
    scan_engine = _get_engine("integrated")
    result = run_async(scan_engine.execute(instruction, interactive=True))

    if export and result.all_findings:
        import json

        Path(export).write_text(json.dumps(result.all_findings, indent=2), encoding="utf-8")
        _c().print(f"[dim]Findings exported to {export}[/dim]")


def run(
    ctx: typer.Context,
    command: str | None = typer.Argument(
        None, help="Natural language command or tool name (optional with --resume)"
    ),
    target: str = typer.Option("", "--target", "-t", help="Target for the command"),
    mode: str = typer.Option(
        None,
        "--mode",
        "-m",
        help="Execution mode: autonomous|integrated|offline|registry",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
    save: bool = typer.Option(False, "--save", "-s", help="Persist workflow execution"),
    resume_plan: str = typer.Option(
        "", "--resume", "-r", help="Resume a persisted plan by ID (or 'latest')"
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
) -> None:
    """Run a natural language instruction through the execution engine.

    Examples:
      siyarix run "scan example.com with nmap and nuclei"
      siyarix run "enumerate subdomains of target.com" --mode autonomous
      siyarix run --resume latest
    """
    assert _get_engine is not None and _display_findings is not None
    assert _intent_router is not None and _session_kernel is not None
    if not no_banner and not _ci_mode:
        print_banner(_c(), _active_theme)

    mode_val: Any = mode
    if mode_val is None:
        parent_params = ctx.parent.params if ctx.parent else {}
        mode = str(parent_params.get("mode", "integrated"))

    # Handle --resume
    if resume_plan:
        try:
            from siyarix.offline_store import OfflineStore
        except ModuleNotFoundError:
            _c().print("[yellow]Plan persistence not available in this version[/yellow]")
            raise typer.Exit(1)
        store = OfflineStore()
        resolved_id = resume_plan
        if resume_plan.lower() == "latest":
            resolved_id = store.get_latest_plan_id() or ""
            if not resolved_id:
                _c().print("[red]No plans found to resume.[/red]")
                raise typer.Exit(1)
        engine = _get_engine(mode)
        _c().print(f"[cyan]Resuming plan: {resolved_id}[/cyan]")
        resume_result = run_async(engine.resume(resolved_id, interactive=True))
        if resume_result is not None and not getattr(resume_result, "success", True):
            raise typer.Exit(1)
        return

    if not command:
        _c().print(
            "[red]Missing command. Pass an instruction, or use --resume <id|latest>.[/red]"
        )
        raise typer.Exit(2)

    instruction = command
    if target:
        try:
            validate_target(target)
        except ValidationError as exc:
            _c().print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)
        instruction += f" on {target}"

    route = _intent_router.route(instruction)
    route.mode = mode if mode != "integrated" else route.mode
    session = _session_kernel.start(objective="direct-command", scope=target or "adhoc")
    op = _session_kernel.add_operation(
        session=session,
        instruction=instruction,
        mode=route.mode,
        risk_tier=route.risk_tier.value,
    )

    if route.requires_confirmation and not dry_run:
        proceed = Prompt.ask(
            f"Risk tier is {route.risk_tier.value}. Continue execution? (y/N)",
            default="N",
        )
        if not proceed.lower().startswith("y"):
            _session_kernel.update_operation(session, op.operation_id, state="canceled")
            _c().print("[yellow]Execution canceled.[/yellow]")
            return

    is_pipeline = "|" in instruction or any(
        t in instruction.lower() for t in [" then ", " and then ", " followed by "]
    )
    result: Any
    if is_pipeline:
        from siyarix.core.pipeline import CommandPipeline

        pipeline = CommandPipeline()
        steps = pipeline.parse(instruction)

        class PipelineExecutionResult:
            def __init__(self, success: bool, all_findings: list) -> None:
                self.success = success
                self.all_findings = all_findings
                self.retries_performed = 0
                self.plan_id = ""

        async def step_executor(step: Any, ctx: Any) -> dict[str, Any]:
            step_engine = _get_engine(route.mode)
            res = await step_engine.execute(
                step.instruction, interactive=True, dry_run=dry_run, persist=save
            )
            return {
                "status": "completed" if res.success else "failed",
                "findings": res.all_findings or [],
                "error": getattr(res, "error_message", "") if not res.success else "",
            }

        pipe_res = run_async(pipeline.execute(steps, step_executor))
        result = PipelineExecutionResult(
            success=pipe_res.success, all_findings=pipe_res.all_findings
        )
        if save and result.all_findings:
            try:
                from siyarix.offline_store import OfflineStore

                store = OfflineStore()
                store.save_scan(instruction, result.all_findings, mode=route.mode)
            except Exception:
                logger.warning("Failed to persist scan results", exc_info=True)
    else:
        engine = _get_engine(route.mode)
        result = run_async(
            engine.execute(instruction, interactive=True, dry_run=dry_run, persist=save)
        )

    # Display results
    if result.success:
        if result.all_findings:
            _display_findings(result.all_findings)
        else:
            _c().print("\n[green]Execution completed successfully.[/green]")
    else:
        error_msg = (
            getattr(result, "error_message", "Unknown error")
            if hasattr(result, "error_message")
            else "Unknown error"
        )
        _c().print(f"\n[red]Execution failed: {error_msg}[/red]")

    final_state = "completed" if result.success else "failed"
    _session_kernel.update_operation(
        session=session,
        operation_id=op.operation_id,
        state=final_state,
        retries=result.retries_performed,
        artifact=result.plan_id or "",
    )
    _session_kernel.save(session)
    if not result.success:
        raise typer.Exit(1)


def agent(
    goal: str = typer.Argument(help="The goal for the autonomous agent to achieve"),
    target: str = typer.Option("", "--target", "-t", help="Target host/IP/URL"),
    max_iterations: int = typer.Option(10, "--max-iter", "-n", help="Maximum agent iterations"),
    mode: str = typer.Option("autonomous", "--mode", "-m", help="Execution mode"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Enable stealth mode"),
) -> None:
    """Launch a goal-driven autonomous agent (observe → reason → act loop).

    The agent continuously plans, executes, and adapts until the goal
    is achieved or max iterations are reached.

    Examples:
      siyarix agent "Perform full recon on target.com" --target target.com
      siyarix agent "Find SQL injection vulnerabilities" -t http://app.local -n 5
      siyarix agent "Enumerate and scan 10.0.0.0/24" --max-iter 15
    """
    if not no_banner and not _ci_mode:
        print_banner(_c(), _active_theme)

    if target:
        try:
            validate_target(target)
        except ValidationError as exc:
            _c().print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)

    from siyarix.core import AgentCore, AgentGoal, AgentMode

    mode_map = {
        "offline": AgentMode.REGISTRY,
        "autonomous": AgentMode.AUTONOMOUS,
        "integrated": AgentMode.HYBRID,
    }
    agent_core = AgentCore(mode=mode_map.get(mode, AgentMode.HYBRID))

    settings = SettingsStore()
    if stealth or settings.get("stealth_mode"):
        agent_core.stealth.enable("medium")

    async def _run_agent() -> None:
        await agent_core.start()
        try:
            agent_goal = AgentGoal(description=goal, target=target)
            await agent_core.execute_goal(agent_goal)
        finally:
            await agent_core.shutdown()

    run_async(_run_agent())


def register_agent_commands(
    app: typer.Typer,
    *,
    console: Console,
    get_engine: Callable[..., Any],
    make_deep_scan_engine: Callable[[], Any],
    display_findings_table: Callable[[list[Any]], None],
    intent_router: Any,
    session_kernel: Any,
    ci_mode: bool,
    active_theme: str,
) -> None:
    """Attach discover / run / agent commands to *app*."""
    global \
        _console, \
        _get_engine, \
        _make_deep_scan_engine, \
        _display_findings, \
        _intent_router, \
        _session_kernel, \
        _ci_mode, \
        _active_theme
    _console = console
    _get_engine = get_engine
    _make_deep_scan_engine = make_deep_scan_engine
    _display_findings = display_findings_table
    _intent_router = intent_router
    _session_kernel = session_kernel
    _ci_mode = ci_mode
    _active_theme = active_theme

    app.command()(discover)
    app.command()(run)
    app.command()(agent)
