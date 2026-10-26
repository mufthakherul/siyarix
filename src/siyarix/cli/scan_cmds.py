# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scan CLI commands (extracted from the CLI god-module — ARCH-01)."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Callable

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from siyarix.async_utils import run_async
from siyarix.audit_log import AuditEventType, AuditSeverity, audit
from siyarix.branding import print_banner
from siyarix.compat import EngineResult
from siyarix.exceptions import ValidationError
from siyarix.validators import validate_target

logger = logging.getLogger(__name__)

# Bound at register time from the CLI god-module.
_console: Console | None = None
_config: Any = None
_get_engine: Callable[..., Any] | None = None
_display_findings: Callable[[list[Any]], None] | None = None
_execute_deep_scan: Callable[..., None] | None = None
_ci_mode: bool = False
_active_theme: str = "default"


def _c() -> Console:
    assert _console is not None
    return _console


def _cfg() -> Any:
    assert _config is not None
    return _config



def get_engine(mode: str = "integrated") -> Any:
    assert _get_engine is not None
    return _get_engine(mode)


def display_findings(findings: list[Any]) -> None:
    assert _display_findings is not None
    _display_findings(findings)


def execute_deep_scan(target: str, output: str = "table", save: bool = False) -> None:
    assert _execute_deep_scan is not None
    _execute_deep_scan(target, output=output, save=save)

def _build_scan_instruction(target: str, *, tool: str = "", nmap_args: str = "") -> str:
    """Build a natural-language scan instruction for a single target."""
    instruction = f"scan {target}"
    if nmap_args:
        instruction += f" flags {nmap_args}"
    if tool:
        instruction += f" with {tool}"
    return instruction


async def _execute_targets_parallel(
    targets: list[str],
    *,
    mode: str,
    tool: str = "",
    nmap_args: str = "",
    parallel: int = 3,
    dry_run: bool = False,
    persist: bool = False,
) -> EngineResult:
    """Run one engine.execute per target with bounded concurrency; merge results."""
    workers = max(1, min(int(parallel), len(targets), 32))
    sem = asyncio.Semaphore(workers)
    _c().print(
        f"[dim]Scanning {len(targets)} targets with {workers} parallel workers[/dim]"
    )

    async def _one(target: str) -> EngineResult:
        instruction = _build_scan_instruction(target, tool=tool, nmap_args=nmap_args)
        engine = get_engine(mode)
        async with sem:
            try:
                return await engine.execute(
                    instruction,
                    interactive=False,
                    dry_run=dry_run,
                    persist=persist,
                )
            except Exception as exc:
                logger.exception("Parallel scan failed for target %s", target)
                return EngineResult(
                    success=False,
                    summary=f"{target}: failed ({exc})",
                    error_message=str(exc),
                )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Parallel scan[/bold cyan]"),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=_c(),
    ) as progress:
        task_id = progress.add_task(
            f"0/{len(targets)} done · 0 ok · 0 fail", total=len(targets)
        )
        completed = 0
        ok_count = 0
        fail_count = 0
        in_flight: set[str] = set()
        lock = asyncio.Lock()

        async def _tracked(target: str) -> EngineResult:
            nonlocal completed, ok_count, fail_count
            async with lock:
                in_flight.add(target)
                active = ", ".join(sorted(in_flight)[:3])
                if len(in_flight) > 3:
                    active += f" +{len(in_flight) - 3}"
                progress.update(
                    task_id,
                    description=(
                        f"{completed}/{len(targets)} done · {ok_count} ok · "
                        f"{fail_count} fail · now: {active or '—'}"
                    ),
                )
            result = await _one(target)
            async with lock:
                in_flight.discard(target)
                completed += 1
                if result.success:
                    ok_count += 1
                else:
                    fail_count += 1
                progress.update(
                    task_id,
                    advance=1,
                    description=(
                        f"{completed}/{len(targets)} done · {ok_count} ok · "
                        f"{fail_count} fail"
                    ),
                )
            return result

        raw_results = await asyncio.gather(
            *[_tracked(t) for t in targets],
            return_exceptions=True,
        )

    merged = EngineResult(success=True, summary="")
    summaries: list[str] = []
    for target, raw in zip(targets, raw_results, strict=True):
        if isinstance(raw, BaseException):
            merged.success = False
            msg = f"{target}: error ({raw})"
            summaries.append(msg)
            merged.error_message = (
                f"{merged.error_message}; {msg}" if merged.error_message else msg
            )
            continue
        for finding in raw.all_findings or []:
            if isinstance(finding, dict):
                tagged = dict(finding)
                tagged.setdefault("target", target)
                tagged.setdefault("scan_target", target)
                merged.all_findings.append(tagged)
            else:
                # Best-effort tag object findings for multi-target rollups.
                try:
                    if getattr(finding, "target", None) in (None, ""):
                        setattr(finding, "target", target)
                    if getattr(finding, "scan_target", None) in (None, ""):
                        setattr(finding, "scan_target", target)
                except Exception:
                    pass
                merged.all_findings.append(finding)
        merged.step_results.extend(raw.step_results or [])
        merged.duration_ms += float(raw.duration_ms or 0.0)
        merged.retries_performed += int(raw.retries_performed or 0)
        if raw.raw_output:
            merged.raw_output = (
                f"{merged.raw_output}\n{raw.raw_output}" if merged.raw_output else raw.raw_output
            )
        if not raw.success:
            merged.success = False
        if raw.error_message:
            merged.error_message = (
                f"{merged.error_message}; {raw.error_message}"
                if merged.error_message
                else raw.error_message
            )
        summaries.append(raw.summary or f"{target}: done")

    preview = "; ".join(summaries[:8])
    if len(summaries) > 8:
        preview += "…"
    ok_n = sum(
        1
        for raw in raw_results
        if not isinstance(raw, BaseException) and getattr(raw, "success", False)
    )
    fail_n = len(targets) - ok_n
    findings_n = len(merged.all_findings or [])
    status = "ok" if merged.success else "partial/fail"
    merged.summary = (
        f"Parallel scan of {len(targets)} targets ({status}; "
        f"{ok_n} ok / {fail_n} fail; {findings_n} findings): {preview}"
    )
    style = "green" if merged.success else "yellow"
    _c().print(
        f"[{style}]Parallel scan complete:[/{style}] "
        f"{ok_n} ok · {fail_n} fail · {findings_n} findings · "
        f"{merged.duration_ms:.0f} ms"
    )
    return merged


def _execute_scan_core(
    targets: list[str],
    tool: str = "",
    mode: str = "integrated",
    output: str = "table",
    timeout: int = 300,
    save: bool = False,
    dry_run: bool = False,
    no_banner: bool = False,
    profile: str = "",
    parallel: int = 3,
    notify: bool = False,
    nmap_args: str = "",
) -> Any:
    """Core scan execution logic (shared between scan and presets)."""
    _ = timeout, no_banner, profile  # reserved for preset/future CLI wiring
    expanded_targets: list[str] = []
    for t in targets:
        if t.startswith("@"):
            target_file = Path(t[1:])
            if target_file.exists():
                lines = [
                    line.strip()
                    for line in target_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                expanded_targets.extend(lines)
                _c().print(f"[dim]Loaded {len(lines)} targets from {target_file}[/dim]")
            else:
                _c().print(f"[red]Target file not found: {target_file}[/red]")
                raise typer.Exit(3)
        else:
            expanded_targets.append(t)
    if not expanded_targets:
        _c().print("[red]No targets specified. Use siyarix scan <target> or @file.txt[/red]")
        raise typer.Exit(1)
    for target in expanded_targets:
        try:
            validate_target(target)
        except ValidationError as exc:
            _c().print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)
    valid_outputs = ("table", "json", "yaml", "csv", "html", "quiet")
    output = output.lower()
    if output not in valid_outputs:
        _c().print(
            f"[red]Invalid output format '{output}'. Valid: {', '.join(valid_outputs)}[/red]"
        )
        raise typer.Exit(1)
    instruction = _build_scan_instruction(
        " ".join(expanded_targets), tool=tool, nmap_args=nmap_args
    )
    audit.log(
        event_type=AuditEventType.SCAN_START,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="started",
        target=",".join(expanded_targets),
        details={
            "tool": tool,
            "mode": mode,
            "targets": expanded_targets,
            "parallel": parallel,
        },
    )
    if len(expanded_targets) > 1:
        # Always one engine.execute per target (parallel workers or sequential).
        # Avoids the old join-all-targets single instruction that lost per-host tagging.
        result = run_async(
            _execute_targets_parallel(
                expanded_targets,
                mode=mode,
                tool=tool,
                nmap_args=nmap_args,
                parallel=parallel,
                dry_run=dry_run,
                persist=save,
            )
        )
    else:
        engine = get_engine(mode)
        result = run_async(
            engine.execute(instruction, interactive=True, dry_run=dry_run, persist=save)
        )
    if dry_run:
        _c().print("[yellow]Dry run complete — no commands executed.[/yellow]")
        return result
    summary_text = str(getattr(result, "summary", None) or "")
    if output != "quiet" and len(expanded_targets) > 1 and parallel > 1 and summary_text:
        _c().print(Panel(summary_text, title="Parallel Scan Summary", border_style="cyan"))
    if output == "quiet":
        pass
    elif result.all_findings:
        if output in ("json", "yaml", "csv", "html"):
            try:
                from ..output import OutputEngine

                output_engine = OutputEngine(output_format=output)

                def _as_dict(finding: Any) -> dict[str, Any]:
                    if isinstance(finding, dict):
                        return finding
                    if hasattr(finding, "to_dict"):
                        return finding.to_dict()
                    try:
                        return vars(finding)
                    except TypeError:
                        return {"value": finding}

                findings_dicts = [_as_dict(f) for f in result.all_findings]
                if output == "json":
                    output_engine.print_json(findings_dicts)
                elif output == "yaml":
                    output_engine.print_yaml(findings_dicts)
                elif output == "csv":
                    output_engine.print_csv(findings_dicts)
                elif output == "html":
                    if hasattr(output_engine, "print_html"):
                        output_engine.print_html(findings_dicts)
                    else:
                        output_engine.print_json(findings_dicts)
            except ImportError:
                display_findings(result.all_findings)
        else:
            display_findings(result.all_findings)
    audit.log(
        event_type=AuditEventType.SCAN_COMPLETE,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="success" if result.success else "failed",
        target=",".join(expanded_targets),
        details={"summary": result.summary, "findings": len(result.all_findings)},
    )
    if notify:
        try:
            from ..notifications import NotificationDispatcher

            dispatcher = NotificationDispatcher()
            status_text = "completed successfully" if result.success else "failed"
            findings_count = len(result.all_findings) if hasattr(result, "all_findings") else 0
            msg = (
                f"🛡️ **Siyarix Scan {status_text}**\n\n"
                f"**Targets:** {', '.join(expanded_targets)}\n"
                f"**Mode:** {mode}\n"
                f"**Findings:** {findings_count}\n"
            )
            run_async(dispatcher.dispatch(msg))
        except Exception as notify_exc:
            logger.debug("Failed to dispatch scan notification: %s", notify_exc)
    return result



def scan(
    ctx: typer.Context,
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, URLs, or @file.txt"),
    tool: str = typer.Option("", "--tool", "-t", help="Specific tool to use"),
    mode: str = typer.Option(
        None,
        "--mode",
        "-m",
        help="Execution mode: autonomous|integrated|offline|registry",
    ),
    output: str = typer.Option(
        "table", "--output", "-o", help="Output: table|json|yaml|csv|html|quiet"
    ),
    _parallel: int | None = typer.Option(
        None,
        "--parallel",
        "-p",
        help=(
            "Max concurrent workers for multi-target scans (1 = sequential per-target; "
            "default from settings default_parallel / SIYARIX_PARALLEL)"
        ),
        min=1,
        max=32,
    ),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per tool (seconds)"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to database"),
    _notify: bool = typer.Option(False, "--notify", "-n", help="Send notification on completion"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
    profile: str = typer.Option("", "--profile", help="Use specific profile"),
) -> None:
    """Run security scans against one or more targets.

    Supports @targets.txt multi-target mode. Prefix a file path with @ to load targets.
    With 2+ targets, --parallel runs independent per-target scans concurrently.

    Examples:
      siyarix scan 192.168.1.1
      siyarix scan 10.0.0.0/24 --tool nmap --mode registry
      siyarix scan @targets.txt --parallel 5
    """
    if not no_banner and not _ci_mode:
        print_banner(_c(), _active_theme)

    mode_val: Any = mode
    if mode_val is None:
        parent_params = ctx.parent.params if ctx.parent else {}
        mode = str(parent_params.get("mode", "integrated"))

    parallel_workers = _parallel
    if parallel_workers is None:
        try:
            parallel_workers = int(_cfg().get("default_parallel") or 3)
        except (TypeError, ValueError):
            parallel_workers = 3
    parallel_workers = max(1, min(int(parallel_workers), 32))

    result = _execute_scan_core(
        targets,
        tool=tool,
        mode=mode,
        output=output,
        timeout=timeout,
        save=save,
        dry_run=dry_run,
        no_banner=no_banner,
        profile=profile,
        parallel=parallel_workers,
        notify=_notify,
    )
    if result is not None and not getattr(result, "success", True):
        raise typer.Exit(1)



def scan_quick(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or @file.txt"),
    mode: str = typer.Option(None, "--mode", "-m", help="Execution mode"),
    _parallel: int | None = typer.Option(
        None,
        "--parallel",
        "-p",
        help=(
            "Max concurrent workers for multi-target scans "
            "(default from settings default_parallel / SIYARIX_PARALLEL)"
        ),
        min=1,
        max=32,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
) -> None:
    """Quick scan preset — fast port discovery (top 100 ports, no service detection).

    Supports ``@targets.txt`` and ``--parallel`` for multi-host campaigns.
    """
    parallel_workers = _parallel
    if parallel_workers is None:
        try:
            parallel_workers = int(_cfg().get("default_parallel") or 3)
        except (TypeError, ValueError):
            parallel_workers = 3
    parallel_workers = max(1, min(int(parallel_workers), 32))
    _execute_scan_core(
        targets,
        tool="nmap",
        mode=mode or "registry",
        output="table",
        timeout=120,
        save=False,
        dry_run=dry_run,
        no_banner=True,
        profile="",
        nmap_args="--top-ports 100",
        parallel=parallel_workers,
    )


def scan_full(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or @file.txt"),
    mode: str = typer.Option(None, "--mode", "-m", help="Execution mode"),
    _parallel: int | None = typer.Option(
        None,
        "--parallel",
        "-p",
        help=(
            "Max concurrent workers for multi-target scans "
            "(default from settings default_parallel / SIYARIX_PARALLEL)"
        ),
        min=1,
        max=32,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
) -> None:
    """Full scan preset — all ports, service + OS detection, default scripts.

    Supports ``@targets.txt`` and ``--parallel`` for multi-host campaigns.
    """
    parallel_workers = _parallel
    if parallel_workers is None:
        try:
            parallel_workers = int(_cfg().get("default_parallel") or 3)
        except (TypeError, ValueError):
            parallel_workers = 3
    parallel_workers = max(1, min(int(parallel_workers), 32))
    _execute_scan_core(
        targets,
        tool="nmap",
        mode=mode or "registry",
        output="table",
        timeout=600,
        save=False,
        dry_run=dry_run,
        no_banner=True,
        profile="",
        nmap_args="-p- -sV -O -sC",
        parallel=parallel_workers,
    )


def scan_deep(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or @file.txt"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to offline store"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
) -> None:
    """Deep scan preset — multi-pass OS detection, service fingerprinting, and vulnerability scanning.

    Runs 4 progressive passes: discovery → fingerprint → vulnerability → enumeration.
    """
    expanded_targets: list[str] = []
    for t in targets:
        if t.startswith("@"):
            target_file = Path(t[1:])
            if target_file.exists():
                lines = [
                    line.strip()
                    for line in target_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                expanded_targets.extend(lines)
                _c().print(f"[dim]Loaded {len(lines)} targets from {target_file}[/dim]")
            else:
                _c().print(f"[red]Target file not found: {target_file}[/red]")
                raise typer.Exit(3)
        else:
            expanded_targets.append(t)

    for target in expanded_targets:
        _c().print(f"\n[bold cyan]Starting deep scan of {target}...[/bold cyan]")
        execute_deep_scan(target, output=output, save=save)


def scan_web(
    targets: list[str] = typer.Argument(..., help="Target URLs or domains"),
    mode: str = typer.Option(None, "--mode", "-m", help="Execution mode"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
) -> None:
    """Web scan preset — HTTP service enumeration (whatweb, nikto, nuclei)."""
    tool = "whatweb+nikto+nuclei"
    updated_targets = [f"http://{t}" if "://" not in t else t for t in targets]
    _execute_scan_core(
        updated_targets,
        tool=tool,
        mode=mode or "registry",
        output="table",
        timeout=300,
        save=False,
        dry_run=dry_run,
        no_banner=True,
        profile="",
    )




def register_scan_commands(
    app: typer.Typer,
    *,
    console: Console,
    config: Any,
    get_engine: Callable[..., Any],
    display_findings_table: Callable[[list[Any]], None],
    execute_deep_scan_fn: Callable[..., None],
    ci_mode: bool,
    active_theme: str,
) -> None:
    """Attach scan / scan-* commands to *app* using CLI runtime dependencies."""
    global _console, _config, _get_engine, _display_findings, _execute_deep_scan, _ci_mode, _active_theme
    _console = console
    _config = config
    _get_engine = get_engine
    _display_findings = display_findings_table
    _execute_deep_scan = execute_deep_scan_fn
    _ci_mode = ci_mode
    _active_theme = active_theme

    app.command()(scan)
    app.command(name="scan-quick")(scan_quick)
    app.command(name="scan-full")(scan_full)
    app.command(name="scan-deep")(scan_deep)
    app.command(name="scan-web")(scan_web)
