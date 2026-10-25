# SPDX-License-Identifier: AGPL-3.0-or-later
"""Production readiness checklist (``siyarix production-check`` / ``doctor``).

Extracted from the CLI god-module so readiness probes stay reviewable and
testable without pulling the full command surface.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from siyarix.async_utils import run_async
from siyarix.config import SettingsStore
from siyarix.health import get_health

_DEFAULT_CONSOLE = Console()

# Operator-safety probes exercised by production-check (keep in sync with
# residual-hunter regressions when adding new hard-blocks).
_DESTRUCTIVE_PROBES: tuple[str, ...] = (
    "chmod -Rf 777 /",
    "curl -o /dev/sda http://example.com/x",
    "rsync -a --delete /tmp/ /",
    "python -c \"Path('/dev/sda').write_bytes(b'x')\"",
    "python -c \"__import__('os').system('rm -rf /')\"",
    "nwipe /dev/sda",
    "chmod -R 777 /tmp/../",
    "dd if=/dev/zero of=/dev/mmcblk0",
    "7z x /tmp/a.7z -o/",
    "bsdtar xf /tmp/x -C /",
    "gdd if=/dev/zero of=/dev/sda",
    "mke2fs /dev/sda",
    "gtar -C / -xf evil.tar",
    "unar -o / evil.rar",
    "cp -t /etc/cron.d /tmp/pwn",
    "rpm --root=/ -ivh evil.rpm",
    "dd_rescue /dev/zero /dev/sda",
    "apk -p / add x",
    "debootstrap stable /",
    "mount -B /tmp/e /etc/passwd",
    "shuf -o /etc/passwd /tmp/x",
    "cp -t/etc/cron.d /tmp/pwn",
    "mount -o rw,bind /tmp/evil /etc/passwd",
    "tar -P -xf evil.tar",
    "ddrescue /tmp/x /etc/passwd",
    "simg2img a.img /dev/sda",
    "bmaptool copy a.img /dev/sda",
    "ginstall -m4755 /tmp/sh /bin/bash",
    # RH-35
    "gem unpack foo.gem --target /",
    "aunpack -X / evil.tar.gz",
)

_SCOPE_DENY_PROBES: tuple[tuple[str, str, str], ...] = (
    ("nmap 0177.1", "10.0.0.0/8", "inet_aton 0177.1"),
    ("curl file:///etc/passwd", "10.0.0.0/8", "file:// under authorized scope"),
    ("smbclient //evil-host/share", "10.0.0.0/8,example.com", "smbclient UNC host"),
    (
        "ansible -i evilhost, all -m ping",
        "10.0.0.0/8,example.com",
        "ansible inventory host",
    ),
    # RH-29: in-scope hop must not allow reverse SOCKS pivot.
    (
        "chisel client 10.0.0.1:8080 R:socks",
        "10.0.0.0/8",
        "chisel R:socks reverse pivot",
    ),
    # RH-30
    ("sshuttle -r user@10.0.0.1 0/0", "10.0.0.0/8", "sshuttle full-tunnel 0/0"),
    # RH-34
    ("docker context use prod", "10.0.0.0/8", "docker context use"),
)


def build_production_payload(
    *,
    strict: bool = False,
    config: SettingsStore | None = None,
) -> dict[str, Any]:
    """Collect readiness checks and return the machine-readable payload."""
    from siyarix.registry_factory import make_tool_registry, permission_gate_enabled
    from siyarix.shell_review import is_preauthorized
    from siyarix.webhooks import _validate_url

    settings = config if config is not None else SettingsStore()
    checks: list[dict[str, str]] = []

    def _add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    _add(
        "python",
        "pass" if sys.version_info >= (3, 11) else "fail",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )

    preauth = is_preauthorized()
    _add(
        "shell_review",
        "warn" if preauth else "pass",
        "SIYARIX_PREAUTHORIZED=1 (non-interactive auto-approve)"
        if preauth
        else "fail-closed unless preauthorized",
    )

    gate_on = permission_gate_enabled()
    _add(
        "permission_gate",
        "pass" if gate_on else "warn",
        "SIYARIX_SAFE_MODE on (PermissionGate default)"
        if gate_on
        else "SIYARIX_SAFE_MODE disabled — lab mode only",
    )
    try:
        reg = make_tool_registry()
        _add(
            "tool_registry",
            "pass"
            if getattr(reg, "_permission_gate", None) is not None or not gate_on
            else "fail",
            "make_tool_registry() builds gated registry",
        )
    except Exception as exc:  # pragma: no cover - defensive
        _add("tool_registry", "fail", f"registry factory error: {exc}")

    offline = os.environ.get("SIYARIX_OFFLINE", "").strip().lower() in {"1", "true", "yes"}
    _add(
        "offline_mode",
        "pass" if offline else "info",
        "SIYARIX_OFFLINE enabled" if offline else "online (CDN fonts optional in reports)",
    )

    webhook = os.environ.get("SIYARIX_WEBHOOK_URL", "").strip()
    if not webhook:
        _add("webhook", "info", "SIYARIX_WEBHOOK_URL unset")
    else:
        try:
            _validate_url(webhook, allow_ip=False)
            _add("webhook", "pass", "destination URL policy ok")
        except ValueError as exc:
            _add("webhook", "fail", str(exc))

    redis_url = os.environ.get("REDIS_URL") or os.environ.get("SIYARIX_REDIS_URL")
    _add(
        "redis",
        "info" if not redis_url else "pass",
        "not configured (compose profile optional)" if not redis_url else "REDIS_URL set",
    )

    scope = (os.environ.get("SIYARIX_ALLOWED_SCOPE") or "").strip()
    _add(
        "allowed_scope",
        "pass",
        (
            f"engagement scope active ({scope[:60]}{'…' if len(scope) > 60 else ''})"
            if scope
            else "unset — research tooling unrestricted; set for engagement-bound automation"
        ),
    )

    cmd_review = bool(settings.get("command_review", True))
    _add(
        "command_review",
        "pass" if cmd_review else "warn",
        "prompt before raw shell commands"
        if cmd_review
        else "disabled — enable for production (CTF profile opts out)",
    )

    try:
        from siyarix.destructive import assert_command_not_destructive
        from siyarix.exceptions import PermissionDeniedError as _PermDenied
        from siyarix.target_scope import assert_command_in_scope as _assert_scope

        assert_command_not_destructive("echo ok")
        for _probe in _DESTRUCTIVE_PROBES:
            try:
                assert_command_not_destructive(_probe)
                raise RuntimeError(f"expected hard-block for: {_probe}")
            except _PermDenied:
                pass
        for cmd, scope_env, label in _SCOPE_DENY_PROBES:
            try:
                _assert_scope(cmd, scope_env=scope_env)
                raise RuntimeError(f"expected scope deny for {label}")
            except _PermDenied:
                pass
        # Unset scope must not hobble research tooling (engagement boundary is optional).
        _assert_scope("nmap evilhost", scope_env="")
        _add(
            "destructive_guard",
            "pass",
            "operator-safety hard-blocks + engagement-scope probes ok "
            "(unset scope leaves research tooling unrestricted)",
        )
    except Exception as exc:  # pragma: no cover - defensive
        _add("destructive_guard", "fail", f"unavailable: {exc}")

    try:
        from siyarix.credential_store import CredentialStore

        store = CredentialStore()
        backend = type(store).__name__
        mode = getattr(store, "_vault_mode", "unknown")
        require_pw = os.getenv("SIYARIX_REQUIRE_MASTER_PASSWORD", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        } or os.getenv("SIYARIX_PRODUCTION", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if mode == "file_key":
            # SX-A06: warn by default; fail under production / require-master-password.
            _add(
                "credentials",
                "fail" if (require_pw or strict) else "warn",
                f"store={backend} mode=file_key — set SIYARIX_MASTER_PASSWORD "
                "for production (key file on disk)",
            )
        else:
            _add("credentials", "pass", f"store={backend} mode={mode}")
    except Exception as exc:  # pragma: no cover - defensive
        _add("credentials", "warn", f"unavailable: {exc}")

    # SX-A01: plugins remain in-process; production must use force + honesty about isolation.
    try:
        from siyarix.plugins.manager import plugin_trust_mode

        trust = plugin_trust_mode()
        production = os.getenv("SIYARIX_PRODUCTION", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        } or os.getenv("SIYARIX_REQUIRE_MASTER_PASSWORD", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        from siyarix.plugins.isolation import plugin_preflight_enabled

        preflight = plugin_preflight_enabled()
        if trust == "off":
            _add(
                "plugin_trust",
                "pass",
                "plugins disabled (SIYARIX_TRUST_PLUGINS unset) — OS isolation N/A",
            )
        elif trust == "force":
            _add(
                "plugin_trust",
                "warn" if (production or strict) else "info",
                "SIYARIX_TRUST_PLUGINS=force — in-process plugins are fully trusted; "
                f"subprocess compile preflight={'on' if preflight else 'off'} "
                "(true OS isolation still open)",
            )
        else:
            _add(
                "plugin_trust",
                "warn" if strict else "info",
                "SIYARIX_TRUST_PLUGINS=1 (lab) — in-process load; use =force under "
                f"SIYARIX_PRODUCTION; preflight={'on' if preflight else 'off'}",
            )
    except Exception as exc:  # pragma: no cover - defensive
        _add("plugin_trust", "warn", f"unavailable: {exc}")

    health = run_async(get_health().check_all())
    _add("health", health.state.value, f"{len(health.components)} components checked")

    fails = sum(1 for c in checks if c["status"] in {"fail", "unhealthy"})
    warns = sum(1 for c in checks if c["status"] in {"warn", "degraded"})
    _n = max(len(checks), 1)
    _penalties = fails * 25 + warns * 8
    score = max(0, min(100, int(round(100 - (_penalties * 100 / (_n * 25))))))
    if fails == 0 and warns == 0:
        score = 100
    grade = (
        "production-ready"
        if fails == 0 and warns == 0
        else "needs-attention"
        if fails == 0
        else "not-ready"
    )
    remediations: list[str] = []
    _hints = {
        "allowed_scope": (
            "optional engagement boundary for authorized tests — "
            "export SIYARIX_ALLOWED_SCOPE='10.0.0.0/8,*.lab.example' "
            "(unset = no scope restriction on research tooling)"
        ),
        "permission_gate": "unset SIYARIX_SAFE_MODE (or set to 1) for production",
        "command_review": "enable command_review in settings / profile",
        "shell_review": "unset SIYARIX_PREAUTHORIZED for interactive review",
        "webhook": "use https:// webhook URLs only (SIYARIX_WEBHOOK_URL)",
        "destructive_guard": (
            "operator-safety hard-blocks failed — reinstall siyarix "
            "(guards accidental wipe of your disks/auth files, not research tools)"
        ),
        "credentials": (
            "export SIYARIX_MASTER_PASSWORD=… (or SIYARIX_REQUIRE_MASTER_PASSWORD=1 "
            "to fail closed on file_key vault)"
        ),
        "plugin_trust": (
            "leave SIYARIX_TRUST_PLUGINS unset for production, or set =force only "
            "for explicitly reviewed in-process plugins (OS isolation still open)"
        ),
    }
    for c in checks:
        if c["status"] in {"fail", "unhealthy", "warn", "degraded"}:
            hint = _hints.get(c["name"])
            if hint:
                remediations.append(f"{c['name']}: {hint}")

    return {
        "checks": checks,
        "fails": fails,
        "warns": warns,
        "score": score,
        "grade": grade,
        "remediations": remediations,
    }


def emit_production_check(
    payload: dict[str, Any],
    *,
    output: str = "table",
    console: Console | None = None,
) -> None:
    """Print the readiness payload as JSON or a Rich table."""
    out = console or _DEFAULT_CONSOLE
    if output == "json":
        print(json.dumps(payload, indent=2), flush=True)
        return

    table = Table(title="Siyarix Production Check", header_style="bold cyan")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Detail", style="white")
    for c in payload["checks"]:
        table.add_row(c["name"], c["status"], c["detail"])
    out.print(table)
    out.print(
        f"[bold]Readiness score:[/bold] {payload['score']}/100 ({payload['grade']})"
    )
    out.print(
        "[dim]Siyarix accelerates authorized security research; "
        "guards protect the operator (optional engagement scope).[/dim]"
    )
    remediations = payload.get("remediations") or []
    if remediations:
        out.print("[dim]Remediation hints:[/dim]")
        for tip in remediations:
            out.print(f"  • {tip}")
    fails = int(payload.get("fails") or 0)
    warns = int(payload.get("warns") or 0)
    if fails:
        out.print(f"[red]{fails} failing check(s)[/red]")
    elif warns:
        out.print(f"[yellow]{warns} warning(s) — review before production[/yellow]")
    else:
        out.print("[green]✓ Production checks look good[/green]")


def run_production_check(
    *,
    output: str = "table",
    strict: bool = False,
    console: Console | None = None,
    config: SettingsStore | None = None,
) -> dict[str, Any]:
    """Run the checklist, emit output, and raise ``typer.Exit`` on failure."""
    payload = build_production_payload(strict=strict, config=config)
    emit_production_check(payload, output=output, console=console)
    fails = int(payload.get("fails") or 0)
    warns = int(payload.get("warns") or 0)
    if strict and (fails or warns):
        raise typer.Exit(2)
    if fails:
        raise typer.Exit(1)
    return payload
