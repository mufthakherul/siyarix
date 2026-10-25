# Production readiness — SX remediation status

This note tracks the audit items from the September 2026 baseline (`177acb6`)
against the current tree on `fix/production-hardening-sx-remediation`.

## Verified closed (evidence in tests / code)

| ID | Topic | Evidence |
| --- | --- | --- |
| SX-001 | Fail-closed shell review | `shell_review.py`, `tests/test_shell_review.py` |
| SX-002 | Execute edited commands | `registry.py` revalidate + kwargs update |
| SX-003 | Autonomous permission gate | `executor_autonomous._exec_one` → `_check_permissions` |
| SX-004 | Target scope IPv6/CIDR | `target_scope.py`, `tests/test_target_scope.py` |
| SX-005 / SX-023 | Report XSS + badge contrast | Jinja2 autoescape + CSP, `tests/test_report_xss.py` |
| SX-006 | Offline queue commits | `offline_queue._transaction`, `tests/test_sx006_*` |
| SX-007 / SX-008 | Credential envelopes / password vault | `credential_store.py`, `tests/test_sx007_*` |
| SX-009 | Audit hash after redact | `audit_log.py`, `tests/test_sx009_*` |
| SX-010 | Dependency-aware scheduling | `executor_autonomous._execute_dependency_aware` |
| SX-011 | CVSS 3.1 Roundup | scores `6.5` for the FIRST example; `tests/test_sx011_*` |
| SX-013–SX-019 | CLI contracts / playbooks | `tests/test_sx_cli_contracts.py` |
| SX-021 | Rich Tree API | `chat/console.py` uses `.add` |
| SX-027 | Redis defaults | compose `profiles: [redis]`, auth, loopback bind |
| SX-028 | Docker target / entrypoint | Makefile `python` target; settings.toml detection |
| SX-029 | CI security gates | `scripts/ci_security_gate.py` |
| SX-030 | Hanging subagent test | `tests/test_core.py` |
| SX-032 | AnyIO advisories | `uv.lock` / `poetry.lock` → 4.15.1 |
| SX-012 | Webhook SSRF destination policy | Literal IP + DNS→private reject; notification path; `tests/test_sx012_webhook_ssrf.py` |
| SX-020 | Hatchling / Twine metadata | `hatchling>=1.21.1,<1.27`; `twine check` passes |
| SX-026 | Rust parser adapters | `siyarix_rust_parsers` function exports via Python adapters |
| SX-031 | mypy consolidation | `.mypy.ini` ↔ `[tool.mypy]`; `mypy src/siyarix` clean; CI runs project mypy |

## Remaining / follow-up

| ID | Status | Notes |
| --- | --- | --- |
| SX-024 | Closed | Offline REPL skips connectivity monitor; HTML reports default `offline=True` (system fonts); online mode widens CSP for Google Fonts only |
| SX-025 | Partial→probes | Local probes for audit chain / shell-review / credential store / PermissionGate / webhook SSRF policy; remaining controls stay `NOT_EVALUATED` with disclaimer |

## Premium ops

- `siyarix production-check` — security/config readiness table (`--strict` for CI); includes `permission_gate`, `tool_registry`, `command_review`, and `destructive_guard`.
- `siyarix scan @targets.txt --parallel N` — true multi-target concurrent scans (merged findings).
- `make_tool_registry()` — shared PermissionGate-on-by-default construction for CLI/chat/plugins/core.
- `siyarix compliance run` — exit `2` on FAIL probes, `3` when NOT_EVALUATED remain (scaffold, not attestation).
- Local-provider `safe_http_*` helpers refuse redirects (block metadata pivots).

## Verification command

```bash
source .venv/bin/activate
mypy src/siyarix
python -m pytest tests/ -q -m "not e2e" --ignore=tests/test_stress_resilience.py
```

Latest local checks on this branch: **mypy clean (258 files)**; pytest **6342 passed**, 6 skipped, 62 deselected (`-m "not e2e"`, stress ignored). Additional closures: `tee -a` auth; dpkg/unsquashfs/git root extract; `mount --bind`; procfs hijacks; curl `--config`/wget `-i` scope; hardlink `ln`; fork-bomb whitespace; mv/rsync/pathlib auth/persistence; ruby/awk inplace; cabextract/jar; chmod auth/setuid; path-qualified scope; TLS `.env`; mmcblk/7z; file://; doctor; SX-025.

Additional post-audit hardening (this branch): atomic offline-queue claim + stale reclaim,
audit flush under RLock, webhook https-only + no-redirect SSRF, playbook step registration, KG vuln
reporting, permission-gate empty-command ordering, injection validator fail-closed,
adversarial CRITICAL plan abort, deep-scan scope enforcement, vault key refuse-silent-rotate,
PermissionGate on by default, no sudo secrets in settings.toml, offline enqueue-on-failure only,
normalized `rm -fr/--recursive` destructive checks, plugin path/entrypoint sandboxing + pip
fail-closed, learned-skill review preserved, atomic settings.toml writes, cache_invalidate rowcount,
CLI multi-target `--parallel` concurrency, compliance status exit codes, chat/CLI registry factory,
DLP↔SecretRedactor pattern sync, broadened `.env` credential skips, non-TTY review guidance,
SecretRedactor URL-password redaction (no longer preserves the secret),
RegistryExecutor/workflow cyclic-dep SKIPPED, dd/mkfs harden, CGNAT/userinfo SSRF,
cache wall-clock TTL + hashed paths, broadened .env skips, generic-handler validation.

Goal status: production gates must stay green (`mypy` + full non-e2e pytest). Absolute “every
possible bug / most-powerful product forever” is not a finite claim — known SX + hunt P0/P1
items are closed with tests; further polish can continue without blocking production use.
