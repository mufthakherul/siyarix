# Production readiness — SX remediation status

Siyarix is an AI orchestration assistant for **security researchers, pentesters,
SOC analysts, and other cybersecurity professionals** — to run authorized work
faster, deeper, and more reliably. Hardening here is **operator safety**
(prevent accidental disk wipe, auth-file clobber, or out-of-engagement pivots),
not a restriction on legitimate security tooling. `SIYARIX_ALLOWED_SCOPE` is
optional; when unset, scope checks are a no-op.

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
| SX-032 | AnyIO advisories | `uv.lock` → 4.15.1 (`poetry.lock` removed; see `LOCKFILES.md`) |
| SX-012 | Webhook SSRF destination policy | Literal IP + DNS→private reject; notification path; `tests/test_sx012_webhook_ssrf.py` |
| SX-020 | Hatchling / Twine metadata | `hatchling>=1.21.1,<1.27`; `twine check` passes |
| SX-026 | Rust parser adapters | `siyarix_rust_parsers` function exports via Python adapters |
| SX-031 | mypy consolidation | `.mypy.ini` ↔ `[tool.mypy]`; `mypy src/siyarix` clean; CI runs project mypy |

## Remaining / follow-up

| ID | Status | Notes |
| --- | --- | --- |
| SX-024 | Closed | Offline REPL skips connectivity monitor; HTML reports default `offline=True` (system fonts); online mode widens CSP for Google Fonts only |
| SX-025 | Partial→probes | Local probes for audit chain / shell-review / credential store / PermissionGate / webhook SSRF policy; remaining controls stay `NOT_EVALUATED` with disclaimer |
| RH-01–05 | Closed | Lexical path normalize before auth/block regexes; `cp --parents` / `rsync -R` auth reconstruction blocked |
| RH-04 | Closed | Shared `dotenv_guard` blocks PERLLIB / Java aliases / CORECLR_* / BASH_FUNC / editors / Ansible plugins / GOCACHEPROG / … |
| RH-06 | Closed | Scope blocks proxychains/torsocks/tunnels, `psql service=`, `ssh -D` |
| SX-A03 | Closed | `_prepare_env` scrubs sudo/master/API secrets from child processes |
| SX-A04 | Closed | Full SHA-256 audit digests; `verify_chain` reads full on-disk JSONL (legacy 16-char accepted) |
| SX-A05 | Closed | Agent PermissionGate uses `permission_gate_enabled()` env-only (no settings.toml silent off) |
| SX-A07/A08 | Closed | `*.enc` chmod 600; config dir 0700; KMS fail-closed when `SIYARIX_KMS_PROVIDER=aws` |
| FEAT/DOC | Partial | Compose API ports removed; classifiers Beta (no iOS); stub module warning; ghost TAXII/MISP/dashboard env scrubbed |
| SX-A02/A10/A11 | Closed | Plugin auto-pip off by default (`SIYARIX_PLUGIN_AUTO_PIP`); git origin re-validated; CWD plugin index removed |
| SX-A06 | Partial | production-check warns + compliance FAIL on file_key until `SIYARIX_MASTER_PASSWORD` |
| CI | Partial | coverage fail-under aligned to 70%; Trivy CRITICAL exit-code 1; CI `production-check` job; stress/chaos markers; ghost integration job removed |
| SX-A01 | Partial | `SIYARIX_TRUST_PLUGINS=1` required before in-process load (manager + legacy loader); true OS isolation still open |
| FEAT-03 | Closed | Swarm gated behind `SIYARIX_EXPERIMENTAL_SWARM`; returns `not_implemented` (no fake success findings) |
| Dashboard | Closed | Security dashboard shows only local DB counts; fabricated MFA/EDR/MTTD KPIs removed |
| CISA KEV | Closed | Feed status `planned` (was false `integrated`) |
| Dual lock | Closed | `poetry.lock` removed; `LOCKFILES.md` documents `uv.lock` SoT |
| Worker pool | Closed | Queue semaphore released on cancel-before-start via done-callback |

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

Latest local checks on this branch: **mypy clean (258 files)**; pytest **6456 passed**, 6 skipped, 62 deselected (`-m "not e2e"`, stress ignored). Mission-aligned operator-safety; unset engagement scope unrestricted; multi-target per-host scans.

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
