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
| SX-012 | Webhook SSRF destination policy | `_validate_url` + notification path; `tests/test_sx012_webhook_ssrf.py` |
| SX-020 | Hatchling / Twine metadata | `hatchling>=1.21.1,<1.27`; `twine check` passes |
| SX-026 | Rust parser adapters | `siyarix_rust_parsers` function exports via Python adapters |
| SX-031 | mypy consolidation | `.mypy.ini` ↔ `[tool.mypy]`; `mypy src/siyarix` clean; CI runs project mypy |

## Remaining / follow-up

| ID | Status | Notes |
| --- | --- | --- |
| SX-024 | Closed | Offline REPL skips connectivity monitor; HTML reports default `offline=True` (system fonts); online mode widens CSP for Google Fonts only |
| SX-025 | Labeled scaffold | Compliance checks return `NOT_EVALUATED` with explicit messaging |

## Premium ops

- `siyarix production-check` — security/config readiness table (`--strict` for CI).

## Verification command

```bash
source .venv/bin/activate
mypy src/siyarix
python -m pytest tests/ -q -m "not e2e" --ignore=tests/test_stress_resilience.py
```

Latest local checks on this branch: **mypy clean (256 files)**; pytest **5989 passed, 6 skipped, 62 deselected** (`-m "not e2e"`, stress ignored).

Goal status: audit P0/P1 blockers closed (incl. SX-012/024/031); SX-025 remains an explicit compliance scaffold; further premium polish optional.
