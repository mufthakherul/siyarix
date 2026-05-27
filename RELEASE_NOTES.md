# Phalanx v0.1.3-beta — Preview Release

## Overview

AI-native cybersecurity operations platform with autonomous execution, multi-agent framework,
and intelligent workflow orchestration. This is a **beta/preview** release marking significant
stability, security, and architectural improvements.

---

## New Features

- **7-Phase Stress/Chaos Test Suite**: 27 tests covering chaos simulation, adversarial input,
  orchestration breakdown, self-healing, security audit, performance limits, and failure auto-fix.
- **Enhanced Kill Switch**: New `is_triggered` property for monitoring emergency-stop state.
- **Transient Error Detection**: Expanded `TRANSIENT_INDICATORS` list in recovery module;
  `is_transient_error()` now handles `FileNotFoundError`, `ConnectionError`, `TimeoutError`.
- **Dependency Security**: `defusedxml` added to core dependencies for XXE attack prevention.

## Fixes

- **Critical**: Removed dead code in `main.py` that would raise `NameError` on CLI startup
  (lines 2270–2288 referencing undefined `registry`/`name`).
- **Critical**: Added missing `logger` initialization in `ux/wizard.py` preventing
  `NameError` on theme selection.
- **Dead Code**: Cleaned 12 stale orphan `.pyc` files from removed modules (`challenge`,
  `collaboration`, `community`, `engine` monolithic, `playbooks`, `plugins`, `stream`,
  `compliance`, `rbac`, `reporting`, `dfir_agent`, `soc_agent`).
- **Lint**: Fixed all 24 ruff violations including unused imports, ambiguous variable
  names (`l` → `line`), and f-string prefix warnings.
- **Version Synchronization**: Unified version from inconsistent `2.0.0` / `1.2.0` values
  to `0.1.3-beta` across 8 reference points: `pyproject.toml`, `__init__.py`, `main.py`,
  `chat.py` (2 locations), `report_engine.py`, `branding.py`, `bootstrap.py`, `poetry.lock`.

## Security Improvements

- **XXE Vulnerability**: Replaced `xml.etree.ElementTree` with `defusedxml` across all parsers.
- **Silent Exception Logging**: 8 instances of `except: pass` replaced with proper logging.
- **Security Hardening**: `eval()` usage now guarded with `literal_eval` fallback + `NameError` catch.
- **Unified Injection Detection**: `_BLOCKED_PATTERNS` removed; `dynamic_resolver` delegates
  entirely to `DangerAnalyzer` for consistent command safety validation.
- **Security Audit**: Bandit scan shows 0 HIGH, 1 MEDIUM (false positive — env var named `shell`),
  41 LOW (standard tooling noise — subprocess, assert, random usage).

## Architecture Improvements

- **Engine Decomposition**: Monolithic 1800-line `engine.py` refactored into `engine/` package
  with 6 focused submodules: `context.py`, `executor.py`, `providers.py`, `recovery.py`,
  `safety.py`, `steps.py`.
- **Cross-Platform Compatibility**: Fixed WSL detection, path handling, and subprocess
  execution for Windows/Linux/macOS parity.

## Performance

- Self-healing backoff with jitter for transient error recovery.
- Worker pool with configurable concurrency limits.
- Caching layer with TTL-based expiration.

## Known Issues / Risks

1. **Type Annotations (Low)**: 106 mypy warnings for pre-existing missing type annotations.
   These do not affect runtime correctness but will be addressed in a future release.
2. **Test Coverage (Medium)**: No formal coverage threshold enforced. Current tests cover
   core paths but deeper branch coverage is needed for production confidence.
3. **AgentLifecycle Stub (Low)**: `agent_lifecycle.py` is a 68-line stub not yet connected
   to process spawning. Non-functional for multi-agent lifecycle management.
4. **Schema Versions**: Some internal format versions (`1.2.0` in audit_log, `2.1.0` in SARIF
   output) remain independent from the project version — this is intentional.

## Build Artifacts

- `phalanx-0.1.3b0.tar.gz`
- `phalanx-0.1.3b0-py3-none-any.whl`

## Tests

- **485 total tests**: 458 existing + 27 stress/chaos
- **0 failures** across all test suites
- **0 lint errors** (ruff clean)
- **0 HIGH severity** security findings

## Recommendation for Production Promotion

**NOT RECOMMENDED** for production use at this stage. This is a beta/preview release
intended for evaluation, testing, and development. Key gaps for production readiness:
- Agent lifecycle management is incomplete
- Type annotation coverage needs improvement
- Formal coverage threshold not enforced
- Multi-agent orchestration needs hardening

Recommend targeting **v1.0.0** after addressing the above gaps.
