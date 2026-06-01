# Changelog

All notable changes to Siyarix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-01

### Changed
- Complete v2 architecture rewrite with AgentCore, Executor, SessionKernel, and PermissionGate.
- Planner moved to `core/planner.py` with `ExecutionPlan`, `StepResult`, `ExecutionStep`, and `StepType`.
- Context management split into `core/context.py` (ContextManager) and standalone `compress_context()`.
- Intent router uses `IntentType` enum and `RiskTier` for threat classification.
- Execution engine runs steps via `Executor` with `_run_step()`, `_execute_step()`, and `_handle_tool_call()`.
- Tool registry uses `ToolRegistry.discover()` with `ToolInfo` dataclass.
- Default `model_provider` from `openrouter` to `auto`.
- Default `persona` from `none` to `auto`.
- `SIYARIX_SYSTEM_PROMPT` rewritten from red-team focus to full-spectrum cybersecurity professional.
- Welcome message updated to community-focused, all-domain greeting.
- Provider connection retry uses session-disabled tracking instead of circuit breakers.
- Single-wave execution replaced with iterative multi-wave loop.
- Tool registry API: `discover()` → `scan_path()`, `capabilities` → `tags`.
- Review panel title: "Shell Injection Review" → "Command Execution Review".
- asyncio Python 3.13 compatibility: `create_task(gather())` → `ensure_future(gather())`.

### Added
- `src/siyarix/tool_executor.py` — adapter module for v1 `ToolExecutor` compatibility.
- `src/siyarix/core/pipeline.py` — `CommandPipeline` module for command orchestration.
- `RiskTier` class (public) for threat level classification.
- `StepStatus.SUCCESS` enum value for step completion tracking.
- `compress_context()` standalone function for context dict compression.
- 900 tests passing (up from 654 initial, 857 before fixes).
- Persona system with 10 security mindsets (red team, blue team, DFIR, cloud, appsec, etc.) plus auto and universal modes.
- Multi-wave execution loop (up to 5 waves) with LLM-driven analysis between waves.
- Live streaming output via Rich Live display with auto-cycling through commands.
- Command review prompt (edit/run/step/cancel) before raw shell execution.
- `/review` slash command to toggle the review prompt.
- `/persona` slash command to switch mindsets at runtime.
- Provider auto-fallback — when `model_provider: auto`, scan providers in priority order, skip session-failed providers.
- `NEUTRAL_SYSTEM_PROMPT` for persona-free operation.
- Streaming subprocess execution (`safe_run_async_stream`) with line-by-line callbacks.

### Fixed
- Offline registry import crash in `main.py` — `_run_batch_lines` rewritten.
- Missing `SessionKernel` methods in compat layer.
- Missing `EngineResult` fields in executor compatibility.
- Missing `StepResult`, `ExecutionStep`, `StepType` classes in planner.
- All 8 collection errors resolved (test_agentic_loop, test_e2e, test_engine_executor, test_execution_engine, test_executor, test_mode_dispatcher, test_tool_executor, test_tool_registry).

### Removed
- `_step_icons` dict, `run_one_tool` function, `_synthesize_agent_response` method.
- `_tools` / `_commands` / `_offline_responder` unused instance attributes.
- Unused `tool_schema.py`, `tool_executor.py`, `interpreter.py`, `kill_switch.py` modules.
- Stale test files: `test_mode_dispatcher.py`, `test_tool_registry.py`, `test_offline_registry.py`, `test_tool_registry_wsl.py`.

## [1.0.0] - 2026-05-30

### Added
- First stable production release.
- AI-powered cybersecurity orchestration with multi-provider support (OpenAI, Gemini, Anthropic, Groq, Ollama, Together, LM Studio).
- 50+ CLI commands across scan, recon, exploit, report, config, and security groups.
- Interactive chat REPL with SQLite-backed session persistence.
- 100+ security tool integration with 18+ output parsers.
- Encrypted credential vault (AES-256-GCM, Fernet, KMS).
- Three-stage permission gate with danger analysis.
- Tamper-evident SHA-256 chained audit trail.
- Stealth mode, kill switch, and OPSEC manager.
- CI/CD pipelines with full linting, type checking, security audit, and coverage.
- Docker, Debian, Homebrew, npm, and Winget packaging.
- Comprehensive test suite with 959+ tests.
