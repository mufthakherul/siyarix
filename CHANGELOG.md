# Changelog

All notable changes to Siyarix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-06-17

### Added
- 24 AI provider profiles: OpenAI, Gemini, Anthropic, Groq, Together, OpenRouter, DeepSeek, xAI (Grok), Mistral AI, Perplexity, Cerebras, Fireworks AI, Z.AI, MiniMax, Moonshot (Kimi), NVIDIA Nemotron, Hugging Face, Azure OpenAI, OpenCode Go, Ollama, LM Studio, llama.cpp, vLLM, LocalAI, plus Registry (heuristic/offline).
- 114+ tool output parsers covering comprehensive security tool ecosystem — nmap, nuclei, masscan, gobuster, ffuf, hydra, nikto, metasploit, burpsuite, zaproxy, sqlmap, wpscan, trivy, grype, semgrep, gitleaks, trufflehog, theHarvester, Amass, Subfinder, Sublist3r, assetfinder, findomain, dnsrecon, dnsenum, massdns, shuffledns, dnsx, httpx, katana, hakrawler, gospider, waybackurls, gau, wfuzz, dirb, dirsearch, feroxbuster, kiterunner, arjun, paramspider, corsy, dalfox, kxss, xsstrike, commix, jwt_tool, wafw00f, whatweb, aquatone, gowitness, bettercap, responder, crackmapexec, impacket, mimikatz, pypykatz, bloodhound, sharphound, certipy, kerbrute, ldapsearch, enum4linux, smbclient, smbmap, evil-winrm, ssh_audit, sslscan, sslyze, testssl, dig, whois, shodan, searchsploit, lynis, scoutsuite, prowler, checkov, kubectl, aws, volatility, yara, tcpdump, dmitry, finger, ike_scan, netcat, smtp_user_enum, hashcat, hash_identifier, john, exiftool, s3scanner, zmap, zgrab, rustscan, naabu, interactsh, recon-ng, aircrack-ng, ettercap, and more.
- Multi-Model Ensemble subsystem with 4 voting strategies (MAJORITY, CONSENSUS, WEIGHTED, BEST_SCORE) and complexity-tiered routing.
- Experience Intelligence (XI) subsystem — ContextTracker, SkillProfiler, Predictor, and recommendation engine for adaptive UX.
- Security command group with incidents, vulns, hunt, mitre, playbooks, and dashboard subcommands.
- Theme system with 6 color themes (system, default, dark, light, minimal, neon) and preview command.
- Goal-driven autonomous agent mode with Observe-Reason-Act loop.
- 9 interaction modes: InteractiveShell, AIConversational, DirectCommand, AutonomousAgent, WorkflowAutomation, TUIDashboard, GuidedWizard, TeamCollaboration, HeadlessAPI.
- FastAPI REST API server with JWT authentication, scan/chat endpoints, and WebSocket streaming.
- Dynamic plugin loader scanning `~/.siyarix/plugins/` directory.
- OpenTelemetry integration for distributed tracing and observability.
- Docker Compose multi-service orchestration (worker, dashboard, Redis, OpenTelemetry collector).
- Support for Python 3.11, 3.12, and 3.13 across Windows, macOS, and Linux.
- 47 GitHub Actions CI/CD workflows including CI, Docker publish, release, CodeQL, SBOM, secrets scan, docs deploy, smoke tests, chaos testing, benchmark, and dependabot.
- 102+ test files covering all modules with 75%+ coverage target.
- Honeypot detection (9 signatures), canary tokens (7 types), trapdoor credentials, and fake banner generator.
- IaC scanner with 15 Terraform checks, 7 Helm checks, CloudFormation, Dockerfile, and secret detection.
- Mobile APK scanner analyzing dangerous permissions (13 checks), insecure flags (5 flags), and hardcoded secrets.
- IoT firmware scanner with 16 security indicators, serial port enumeration, device type detection.
- Offline Response Registry with template packs, fuzzy matching, dynamic variable resolution, and hot-reloading.
- Session branching for concurrent workflow exploration.
- Shell completions generation for bash, zsh, fish, and PowerShell.
- Command palette with interactive selection interface.
- CI gate command for pipeline integration.
- Audit trail verify command for chain integrity validation.

### Changed
- Provider count expanded from 10 to 24+ provider profiles with `ProviderManager` singleton architecture.
- Parser count expanded from 18+ to 114+ parsers with protocol-based `ParserRegistry`.
- Default `model_provider` changed from `openrouter` to `auto` (automatic scanning of configured providers).
- Default `persona` changed from `none` to `auto` (auto-select best-fit persona).
- Session-disabled provider tracking replaced circuit breaker pattern for per-session failure management.
- Multi-wave execution expanded from 5 to 25 max waves with enhanced LLM-driven analysis between waves.
- Live streaming output enhanced with auto-cycling through running commands and colored status indicators.
- Tests reorganized into feature-category files with standardized naming conventions.
- Code comments standardized and unprofessional naming removed across codebase.
- Build system migrated from setuptools to Hatchling.
- Documentation overhauled with modern MkDocs Material theme and comprehensive 70+ page documentation site.

### Fixed
- Offline registry import crash in batch mode with `_run_batch_lines` rewrite.
- Missing `SessionKernel` methods in compat layer.
- Missing `EngineResult` fields in executor compatibility.
- All 8 collection errors resolved across agentic loop, E2E, executor, mode dispatcher, and tool registry tests.
- Python 3.13 compatibility for asyncio (`create_task(gather())` → `ensure_future(gather())`).
- NameError import failures and missing test fixtures.
- Broken tests after script relocation and refactoring.

### Removed
- Legacy `_step_icons` dict, `run_one_tool` function, `_synthesize_agent_response` method.
- Unused `_tools` / `_commands` / `_offline_responder` instance attributes.
- Deprecated `tool_schema.py`, `tool_executor.py`, `interpreter.py`, `kill_switch.py` modules.
- Stale and consolidated test files after reorganization.
- Unprofessional naming conventions and AI-generated comments.

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
