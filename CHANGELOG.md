# Changelog

All notable changes to Siyarix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-06-30

### Added
- Configurable health check timeouts
- Real-time provider statuses rendering in interactive REPL
- Automated release pipelines for Chocolatey (NuGet pack/push) and Homebrew custom tap syncing

### Changed
- Relocated installer scripts (`install.sh`, `install.ps1`, `install-termux.sh`) into a dedicated `installer/` directory and updated referencing configurations
- Removed post-installation checks and diagnostics from all installer scripts

### Fixed
- OpenSSF Scorecard token permissions and action dependency pinning
- PowerShell session automatically closing on install completion
- Android Termux installer missing package wheels for cryptography
- Non-UTF-8 local encoding issues in Windows audit logging
- CodeQL alert fixes for resource leak warnings
- Fixed various workflow and validation failures in CI pipelines

## [1.0.0] - 2026-06-17

### Added

#### AI & Provider Ecosystem
- **24 AI provider profiles** with `ProviderManager` singleton architecture: OpenAI, Google Gemini, Anthropic, Groq, Together AI, OpenRouter, DeepSeek, xAI (Grok), Mistral AI, Perplexity, Cerebras, Fireworks AI, Z.AI, MiniMax, Moonshot (Kimi), NVIDIA Nemotron, Hugging Face Inference, Azure OpenAI, OpenCode Zen, Ollama, LM Studio, llama.cpp, vLLM, LocalAI, plus offline Registry (heuristic/offline fallback)
- **Multi-Model Ensemble** subsystem with 4 voting strategies: MAJORITY, CONSENSUS, WEIGHTED, BEST_SCORE, with complexity-tiered routing
- **Continuous Learning** system (`core/learning.py`): semantic memory via vector embeddings with cosine similarity search and experience recording
- Multi-Provider failover with circuit breaker pattern and exponential backoff

#### Tool Parsers
- **80+ security tool output parsers** via protocol-based `ParserRegistry` covering the full security tool ecosystem:
  - Reconnaissance: nmap, masscan, rustscan, naabu, zmap, zgrab, dnsrecon, dnsenum, massdns, shuffledns, dnsx, httpx, katana, hakrawler, gospider, waybackurls, gau, subfinder, sublister, assetfinder, findomain, amass, recon-ng, theHarvester, dig, whois, shodan, dmitry, finger, ike_scan
  - Web Application: gobuster, ffuf, wfuzz, dirb, dirsearch, feroxbuster, kiterunner, arjun, paramspider, corsy, dalfox, kxss, xsstrike, commix, nikto, wpscan, whatweb, aquatone, gowitness, wafw00f, jwt_tool, interactsh
  - Vulnerability: nuclei, sqlmap, searchsploit, lynis, scoutsuite, prowler, checkov
  - Exploitation: metasploit (msfconsole/msfvenom), burpsuite, zaproxy, bettercap, impacket, crackmapexec, responder, mimikatz, pypykatz, bloodhound, sharphound, certipy, kerbrute, evil-winrm, hashcat, hash_identifier, john
  - Network & Cloud: tcpdump, netcat, smtp_user_enum, smbclient, smbmap, ldapsearch, enum4linux, s3scanner, kubectl, aws, terraform
  - Container & Code: trivy, grype, semgrep, gitleaks, trufflehog, yara, exiftool
  - Forensics: volatility
  - Wireless: aircrack-ng, ettercap
  - TLS/SSL: ssh_audit, sslscan, sslyze, testssl

#### Architecture & Core
- **AgentCore** with 4 operational modes: REGISTRY, AUTONOMOUS, HYBRID, INTERACTIVE
- **Swarm Multi-Agent orchestration** for decomposing complex objectives
- **Continuous Learning** loop with semantic memory and knowledge graph persistence
- **Agent loop**: LLM-first planning, parallel execution, LLM synthesis in closed feedback loop
- **Command Pipeline**: chain tool executions via `|` / `then` / `and then` operators
- **Plugin system** with dynamic discovery from `~/.siyarix/plugins/`

#### CLI & Interface
- **50+ CLI commands** across 12 command groups: scan, recon, exploit, report, config, security, incidents, vulns, hunt, mitre, playbooks, dashboard
- **Interactive REPL** with 40+ slash commands
- **12 color themes**: CYBER_NOIR, MATRIX, BLOODMOON, ARCTIC, GOLDENROD, ECLIPSE, SYNTHWAVE, DARK, LIGHT, NEON, MINIMAL, DEFAULT, with preview command
- **Goal-driven autonomous agent** mode with Observe-Reason-Act loop
- **FastAPI REST API** server with JWT authentication, scan/chat endpoints, and WebSocket streaming at `/v1/*`
- **8 output formats**: TABLE, JSON, YAML, CSV, HTML, XML, RAW, QUIET
- **4 report engine formats**: MARKDOWN, HTML, JSON, SARIF
- **Shell completions** for bash, zsh, fish, PowerShell
- **Session branching** for concurrent workflow exploration
- **Command palette** with interactive selection interface
- **CI gate command** for pipeline integration

#### Security & Safety
- **Permission Gate**: two-stage AI-driven danger analysis with configurable risk thresholds
- **Credential Store**: AES-256-GCM encrypted vault for API keys and secrets
- **Stealth Engine**: TOR routing support with 9 honeypot detection signatures
- **DLP Engine**: pattern-based sensitive data detection and prevention
- **OPSEC Manager**: operational security controls and countermeasures
- **Tamper-Evident Audit Log**: SHA-256 chained cryptographic audit trail with `verify` command for chain integrity validation
- **Event Bus**: asynchronous event-driven internal communication
- **Health Checker**: comprehensive `siyarix health` diagnostics
- **Metrics**: performance and usage instrumentation
- **Canary tokens**: 7 types of configurable canary tokens for intrusion detection
- **Trapdoor credentials**: fake credential generation for attacker deception
- **Fake banner generator**: service banner deception

#### Compliance & Intelligence
- **Compliance Engine**: framework-based compliance checking (PCI-DSS, HIPAA, ISO 27001, SOC 2)
- **Threat Intel**: STIX-based structured threat intelligence consumption and correlation
- **Knowledge Graph**: in-memory infrastructure relationship modeling
- **Offline Response Registry**: template packs, fuzzy matching, dynamic variable resolution, hot-reloading
- **Expert personas**: 10 specialized security mindsets (Red Team, Blue Team, DFIR, Cloud Security, AppSec, Malware Analysis, Threat Intel, Compliance, Network Security, Social Engineering)

#### Infrastructure
- **Support for Python 3.11, 3.12, 3.13** across Windows, macOS, and Linux
- **47 GitHub Actions CI/CD workflows**: CI, Docker publish, release, CodeQL, SBOM generation, secrets scan, docs deploy, smoke tests, chaos testing, benchmarks, Dependabot
- **102+ test files** covering all modules with 75%+ coverage target
- **OpenTelemetry integration** for distributed tracing and observability
- **Docker Compose** multi-service orchestration (worker, dashboard, Redis, OpenTelemetry collector)
- **Build system migration** from setuptools to Hatchling

### Changed

- Provider count expanded from 10 to 24+ with `ProviderManager` singleton architecture
- Parser count expanded from 18+ to 80+ with protocol-based `ParserRegistry`
- Default `model_provider` from `openrouter` to `auto` (automatic scanning of configured providers)
- Default `persona` from `none` to `auto` (auto-select best-fit persona)
- Session-disabled provider tracking replaced circuit breaker pattern for per-session failure management
- Multi-wave execution expanded from 5 to 25 max waves with enhanced LLM-driven analysis between waves
- Live streaming output enhanced with auto-cycling through running commands and colored status indicators
- Tests reorganized into feature-category files with standardized naming conventions
- Code comments standardized and unprofessional naming removed across codebase
- Documentation overhauled with modern MkDocs Material theme and comprehensive 70+ page documentation site

### Fixed

- Offline registry import crash in batch mode with `_run_batch_lines` rewrite
- Missing `SessionKernel` methods in compat layer
- Missing `EngineResult` fields in executor compatibility
- All 8 collection errors resolved across agentic loop, E2E, executor, mode dispatcher, and tool registry tests
- Python 3.13 compatibility for asyncio (`create_task(gather())` to `ensure_future(gather())`)
- NameError import failures and missing test fixtures
- Broken tests after script relocation and refactoring

### Removed

- Legacy `_step_icons` dict, `run_one_tool` function, `_synthesize_agent_response` method
- Unused `_tools` / `_commands` / `_offline_responder` instance attributes
- Deprecated `tool_schema.py`, `tool_executor.py`, `interpreter.py`, `kill_switch.py` modules
- Stale and consolidated test files after reorganization
- Unprofessional naming conventions and AI-generated comments

## [0.2.0] - 2026-06-01

### Added

- `src/siyarix/tool_executor.py` -- adapter module for v1 `ToolExecutor` compatibility
- `src/siyarix/core/pipeline.py` -- `CommandPipeline` module for command orchestration
- `RiskTier` class (public) for threat level classification
- `StepStatus.SUCCESS` enum value for step completion tracking
- `compress_context()` standalone function for context dict compression
- 900 tests passing (up from 654 initial, 857 before fixes)
- Persona system with 10 security mindsets plus auto and universal modes
- Multi-wave execution loop (up to 5 waves) with LLM-driven analysis between waves
- Live streaming output via Rich Live display with auto-cycling through commands
- Command review prompt (edit/run/step/cancel) before raw shell execution
- `/review` slash command to toggle the review prompt
- `/persona` slash command to switch mindsets at runtime
- Provider auto-fallback -- when `model_provider: auto`, scan providers in priority order, skip session-failed providers
- `NEUTRAL_SYSTEM_PROMPT` for persona-free operation
- Streaming subprocess execution (`safe_run_async_stream`) with line-by-line callbacks

### Changed

- Complete v2 architecture rewrite with AgentCore, Executor, SessionKernel, and PermissionGate
- Planner moved to `core/planner.py` with `ExecutionPlan`, `StepResult`, `ExecutionStep`, and `StepType`
- Context management split into `core/context.py` (ContextManager) and standalone `compress_context()`
- Intent router uses `IntentType` enum and `RiskTier` for threat classification
- Execution engine runs steps via `Executor` with `_run_step()`, `_execute_step()`, and `_handle_tool_call()`
- Tool registry uses `ToolRegistry.discover()` with `ToolInfo` dataclass
- Default `model_provider` from `openrouter` to `auto`
- Default `persona` from `none` to `auto`
- `SIYARIX_SYSTEM_PROMPT` rewritten from red-team focus to full-spectrum cybersecurity professional
- Welcome message updated to community-focused, all-domain greeting
- Provider connection retry uses session-disabled tracking instead of circuit breakers
- Single-wave execution replaced with iterative multi-wave loop
- Tool registry API: `discover()` to `scan_path()`, `capabilities` to `tags`
- Review panel title: "Shell Injection Review" to "Command Execution Review"
- asyncio Python 3.13 compatibility: `create_task(gather())` to `ensure_future(gather())`

### Fixed

- Offline registry import crash in `main.py` -- `_run_batch_lines` rewritten
- Missing `SessionKernel` methods in compat layer
- Missing `EngineResult` fields in executor compatibility
- Missing `StepResult`, `ExecutionStep`, `StepType` classes in planner
- All 8 collection errors resolved (test_e2e, test_engine_executor, test_execution_engine, test_executor, test_planner, test_tool_handlers, test_registry, test_autonomous_loop)

### Removed

- `_step_icons` dict, `run_one_tool` function, `_synthesize_agent_response` method
- `_tools` / `_commands` / `_offline_responder` unused instance attributes
- Unused `tool_schema.py`, `tool_executor.py`, `interpreter.py`, `kill_switch.py` modules
- Stale test files: `test_mode_dispatcher.py`, `test_tool_registry.py`, `test_offline_registry.py`, `test_tool_registry_wsl.py`

## [0.1.0] - 2026-05-30

### Added

- First stable production release
- AI-powered cybersecurity orchestration with multi-provider support (OpenAI, Gemini, Anthropic, Groq, Ollama, Together, LM Studio)
- 50+ CLI commands across scan, recon, exploit, report, config, and security groups
- Interactive chat REPL with SQLite-backed session persistence
- 100+ security tool integration with 18+ output parsers
- Encrypted credential vault (AES-256-GCM, Fernet, KMS)
- Three-stage permission gate with danger analysis
- Tamper-evident SHA-256 chained audit trail
- Stealth mode, kill switch, and OPSEC manager
- CI/CD pipelines with full linting, type checking, security audit, and coverage
- Docker, Debian, Homebrew, and Winget packaging
- Comprehensive test suite with 959+ tests
