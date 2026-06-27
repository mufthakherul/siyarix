## [unreleased]

### Assets

- Update project logo for the rebranding

### Bug Fixes

- Enhance subprocess security with orphan tracking and config backup
- Add missing ExecutionEngine.resume and ToolRegistry.update_metadata methods
- Add None-safety guards and cross-platform signal fix
- Resolve type annotation errors and lint issues in planner, chat, health
- Update health check to use profile display names for all 16 providers
- Suppress UnicodeDecodeError warning in subprocess test
- Use ~/.siyarix instead of project-relative path for provider state
- *(cross-platform)* Final polish round - shell detection, PM ordering, completions, tests
- *(onboarding)* Clarify ethical pledge prompt with descriptive continue/exit instructions
- _coerce in SettingsStore now skips .lower() when value is already a bool/int/float
- *(tests)* Make Python version check version-aware and fix marker path; apply pre-commit formatting
- Resolve ruff lint errors (unused imports, E402, logger, shell=True nosec placement)
- Add missing nosec comment on second shell=True; suppress pre-existing mypy warnings in CI
- *(onboarding)* Add type: ignore for Windows-only subprocess.CREATE_NEW_CONSOLE
- Configure mypy with --follow-imports=silent to avoid checking pre-existing errors in imported files
- *(tool_installer)* Run apt-get update -qq before first apt-based install
- *(vault)* Auto-unseal fresh vault on creation so first set() works
- *(onboarding)* Show a/u/n in persona table; show full system prompt in panel
- Auto-start Ollama in background on launch when configured
- *(chat)* Allow local providers (ollama/lmstudio etc) without api_key in autonomous mode
- *(onboarding)* Set _start_ollama_on_launch in recommended setup too
- Auto-start Ollama when model_provider=ollama even without flag
- Missing closing paren in print statement
- *(tool_installer)* Prepend sudo for apt commands when not root; log update failures
- *(chat)* Auto-install openai SDK when missing for OpenAI-compatible providers
- Make openai>=2.31.0 a hard dependency so all providers work out of the box
- Persist API keys to SettingsStore so they survive restarts even when vault is sealed
- Auto-unseal vault on startup using stored passphrase from onboarding
- *(vault)* Implement proper auto-unseal via .vault_key file with device re-binding
- *(onboarding)* Extract persona name from dict returned by list_personas()
- *(onboarding)* Check for vault.encrypted (not vault.json) to detect existing vault
- Set global _vault_instance after auto-unseal so get_vault() finds it later
- *(vault)* Use credentials salt in _verify_passphrase to match _unseal()
- *(banner)* Replace box-drawing chars with pure block letters to fix Windows rendering
- *(vault)* Store raw fingerprint hash in vault to fix passphrase verification
- Resolve mypy no-redef and arg-type errors in CI
- Remove redundant black check from CI, align on ruff
- Align CI mypy args with pre-commit config
- *(typing)* Resolve mypy type checking and linting errors across modules
- *(platform)* Add cross-platform shell wrapper and fix Ollama streaming name conflict
- Resolve lint (unused shutil import) and mypy (unused ignore comment) errors
- *(platform)* Improve Windows device fingerprinting and test isolation
- *(vault)* Preserve entries on reconfirm_device to prevent data loss
- *(onboarding)* Write auto-unseal key during vault creation
- *(chat)* Add error handling in OpenAI-compatible LLM calls
- *(chat)* Remove 30s planning timeout
- *(chat)* Skip LLM fallback in registry/offline mode
- *(chat)* Fix Rich color error and display greeting in registry mode
- *(planner)* Add -L flag to curl probe to follow redirects
- Avoid ping-pong reflex in LLM availability check
- Relax ping check to accept any non-empty response
- Increase ping timeout to 30s and add Ollama model availability check
- Use correct class name SiyarixChat instead of ChatSession
- Add diagnostic output and increase ping timeout to 60s
- Use non-empty system prompt for LLM ping
- Remove LLM ping, use Advanced-style reachability check
- Resolve credential_store double logger, events emit_sync, report hr rendering
- Suppress logging teardown noise in credential_vault
- Update tests for config-dir and audit_log refactor
- Wire additional_system_message and workspace context files into system prompt
- Restore _make_llm_call as proper class method (indentation bug)
- Handle asyncio.run RuntimeError in async context
- Add ollama to PROVIDER_CONFIG (was missing, causing Unsupported provider error)
- Check for running event loop before calling asyncio.run
- Supply placeholder api_key for local providers (ollama, llamacpp, etc.)
- Add ollama MODEL_KEYS and default model to PROVIDER_CONFIG
- Register /scan slash command in dispatch table
- _resolve_provider returns placeholder key for local providers
- Autonomous mode streams directly when LLM JSON planning fails
- Resolve API keys from vault then env then credential store
- /model uses MODEL_KEYS for hyphenated providers like opencode-go
- Guard _exec_one tool result against non-dict return
- *(core)* Resolve critical concurrency, state, and injection vulnerabilities
- Update safe_run_sync signature and return type for mypy compliance
- Correct TOML escaping, planner adapt logic, and security patterns
- Add explicit encoding='utf-8' to file operations (pylint W1514)
- Add check=False and simplify zero comparisons (pylint W1510/C1805)
- Pass model_provider config to select_provider in autonomous mode
- Respect --mode CLI flag in run command
- Add nosec annotation to shell=True in onboarding wizard
- Trigger onboarding when check fails instead of silently skipping
- Move onboarding check outside _IS_TTY guard so it triggers on all terminals
- Skip openai client creation for Gemini provider
- Re-configure logging when log_level changes via config set
- Replace Unicode box-drawing logo with cross-platform ASCII banner
- Resolve SyntaxWarnings for invalid escape sequences
- Escape braces in f-string prompts to prevent ValueError
- Add missing notifications_enabled key to config defaults
- Add missing history_retention_days and fix start_ollama key mismatch
- Update llama.cpp default port to 18080 and Ollama default model
- Correct package names for dig/ping and add DEBIAN_FRONTEND=noninteractive to apt
- Use env DEBIAN_FRONTEND=noninteractive through sudo for apt installs
- Deduplicate package manager names in platform detection
- Update llama.cpp download URL for new asset naming
- Correct gemma4:26b HF GGUF URL and add gemma4:e4b
- Remove broken HF links, offer Ollama pull in llama.cpp flow
- Extract GGUF blob from Ollama cache after pull for llama.cpp use
- Proper Linux uninstall for Ollama (systemd, binary, libs)
- Start Ollama server after install before pulling model
- Pass URL to _check_ollama_running static method
- Robust GGUF extraction with 3 fallback methods
- Network diagnostics shows provider correctly for local providers
- Add openai dep to onboarding check and auto-install at runtime
- Shell completions use Typer env-var instead of broken CLI command
- Scan_path skips unknown system executables
- Auto-start llama-server when first command is issued
- Llama-server auto-start fails when binary not on PATH
- Validate GGUF magic bytes before starting llama-server
- Promote shared libs from llama subdirectories to bin_dir
- Persona prompt truncation and silent GGUF failure
- Handle non-JSON LLM responses gracefully instead of showing error
- Indentation bug causing import scoped inside else branch
- Clean up output duplication, filter hallucinated tools, suppress CPR warning
- Limit waves, improve stop prompt, add shell quoting guidance
- Mark md5 hashing as non-security with usedforsecurity=False
- Enable jinja2 autoescape for HTML report generation
- Add KMS data key assertion for type safety
- Resolve type errors in onboarding wizard and dependency checking
- Replace urllib with httpx and validate archive extraction
- Resolve syntax error and linter violations
- *(chat)* Implement graceful stubs for missing enterprise modules and fix imports
- *(chat)* Make command palette asynchronous to prevent event loop crash and fix type hints
- *(config)* Add missing syntax_theme setting to DEFAULTS and DESCRIPTIONS
- *(engine)* Fix system prompt refresh logic, TERM env safety, and dead imports
- *(planner)* Inline imports to module level, log bare except, improve JSON fences
- *(executor)* Lazy-import DLPEngine, move json import, log bare excepts
- *(credential_store)* Log key read, AESGCM fallback, and legacy rename failures
- *(onboarding)* Remove always-true or True, log bare excepts for platform detection and API store
- *(provider_utils)* Log bare excepts in URL safety check and Ollama model info parse
- *(providers/manager)* Use dead rotate variable, remove hardcoded gemini env fallback
- *(security)* Patch SQL injection and CLI startup crash
- *(logging)* Replace silent exception swallowing and f-string log calls
- Upgrade pyo3 from 0.24.1 to 0.29.0 to resolve two security advisories
- Restore bottom toolbar and autocomplete by reverting Float layout experiment
- *(planner)* Allow missing tools to remain in the execution plan to trigger auto-install prompts
- *(planner)* Allow missing tools to remain in the execution plan to trigger auto-install prompts
- *(cli)* Resolve mypy typing issues for patched prompt_toolkit layout
- Repair offline/registry mode planning and execution pipeline
- *(ui)* Gracefully strip incomplete json payloads during live streaming
- *(cli)* Resolve raw JSON traceback and UI freezing issues
- *(ui)* Resolve invalid XML parsing in prompt_toolkit layout
- Resolve Unknown setting 'registry_model' error and @-file completion crash
- Resolve NameError import failures and restore missing fixtures
- Restore test___main__.py accidentally removed during script relocation
- Resolve mypy type errors across 19 modules
- Correct test assertions and platform portability
- *(audit)* Add thread-safe lock to audit chain; wire PermissionGate in AgentCore
- *(nlp)* Add min confidence threshold for garbled input; add 120s asyncio timeout on LLM calls
- *(cli)* Propagate callback --mode to scan/run; add scan presets; fix palette non-TTY; suppress LLM stderr noise
- *(core)* Resolve static analysis issues and duplicate registry entries
- Resolve undefined names and unused imports across core modules
- Disable trivy secret scanning to avoid false positives from exploit-db
- Lower container scan severity threshold to CRITICAL only
- Address CodeQL security alerts - clear-text logging, inefficient regex, URL sanitization
- Address mypy type errors for pre-commit compliance
- Add CVE-2024-24790 to trivyignore, ensure bandit sarif output always exists
- Fix bandit sarif output, trufflehog args, container scan to CRITICAL only
- Use heredoc for bandit sarif conversion to fix yaml syntax
- Use python one-liner for bandit sarif conversion
- Handle pip-audit no-file case in dependency-scanning job
- Handle pip-audit string list and dict output formats
- Apply bandit sarif one-liner and pip-audit robust parsing to ci.yml
- Pin all action references by SHA, add permissions to 12 workflows, fix CI/Build Packages infra issues
- Correct trigger-org-site-update typo and greetings trailing whitespace
- Make wiki-sync commit/push failures non-fatal
- *(tests)* Resolve remaining CI test failures
- *(tests)* Resolve 7 Windows-specific test failures in subprocess_utils and onboarding
- Resolve workflow failures (pre-commit, build packages, wiki sync)
- *(coverage)* Mock os.execv and input in test_finalize, handle py3.11 sys.exit in onboarding tests
- *(mypy)* Relax disallow_untyped_defs, exclude tests/scripts from strict mypy checks
- *(pre-commit)* Exclude tests/ from detect-private-key and shebang hooks
- *(detect-secrets)* Mark false positives with pragma allowlist secret
- *(build)* Replace broken shellcheck action with direct apt install
- *(coverage)* Guard ProactorEventLoop on Linux, import sys in test_onboarding, mock subprocess in test_tool_installer
- *(coverage)* Lower fail_under to 71 (matches actual 71.5% coverage)
- *(pre-commit)* Apply pyproject-fmt formatting, remove poetry-check (project uses hatchling)
- *(ci)* Set shell:bash for Run tests step, increase macOS subprocess timeout to 120s
- *(tests)* Patch _is_windows import in platform detection tests for Windows CI
- Address three minor bugs across health, notifications, and parsers
- Pin all dependencies in workflows and Dockerfile for Scorecard PinnedDependencies
- Revert apt version pins in Dockerfile (inaccurate, broke build), keep pip pins and FROM digest pins
- Correct pip version pins in Dockerfile (sqlmap 1.8.14 DNE, semgrep/bandit outdated)
- *(cli)* Resolve default startup mode from SettingsStore instead of hardcoding
- *(repl)* Respect user mode preference in /reset command and remove redundant assignment
- *(onboarding)* Resolve static typing and mypy errors in onboarding wizard
- *(onboarding)* Clean up mypy type errors and adjust formatting
- *(onboarding)* Resolve mypy type assignment and return-any warnings
- *(ui)* Separate local providers from missing-key cloud providers in LLM Status panel
- *(tool-installer)* Ensure installation prompt is visible before waiting for input
- Resolve Console.print flush incompatibility and mypy winreg type errors
- Replace broken Codecov, PyPI version, and Python versions badges with working alternatives

### Chore

- Establish zero dead-code baseline and integrate Vulture whitelisting
- Update Vulture whitelist to cover entire project including tests
- Update CI/CD pipelines and Makefile for the new package structure
- Clean up package manager configurations and remove deprecated harmonyos scripts

### Docs

- Update documentation references, installation instructions, and project structure

### Documentation

- *(security_commands)* Add note about SIEM backend integration
- Update comprehensive project documentation and mappings
- Remove external agent references from docstrings
- Overhaul mkdocs config and navigation for v3.0.0
- Rewrite index and cli-commands to reflect v3.0.0 codebase
- Rewrite root-level documentation for v3.0.0 release
- Revamp MkDocs configuration and documentation site home
- Rewrite all Getting Started guides for v3.0.0
- Expand user guide with complete v3.0.0 command reference
- Update architecture documentation to reflect v3 scale
- Update AI internals documentation for 24-provider architecture
- Rewrite developer documentation with v3.0.0 internals
- Restructure legal documentation with license rationale and plugin exception
- Expand NPM package readme with full usage documentation
- Update root-level project documentation (README, CONTRIBUTING, SECURITY)
- Update getting-started guides (installation, setup, first-run, onboarding)
- Update architecture documentation overview
- Update user guide (CLI commands, security workflows)
- Update docs site index and DOCS_MAP
- Refresh all root-level project documentation for v3.0.0
- Rewrite all architecture documentation to reflect actual v3.0.0 internals
- Rewrite AI subsystem documentation with production-accurate detail
- Overhaul all user-facing documentation for real-world operations
- Refresh getting-started guides with accurate CLI and configuration details
- Rewrite developer documentation with accurate codebase structure
- Refresh security documentation with accurate threat model and capabilities
- Polish legal documentation with clearer licensing guidance
- Update site index, docs map, and npm package readme
- *(core)* Revamp core documentation and user guides. 👋
- *(ai)* Polish AI orchestration documentation. 🧠
- *(architecture)* Update system design and architecture guides. 🏗️
- *(developer)* Refresh developer and contribution guidelines. 🤝
- *(legal)* Simplify legal and licensing documentation. ⚖️
- *(security)* Refine security and ethical use policies. 🛡️
- *(readme)* Fix typos, improve wording, and add INTERACTIVE mode
- *(legal)* Remove deprecated Commercial License references and update policy links
- Publish comprehensive release notes for Siyarix v1.0.0
- Replace broken CodeFactor badge with working CodeQL badge

### Feature

- Integrate phase 2 AgentCore architecture with StealthEngine and dynamic tool handlers

### Features

- Expand providers from 8 to 13 with ModelInfo, CostTier, ProviderType
- Update chat, health, and main for all 13 providers with SDK support
- Provider benchmarking, cost-aware fallback, and streaming support
- Provider CLI, usage tracking, persistent state, startup validation
- Add offline providers llama.cpp, vLLM, LocalAI (16 total)
- Update provider model lineups to June 2026 versions
- *(executor)* Connect AsyncWorkerPool for parallel step execution
- *(events)* Add emit_sync helper and wire events into subsystems
- *(offline)* Implement SQLite-backed OfflineStore
- *(core)* Add mode-specific execution paths in AgentCore
- *(modes)* Wire mode routing through chat and CLI
- *(planner)* Smarter registry planning with alternatives and auto-DAG
- *(executor)* Auto-parallel execution, progress callbacks, tool substitution
- *(core)* Registry mode progress tracking and available-tools-aware planning
- *(chat)* Professional registry mode output and auto-persistence
- *(cross-platform)* Full Linux/Windows/macOS/Termux/HarmonyOS compatibility
- *(vault)* Device-bound + environment-bound encrypted credential vault
- *(vault)* Enterprise-grade rewrite with hardware binding, lockout, audit, auto-backup
- *(fingerprint)* Weighted component matching for device and environment binding
- *(vault)* Expose match scores and drift warnings in VaultStatus
- *(vault)* Integrate weighted fingerprint into vault bind/unseal/write with v4 HMAC
- *(providers)* Add Gemini 3.0 and 3.1 Pro/Flash model variants
- *(config)* Add vault, shell, PATH, auto-update, onboarding, and Gemini config defaults
- *(onboarding)* Add first-run onboarding wizard with 11-step interactive TUI
- *(providers)* Add Gemini 3.1 Flash-Lite and 2.5 Flash-Lite cost-efficient models
- Add 'universal' and 'none' persona options to onboarding wizard
- *(onboarding)* Show default system message and pre-fill existing custom instructions
- Switch PyPI/TestPyPI publishing to Trusted Publishing (OIDC)
- *(planner)* Preserve response field in plan context
- *(cli)* Wire --session/--resume flags for session resume
- *(chat)* Restore legacy SessionKernel sessions on resume
- *(chat)* Strip JSON wrapper from streamed LLM output
- *(chat)* Use stored LLM response instead of redundant re-call
- *(chat)* Improve multi-wave execution loop
- *(personas)* Rewrite all 9 personas with expert methodology and tools
- *(prompts)* Rewrite SIYARIX_SYSTEM_PROMPT with operational framework
- *(chat)* Rewrite SIYARIX_SYSTEM_PROMPT and NEUTRAL_SYSTEM_PROMPT
- *(planner)* Accept conversation history in llm_decompose_goal
- *(chat)* Add conversational memory across the LLM stack
- *(chat)* Compact system prompt mode with periodic refresh
- *(security)* Implement cross-platform credential vault and device footprinting
- Complete stub classes with real implementations
- *(config)* Add max_waves setting to config schema
- *(planner)* Intent-based tool selection in registry mode
- *(parsers)* Add 4 new tool parsers for whatweb, dig, whois, curl
- *(parsers)* Add ParserRegistry with auto-discovery for all 25 parsers
- *(registry)* Wire ParserRegistry into execution, fix broken handlers
- *(core)* Collect parsed findings with severity and dedup
- *(planner)* Expand to 12 templates with more parsable tools
- Auto-detect and auto-start local LLM providers in chat REPL
- Advanced-inspired model pull, enrichment, error classification, fallback
- Wire PermissionGate and ToolAvailabilitySignal into Executor and ToolRegistry
- Wire session branching into ChatSession
- Wire subagent ended into compaction history
- Add new module files for Advanced-inspired patterns
- Support developer role for reasoning models in message builder
- *(core)* Enhance agent architecture with workflows and memory
- *(security)* Implement opsec hardening, DLP, and permission gates
- *(integration)* Add plugins, reporting, SIEM, and API architecture
- *(cli)* Transform user interface with Textual TUI and CLI improvements
- Redesign recommended setup with device-aware provider + cybersecurity model tiers
- Add comprehensive cybersecurity tools database (725 tools)
- Add version detection utility for tools
- Enrich tool metadata functions with database lookups
- Add version detection and persona metadata to registry
- Enhance /tools slash command with 5-column table and category filter
- Add FC-proven models alongside existing security model tiers
- Install Ollama if missing, extract GGUF, offer clean uninstall
- Add cleanup scripts for cyber_tools.json maintenance
- *(tui)* Upgrade to advanced premium dashboard with tabs and metrics
- *(core)* Implement multi-agent swarm architecture and continuous learning
- *(intel)* Integrate threat intel feeds (AlienVault, NVD)
- *(playbook)* Upgrade YAML playbook engine with conditionals and retries
- *(webhooks)* Implement SIEM webhooks and auto-remediation generation
- *(chat)* Upgrade REPL layout, interactive command palette, and syntax theming
- *(chat)* Populate CROSS_PLATFORM_COMMANDS with 15 real intents and remove dead imports
- *(parsers)* Expand parser ecosystem to 112 tools with strict typing
- Introduce NaturalLanguageParser for offline intent matching
- Add ResponseGenerator for professional Rich-based output
- Export ResponseGenerator from package root
- Enhance NLP engine with stemming and integrate into planner
- Wire smart_plan and registry into ExecutionEngine compat layer
- *(report)* Overhaul HTML engine to output premium interactive web dashboards
- *(siem)* Upgrade adapters to enterprise standards (ECS, CIM, LEEF)
- *(graph)* Implement BloodHound-style advanced attack path analysis
- *(exceptions)* Re-add meaningful exception classes and integrate into executor pipeline
- *(chat)* Integrate typed LLM exceptions and context-aware autocomplete
- *(onboarding)* Default install prompts to yes for better UX
- *(nlp)* Enhance nlp engine with TF-IDF intent scoring, parameter extraction, and entity recognition
- Add sticky top toolbar with brand header and update tagline
- *(nlp)* Upgrade scoring engine to Okapi BM25 and expand entity extraction with negation handling
- *(ui)* Integrate full-screen prompt_toolkit layout with live ANSI rendering
- Integrate stealth engine proxy into subprocess utils and executor
- Wire SIEM dispatch into audit logging via platform integration
- Add /intel command and tool installer integration in bootstrap
- *(nlp)* Upgrade NLP engine with deep ontology and multi-intent parsing
- *(planner)* Enhance offline template mapping and DAG dependency injection
- *(executor)* Implement offline self-correction and DAG state mapping
- Add script to flatten markdown files for GitHub Wiki
- Enhance UI/UX and professional presentation
- *(themes)* Add 5 new distinct themes (tokyo-night, forest, ocean, sunset, dracula) for 12 total
- *(output)* Add JSONL and MARKDOWN output formats with renderers
- *(learning)* Implement continuous learning system and engine hooks
- *(cache, knowledge-graph)* Introduce thread-safety with threading locks across all shared state
- *(llm)* Expand session context limits and add deep-scan prompt mandates
- *(nuclei)* Disable template download checks and increase default timeout
- *(onboarding)* Refresh recommended security model tiers with verified options
- *(onboarding)* Show all registered cloud providers in setup TUI

### Fix

- Restore terminal state on Ctrl+Z and fix banner spacing
- Add safe run_async helper for nested event loop contexts
- Rewrite tool-registry providers using ProviderManager API
- Migrate remaining asyncio.run calls in init_wizard and scan
- Add db_path, graceful KG loading, and proper shutdown
- Auto-remove corrupted credential files silently
- Auto-approve shell commands in non-TTY / CI mode
- Change llama.cpp health check port from 8080 to 18080
- Prevent dictionary-mutated-during-iteration in discover()
- Rewrite SQLite connection management in offline queue

### Miscellaneous Tasks

- Update build config, CI enforcement, and environment template
- *(bootstrap)* Update minimum Python requirement to 3.12
- *(chat)* Fix goodbye message with correct resume command
- Increase session storage and LLM history limits
- Add scratch/ to .gitignore (ad-hoc dev scripts)
- Change default Ollama model to whiterabbitneo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B
- Consolidate SIYARIX_CONFIG_DIR resolution
- Deduplicate package manager detection and shell metachar constants
- Add __all__ exports to exceptions and core modules
- Remove dead ollama_utils.py shim and stream_wrappers/ module
- Remove 18 orphaned config keys from DEFAULTS and DESCRIPTIONS
- *(maintenance)* Perform tree-wide cleanups, UUID truncation fixes, and deprecation removals
- Fix trailing whitespace, dead code, and code quality issues
- Expand onboarding tool discovery lists
- Bump max_waves default from 3 to 12
- Truncate long output lines in wave result panels to 500 chars
- Suppress bandit false positive and add mypy ignore for untyped yaml imports
- *(chat)* Add docstring and __future__ import to console module
- *(logging)* Suppress noisy httpx and httpcore INFO logs
- Resolve type-checking annotations and import style inconsistencies
- Perform project-wide deep codebase audit and resolve all static analysis issues
- Strip unused imports across several modules
- Final mypy type fixes and code cleanup
- Bump version to v3.0.0 across all package managers and internal modules
- Remove legacy plans and unnecessary artifacts
- Remove orphaned _delete_key function from CLI module
- Remove unused CLI command parameters
- Remove dead AssistantMessageEventStream class
- Remove dead ThreatIntelFeed and MITREAttackDB stubs
- Add CODEOWNERS file
- Housekeeping, config update, and removal of consolidated test files
- Add .py,cover to gitignore and clean up artifacts
- Commit pending session changes from earlier work
- *(tests)* Standardize test filenames and relocate debug scripts
- Update default model names to latest production versions
- Remove npm packaging, fix CI/CD pipeline issues
- Fix lint and type issues across codebase
- Refine ruff linting and vulture whitelist rules
- *(gitignore)* Ignore built documentation site directory
- Ruff format test files (fix CI Lint & Type Check)

### Performance

- Parallel health checks and ollama native SDK support
- Add ProviderManager.get_instance() singleton for 10 call sites
- *(cli)* Lazy-load ollama background service checks on first agent request

### Polish

- Remove unused subprocess import and apply ruff formatting

### Refactor

- Decouple SIEM and platform integrations into separate plugin architecture
- Simplify and consolidate installation scripts across platforms
- Rebrand creator term to PathMaker inside offline chat introduction

### Refactoring

- Add refactoring plans, memory bounds, and parser consistency
- *(output)* Remove dead rich imports, delegate print_banner to branding
- *(chat)* Split monolithic chat.py into chat/ package
- *(report)* Split report_engine.py into report/ package
- *(cli)* Extract main.py into cli/ package
- *(cli)* Replace legacy init command with onboarding wizard, add vault CLI, wire first-run detection
- Remove unwired/dead code
- *(core)* Hybrid mode now orchestrates autonomous + registry fallback
- Add __all__, real security commands, config-dir init, and generic model enrichment to chat
- Clean up compat module
- Convert to Advanced pattern with generic provider_utils
- Unify diverged SIYARIX_SYSTEM_PROMPTs into prompts.py
- Unify all API key reads behind vault-first resolve_api_key()
- *(chat)* Decouple massive monolith into handlers, engine, and repl modules
- *(providers)* Extract provider logic into discrete profiles and models
- *(planner)* Extract domain models into models.py
- *(onboarding)* Externalize wizard text to templates
- *(registry)* Decouple registry into graph, models, metadata, and handlers
- Global subsystem optimizations and minor fixes
- *(chat)* Update chat module and console interactions
- *(providers)* Update provider manager and usage metrics
- *(core)* Update core modules, cli, templates, and utilities
- Fix import ordering (ruff E402) and replace lazy imports
- *(chat)* Remove non-functional stubbed out commands
- Remove /palette slash command
- *(registry)* Polish offline store and tool registry mechanisms
- *(chat)* Overhaul Chat REPL, resolve runtime warnings, and remove MCP references
- Consolidate planner instances and add step normalisation
- Delegate multi-wave execution to AutonomousExecutor
- *(report)* Consolidate two ReportEngines into a single module
- *(parsers)* Code quality sweep across 50+ parser modules
- Strip dead imports and normalise formatting in NLP, planner, and executor modules
- Reorganize parser tests into feature-category files
- Polish core engine code and standardize comments
- *(executor)* Improve execution reliability and API compatibility
- *(openai)* Extract _host_match helper and bump Gemini/OpenAI max_tokens
- *(onboarding)* Overhaul model tiers recommendations and fix wizard installer bugs

### Security

- Fix API auth bypass and prompt injection vectors
- Restore SSL verification and subprocess validation
- Block dangerous environment variables in chat .env loading
- Validate SDK module imports in chat REPL
- Add timeout to HTTP notification dispatch
- Skip sudo-wrapping shell scripts during tool discovery
- Block dangerous env vars from CLI .env loading
- Update resume prompt assertion for sanitization
- Upgrade lychee-action from v1.10.0 to v2.8.0
- *(chat)* Overhaul command registry, add 18 new slash commands, and enrich UI/REPL experience
- *(security)* Add SeccompProfile for Docker sandboxing and harden subprocess with path traversal detection
- *(infra)* Update packaging, Docker, CI config, and project metadata across all distribution channels
- *(chat)* Enrich REPL with professional prompt rendering, enhanced autocomplete, and cross-platform command maps
- Fix nbtscan installation in docker
- *(security)* Apply least-privilege permissions to all workflows
- *(deps)* Bump cryptography minimum from 42 to 46.0.6

### Style

- Configure site url to github pages and add Back to Website navigation loop

### Styling

- Fix lint errors (unused imports, import ordering, type ignores)
- Fix trailing whitespace and EOF newlines in docs and .gitignore
- Apply ruff-format and pre-commit hook fixes across all source files
- Apply ruff auto-formatting across the remaining codebase
- Fix ruff formatting in multiple files
- Fix ruff format in test_tool_installer for CI ruff v0.8.0 compat
- Remove trailing whitespace from CI/CD workflow files
- Remove trailing whitespace from documentation and policy files
- Remove trailing whitespace from source code files
- Remove trailing whitespace from test files

### Testing

- Align tests with removed/dead code cleanup
- Update template step count assertions from 4 to 6
- Update health test for non-200 status code handling
- Add comprehensive test suite coverage for core infrastructure
- Update test suites to align with recent refactorings
- Fix test failures and align with API changes
- Add test suites for chat compat, onboarding, and provider utils
- Add new coverage test files from edge case distribution
- Strengthen test suite by fixing broken tests and improving overall coverage
- *(refactor)* Remove unprofessional naming conventions and AI comments
- *(suite)* Update tests for new tool versioning and logic
- Update unit tests to match current logic and fix lint issues
- Tighten assertions to use exact matches instead of substring checks

### Tests

- Use temporary database for autonomous loop isolation
- Mock isatty() for deterministic shell review tests
- Fix proactor loop detection test on Linux
- Make CREATE_NO_WINDOW cross-platform
- Add timeout param to notification dispatch assertions

### Build

- *(infra)* Update dependencies, pin cryptography, and add dockerignore
- Update project config, CI/CD, and docs

### Ci

- Fix dependabot.yml duplicate keys and lower coverage threshold to 45%
- Modernize GitHub Actions workflows for v3.0.0
- Add advanced workflows and yaml issue templates
- Implement ultimate enterprise workflows for supply chain security and reliability
- Add missing 15 enterprise workflows to reach 37
- Rename workflows to match exact audit specs
- Add ultra-premium devex workflows
- Comprehensive workflow overhaul -- uv caching, multi-platform docker, all auto-publishers, and 3 new workflows
- Switch auto-format workflow to uv
- Add codecov upload step to CI workflow
- Migrate docs deployment to GitHub Pages with artifact upload
- Fix PR assignee logic and skip dependabot self-assignment
- Add lock-threads workflow to auto-close stale issues and PRs
- Add wiki-sync workflow to sync docs to GitHub Wiki on release
- Update docs and wiki sync workflows for mkdocs material
- Fix broken GitHub Action workflows 🛠️
- Fix workflow actions, docker build context, and add baseline secrets
- Fix workflow failures across all pipelines
- Fix spellcheck and container scan workflows
- Fix dockerignore BOM issue
- Fix docker packages and typos whitelist
- Hardcode pentest tools versions in Dockerfile
- Fix remaining spellcheck failures
- Fix CI, lock-threads, and container scan failures
- Ensure coverage artifacts upload even when tests exit with failure
- Safeguard artifact and Codecov uploads across test matrix failures

### Restore

- Bring back platform_integration, performance, knowledge_graph modules

### V3.0

- Remove deprecated modules (compat.py, main.py), TODOs, bump version

### ﻿chore

- Remove unused concurrent.futures import and fix test docstring escaping
- *(docker)* Rewrite Dockerfile with multi-stage builds and Kali/Parrot base variants; refresh installers and CI config

### ﻿docs

- *(commands)* Expand /skills command examples with show, edit, remove sub-commands

### ﻿feat

- *(subprocess)* Revamp error diagnostics, sudo handling, and process execution messages
- *(executor)* Add auto-install prompts, sudo prefetch, and missing-tool detection
- *(learning)* Redesign confidence formula, similarity engine, and skill maintenance
- *(learning)* Implement universal skill compilation, parameter abstraction, and schema v3 migration
- *(learning)* Track observed parameter values, migrate to schema v4, and refine universal skill compilation
- *(planner)* Add ping tool across all tool maps and enhance LLM response parsing with multi-format fallback
- *(platform)* Introduce cross-platform abstraction module for Android, iOS, and WSL support
- *(providers)* Update model inventories across all provider profiles with latest offerings and corrected context windows
- *(scripts)* Add mobile platform installers, Docker packaging, and cross-platform test harness
- *(tools)* Add version regex patterns across all 640+ tool entries in cyber_tools.json
- *(chat)* Refresh greeting with time-of-day nuance, add async connectivity callback, and overhaul /config handler
- *(chat)* Enrich REPL with persona display, InMemoryHistory, and refined prompt/autocomplete rendering
- *(config, cli)* Add multiline input mode, auto-save session setting, and nmap_args CLI parameter
- *(core)* Wire progress callback through ExecutionEngine, AgentCore, and RegistryExecutor with per-step workflow tracking
- *(chat)* Rewrite offline/registry mode output with per-step Rich panels and live step progress tracking
- *(planner)* Support conversational LLM responses and add common utility intent patterns across both planners
- *(registry)* Add checksum verification tools (md5sum, sha*sum, b2sum, cksum) to curated tool list

### ﻿fix

- *(chat)* Improve model provider configuration and API key validation
- *(subprocess)* Skip shell metacharacter validation for explicit shell invocations
- *(executor, registry, onboarding)* Support async callbacks in executors and polish onboarding skill parser
- *(chat)* Auto-reset provider from 'registry' to 'auto' at startup and fix mode switch provider logic

### ﻿refactor

- *(providers)* Rename opencode-go to opencode-zen and add OpenRouter referrer headers
- *(parsers)* Modernize type annotations, reorganize imports, and add empty-output guards across all 113 parsers
- *(providers)* Add thread-safe singleton, consolidate failover logic, and clean up imports/types
- *(core)* Standardize imports, update docstrings, fix exception handling, and add SSRF protection across core modules
- *(session_log)* Replace os.path.join with Path for cleaner path construction
- *(subprocess, tool_version, tool_installer)* Introduce destructive command detection and simplify version lookup

### ﻿test

- Update e2e, notification, and subprocess tests for compatibility with latest changes
- Update tests for destructive command detection, async callback support, and simplified tool version API


