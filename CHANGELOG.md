# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-07-01

### Miscellaneous Tasks

- Sync all version references to 1.0.1
- *(release)* Update changelog for v1.0.1

### Ci

- Fix setup-nuget, git-cliff install, winget publish error, labeler v5 syntax, and lychee argument error
- Run publish-chocolatey on windows-latest for native NuGet support

## [1.0.1] - 2026-07-01

### Bug Fixes

- *(release)* Update gh-pages action SHA, replace git-cliff-action with direct install, allow TestPyPI failure
- *(ci)* Fix workflow failures and configuration KeyError
- *(termux)* Add precompiled dependencies to installer
- *(ci)* Update downstream compatibility validations and lock threads version
- *(install)* Prevent powershell terminal from closing on exit and fix pipeline corruption
- *(session)* Resolve encoding issues and integrate audit logger
- *(typing)* Resolve mypy type errors in Prompt.ask and session export
- *(ci)* Add security-events permissions for docker publish and follow redirects in homebrew archive check
- *(core)* Remove redundant comparison, fix regex typo, and clean up unused parser regexes
- *(core)* Refactor sudo password cache, declare ToolHandler public, and clean up unused imports/variables
- *(lint)* Remove unused import in zgrab_parser and unused type ignore in executor_autonomous
- *(lint)* Resolve mypy type check and ruff import order warnings
- *(lint)* Resolve remaining unused variables, empty excepts, and ineffectual awaits
- *(lint)* Resolve unused global/local variables and type checking issues in CLI/parsers/tests
- *(security)* Resolve final batch of CodeQL scanning alerts and add custom codeql-config.yml to ignore noisy quality checks
- *(typecheck)* Resolve dict item types in scripts/test_platform.py to satisfy pre-commit mypy
- *(security)* Resolve final Python CodeQL alert, suppress urlopen warnings, and disable Scorecard SARIF uploads
- *(ci)* Update labeler.yml format, fix auto-merge enableAutoMerge function, and prevent version-validation bash dollar expansion
- *(ci)* Align all CodeQL actions to v3 commit hash to prevent version mismatch failure
- *(ci)* Exclude CHANGELOG.md files from end-of-file-fixer to prevent automated PR check failures
- *(ci)* Set docs and wiki-sync to trigger only at release and fix wiki-sync rsync .git deletion

### Documentation

- Convert github-style alert callouts to native mkdocs-material admonitions
- Fix home and map page front matter and header welcome note positioning
- Update changelog (#70)
- Update changelog (#89)
- Update changelog (#90)
- Update changelog (#91)
- Update changelog (#92)
- Update changelog (#93)
- Update changelog (#94)
- Update changelog (#95)
- Update changelog (#96)
- Align project policies and security disclaimers with v1.0.1 release
- Add v1.0.1 release notes and update changelogs
- Document OpenSSF Scorecard supply chain controls and update docs map
- Update documentation and wiki staging version references to v1.0.1
- Update changelogs and v1.0.1 release notes for installer relocation and release automation

### Features

- *(provider_utils)* Make health check timeout configurable
- *(repl)* Perform live health checks for local providers in status gathering
- *(ui)* Render each provider's real-time status on its own line in the LLM Status panel
- Update Siyarix application version to v1.0.1 in source code and unit tests

### Miscellaneous Tasks

- Update default project and container build versions to v1.0.1
- Bump default installation target version to v1.0.1 in setup scripts
- Update deployment package descriptors for v1.0.1 release
- Update installers to support smart Python setup and virtual environments
- Relocate installer scripts to installer/ directory

### Security

- *(deps)* Bump trufflesecurity/trufflehog (#81)

### Styling

- *(docs)* Revamp stylesheet to improve sidebar, scrollbars, tables, and light mode contrast
- Fix linting issues from previous commit
- Fix ruff formatting from previous typing commit
- Format modified files with ruff
- Apply pre-commit line endings, json formatting, and ruff assertion fixes
- Apply pre-commit formatting to git-cliff/CHANGELOG.md

### Testing

- Fix duplicate dictionary keys and identical expression comparison warnings

### Build

- Update dependency lock files (#88)
- *(deps)* Bump actions/upload-artifact from 4.6.2 to 7.0.1 (#87)
- *(deps)* Bump softprops/action-gh-release from 2.6.2 to 3.0.1 (#86)
- *(deps)* Bump actions/upload-pages-artifact from 3.0.1 to 5.0.0 (#85)
- *(deps)* Bump actions/deploy-pages from 4.0.5 to 5.0.0 (#84)
- *(deps)* Bump github/codeql-action/upload-sarif (#83)
- *(deps)* Bump amannn/action-semantic-pull-request from 5 to 6 (#82)
- *(deps)* Bump github/codeql-action/autobuild from 3.36.2 to 4.36.2 (#80)
- *(deps)* Bump docker/metadata-action from 5.10.0 to 6.1.0 (#79)
- *(deps)* Bump docker/setup-buildx-action from 3.12.0 to 4.1.0 (#78)

### Ci

- Pin lock-threads action to secure commit hash
- Add workflow_dispatch to CodeQL Weekly Deep Scan
- Update CI workflow templates and bug report placeholder for v1.0.1
- Automate Siyarix package updates to Chocolatey and Homebrew on release
- Fix trailing whitespace in homebrew-publish workflow
- Fix pre-commit hooks and false positive typos in installers

## [1.0.0] - 2026-06-27

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
- *(release)* Resolve PyPI publish blocked by check-wheel-contents W002 and missing installer asset

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

## [0.2.0] - 2026-06-01

### Bug Fixes

- Critical import errors and module compatibility
- CLI commands and chat REPL broken imports
- Test suite compatibility with v2 architecture
- Improve goal decomposition for scan commands
- Improve recon tool handlers for shodan/amass
- Flesh out ExecutionEngine compat wrapper
- Replace removed AgentLoop/AgenticLoop with AgentCore
- Rewrite test suite for v2 architecture
- Add step_results to EngineResult and suppress ptk warning
- Make agent loop work with current v2 architecture
- Print agent response after execution
- Suppress RuntimeWarning and show step details
- Add timeouts to agent execution and LLM synthesis
- _print_plan crashing on PlanStep objects
- /log crashing on empty session log files
- SettingsStore.get() crashes when caller passes a default value
- Greet users on hello/hi and return empty plan for casual chat
- Update repo URL in greeting to mufthakherul/siyarix
- List all LLM providers in greeting including Ollama/local
- Always use unified agent flow in integrated mode
- Enforce mode-specific workflows (autonomous=LLM-only, integrated=hybrid, registry=heuristic)
- Resolve auto provider and show greeting in agent flow
- Set openrouter as default model provider instead of auto
- Handle dict response from llm_call in planner (llm_decompose_goal)
- Shell_review Syntax rendering - use Group renderable instead of f-string
- Add click as dev dependency for integration tests

### Documentation

- Add v2.0.0 changelog and update release badge

### Features

- Add event bus and tool capability registry
- Add multi-layer memory system and provider manager
- Rewrite planner and executor with new architecture
- Add validator, context manager, workflow engine, and MCP
- Update core agent and package init for v2 architecture
- Add real tool execution handlers and fix target extraction
- Raise default context window to 1M tokens
- Add ToolExecutor adapter and CommandPipeline
- Add StepStatus.SUCCESS and ExecutionPlan metadata fields
- Add LLM synthesis after agent execution for chatbot responses
- Configurable agent_timeout setting (default 120s)
- Scale tool system to 12000+ tools with dynamic discovery + inverted index + top-k LLM schema
- Add CTF/vuln-lab assessment templates + whole-word tool matching
- Planner method to let an LLM decide what tools to run
- Allow callers to supply a pre-made plan to execute_goal
- Try LLM planner first in the agent loop, fall back to heuristic
- Redesign LLM agent flow with health check, parallel tools, and live output
- 29min timeout, AI can execute raw commands, removed registry dependency
- Upgrade all system prompts to elite red-team operator persona

### Miscellaneous Tasks

- Drop tests for permanently removed v1 modules
- Bump default agent_timeout to 1200s, show config hint on timeout
- Release v2.0.0 — merge unreleased changes into final release
- Sync all version references to 2.0.0

### Refactoring

- Remove old agent loop, tool registry, and engine types
- Remove old execution engine module
- Remove old offline registry and core submodules
- Pull LLM provider boilerplate into a shared helper
- Unified single system prompt, removed dead code
- Remove dead modules, fix broken MCP import, wire shell_review
- LLM no longer constrained by static tool list or registry

### Bump

- Tag all packages as v2.0.0

## [0.1.0-beta] - 2026-05-31

### Bug Fixes

- Add missing progress module and packaging script gaps
- Stabilize workflows baseline and README branding
- Replace xml.etree.ElementTree with defusedxml, fix bare exception in audit_log
- Resolve all mypy type errors across output, executor, and planner modules
- Rewrite _cmd_report with ReportEngine API, add missing imports and CommandProfileStore types
- Resolve all test failures, skipped tests, and warnings
- Remove stripped features from /help, fix learning_memory import crash
- Remove dead handler code for stripped v1.0 features, fix execution pipeline bugs
- Strip all remaining dead code and doc references to removed v1.0 features
- Production readiness — UI audit, NL routing fixes, security hardening
- Set Gemini default model to gemini-2.0-flash across all config locations
- Auto-load API keys from CredentialStore at startup, display scan findings table
- Allow version specifiers with >=, <=, == in validate_cmd_list
- Add TTL caching for model provider availability checks (OllamaModel, _OpenAICompatibleModel)
- Migrate Gemini SDK from deprecated google.generativeai to google.genai
- Autonomous mode falls back to interpreter when all model providers fail
- Implement /config panel and extend /model to all 10 providers
- Restore original Rich UI style and fix prompt RuntimeWarning
- Resolve KeyError in cache status command
- Remove unavailable gi module filter from pytest.ini
- Sync install.sh version with pyproject.toml (0.1.3 → 1.0.0)

### Features

- Add CHANGELOG.md and 46 chat module tests
- Add Offline Response Registry for AI-free natural responses
- *(agent)* Add AgentLoop module for direct LLM tool calling
- *(agent)* Add agent loop supporting modules
- *(planner)* Add chat() methods for multi-turn agent conversations
- *(providers)* Add OpenRouter adapter
- *(chat)* Integrate agent loop with LLM provider routing
- Add OpenRouter support across config, CLI, engine, and health
- Improve NL routing with tool aliases, intent patterns, and confidence scoring
- Expand Stage 3 security keywords from 7 to 30+ terms
- Improve planner fallback for unknown and custom intents
- Add graceful rate-limit handling in LLM planner
- Improve CLI UX - display run results, fix CSV output, sync theme

### Miscellaneous Tasks

- Bump version to 1.0.0 across all packaging manifests
- Define extras, add py.typed marker, update project metadata
- Remove unused re import in engine/executor.py
- Remove empty stub packages security/ and session/
- Soften greeting template wording ('many' → 'maybe many')
- Remove obsolete audit reports
- Bump version to 1.0.0-beta

### Testing

- Suppress gi PyGIDeprecationWarning in test suite
- Update health test for 5 model providers

### Security

- Harden LLM tool execution paths
- Fix path traversal detection to catch 2+ levels
- Add newline and null byte blocking to command validation
- Expand agent command blocklist and remove dead code

### V1.0

- Remove test files for stripped v2 modules
- Fix test files for stripped modules
- Remove XI references, add init wizard
- Add circuit breaker + graceful provider fallback
- Polish CLI help text and module docstrings
- Fix remaining test failures, final cleanup
- Resolve all audit gaps — production hardening

### V1.0.0-beta.1

- Strip advanced modules, preserve core

## [0.0.3.3] - 2026-05-28

### Bug Fixes

- Drop siyarix-agent -> siyarix, purge all legacy footprints (siyarix/siyarix/siyarix=0)
- Handle string-level notification level in NotificationCenter._render
- Resolve bugs in importer, validators, and attack_path modules
- Resolve mypy type errors in core infrastructure modules
- Resolve mypy type errors in planning and execution modules
- Resolve mypy type errors in scanner, stealth, and misc modules
- Relax test assertions for Windows timer and scanner differences
- Correct mock patches and response format in planner tests
- Resolve fixture scoping and mock patching issues in test files
- Clean ruff warnings in tracked test files
- Correct variable naming mismatches and test assertions
- Replace LICENSE with verbatim AGPL-3.0 from gnu.org
- Harden workflows and package build inputs
- Make deb conffile present during package build

### Documentation

- Replace static coverage badge with dynamic Codecov badge
- Remove all stale documentation files
- Create comprehensive documentation system with 37 files across 7 sections
- Fill 19 gaps identified by codebase audit — all undocumented features now covered
- Rewrite README.md with honest early-stage framing, grounded capabilities
- Professional README with branding pack, stats cards, banner, badges

### Features

- Multi-platform packaging — pip, npm, apt, brew, winget, choco, docker, harmonyos
- Implement ESC/? key handling and /cancel command in chat REPL
- *(config)* Add Discovered Tools section to config panel

### Miscellaneous Tasks

- Add ruff lint per-file-ignores for test files
- Add generated files to .gitignore
- Update pyproject.toml license to AGPL-3.0-only
- Remediate license and dependency risks

### Refactoring

- *(chat)* Reorganize help, prune advanced handlers, fix providers
- Update imports and references after module removal

### Security

- Siyarix -> siyarix (complete system-wide migration)
- Adopt AGPL-3.0 as primary open-source license
- Establish ethics, AI, trademark, and commercial framework
- Normalize NOTICE for multi-provider AI, add AI_PROVIDER_POLICY.md, set AGPL-3.0-or-later

### Testing

- Add coverage tests for core and scanner modules
- Add coverage tests for security, storage, and config modules
- Add coverage tests for UX, agent, and platform modules

### Audit

- Production readiness fixes - security, stability, dependencies

### Brand

- Add Siyarix logo asset (assets/logo.png)

### Branding

- Replace ASCII banner subtitle with SIYARIX identity

### Cleanup

- Remove deprecated scripts, old modules, and unused tests

### Community

- Add security policy, contribution guide, and templates

### Legal

- Add NOTICE, SPDX headers, and complete policy wiring
- Migrate project license from MIT to AGPL-3.0-or-later, rebrand URLs to siyarix

### Remove

- SOCAgent and DFIRAgent - fake SIEM/Volatility simulators

## [0.0.3.2] - 2026-05-27

### Bug Fixes

- Cross-platform compatibility and encoding

### Refactoring

- Consolidate model providers, danger patterns, remove dead code
- Critical security fixes, dead code removal, parser protocol
- Decompose engine.py into engine/ package with 6 submodules
- Unify security validation into security_hardening.py
- Remove local _now_iso() from 20 parser files

## [0.0.3.1] - 2026-05-26

### Bug Fixes

- *(providers)* Consolidate dead-code adapters into providers.py
- Undefined name and security issues

### Documentation

- Update architecture.md for provider consolidation
- Remove Web Dashboard section
- Remove all plugin references from documentation
- Add AGENTS.md and configuration files

### Features

- *(ui)* Unified welcome with system status; remove websockets dep
- Add interactive ConfigPanel with 9 sections
- Populate slash autocomplete with all 85 commands
- Add OPENCODE_API_KEY env var and base_url support to OpenAIModel
- Add OpenCodeAdapter provider for OpenCode API
- Enhance tool registry with external metadata support and capability inference
- Add tool metadata generation script and data directory

### Miscellaneous Tasks

- Remove unused imports and variables across 19 files
- Remove dead web UI code
- Remove community, challenge, collaboration source files
- Remove plugin system source and tests

### Performance

- *(offline_store)* Connection timeout, batch import, LRU cache
- *(performance)* Cached properties, validation, dynamic caps

### Refactoring

- *(engine)* Delegate all step execution to ToolExecutor
- *(cli)* Consolidate into 3 usage modes
- Remove community/team/challenge/collab from CLI, chat, config
- Remove mode dispatcher infrastructure
- Remove numbered mode switching from chat REPL
- Remove dashboard_app CLI group and wizard command
- Clean up UX exports and autocomplete
- Remove redundant slash commands handled by NL
- Wire /config to ConfigPanel, remove subcommand clutter
- Consolidate alias commands in help display
- Add aliases for /clear and /new
- Remove all plugin imports and references from source

### Testing

- Update for removed mode and wizard features

## [0.0.3] - 2026-05-26

### Bug Fixes

- *(deception)* Use full SHA-256 hash for trapdoor credential comparison
- *(exploitation)* Propagate all previous phase step IDs as dependencies
- *(exploitation)* Rewrite msfvenom payload generator with key=value syntax, auto-format, and validation
- *(cli)* Remove extraneous default arg from config.get() for lmstudio_url; SettingsStore provides defaults via DEFAULTS dict
- *(exports)* Update __init__.py imports and add missing learning/pedagogical exports
- *(cli)* Implement plugin install logic in main.py
- Resolve failing workflows and validate runtime/tool outputs

### Documentation

- *(hybrid-migrate)* Align file counts and method names with actual implementation
- *(migration)* Update changelog with Phase 11 enterprise feature completion including PersonaEngine, 4 new providers, AES-256-GCM vault, exit codes, bootstrap enhancements, and CLI upgrades
- Update migration.md with Phase 12 changelog and progress status

### Features

- *(persona)* Add PersonaEngine module with 7 built-in personas, intent classification, tool ACL filtering, workflow templates, hot-swap, and custom YAML persistence
- *(providers)* Add GroqModel, TogetherModel, LMStudioModel, and CustomModel to planner with circuit breaker registration
- *(providers)* Add GroqAdapter, TogetherAdapter, LMStudioAdapter, CustomAdapter, and AnthropicAdapter with provider registry registration
- *(providers)* Register all new providers in engine preference chains with hierarchical fallback ordering (groq, together, lmstudio, anthropic)
- *(config)* Add defaults and descriptions for groq_model, together_model, lmstudio_url, lmstudio_model, and persona settings
- *(vault)* Implement AES-256-GCM encryption with HKDF key derivation for credential vault
- *(vault)* Add master key rotation and Fernet-to-AESGCM migration for enterprise credential management
- *(exceptions)* Add EXIT_CODE_MAP with MRO-ordered exit code matching (0=success, 1=execution, 2=permission, 3=tool, 4=provider/timeout)
- *(bootstrap)* Add terminal/shell detection (T3), database backend check (T7), interactive install prompts (T9), auto-install flow (T10), and extended tool detection
- *(chat)* Add /work-mode slash command with persona switching, interactive builder, list, and auto-detection mode
- *(chat)* Add /key rotate slash command for credential vault master key rotation
- *(cli)* Add --work-mode persona flag, @targets.txt multi-target mode, Rich progress indicators, and all provider API key loading
- *(tool-registry)* Expand with 30+ new tools, PATH scanning, missing categories
- *(tool-installer)* Add 40+ install methods for all missing tools
- *(persona)* Add REVIEW ACL permission level to ToolACL
- *(safety)* Create permission gate with 3-stage filtering
- *(safety)* Create kill switch for emergency stop
- *(safety)* Create shell injection review loop
- *(safety)* Enhance masking with JWT/cookie/credential patterns
- *(safety)* Enhance response sensor with kill switch and permission gate
- *(safety)* Integrate kill switch and permission gate into engine
- *(agent)* Create agent lifecycle management module
- *(collab)* Create team collaboration session module
- *(coder)* Create code generation and review bridge
- *(mcp)* Create MCP client for research mode integration
- *(learning)* Create tool pattern learning memory with persistence
- *(learning)* Create user learning module with adaptive pedagogical output
- *(chat)* Add 15 new slash commands for Phase 6-10 features
- *(exports)* Update __init__.py with all new Phase 6-10 module exports
- *(learning)* Rewrite learning_memory with N-gram, decay, Bayesian confidence, anti-patterns
- *(learning)* Rewrite user_learning with auto-detect, milestones, session history, preferences
- *(chat)* Enhance /learning with 15 subcommands for full learning system access
- *(exports)* Add SessionContext and SessionRecord to learning module exports
- *(learning)* Implement user correction tracking, task classification, and flag effectiveness
- *(learning)* Implement pedagogical engine with CVE explainers and interactive drill-down
- *(integration)* Wire correction tracking into execution engine and pedagogical output into chat
- *(session_log)* Create structured session logging system (Chapter 11)
- *(integration)* Wire session logging into execution engine
- *(chat)* Add 11 missing slash commands for Chapters 11, 12, 15

### Miscellaneous Tasks

- *(exports)* Add PersonaEngine, Persona, PersonaName, ToolACL, WorkflowTemplate, LearningBias, and BUILTIN_PERSONAS to public API
- Plan workflow-failure fixes

### Performance

- *(distributed)* Implement Redis connection pooling for queue operations

### Refactoring

- *(canary)* Migrate CanaryTokenType from str+Enum to StrEnum
- *(shell)* Fix duplicate ShellType enums and add missing platform import

### Styling

- *(tests)* Fix ruff E402 - move pytestmark after all imports (part 1)
- *(tests)* Fix ruff E402 - move pytestmark after all imports (part 2)
- *(tests)* Fix ruff E402 - move pytestmark after all imports (part 3)

### Testing

- *(conftest)* Add mock_execution_plan fixture for planner/engine tests
- *(exploitation)* Update dependency linking test for cross-phase dependencies
- *(exploitation)* Update msfvenom payload generation test with key=value assertions
- *(infra)* Expand pytest markers to cover all 16 module categories
- *(markers)* Add module-level markers for feature test modules
- *(markers)* Add module-level markers for infra/adversarial test modules
- *(markers)* Add module-level markers for telemetry/workflow modules

## [0.0.2] - 2026-05-25

### Bug Fixes

- *(output)* Consolidate output engine into __init__.py, delete shadowing output.py
- *(engine)* Consolidate output engine, fix prompt_confirm signature with default param
- *(providers)* Fix type annotations, add provider registry, improve error handling
- *(pty)* Add type annotations and improve PTY detection logic
- *(security)* Improve masking engine, credential store type annotations
- *(core)* Add type annotations for config, auth, exceptions, and logging modules
- *(planner)* Add type annotations and improve plan generation logic
- *(core)* Add type annotations for engine types, health, audit log, branding
- *(scheduler)* Add type annotations and improve scan scheduling
- *(orchestration)* Fix yaml redefinition shadowing, add type annotations
- *(ux)* Fix Completion type alias, add type annotations for autocomplete, wizard, split-pane, command palette
- *(xi)* Add type annotations and fix service module unused import
- *(security)* Add type annotations for attack path, compliance, RBAC, security hardening
- *(orchestration)* Fix yaml redefinition, remove unused imports
- *(output)* Add type annotations for reporting module
- *(session)* Add type annotations for session replay, session manager, telemetry SIEM, attack graph
- *(parsers)* Add type annotations and fix import patterns across 8 parsers
- *(core)* Add type annotations for chat, command profiles, executor, interpreter, knowledge graph
- *(core)* Add type annotations for playbooks, plugins, progress, validators, worker pool
- *(core)* Add type annotations for response sensor, rust accel, shell knowledge, tool executor/registry

### Documentation

- *(overview)* Expand project overview with architecture highlights and key features
- *(architecture)* Document Clean Architecture layers, DDD aggregates, and module topology
- *(migration)* Update migration plan with completed phases and verified modules
- *(hybrid)* Update hybrid migration document with verified Phase 1-5 implementations
- *(main)* Rewrite README, installation, and usage guides with comprehensive documentation
- *(architecture)* Document Clean Architecture layers and module topology
- *(overview)* Expand project overview with architecture highlights

### Features

- *(masking)* Add ResponseSensor, integrate with planner, add masking/redaction tests
- Implement new features including masking engine, provider registry, and scan scheduler; add logging configuration and playbook system
- Add new features including masking engine, provider registry, scan scheduler, and centralized logging configuration; implement playbook system and worker pool for task management
- Implement phase1 adaptive feedback loop and coordinator wiring
- *(docker)* Add Dockerfile for containerized Siyarix deployment with Python 3.11
- *(build)* Add Makefile with build, test, lint, and docker targets
- *(observability)* Add OpenTelemetry collector configuration for tracing and metrics
- *(bootstrap)* Add system bootstrap and environment initialization module
- *(cloud)* Add cloud scanner module for multi-provider credential detection
- *(compliance)* Add compliance runner for regulatory framework checks
- *(report)* Add report engine for structured output generation
- *(playbook)* Add playbook engine for automated response workflows
- *(tools)* Add tool installer for automated security tool deployment
- *(cvss)* Add CVSS 3.1 scoring module for vulnerability assessment
- *(adversarial)* Add adversarial testing module with 8 IDS evasion patterns
- *(threat-intel)* Add threat intel module with STIX/MISP/MITRE integration
- *(canary)* Add canary token detection module for deception infrastructure
- *(distributed)* Add distributed execution module with Redis and memory backends
- *(stealth)* Add stealth module with traffic obfuscation and evasion
- *(terminal)* Add terminal detection module for environment fingerprinting
- *(new)* Add src/siyarix/multi_model_ensemble.py
- *(new)* Add src/siyarix/parsers/aircrack_parser.py
- *(new)* Add src/siyarix/parsers/bettercap_parser.py
- *(new)* Add src/siyarix/parsers/ettercap_parser.py
- *(new)* Add src/siyarix/parsers/impacket_parser.py
- *(new)* Add src/siyarix/security/__init__.py
- *(new)* Add src/siyarix/telemetry/opentelemetry.py
- *(main)* Add CLI entry points for all phases, improve argument handling
- *(workflow)* Add workflow generator with template engine and conditional branching
- *(agent)* Implement Phase 1 coordinator with DAG dispatch and dep resolution
- *(agent)* Implement Phase 4 DFIR agent with 9 IOC detection types
- *(agent)* Implement Phase 4 SOC agent with 8 automated response rules
- *(threat-intel)* Add threat intelligence module with STIX/MISP/MITRE integration

### Miscellaneous Tasks

- *(cleanup)* Remove MIGRATION_PLAN.md
- *(cleanup)* Remove output.py
- *(config)* Update pyproject.toml with ruff and mypy strict configuration
- *(config)* Update .env.example with all configuration options and defaults

### Testing

- *(infra)* Add __init__.py for test configuration
- *(infra)* Add conftest.py for test configuration
- *(infra)* Add pytest.ini for test configuration
- *(phase1)* Add test_bootstrap.py for Phase 1 modules
- *(phase1)* Add test_cloud_scanner.py for Phase 1 modules
- *(phase1)* Add test_compliance_runner.py for Phase 1 modules
- *(phase1)* Add test_playbook_engine.py for Phase 1 modules
- *(phase1)* Add test_report_engine.py for Phase 1 modules
- *(phase3)* Add test_ml_anomaly.py for Phase 3 analysis modules
- *(phase4)* Add test_deception.py for Phase 4 defense modules
- *(phase2)* Add test_tool_installer.py for Phase 2 exploitation modules
- *(phase3)* Add test_adversarial_tester.py for Phase 3 analysis modules
- *(phase4)* Add test_stealth.py for Phase 4 defense modules
- *(phase3)* Add test_threat_intel.py for Phase 3 analysis modules
- *(phase4)* Add test_terminal_detection.py for Phase 4 defense modules
- *(phase3)* Add test_multi_model_ensemble.py for Phase 3 analysis modules
- *(modules)* Add test_telemetry_siem.py
- *(modules)* Add test_opentelemetry.py
- *(modules)* Add test_parsers_all.py
- *(modules)* Add test_agents_coordinator.py
- *(modules)* Add test_agents_dfir.py
- *(modules)* Add test_agents_soc.py
- *(xi)* Add test_xi_context_tracker.py for XI module tests
- *(xi)* Add test_xi_predictor.py for XI module tests
- *(xi)* Add test_xi_service.py for XI module tests
- *(xi)* Add test_xi_skill_profiler.py for XI module tests
- *(modules)* Add remaining Phase 2-4 test files for canary, cvss, distributed, exploitation
- *(fix)* Fix ruff and mypy issues in branding, execution engine, intent router, parser, provider tests
- *(fix)* Fix ruff and mypy issues in response sensor, session kernel, subprocess, tool executor, UX, worker tests

## [0.0.1] - 2026-05-24

### Bug Fixes

- Resolve all github actions security workflow errors and sql injection alerts
- Make security workflows robust with Direct OSV-Scanner and tagged Scorecard
- Add continue-on-error: true to secrets detection tools
- Use official google/osv-scanner-action@v2 with native lockfile scan
- Correct hyphens to underscores in scorecard inputs and bump to v2.4.3
- Use google/osv-scanner-action reusable workflow instead of step
- Correct google/osv-scanner-action reusable workflow tag to @v1
- Use step-based google/osv-scanner-action@v2.3.8 for maximum stability
- Use correct google/osv-scanner-action@v2 reusable workflow path
- Use correct osv-scanner/action@v2 with results-file-name set
- Use correct google/osv-scanner-action/github-action@v2 path
- *(planner)* Log concise warning for Ollama availability to avoid noisy tracebacks
- Resolve CI and security workflow failures from failed runs
- Resolve workflow YAML parsing errors
- Correct AI workflow expression errors
- Resolve GitHub Actions workflow failures

### Documentation

- *(chore)* Add branding assets, docs, and packaging artifacts
- Add comprehensive documentation (overview, install, usage, architecture, CLI ref, development, contributing, FAQ, troubleshooting)
- Update CLI references and usage examples
- Add architecture analysis, technical audit, and roadmap
- Update implementation roadmap
- Update core reference, architecture, usage, and security for v1.2.0
- Update overview and installation for v1.2.0 features
- Finalize v1.2.0 updates for dev, faq, and troubleshooting
- Update README and docs to reflect Gemini, key/theme commands and CLI UX improvements
- Add ultra-enterprise redesign master blueprint
- Rewrite root documentation for open-source community
- *(planning)* Update architectural audit and roadmap files
- *(npm)* Update npm package wrapper documentation
- Add guides for extending parsers and configuring ai models
- Comprehensively rewrite architecture and cli reference
- Enhance contributing and local development guides
- Rewrite faq and troubleshooting sections
- Expand installation steps and project overview
- Enhance usage examples and security guidelines
- Update README, overview, architecture, and development guides
- Add defensive testing evidence report with screenshots

### Features

- *(core)* Add Siyarix package metadata and CLI source
- *(repl)* Add interactive chat REPL and cross-platform shell translation layer
- *(cli)* Enhance security commands with live dashboard, threat hunting, playbooks, and MITRE ATT&CK coverage tables
- *(planner)* Improve Ollama integration with lazy availability checks, add cybersecurity system prompt guidelines, and extend aliases
- *(registry)* Add discovery caching (TTL) and expand known security tools list
- *(main)* Wire up auth keyring management, config settings, shell completions, and plugin registration
- *(repl)* Refine shell normalization, detection logic, and clean up imports
- Expand tool registry and safe commands with cloud & containers
- Add shell intelligence, device detection, and terminal telemetry
- Expand rule interpreter with cloud, compliance and config categories
- *(engine)* Add workflow persistence, retries, and health metrics
- *(cli)* Expand findings, reports, and CI/CD gate commands
- Add command profiles module for execution control
- Enhance shell knowledge system with command discovery
- Enhance core engine, planner, and interactive chat system
- Update shell knowledge, tool registry, and platform utilities
- *(chat)* Improved welcome banner, prompt, provider status, and gemini installer flow
- *(config)* Add provider-specific model defaults (openai_model, anthropic_model)
- Add kernel, router, xi service, and workflow runtime foundations
- *(core)* Implement Unified Mode Dispatcher, Semantic Intent Router, and Command Pipelines
- *(ux)* Implement premium terminal UX systems (smart autocomplete, fuzzy command palette, split-pane layout, guided setup wizard)
- *(repl)* Integrate premium UX systems and dispatcher into main CLI and chat REPL
- *(security)* Implement security hardening (injection sanitization, secret redaction), persistent sessions, and premium notifications center
- *(orchestration)* Implement multi-agent teams, workflow generators, knowledge graphs, and PTY support
- *(xi)* Implement Experience Intelligence services, context trackers, predictors, and skill profilers
- *(recon)* Add Shodan, Amass, and Subfinder parsers and register in tool registry
- *(security)* Implement offline attack path analyzer
- *(output)* Implement offline premium executive report generator
- *(core)* Implement offline task interpreter, dynamic loop execution, and conditional logic branching

### Miscellaneous Tasks

- Add PyPI metadata (readme, authors, urls)
- Add security, conduct, templates, CI, pre-commit, dependabot and siyarix shim
- Global branding update from Siyarix to Siyarix
- Update .gitignore to ignore tool-generated directories
- Setup comprehensive CI/CD workflows and linting
- Add .graphifyignore and update .gitignore for graphify
- Update .gitignore to include build artifacts, cache directories, and language-specific output paths
- Bump version to 0.4.0 and update dependencies
- Update .gitignore to exclude sensitive and local session files
- Update ci/cd workflows and project configuration
- Untrack and ignore internal planning, design, and audit documents

### Refactoring

- Rename internal module siyarix_agent -> siyarix and update imports/docs/installer
- Core logic modules and professionalize nomenclature
- Test suite cleanup and professional naming
- *(core)* Improve settings, add Ollama configuration, version metadata, and subprocess type-safety
- *(audit)* Improve audit logger with memory limits, atomic saves, and stderr output support
- Add explicit exports and lint cleanups in parsers package
- Extract UI panels layout variables in security commands
- Remove unused Tor SOCKS proxy and identity rotation options
- Update main entry point with improved command handling
- Improve chat module architecture
- Enhance credential store security and functionality
- Expand security commands and enhance credential management
- *(core)* Enhance execution engine, offline store, and AI planner circuit breakers
- *(core)* Migrate main execution and planning modules to siyarix namespace
- *(parsers)* Migrate security tool parsers
- *(ux)* Migrate user experience and ui components
- *(orchestration)* Migrate workflow and intelligence modules
- Complete remaining source migration from siyarix to siyarix

### Styling

- PEP 8 formatting and whitespace cleanups across multiple source files

### Testing

- Add CLI, hybrid engine, and registry test suite
- *(repl)* Add shell knowledge unit tests and clean up unused imports
- Add engine retry tests and new integration test suite
- Update shell knowledge tests
- Add comprehensive unit tests for new v1.2.0 features
- Stabilize workflow runtime tests and validate full suite
- *(premium)* Add comprehensive test suites for UX and pipeline features
- Add comprehensive offline e2e and unit testing suites
- Clean imports in CI-failing test modules

### Assets

- Add modern minimalistic siyarix logo

### Build

- Rebrand package configuration and pre-commit hooks

### Ci

- *(publish)* Add GitHub Actions workflow to publish to PyPI on tag

### Deps

- Update project dependencies

### Design

- Remove old logo and create new professional Siyarix logo

### Sec

- Resolve all 16 low-severity bandit security scan alerts

### Security

- Upgrade download-artifact action to v4.1.3


