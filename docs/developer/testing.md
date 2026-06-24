# Testing

Siyarix maintains a comprehensive test suite with **pytest** (`asyncio_mode=auto`) targeting **75%+ code coverage** across all modules with branch coverage enabled.

## Framework

- **pytest** with `pytest-asyncio` (auto mode) for async test support
- **pytest-cov** for coverage reporting with `branch=true`
- Custom markers: `bootstrap`, `cvss`, `report`, `stealth`, `terminal`, `tool_installer`, `e2e`
- `conftest.py` provides shared fixtures across test modules
- Coverage enforced via `pyproject.toml` (`fail_under = 75`, `branch = true`)

## Running Tests

```bash
pytest                              # All tests
pytest --cov=siyarix                # With coverage
pytest tests/test_planner.py        # Specific file
pytest -k "provider"                # Keyword match
pytest -v                           # Verbose
pytest -x                           # Stop on first failure
pytest -n auto                      # Parallel execution
pytest -m "not e2e"                 # Unit tests only
```

## Test Structure

Tests mirror the source structure in `tests/` with 110+ test files:

```
tests/
├── conftest.py                        # Shared fixtures
├── test_core.py                       # Core agent tests
├── test_core_components.py            # Component-level core tests
├── test_cli_main.py                   # CLI tests
├── test_e2e.py                        # End-to-end tests
├── test_e2e_simulation.py             # Simulated E2E tests
├── test_stress_resilience.py          # Stress/resilience tests
├── test_providers.py                  # Provider tests
├── test_providers_manager.py          # ProviderManager tests
├── test_providers_state.py            # State manager tests
├── test_providers_types.py            # Type system tests
├── test_providers_usage.py            # Usage tracking tests
├── test_planner.py                    # Planner router tests
├── test_planner_autonomous.py         # Autonomous planner tests
├── test_planner_registry.py           # Registry planner tests
├── test_executor.py                   # Executor tests
├── test_executor_autonomous.py        # Autonomous executor tests
├── test_credential_store.py           # Credential vault tests
├── test_permission_gate.py            # Permission gate tests
├── test_audit_chain.py                # Audit trail tests
├── test_knowledge_graph.py            # Knowledge graph tests
├── test_config.py                     # Config tests
├── test_cache_manager.py              # Cache tests
├── test_compaction.py                 # Compaction tests
├── test_compat_models.py              # Compatibility model tests
├── test_connectivity.py               # Connectivity tests
├── test_cvss_scorer.py                # CVSS scoring tests
├── test_events.py                     # Event bus tests
├── test_exceptions.py                 # Exception hierarchy tests
├── test_health.py                     # Health check tests
├── test_memory.py                     # Memory tests
├── test_metrics.py                    # Metrics tests
├── test_models.py                     # Model tests
├── test_model_aliases.py              # Model alias tests
├── test_nlp_engine.py                 # NLP engine tests
├── test_notifications.py              # Notification tests
├── test_offline_store.py              # Offline store tests
├── test_ollama_utils.py               # Ollama utility tests
├── test_onboarding.py                 # Onboarding tests
├── test_opsec.py                      # OPSEC tests
├── test_output_config.py              # Output config tests
├── test_output_init.py                # Output engine tests
├── test_performance.py                # Performance tests
├── test_personas.py                   # Persona tests
├── test_playbook.py                   # Playbook tests
├── test_plugins_loader.py             # Plugin loader tests
├── test_provider_utils.py             # Provider utility tests
├── test_registry.py                   # Tool registry tests
├── test_report_engine.py              # Report engine tests
├── test_response_generator.py         # Response generator tests
├── test_security_commands.py          # Security command tests
├── test_security_hardening.py         # Hardening tests
├── test_session_branching.py          # Session branching tests
├── test_session_kernel.py             # Session kernel tests
├── test_session_log.py                # Session log tests
├── test_shell_review.py               # Shell review tests
├── test_stealth.py                    # Stealth tests
├── test_subprocess_safe_run.py        # Subprocess safety tests
├── test_subprocess_utils.py           # Subprocess utility tests
├── test_threat_intel.py               # Threat intel tests
├── test_tool_availability.py          # Tool availability tests
├── test_tool_call_repair.py           # Tool call repair tests
├── test_tool_graph.py                 # Tool graph tests
├── test_tool_handlers.py              # Tool handler tests
├── test_engine_context.py             # Engine context tests
├── test_engine_executor.py            # Engine executor tests
├── test_engine_providers.py           # Engine provider tests
├── test_engine_safety.py              # Engine safety tests
├── test_execution_engine.py           # Execution engine tests
├── test_chat.py                       # Chat tests
├── test_chat_engine.py                # Chat engine tests
├── test_chat_handlers.py              # Chat handler tests
├── test_chat_openai_compat.py         # OpenAI compat tests
├── test_bootstrap.py                  # Bootstrap tests
├── test_branding.py                   # Branding tests
├── test_intent_router.py              # Intent router tests
├── test_autonomous_loop.py            # Autonomous loop tests
├── test_main.py                       # Main entry tests
├── test_logging_config.py             # Logging config tests
├── test_parsers/                      # Parser test suite
│   ├── test_nmap_parser.py
│   ├── test_nuclei_parser.py
│   ├── test_parsers_ad_windows.py
│   ├── test_parsers_boundary.py
│   ├── test_parsers_cloud_security.py
│   ├── test_parsers_dns_recon.py
│   ├── test_parsers_gobuster.py
│   ├── test_parsers_network.py
│   ├── test_parsers_nmap.py
│   ├── test_parsers_registry.py
│   ├── test_parsers_web_fuzz.py
│   ├── test_parsers_web_vuln.py
│   └── ... (80+ individual parser tests)
├── scripts/                           # Test helper scripts
└── ...
```

## Writing Tests

### Async Tests

```python
import pytest

@pytest.mark.asyncio
async def test_async_behavior():
    result = await some_async_function()
    assert result is not None
```

### Mocking Providers

```python
@pytest.mark.asyncio
async def test_planner_with_mock_provider():
    planner = TaskPlanner()
    planner.providers = [MockProvider()]
    result = await planner.plan("scan test")
    assert result is not None
```

### Using Fixtures

```python
@pytest.fixture
def temp_config(tmp_path):
    config_path = tmp_path / "settings.toml"
    config_path.write_text('[default]\nkey = "value"')
    os.environ["SIYARIX_CONFIG"] = str(config_path)
    yield config_path
    del os.environ["SIYARIX_CONFIG"]
```

## Coverage

```bash
pytest --cov=siyarix --cov-report=term-missing
```

Coverage is enforced in CI via `pyproject.toml` (`fail_under = 75`, `branch = true`).

## Code Quality

```bash
ruff check src/ tests/               # Lint
ruff check --fix src/ tests/         # Auto-fix
ruff format src/ tests/              # Format
mypy src/siyarix/                    # Type check (strict mode, disallow_untyped_defs)
vulture src/siyarix/                 # Dead code detection
bandit -r src/siyarix/               # Security scan
```

## CI Matrix

Tests run on every PR and push to main via GitHub Actions:

| Dimension | Values |
|-----------|--------|
| Python | 3.11, 3.12, 3.13 |
| OS | ubuntu-latest, windows-latest, macos-latest |
| Tests | Unit + integration + E2E |
| Lint | Ruff + MyPy |
| Security | Bandit (SARIF), pip-audit (critical/high fail) |
| Compatibility | Build sdist/wheel, check-wheel-contents, twine check |

## Pre-commit Hooks

```bash
pre-commit install
```

Pre-commit hooks run Ruff (lint + format), mypy, Bandit, typos, detect-secrets, YAML/JSON/TOML validation, trailing whitespace check, end-of-file fixer, large file check, private key detection, and more. Configuration in `.pre-commit-config.yaml`.

### Hook Suite

| Hook | Purpose |
|------|---------|
| `ruff` | Lint with auto-fix |
| `ruff-format` | Format with ruff |
| `mypy` | Static type checking |
| `check-yaml` | YAML validation |
| `check-json` | JSON validation |
| `check-toml` | TOML validation |
| `trailing-whitespace` | Remove trailing whitespace |
| `end-of-file-fixer` | Ensure files end with newline |
| `check-added-large-files` | Prevent large file commits |
| `detect-private-key` | Prevent private key commits |
| `detect-secrets` | Prevent secret commits |
| `bandit` | Security linting |
| `typos` | Spelling check |
| `pyproject-fmt` | Format pyproject.toml |
| `poetry-check` | Validate pyproject.toml |
