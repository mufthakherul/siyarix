# Testing

Siyarix maintains a comprehensive test suite with **102+ test files** targeting **75%+ code coverage** across all modules.

---

## Test Framework

- **pytest** with `pytest-asyncio` (auto mode) for async test support
- **pytest-cov** for coverage reporting
- Custom markers: `bootstrap`, `cvss`, `report`, `stealth`, `terminal`, `tool_installer`, `e2e`, `integration`

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=siyarix

# Run specific test file
pytest tests/test_planner.py

# Run tests matching a keyword
pytest -k "provider"

# Verbose output
pytest -v

# Stop on first failure
pytest -x

# Run tests in parallel
pytest -n auto

# Run only unit tests (skip integration)
pytest -m "not integration"
```

## Test Structure

Tests mirror the source structure in `tests/`:

```
tests/
├── conftest.py              # Shared fixtures
├── test_core.py             # Core agent tests
├── test_cli_main.py         # CLI tests
├── test_e2e.py              # End-to-end tests
├── test_providers.py        # Provider tests
├── test_planner.py          # Planner tests
├── test_executor.py         # Executor tests
├── test_credential_store.py # Credential vault tests
├── test_permission_gate.py  # Permission gate tests
├── test_knowledge_graph.py  # Knowledge graph tests
├── test_audit_log.py        # Audit trail tests
├── test_parsers/
│   ├── test_nmap_parser.py
│   ├── test_nuclei_parser.py
│   └── ... (100+ parser tests)
├── test_security/
│   ├── test_compliance.py
│   ├── test_threat_intel.py
│   └── test_deception.py
├── test_engine/
│   ├── test_recovery.py
│   ├── test_safety.py
│   └── test_steps.py
├── test_xi/
│   ├── test_context_tracker.py
│   └── test_skill_profiler.py
├── test_chat/
│   ├── test_engine.py
│   └── test_handlers.py
└── ... (additional test files per module)
```

## Writing Tests

### Async tests

```python
import pytest

@pytest.mark.asyncio
async def test_async_behavior():
    result = await some_async_function()
    assert result is not None
```

### Mocking providers

```python
@pytest.mark.asyncio
async def test_planner_with_mock_provider():
    planner = TaskPlanner()
    planner.providers = [MockProvider()]
    result = await planner.plan("scan test")
    assert result is not None
```

### Using fixtures

```python
@pytest.fixture
def temp_config(tmp_path):
    config_path = tmp_path / "settings.toml"
    config_path.write_text('[default]\nkey = "value"')
    os.environ["SIYARIX_CONFIG"] = str(config_path)
    yield config_path
    del os.environ["SIYARIX_CONFIG"]
```

## Coverage Targets

```bash
# Current coverage target: 75%+
pytest --cov=siyarix --cov-report=term-missing
```

Coverage is enforced in CI via `pyproject.toml` (`fail_under = 75`).

## Code Quality

```bash
# Linting with Ruff
ruff check src/ tests/
ruff check --fix src/ tests/   # Auto-fix

# Formatting with Ruff
ruff format src/ tests/

# Type checking with MyPy (strict mode)
mypy src/siyarix/

# Dead code detection with Vulture
vulture src/siyarix/

# Security scanning with Bandit
bandit -r src/siyarix/
```

## CI Testing Matrix

Tests run on every pull request and push to main via GitHub Actions (47 workflows):

| Dimension | Values |
|-----------|--------|
| **Python** | 3.11, 3.12, 3.13 |
| **OS** | ubuntu-latest, windows-latest, macos-latest |
| **Tests** | Unit + integration + E2E |
| **Lint** | Ruff + MyPy |
| **Security** | Bandit (SARIF), pip-audit (critical/high fail) |
| **Compatibility** | Build sdist/wheel, check-wheel-contents, twine check |

## Pre-commit Hooks

The repository includes pre-commit configuration:

```bash
pre-commit install
```

This runs Ruff, MyPy, and other checks automatically before each commit. Configuration is in `.pre-commit-config.yaml`.
