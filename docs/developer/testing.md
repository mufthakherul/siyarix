# Testing

## Test framework

Siyarix uses **pytest** with **pytest-asyncio** for async test support.

## Running tests

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
```

## Test structure

Tests mirror the source structure:

```
tests/
├── test_main.py
├── test_chat.py
├── test_config.py
├── test_planner.py
├── test_providers.py
├── test_executor.py
├── test_permission_gate.py
├── test_knowledge_graph.py
├── test_credential_store.py
├── test_audit_log.py
├── test_parsers/
│   ├── test_nmap_parser.py
│   ├── test_nuclei_parser.py
│   └── ...
└── ...
```

## Writing tests

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

## Coverage targets

```bash
# Current coverage target: 75%+
pytest --cov=siyarix --cov-report=term-missing
```

## Linting

```bash
# Run Ruff linter
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/
```

## Type checking

```bash
mypy src/siyarix/
```

## Pre-commit hooks

The repository includes pre-commit configuration. Install with:

```bash
pre-commit install
```

This runs Ruff and mypy automatically before each commit.
