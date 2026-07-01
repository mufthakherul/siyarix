# 🧪 Testing

Siyarix aims to be a reliable tool, so I've written a solid test suite using **pytest** (with `asyncio_mode=auto`). Testing is crucial as the project grows!

## 🏗️ Framework & Tooling

- **pytest** and `pytest-asyncio` for async tests.
- **pytest-cov** for coverage tracking.
- Custom pytest markers (like `e2e`, `stealth`) to group test runs.
- `conftest.py` for shared fixtures.

## 🚀 Running Tests

Running tests locally is easy:

```bash
# Run the entire suite
pytest

# Run tests and generate a coverage report
pytest --cov=siyarix

# Run a specific test file
pytest tests/test_planner.py

# Exclude End-to-End (e2e) tests for a quicker run
pytest -m "not e2e"
```

!!! tip
    Use `pytest -x` to stop the test runner on the first failure.

## 📁 Test Directory Structure

The `tests/` directory generally mirrors `src/siyarix/`:

```text
tests/
├── conftest.py                        # Shared fixtures & mocks
├── test_core.py                       # Core logic tests
├── test_cli_main.py                   # CLI tests
├── test_e2e.py                        # Basic end-to-end tests
├── test_providers_manager.py          # Provider tests
├── test_parsers/                      # Parser tests
└── ...
```

## ✍️ Writing Tests

### Async Tests
Because Siyarix is mostly async, tests usually are too:
```python
import pytest

@pytest.mark.asyncio
async def test_async_behavior():
    result = await some_async_function()
    assert result is not None
```

### Mocking Providers
Please use mock providers instead of hitting real APIs in unit tests:
```python
@pytest.mark.asyncio
async def test_planner_with_mock_provider():
    planner = TaskPlanner()
    planner.providers = [MockProvider()]

    result = await planner.plan("scan test")
    assert result is not None
```

## 📊 Coverage

To check coverage manually:
```bash
pytest --cov=siyarix --cov-report=term-missing
```

!!! warning
    The CI pipeline will check test coverage. It's best to run it locally before pushing a PR!

## ✨ Code Quality & Linting

I use a few tools to keep the code clean:

```bash
ruff check src/ tests/               # Linting checks
ruff format src/ tests/              # Auto-formatter
mypy src/siyarix/                    # Static type checking
```

## 🤖 CI and Pre-commit

GitHub Actions automatically runs tests on Pull Requests across Python 3.11+.

### Pre-commit Hooks
You can install pre-commit hooks to automatically check your code locally before committing:

```bash
pre-commit install
```
This runs Ruff, MyPy, and basic checks every time you type `git commit`.
