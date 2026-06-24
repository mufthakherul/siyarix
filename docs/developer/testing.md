# 🧪 Testing

Reliability is paramount for an automated security orchestration platform. Siyarix maintains a highly comprehensive test suite using **pytest** (with `asyncio_mode=auto`), demanding **75%+ code coverage** across all modules with strict branch coverage enabled.

## 🏗️ Framework & Tooling

Our testing strategy relies on top-tier Python tooling:
- **pytest** combined with `pytest-asyncio` ensures seamless async test support.
- **pytest-cov** generates detailed coverage reports (with `branch=true`).
- **Custom Markers:** We use markers like `bootstrap`, `cvss`, `report`, `stealth`, `e2e`, and more to logically group test runs.
- **conftest.py** provides a rich ecosystem of shared mock fixtures.
- **Enforcement:** Code coverage limits are strictly enforced via `pyproject.toml` (`fail_under = 75`).

## 🚀 Running Tests

Running tests locally is highly flexible:

```bash
# Run the entire suite
pytest

# Run tests and generate a coverage report
pytest --cov=siyarix

# Run a specific test file
pytest tests/test_planner.py

# Run tests matching a specific keyword
pytest -k "provider"

# Run tests in parallel to save time!
pytest -n auto

# Exclude End-to-End (e2e) tests to run only fast unit tests
pytest -m "not e2e"
```

> [!TIP]
> If you are actively debugging, use `pytest -x` to force the test runner to stop on the very first failure!

## 📁 Test Directory Structure

With over 110+ test files, our `tests/` directory mirrors the structure of `src/siyarix/`:

```text
tests/
├── conftest.py                        # Shared fixtures & mocks
├── test_core.py                       # Core agent logic tests
├── test_cli_main.py                   # CLI boundary tests
├── test_e2e.py                        # Full end-to-end integration tests
├── test_providers_manager.py          # Provider failover & tracking tests
├── test_planner_autonomous.py         # LLM prompt and planning tests
├── test_knowledge_graph.py            # Graph traversal tests
├── test_dlp.py                        # Secret masking tests
├── test_parsers/                      # 80+ dedicated tool parser tests!
│   ├── test_nmap_parser.py
│   ├── test_nuclei_parser.py
│   └── ... 
└── scripts/                           # Useful test helper scripts
```

## ✍️ Writing Tests

We encourage developers to write clean, deterministic tests.

### Async Tests
Because Siyarix is heavily async, your tests will be too:
```python
import pytest

@pytest.mark.asyncio
async def test_async_behavior():
    result = await some_async_function()
    assert result is not None
```

### Mocking Providers
Never hit real APIs in unit tests. Always use mock providers:
```python
@pytest.mark.asyncio
async def test_planner_with_mock_provider():
    planner = TaskPlanner()
    planner.providers = [MockProvider()] # Use our custom mock!
    
    result = await planner.plan("scan test")
    assert result is not None
```

### Using Fixtures
Fixtures are your best friend for setup/teardown logic:
```python
@pytest.fixture
def temp_config(tmp_path):
    config_path = tmp_path / "settings.toml"
    config_path.write_text('[default]\nkey = "value"')
    os.environ["SIYARIX_CONFIG"] = str(config_path)
    
    yield config_path
    
    del os.environ["SIYARIX_CONFIG"]
```

## 📊 Coverage Enforcement

To check coverage manually:
```bash
pytest --cov=siyarix --cov-report=term-missing
```

> [!WARNING]
> CI pipelines will automatically fail your Pull Request if code coverage drops below 75% or if branch coverage drops. Always run coverage checks locally before pushing!

## ✨ Code Quality & Linting

Beyond testing, we enforce strict code quality using a suite of tools:

```bash
ruff check src/ tests/               # Linting checks
ruff format src/ tests/              # Auto-formatter
mypy src/siyarix/                    # Strict static type checking
vulture src/siyarix/                 # Dead code detection
bandit -r src/siyarix/               # Static security scanning
```

## 🤖 CI Matrix & Pre-commit Hooks

Our GitHub Actions CI runs tests on every PR across a robust matrix:
- **Python Versions:** 3.11, 3.12, 3.13
- **Operating Systems:** Ubuntu, Windows, macOS
- **Security:** Automated SARIF generation via Bandit and `pip-audit`.

### Pre-commit Hooks
Save yourself time and catch errors locally by installing pre-commit hooks:

```bash
pre-commit install
```

Our hook suite will automatically run Ruff, MyPy, secret detection (preventing you from accidentally committing private keys or API tokens!), JSON/YAML validation, and typo checks every time you type `git commit`.
