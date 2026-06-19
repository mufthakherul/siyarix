.PHONY: install install-dev test lint typecheck clean build build-all build-python build-deb build-docker build-installers docker-build docker-up docker-down help install-sh install-ps1

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# === Python ===

install: ## Install production dependencies
	pip install -e .

install-dev: ## Install development dependencies
	pip install -e ".[all,cli,siem,autonomous]"
	pip install pytest pytest-asyncio pytest-cov ruff mypy pre-commit

build: ## Build Python distribution packages (sdist + wheel)
	pip install build
	python -m build

build-python: build ## Alias for build

# === Tests & Lint ===

test: ## Run all tests
	python -m pytest tests/ -v --tb=short --cov=src/siyarix --cov-report=term --cov-report=html

test-quick: ## Run quick tests (exclude slow)
	python -m pytest tests/ -v --tb=short -m "not slow" -x

lint: ## Run ruff linter
	ruff check src/siyarix/ tests/

lint-fix: ## Run ruff linter with auto-fix
	ruff check --fix src/siyarix/ tests/

typecheck: ## Run mypy type checker
	mypy src/siyarix/

format: ## Run ruff formatter
	ruff format src/siyarix/ tests/

security: ## Run security checks (Bandit + TruffleHog + GitLeaks + pip-audit)
	bandit -r src/siyarix/ -f json -o bandit-report.json || true
	@echo "--- TruffleHog ---"; trufflehog filesystem . --no-verification --max-depth 5 2>/dev/null || echo "trufflehog not installed (CI uses it separately)"
	@echo "--- GitLeaks ---"; gitleaks detect --no-git -v 2>/dev/null || echo "gitleaks not installed (CI uses it separately)"
	@echo "--- pip-audit ---"; pip-audit 2>/dev/null || echo "pip-audit not installed (CI uses it separately)"

coverage: ## Run tests with coverage report
	python -m pytest tests/ -v --tb=short --cov=siyarix --cov-report=term-missing --cov-fail-under=50

benchmark: ## Run performance benchmarks
	python -m pytest tests/ -v --tb=short -m "benchmark" --benchmark-only 2>/dev/null || echo "pytest-benchmark not installed; install with: pip install pytest-benchmark"

# === Clean ===

clean: ## Clean build artifacts and caches
	rm -rf build/ dist/ *.egg-info/ *.deb
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

# === DEB Package ===

build-deb: ## Build Debian/Ubuntu/Kali .deb package
	@echo "Building .deb package..."
	bash packages/deb/build-deb.sh

build-apt-repo: ## Build APT repository structure
	@echo "Building APT repository..."
	bash packages/deb/build-apt-repo.sh

# === Installers ===

build-installers: ## Validate install.sh and install.ps1
	@echo "Validating installers..."
	bash -n install.sh
	@if command -v pwsh &>/dev/null; then pwsh -NoProfile -Command "Get-Content install.ps1" > /dev/null; fi
	bash -n packages/harmonyos/install-harmonyos.sh

install-sh: ## Test install.sh locally (dry-run)
	@echo "Running install.sh (pass any flag to actually install)..."
	bash install.sh

install-ps1: ## Test install.ps1 locally (dry-run)
	@echo "To run on Windows: irm https://siyarix.dev/install.ps1 | iex"
	pwsh -NoProfile -File install.ps1 2>/dev/null || echo "PowerShell not available on this platform"

# === All Builds ===

build-all: clean build build-deb build-installers ## Build all package formats

# === Docker ===

docker-build: ## Build Docker image
	docker compose build

docker-up: ## Start all Docker services
	docker compose up -d

docker-down: ## Stop all Docker services
	docker compose down

docker-logs: ## View Docker logs
	docker compose logs -f

# === Git ===

pre-commit: ## Run pre-commit hooks
	pre-commit run --all-files

# === PyPI Publish ===

publish-pypi: ## Publish to PyPI (requires twine credentials)
	twine upload dist/*

publish-testpypi: ## Publish to TestPyPI
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
