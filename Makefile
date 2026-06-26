.PHONY: help install install-dev build build-python build-deb build-all clean clean-dist docs pre-commit test test-quick test-e2e lint lint-fix format format-check typecheck security security-scan coverage benchmark build-docker docker-build docker-up docker-down docker-logs docker-scan docker-build-production build-installers install-sh install-ps1 build-apt-repo publish-pypi publish-testpypi vulture check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# === Python ===

install: ## Install production dependencies
	pip install -e .

install-dev: ## Install development dependencies
	pip install -e ".[all,cli,siem,api,autonomous,dev]"

build: ## Build Python distribution packages (sdist + wheel)
	pip install build
	python -m build

build-python: build ## Alias for build

# === Tests & Lint ===

test: ## Run all tests
	python -m pytest tests/ -v --tb=short --cov=src/siyarix --cov-report=term --cov-report=html

test-quick: ## Run quick tests (exclude slow, exclude integration)
	python -m pytest tests/ -v --tb=short -m "not slow and not integration" -x

test-e2e: ## Run end-to-end integration tests
	python -m pytest tests/ -v --tb=short -m "e2e or integration"

lint: ## Run ruff linter
	ruff check src/siyarix/ tests/

lint-fix: ## Run ruff linter with auto-fix
	ruff check --fix src/siyarix/ tests/

format: ## Run ruff formatter
	ruff format src/siyarix/ tests/

format-check: ## Check ruff formatting without modifying
	ruff format --check src/siyarix/ tests/

typecheck: ## Run mypy type checker
	mypy src/siyarix/

security: ## Run security checks (Bandit + pip-audit)
	@echo "--- Bandit ---"
	-bandit -r src/siyarix/ -f json -o bandit-report.json
	@echo "--- pip-audit ---"
	-pip-audit --format json --output pip-audit.json

coverage: ## Run tests with coverage report
	python -m pytest tests/ -v --tb=short --cov=siyarix --cov-report=term-missing --cov-fail-under=50

benchmark: ## Run performance benchmarks
	python -m pytest tests/ -v --tb=short -m "benchmark" --benchmark-only 2>/dev/null || echo "pytest-benchmark not installed; install with: pip install pytest-benchmark"

vulture: ## Run dead code detection
	vulture src/siyarix/ .vulture_whitelist.py

check: lint format-check typecheck test-quick ## Run all quick quality checks

# === Clean ===

clean: ## Clean all build artifacts, caches, and temporary files
	rm -rf build/ dist/ *.egg-info/ *.deb *.rpm
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage htmlcov/ coverage.xml
	rm -rf bandit-*.json safety-report.json pip-audit.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	rm -rf .tox/ .nox/

clean-dist: clean ## Clean all artifacts including site docs and node_modules
	rm -rf site/ node_modules/ .next/
	rm -rf *.egg-info/ dist/ build/

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

install-sh: ## Test install.sh locally (dry-run)
	@echo "Running install.sh (pass any flag to actually install)..."
	bash install.sh

install-ps1: ## Test install.ps1 locally (dry-run)
	@echo "To run on Windows: irm https://siyarix.github.io/install.ps1 | iex"
	pwsh -NoProfile -File install.ps1 2>/dev/null || echo "PowerShell not available on this platform"

# === All Builds ===

build-all: clean build build-deb build-installers ## Build all package formats

# === Docker ===

docker-build: ## Build Docker development image
	docker compose build

docker-build-production: ## Build Docker production image directly
	docker build --target production -t siyarix:latest .

docker-up: ## Start all Docker services
	docker compose up -d

docker-down: ## Stop all Docker services
	docker compose down

docker-logs: ## View Docker logs
	docker compose logs -f

docker-scan: ## Scan Docker image for vulnerabilities
	trivy image siyarix:latest 2>/dev/null || grype siyarix:latest 2>/dev/null || echo "No container scanner found (install trivy or grype)"

# === Docs ===

docs: ## Build documentation site with mkdocs
	mkdocs build --strict

docs-serve: ## Serve documentation locally
	mkdocs serve

# === Security Scan ===

security-scan: ## Run comprehensive security scan (trivy + semgrep + bandit)
	@echo "=== Bandit ==="
	-bandit -r src/siyarix/ -f json -o bandit-report.json
	@echo "=== Safety ==="
	-safety check --full-report 2>/dev/null || echo "Safety not installed"
	@echo "=== pip-audit ==="
	-pip-audit --format json --output pip-audit.json 2>/dev/null || echo "pip-audit not available"
	@echo "=== Semgrep ==="
	-semgrep --config=auto src/siyarix/ 2>/dev/null || echo "Semgrep not installed"
	@echo "=== Dependency Check ==="
	-pip list --outdated 2>/dev/null | head -20

# === Git ===

pre-commit: ## Run pre-commit hooks on all files
	pre-commit run --all-files

# === PyPI Publish ===

publish-pypi: ## Publish to PyPI (requires twine credentials)
	twine upload dist/*

publish-testpypi: ## Publish to TestPyPI
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
