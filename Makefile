.PHONY: install install-dev test lint typecheck clean build docker-build docker-up docker-down help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -e .

install-dev: ## Install development dependencies
	pip install -e ".[all,cli,siem,autonomous]"
	pip install pytest pytest-asyncio pytest-cov ruff mypy pre-commit

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

security: ## Run security checks
	bandit -r src/siyarix/ -f json -o bandit-report.json || true

clean: ## Clean build artifacts and caches
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

build: ## Build distribution packages
	pip install build
	python -m build

docker-build: ## Build Docker image
	docker compose build

docker-up: ## Start all Docker services
	docker compose up -d

docker-down: ## Stop all Docker services
	docker compose down

docker-logs: ## View Docker logs
	docker compose logs -f

pre-commit: ## Run pre-commit hooks
	pre-commit run --all-files

coverage: ## Run tests with coverage report
	python -m pytest tests/ -v --tb=short --cov=src/siyarix --cov-report=term-missing --cov-fail-under=80

benchmark: ## Run performance benchmarks
	python -m pytest tests/ -v --tb=short -m "benchmark" --benchmark-only 2>/dev/null || echo "pytest-benchmark not installed; install with: pip install pytest-benchmark"
