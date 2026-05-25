# Installation Guide

---

## 📋 Prerequisites

- **Python 3.11+** (required for modern features)
- **pip** or **uv** (recommended for speed)
- **Git** (for source installation)

---

## 📦 Installation Methods

### Method 1: PyPI (Stable)
```bash
pip install siyarix
```

### Method 2: Full Installation (Recommended)
```bash
pip install "siyarix[all,cli,siem]"
```
Includes: AI planners (OpenAI, Gemini), CLI tools (prompt_toolkit, jinja2), SIEM connectors (httpx)

### Method 3: Source (Development)
```bash
git clone https://github.com/mufthakherul/siyarix.git
cd siyarix
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .\.venv\Scripts\activate.ps1  # Windows
pip install -e ".[all,cli,siem]"
```

### Method 4: Docker
```bash
docker compose up -d
```
Runs siyarix, worker, dashboard, redis, and OpenTelemetry collector.

---

## 🔧 Configuration

### First-Run Bootstrap
When you run `siyarix` for the first time, the bootstrap engine:
1. Detects your platform (OS, shell, terminal, WSL)
2. Verifies Python ≥3.11
3. Checks runtime dependencies
4. Creates `~/.siyarix/` directory structure
5. Writes initialization marker

### Directory Structure
```
~/.siyarix/
├── config.yaml           # Main configuration
├── personas/             # Custom personae
│   └── custom/
├── plugins/              # Plugin store
├── memory/               # Learning data (SQLite)
├── logs/                 # Session logs + audit
├── vault/                # Encrypted credentials
├── cache/                # Tool output, AI plans, DNS
├── templates/            # Reports, playbooks
├── masking/              # Custom masking rules
├── canary/               # Canary token storage
└── playbooks/            # Saved playbooks
```

### API Key Configuration
```bash
# Interactive (secure — keys never touch shell history)
siyarix
/key set gemini <your-api-key>
/key set openai <your-api-key>

# Environment variables (for CI/automation)
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=...
```

---

## 🐳 Docker Setup

### Quick Start
```bash
docker compose up -d
```

### Multi-Service Architecture
| Service | Description | Scale |
|---------|-------------|-------|
| `siyarix` | Main application | 1 |
| `siyarix-worker` | Task execution | 3+ |
| `siyarix-dashboard` | Web UI | 1 |
| `redis` | Task queue | 1 |
| `otel-collector` | Telemetry | 0+ |

### Custom Configuration
```bash
# Override environment variables
SIYARIX_LOG_LEVEL=DEBUG docker compose up -d

# Enable telemetry
docker compose --profile telemetry up -d
```

---

## 🔨 Makefile Targets

| Target | Description |
|--------|-------------|
| `make install` | Install production dependencies |
| `make install-dev` | Install dev + all extras |
| `make test` | Run full test suite |
| `make test-quick` | Run fast tests (skip slow) |
| `make lint` | Ruff linter check |
| `make lint-fix` | Auto-fix lint issues |
| `make typecheck` | Mypy strict type check |
| `make format` | Ruff formatter |
| `make security` | Bandit security scan |
| `make clean` | Remove build artifacts |
| `make build` | Build distribution packages |
| `make docker-build` | Build Docker images |
| `make docker-up` | Start Docker services |
| `make coverage` | Tests with coverage report (≥80%) |
| `make benchmark` | Performance benchmarks |

---

## 🔄 CI/CD Pipeline

Siyarix includes 14 GitHub Actions workflows:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR | Ruff, mypy, pytest, coverage ≥80% |
| `coverage.yml` | Push | Coverage on 3.11 + 3.12 |
| `publish.yml` | `v*` tag | PyPI release |
| `security.yml` | Push | Dependency security scan |
| `pre-commit.yml` | PR | Pre-commit hook validation |
| `stale.yml` | Daily | Stale issue/PR management |
| `release.yml` | Release | Release automation |
| `dependency-review.yml` | PR | Dependency review |
| `auto-merge.yml` | PR | Auto-merge approved PRs |

---

## ✅ Verification

```bash
# Verify installation
siyarix --version

# Run health checks
siyarix health

# Run test suite
pytest -v

# Full verification
make test && make lint && make typecheck && make security
```
