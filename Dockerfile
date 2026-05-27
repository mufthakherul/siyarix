FROM python:3.11-slim AS base

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install siyarix
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install -e ".[all,cli,siem]"

# Runtime deps for security tools (optional, for full functionality)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS production
COPY --from=base /app /app
ENTRYPOINT ["siyarix"]
CMD ["--help"]

FROM base AS development
RUN pip install pytest pytest-asyncio pytest-cov ruff mypy
COPY tests/ tests/
COPY .pre-commit-config.yaml ./
ENTRYPOINT ["bash"]
