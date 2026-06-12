FROM python:3.11-slim AS base

WORKDIR /app

LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/mufthakherul/siyarix" \
      org.opencontainers.image.title="siyarix"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

FROM base AS builder

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
RUN pip install --user ".[all]"

FROM base AS production
# Create non-root user
RUN useradd -m siyarix

# Runtime deps for security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chown=siyarix:siyarix /root/.local /home/siyarix/.local
USER siyarix
ENV PATH=/home/siyarix/.local/bin:$PATH

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["siyarix", "--help"]

ENTRYPOINT ["siyarix"]
CMD ["--help"]

FROM base AS development
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
RUN pip install ".[all,dev]"
COPY tests/ tests/
COPY .pre-commit-config.yaml ./
ENTRYPOINT ["bash"]
