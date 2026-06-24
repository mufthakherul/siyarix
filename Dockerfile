# SPDX-License-Identifier: AGPL-3.0-or-later
# =============================================================================
# Siyarix - Multi-stage Dockerfile
# =============================================================================
# Build with:
#   docker build --build-arg BASE=python -t siyarix:latest .   (default)
#   docker build --build-arg BASE=kali   -t siyarix:kali   .
#   docker build --build-arg BASE=parrot -t siyarix:parrot .
# =============================================================================
ARG PYTHON_VERSION=3.11
ARG SIYARIX_VERSION=1.0.0
ARG BASE=python

# =============================================================================
# Stage 1 -- Builder: Build the siyarix wheel
# =============================================================================
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel && \
    ls -la dist/

# =============================================================================
# Stage 2 -- Python base (default, lightweight pentest tools)
# =============================================================================
FROM python:${PYTHON_VERSION}-slim AS python

LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/mufthakherul/siyarix" \
      org.opencontainers.image.title="siyarix" \
      org.opencontainers.image.description="AI Cybersecurity Orchestration Agent (Python base)" \
      org.opencontainers.image.version="${SIYARIX_VERSION}" \
      org.opencontainers.image.vendor="MD MUFTHAKHERUL ISLAM MIRAZ"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SIYARIX_VERSION=${SIYARIX_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /app

# Install system packages and common pentest tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    unzip \
    xz-utils \
    nmap \
    netcat-openbsd \
    dnsutils \
    whois \
    masscan \
    nikto \
    hydra \
    john \
    hashcat \
    sslscan \
    whatweb \
    wafw00f \
    theharvester \
    sublist3r \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Download and install Go-based security tools
RUN set -eux; \
    mkdir -p /tmp/gobin; \
    cd /tmp/gobin; \
    \
    curl -sL "https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz" -o gobuster.tar.gz; \
    tar -xzf gobuster.tar.gz gobuster; \
    \
    FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r '.tag_name' | sed 's/^v//'); \
    curl -sL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" -o ffuf.tar.gz; \
    tar -xzf ffuf.tar.gz ffuf; \
    \
    HTTPX_URL=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url'); \
    curl -sL "$HTTPX_URL" -o httpx.zip; \
    unzip -o httpx.zip -d httpx_extract; \
    \
    SUBF_URL=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url'); \
    curl -sL "$SUBF_URL" -o subfinder.zip; \
    unzip -o subfinder.zip -d subfinder_extract; \
    \
    NUC_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url'); \
    curl -sL "$NUC_URL" -o nuclei.zip; \
    unzip -o nuclei.zip -d nuclei_extract; \
    \
    AMASS_URL=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url'); \
    curl -sL "$AMASS_URL" -o amass.zip; \
    unzip -o amass.zip -d amass_extract; \
    \
    TH_URL=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64.tar.gz")) | .browser_download_url'); \
    curl -sL "$TH_URL" -o trufflehog.tar.gz; \
    tar -xzf trufflehog.tar.gz trufflehog; \
    \
    GL_URL=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64.tar.gz")) | .browser_download_url'); \
    curl -sL "$GL_URL" -o gitleaks.tar.gz; \
    tar -xzf gitleaks.tar.gz gitleaks; \
    \
    mv gobuster /usr/local/bin/; \
    mv ffuf /usr/local/bin/; \
    mv httpx_extract/httpx /usr/local/bin/ 2>/dev/null || true; \
    mv subfinder_extract/subfinder /usr/local/bin/ 2>/dev/null || true; \
    mv nuclei_extract/nuclei /usr/local/bin/ 2>/dev/null || true; \
    mv amass_extract/amass_*/amass /usr/local/bin/ 2>/dev/null || true; \
    mv trufflehog /usr/local/bin/; \
    mv gitleaks /usr/local/bin/; \
    chmod +x /usr/local/bin/*; \
    \
    rm -rf /tmp/gobin

# Install Python-based security tools
RUN pip install --no-cache-dir \
    sqlmap \
    nbtscan \
    wfuzz \
    semgrep \
    bandit

# Clone exploit databases
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# Install siyarix wheel and create non-root user
COPY --from=builder /build/dist/*.whl /tmp/

RUN groupadd -r siyarix && \
    useradd -m -r -g siyarix siyarix && \
    mkdir -p /home/siyarix/.siyarix && \
    WHL=$(ls /tmp/*.whl) && \
    pip install --no-cache-dir "${WHL}[all]" && \
    chown -R siyarix:siyarix /home/siyarix && \
    rm -f /tmp/*.whl

COPY scripts/docker_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown siyarix:siyarix /entrypoint.sh

USER siyarix

ENV PATH=/home/siyarix/.local/bin:$PATH \
    SIYARIX_HOME=/home/siyarix/.siyarix \
    SIYARIX_NO_TELEMETRY=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["siyarix", "--help"]

ENTRYPOINT ["/entrypoint.sh"]
CMD []

# =============================================================================
# Stage 3 -- Kali Linux base (full pentesting suite)
# =============================================================================
FROM kalilinux/kali-rolling AS kali

LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/mufthakherul/siyarix" \
      org.opencontainers.image.title="siyarix" \
      org.opencontainers.image.description="AI Cybersecurity Orchestration Agent (Kali Linux base)" \
      org.opencontainers.image.version="${SIYARIX_VERSION}" \
      org.opencontainers.image.vendor="MD MUFTHAKHERUL ISLAM MIRAZ"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SIYARIX_VERSION=${SIYARIX_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /app

RUN apt-get update && apt-get install -y \
    kali-linux-headless \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dist/*.whl /tmp/
RUN WHL=$(ls /tmp/*.whl) && \
    pip install --no-cache-dir "${WHL}[all]" && \
    rm -f /tmp/*.whl

RUN groupadd -r siyarix && \
    useradd -m -r -g siyarix siyarix && \
    mkdir -p /home/siyarix/.siyarix && \
    chown -R siyarix:siyarix /home/siyarix

COPY scripts/docker_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER siyarix

ENV PATH=/home/siyarix/.local/bin:$PATH \
    SIYARIX_HOME=/home/siyarix/.siyarix \
    SIYARIX_NO_TELEMETRY=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["siyarix", "--help"]

ENTRYPOINT ["/entrypoint.sh"]
CMD []

# =============================================================================
# Stage 4 -- ParrotOS base (security tools)
# =============================================================================
FROM parrotsec/parrot-core AS parrot

LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/mufthakherul/siyarix" \
      org.opencontainers.image.title="siyarix" \
      org.opencontainers.image.description="AI Cybersecurity Orchestration Agent (ParrotOS base)" \
      org.opencontainers.image.version="${SIYARIX_VERSION}" \
      org.opencontainers.image.vendor="MD MUFTHAKHERUL ISLAM MIRAZ"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SIYARIX_VERSION=${SIYARIX_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /app

RUN apt-get update && apt-get install -y \
    parrot-tools-full \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dist/*.whl /tmp/
RUN WHL=$(ls /tmp/*.whl) && \
    pip install --no-cache-dir "${WHL}[all]" && \
    rm -f /tmp/*.whl

RUN groupadd -r siyarix && \
    useradd -m -r -g siyarix siyarix && \
    mkdir -p /home/siyarix/.siyarix && \
    chown -R siyarix:siyarix /home/siyarix

COPY scripts/docker_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER siyarix

ENV PATH=/home/siyarix/.local/bin:$PATH \
    SIYARIX_HOME=/home/siyarix/.siyarix \
    SIYARIX_NO_TELEMETRY=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["siyarix", "--help"]

ENTRYPOINT ["/entrypoint.sh"]
CMD []

# =============================================================================
# Final stage -- selected by the BASE build argument
# =============================================================================
FROM ${BASE}
