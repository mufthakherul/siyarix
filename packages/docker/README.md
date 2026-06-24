# Siyarix — Docker Guide

## Available Images

| Build arg `BASE=` | Stage `--target` | Description                                  |
| ----------------- | ---------------- | -------------------------------------------- |
| `python` (default)| `python`         | Python 3.11-slim + common pentest tools      |
| `kali`            | `kali`           | Kali Linux rolling + `kali-linux-headless`   |
| `parrot`          | `parrot`         | ParrotOS core + `parrot-tools-full`          |

## Building

```bash
# Python base (default)
docker build -t siyarix:latest .

# Kali Linux base (full pentesting suite — 3-6 GB)
docker build --build-arg BASE=kali -t siyarix:kali .

# ParrotOS base
docker build --build-arg BASE=parrot -t siyarix:parrot .

# Build only a specific stage (faster -- skips unrelated stages)
docker build --target kali -t siyarix:kali .
```

### Build options

| Build arg           | Default    | Description                            |
|---------------------|------------|----------------------------------------|
| `PYTHON_VERSION`    | `3.11`     | Python version for the builder & python base |
| `SIYARIX_VERSION`   | `1.0.0`    | Version label in the image metadata    |
| `BASE`              | `python`   | Base image variant (python / kali / parrot) |

## Running

### Interactive TTY

```bash
docker run --rm -it siyarix:latest
```

### Single command

```bash
docker run --rm siyarix:latest siyarix scan --target example.com
```

### With config volume (persistent)

```bash
docker run --rm -it \
  -v siyarix_config:/home/siyarix/.siyarix \
  -v "$(pwd)/output:/home/siyarix/output" \
  siyarix:latest
```

### Kali variant

```bash
docker run --rm -it siyarix:kali
docker run --rm siyarix:kali nmap -sV target.com
```

### With Redis caching

```bash
docker network create siyarix_net
docker run -d --network siyarix_net --name siyarix-redis redis:7-alpine
docker run --rm -it \
  --network siyarix_net \
  -e REDIS_URL=redis://siyarix-redis:6379 \
  siyarix:latest
```

## Docker Compose

```bash
# Start the Python-based service
docker compose up -d siyarix

# Start the Kali-based service
docker compose --profile kali up -d siyarix-kali

# Start everything including OpenTelemetry
docker compose --profile telemetry up -d

# Attach to the running container
docker attach siyarix

# Run a one-off command
docker compose exec siyarix siyarix scan --target example.com
```

### Environment variables

| Variable                     | Default          | Description                            |
|------------------------------|------------------|----------------------------------------|
| `SIYARIX_LOG_LEVEL`          | `INFO`           | Log level                              |
| `SIYARIX_PERSONA`            | `bug_hunter`     | Agent persona                          |
| `SIYARIX_PROVIDER`           | `noop`           | AI provider (`noop`, `openai`, `gemini`, `anthropic`) |
| `SIYARIX_NO_TELEMETRY`       | `1`              | Disable telemetry                      |
| `SIYARIX_TAG`                | `latest`         | Image tag for the Python variant       |
| `SIYARIX_TAG_KALI`           | `kali`           | Image tag for the Kali variant         |
| `SIYARIX_API_PORT`           | `8000`           | Host port for the Python API           |
| `SIYARIX_KALI_API_PORT`      | `8001`           | Host port for the Kali API             |
| `SIYARIX_CUSTOM_DIR`         | `./custom`       | Custom scripts / tools directory       |
| `REDIS_URL`                  | *(empty)*        | Redis connection string                |
| `REDIS_PORT`                 | `6379`           | Redis host port                        |
| `OTEL_EXPORTER_OTLP_ENDPOINT`| *(empty)*        | OpenTelemetry endpoint                 |
| `OTEL_PORT`                  | `4318`           | OpenTelemetry collector port           |

## Tools included

### Python base (`python`)

**Network scanners** — nmap, masscan, netcat, dnsutils, whois

**Web tools** — nikto, hydra, whatweb, wafw00f, gobuster, ffuf, wfuzz, sqlmap

**Subdomain / recon** — sublist3r, theHarvester, amass, subfinder, httpx

**Vulnerability scanning** — nuclei, nikto, sslscan, testssl.sh

**Secret / code scanning** — trufflehog, gitleaks, semgrep, bandit

**Exploit tools** — searchsploit (exploitdb), hydra, john, hashcat

### Kali base (`kali`)

Everything above plus **all tools from `kali-linux-headless`** including Metasploit, Burp Suite (community), wireshark, aircrack-ng, and 600+ other security tools.

### ParrotOS base (`parrot`)

Everything above plus **all tools from `parrot-tools-full`**.

## Volumes

| Volume name              | Mount point                        | Purpose                  |
|--------------------------|------------------------------------|--------------------------|
| `siyarix_config`         | `/home/siyarix/.siyarix`           | Configuration & state    |
| `siyarix_kali_config`    | `/home/siyarix/.siyarix`           | Kali variant config      |
| `siyarix_output`         | `/home/siyarix/output`             | Scan outputs             |
| `siyarix_redis_data`     | `/data`                            | Redis persistence        |

## Tips

- The Kali image is **large** (3–6 GB). Use the Python base for quick tasks.
- Use `--target` to avoid building unrelated stages: `docker build --target python -t siyarix:latest .`
- Mount a custom directory to `/home/siyarix/custom` for your own scripts.
- For production, mount a volume for `/home/siyarix/.siyarix` to persist config and session data.
- Set `SIYARIX_PROVIDER=openai` and `OPENAI_API_KEY=sk-...` to enable the AI agent.
