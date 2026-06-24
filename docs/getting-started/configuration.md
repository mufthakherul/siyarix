# Configuration Guide

Siyarix uses a layered configuration system with four tiers (lowest to highest priority): code defaults, settings file, environment variables, and CLI flags. This ensures flexibility across development, production, and CI environments.

## Configuration Layers

1. **Code defaults** — Defined in `config.py` `DEFAULTS` dict
2. **Settings file** — `~/.siyarix/settings.toml` (TOML format, human-editable)
3. **Environment variables** — Prefixed with `SIYARIX_` (see mapping below)
4. **CLI flags** — Per-command overrides

## Environment Variables

| Variable | Config key | Description |
|----------|------------|-------------|
| `SIYARIX_CONFIG` | `_config_path` | Path to custom config file |
| `SIYARIX_HOME` | `_home_dir` | Override `~/.siyarix/` directory |
| `SIYARIX_DEBUG` | `log_level` | Enable debug logging |
| `SIYARIX_PROVIDER` | `model_provider` | AI provider override |
| `SIYARIX_TIMEOUT` | `scan_timeout` | Tool timeout in seconds |
| `SIYARIX_LOG_LEVEL` | `log_level` | Logging level |
| `SIYARIX_NO_TELEMETRY` | `_no_telemetry` | Disable telemetry |
| `SIYARIX_SAFE_MODE` | `_safe_mode` | Restrict to reconnaissance only |
| `SIYARIX_PERSONA` | `persona` | Active persona override |
| `SIYARIX_STEALTH` | `stealth_mode` | Enable stealth mode |

## AI Provider Models

Each provider has a configurable model name in `settings.toml`:

```toml
model_provider = "auto"
openai_model = "gpt-4o"
gemini_model = "gemini-2.5-flash"
anthropic_model = "claude-sonnet-4-20250514"
deepseek_model = "deepseek-chat"
groq_model = "llama-3.3-70b-versatile"
together_model = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
openrouter_model = "openai/gpt-4o"
xai_model = "grok-2-1212"
mistral_model = "mistral-large-2407"
perplexity_model = "sonar-pro"
azure_model = "gpt-4o"
cerebras_model = "llama3.1-70b"
fireworks_model = "accounts/fireworks/models/llama-v3p1-70b-instruct"
zai_model = "glm-4"
minimax_model = "MiniMax-Text-01"
moonshot_model = "moonshot-v1-8k"
nvidia_model = "nvidia/llama-3.1-nv-70b"
opencode_zen_model = "deepseek-chat"
huggingface_model = ""
```

## Local-Only Providers

| Provider | Endpoint | Setup |
|----------|----------|-------|
| Ollama | `http://localhost:11434` | `ollama pull llama3.1 && ollama serve` |
| LM Studio | `http://localhost:1234` | Enable API server in settings |
| llama.cpp | `http://localhost:18080` | `llama-server --model model.gguf --port 18080` |
| vLLM | `http://localhost:8000` | `vllm serve model` |
| LocalAI | `http://localhost:8080` | `local-ai run` |
| Registry | Built-in | Heuristic planner, no external calls |

## Proxy Configuration

```toml
# Single proxy
proxy = "http://proxy.example.com:8080"

# Proxy pool for rotation
proxy_pool = "http://proxy1:8080,http://proxy2:8080"
```

The proxy pool rotates through the list for each connection.

## Client Profile

Controls HTTP fingerprint for web requests:

```toml
client_profile = "desktop_chrome"
# Options: desktop_chrome, desktop_firefox, android_mobile, ios_safari
```

## Color Themes

```toml
color_theme = "dark"
```

Preview themes: `siyarix themes`

Available themes: `cyber_noir`, `matrix`, `bloodmoon`, `arctic`, `goldenrod`, `eclipse`, `synthwave`, `dark`, `light`, `neon`, `minimal`, `default`

## Config Commands

```bash
siyarix config list           # Show all settings
siyarix config get <key>      # Get a single value
siyarix config set <key> <value>  # Set a value
siyarix config reset           # Reset to defaults
siyarix config edit            # Open in $EDITOR
```

## Credential Management

```bash
siyarix auth set-key <provider>    # Store API key (hidden input)
siyarix auth show                  # List configured providers
siyarix creds list                 # List stored credentials
siyarix creds set <provider> <key> # Store a credential
siyarix creds get <provider>       # Retrieve (masked)
siyarix creds delete <provider>    # Remove
siyarix creds rotate               # Rotate encryption key
```

## Full .env Template

See `.env.example` in the repository root for a complete template covering:

- General settings (home, config path, debug, log level, mode, persona, provider, timeout, safe mode, telemetry, stealth)
- AI provider API keys (OpenAI, Anthropic, Gemini, Groq, Mistral, DeepSeek, Together, OpenRouter, Perplexity, Azure)
- Redis configuration
- Threat intelligence (STIX/TAXII, MISP)
- SIEM forwarding (Splunk, Elastic)
- OpenTelemetry
- Dashboard
- Remote orchestrator
- Notifications (Slack, Discord, Teams, email/SMTP)

## Next Steps

- [Troubleshooting](troubleshooting.md)
- [CLI Commands](../user/cli-commands.md)
