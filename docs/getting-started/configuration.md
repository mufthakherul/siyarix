# Configuration Guide

Siyarix uses a layered configuration system: defaults, environment variables, settings file, and CLI flags.

## Configuration layers (lowest to highest priority)

1. **Code defaults** (`config.py` `DEFAULTS` dict)
2. **Settings file** (`~/.siyarix/settings.toml`)
3. **Environment variables** (prefixed with `SIYARIX_`)
4. **CLI flags** (per-command)

## Environment variables

| Variable | Config key | Description |
|----------|------------|-------------|
| `SIYARIX_CONFIG` | `_config_path` | Path to custom config file |
| `SIYARIX_HOME` | `_home_dir` | Override `~/.siyarix/` directory |
| `SIYARIX_DEBUG` | `log_level` | Enable debug logging (set to `debug`) |
| `SIYARIX_PROVIDER` | `model_provider` | AI provider override |
| `SIYARIX_TIMEOUT` | `scan_timeout` | Tool timeout in seconds |
| `SIYARIX_LOG_LEVEL` | `log_level` | Logging level |
| `SIYARIX_NO_TELEMETRY` | `_no_telemetry` | Disable telemetry |
| `SIYARIX_SAFE_MODE` | `_safe_mode` | Enable safe mode (no destructive actions) |

## AI provider model settings

Each supported provider has a configurable model name:

```toml
model_provider = "auto"
gemini_model = "gemini-1.5-pro"
openai_model = "gpt-4o"
anthropic_model = "claude-3-opus-20240229"
groq_model = "llama3-70b-8192"
together_model = "mistralai/Mixtral-8x7B-Instruct-v0.1"
ollama_url = "http://localhost:11434"
ollama_model = "llama3.1"
lmstudio_url = "http://localhost:1234"
```

## Local-only providers (no API key needed)

- **Ollama**: Run local models via `http://localhost:11434`
- **LM Studio**: Run local models via `http://localhost:1234`
- **Noop**: Built-in testing/offline provider (no external calls)

## Proxy configuration

```toml
proxy = "http://proxy.example.com:8080"
proxy_pool = "http://proxy1:8080,http://proxy2:8080"
```

The proxy pool rotates through the list for each connection.

## Client profile

Controls HTTP fingerprint:

```toml
client_profile = "desktop_chrome"
# Options: desktop_chrome, desktop_firefox, android_mobile, ios_safari
```

## Color themes

```toml
color_theme = "dark"
# Options: system, default, dark, light, minimal, neon
```

Preview themes:

```bash
siyarix themes
```

## Config commands

```bash
siyarix config list          # Show all settings
siyarix config get <key>     # Get a single value
siyarix config set <key> <value>  # Set a value
siyarix config reset          # Reset to defaults
siyarix config edit           # Open in $EDITOR
```

## Credential management

```bash
siyarix creds list                    # List stored credentials
siyarix creds set <provider> <key>    # Store a credential
siyarix creds get <provider> <key>    # Retrieve (masked)
siyarix creds delete <provider> <key> # Remove a credential
siyarix creds rotate                  # Rotate encryption key
```

## Next steps

- [Troubleshooting](troubleshooting.md)
- [CLI Commands](../user/cli-commands.md)
