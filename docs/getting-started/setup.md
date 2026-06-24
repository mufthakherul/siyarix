# Setup & Configuration

After installing Siyarix, configure your AI provider credentials and workspace preferences. The process is designed to be straightforward and secure.

## First-Run Wizard

The easiest way to configure Siyarix is to launch it — the interactive wizard runs automatically on first launch:

```bash
siyarix
```

Re-run the wizard at any time:

```bash
siyarix init
siyarix init --force
```

## API Keys

Set at least one AI provider API key as an environment variable:

```bash
export OPENAI_API_KEY="sk-..."           # OpenAI
export GEMINI_API_KEY="..."              # Google Gemini
export ANTHROPIC_API_KEY="sk-ant-..."    # Anthropic Claude
export GROQ_API_KEY="gsk_..."            # Groq
export TOGETHER_API_KEY="..."            # Together AI
export DEEPSEEK_API_KEY="sk-..."         # DeepSeek
export MISTRAL_API_KEY="..."             # Mistral AI
export PERPLEXITY_API_KEY="..."          # Perplexity
export OPENROUTER_API_KEY="..."          # OpenRouter
export XAI_API_KEY="..."                 # xAI (Grok)
export AZURE_OPENAI_KEY="..."            # Azure OpenAI
```

### .env File

Place a `.env` file in the current directory or `~/.siyarix/.env`:

```env
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
ANTHROPIC_API_KEY=sk-ant-...
```

Siyarix loads it automatically on startup. See `.env.example` in the repository root for a complete template with all supported variables.

## Credential Vault

For encrypted storage of API keys and secrets using AES-256-GCM with OS keyring integration:

```bash
siyarix auth set-key openai          # Prompts for key (input hidden)
siyarix auth show                    # List configured providers
siyarix creds list                   # List stored credentials
siyarix creds set <provider> <key>   # Store a credential
siyarix creds rotate                 # Rotate encryption key
```

The `CredentialStore` uses **AES-256-GCM** encryption (with Fernet/AES-128-CBC fallback) via the `cryptography` library:

- **Key storage**: OS system keyring via `keyring` library (preferred), with encrypted file fallback in `~/.siyarix/.cred_store_key`
- **Key derivation**: PBKDF2 with SHA-256 and 600,000 iterations (OWASP recommended)
- **KMS support**: Optional AWS KMS envelope encryption for enterprise deployments (`SIYARIX_KMS_PROVIDER=aws`)
- **Rate limiting**: Token-bucket rate limiter (10 req/s) to prevent brute force
- **Auto-clear**: Credentials cleared from memory on session end
- **Migration**: Automatic migration from legacy config files to the encrypted credential store
- **Security**: Keys never written to source code, config files, logs, or debug output

## Settings Management

Settings are persisted in `~/.siyarix/settings.toml` (TOML format). Manage via CLI:

```bash
siyarix config list                  # View all settings
siyarix config get model_provider    # Get single value
siyarix config set model_provider gemini  # Set value
siyarix config edit                  # Open in $EDITOR
siyarix config reset                 # Restore defaults
```

## Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `model_provider` | `auto` | AI provider: `auto`, `openai`, `gemini`, `anthropic`, `ollama`, etc. |
| `default_output_format` | `table` | Output style: `table`, `json`, `yaml`, `csv`, `html`, `xml`, `raw`, `quiet` |
| `default_parallel` | `3` | Max tools to run in parallel during --all scans |
| `scan_timeout` | `300` | Seconds before a running tool is killed |
| `log_level` | `warning` | Logging verbosity: `debug`, `info`, `warning`, `error` |
| `color_theme` | `default` | Theme: `cyber_noir`, `matrix`, `bloodmoon`, `arctic`, `goldenrod`, `eclipse`, `synthwave`, `dark`, `light`, `neon`, `minimal`, `default` |
| `stealth_mode` | `false` | Enable OPSEC features (TOR, jitter, proxy rotation) |
| `persona` | `auto` | AI mindset: `auto`, `redteam`, `blueteam`, `dfir`, `appsec`, `network`, `malware`, `osint`, `compliance`, `cloud`, `ics`, `universal` |
| `max_waves` | `25` | Max plan-execute-measure cycles per goal |
| `agent_timeout` | `1740` | Max seconds for agent execution (29 min) |
| `auto_save_session` | `false` | Auto-save session logs on exit (no footprint by default) |
| `history_retention_days` | `90` | Days to retain command history (0 = forever) |
| `notifications_enabled` | `true` | Enable Slack/Discord notifications for key events |

## Next Steps

- [First Run](first-run.md) — Execute your first command
- [Configuration Deep-Dive](configuration.md) — Full settings reference
