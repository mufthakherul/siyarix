# 🎛️ Configuration Deep-Dive

Welcome to the control room! 

Siyarix is built to be extremely flexible. Whether you are running it locally on your laptop, deploying it in a CI/CD pipeline, or running it headlessly on a remote server, our layered configuration system ensures you can customize it exactly how you need it.

---

## 🥞 The 4-Layer Configuration System

To make Siyarix adaptable across development, production, and CI environments, we use a 4-tier priority system. When Siyarix looks for a setting (like which AI model to use), it checks these layers from bottom to top:

1. **Code Defaults** — The fallback defaults hardcoded into the `config.py` file.
2. **Settings File** — Your personal `~/.siyarix/settings.toml` file.
3. **Environment Variables** — System variables prefixed with `SIYARIX_`.
4. **CLI Flags** — *Highest Priority.* Flags passed directly into the command line.

*What does this mean for you?* It means you can set a global default in your settings file, but easily override it on the fly for a single scan using a CLI flag!

---

## 🌐 Environment Variables Reference

If you are automating Siyarix via scripts or CI pipelines, environment variables are your best friend. 

| Environment Variable | What It Controls | Example |
|----------|------------|-------------|
| `SIYARIX_PROVIDER` | Forces the AI provider | `openai` |
| `SIYARIX_PERSONA` | Overrides the active persona | `redteam` |
| `SIYARIX_LOG_LEVEL` | Sets the logging verbosity | `debug` |
| `SIYARIX_SAFE_MODE` | Restricts AI to reconnaissance only | `true` |
| `SIYARIX_TIMEOUT` | Max tool execution time (seconds) | `300` |
| `SIYARIX_STEALTH` | Enables OPSEC stealth mode | `true` |
| `SIYARIX_HOME` | Overrides the default `~/.siyarix/` folder | `/tmp/custom_dir` |
| `SIYARIX_CONFIG` | Overrides the default `settings.toml` path | `/path/to/my_config.toml` |

---

## 🤖 Configuring AI Provider Models

Siyarix supports an incredible 26+ AI providers. In your `settings.toml`, you can explicitly tell Siyarix exactly which model to use for each provider.

```toml
# Tell Siyarix to automatically pick the best available provider
model_provider = "auto"

# Fine-tune the specific models for each provider:
openai_model = "gpt-4o"
gemini_model = "gemini-2.5-flash"
anthropic_model = "claude-3-7-sonnet-20250219"
deepseek_model = "deepseek-chat"
groq_model = "llama-3.3-70b-versatile"
# ... and many more!
```

---

## 🏠 Running 100% Offline (Local Providers)

Need to run an air-gapped pentest? Siyarix natively integrates with local AI engines. No internet required.

| Provider | Default Endpoint | How to start it locally |
|----------|----------|-------|
| **Ollama** | `http://localhost:11434` | `ollama pull llama3.1 && ollama serve` |
| **LM Studio** | `http://localhost:1234` | Open the app and enable the "Local Inference Server" |
| **llama.cpp** | `http://localhost:18080` | `llama-server --model model.gguf --port 18080` |
| **vLLM** | `http://localhost:8000` | `vllm serve [model_name]` |
| **Registry** | *Built-in* | Automatically falls back to a hardcoded, non-AI planner! |

---

## 🕵️ OPSEC & Proxy Configuration

If you need to route Siyarix traffic through a proxy (or a pool of proxies), it's incredibly easy to set up in your `settings.toml`.

```toml
# Route everything through a single proxy (like Burp Suite or ZAP)
proxy = "http://127.0.0.1:8080"

# Or, define a Proxy Pool! Siyarix will intelligently rotate through them.
proxy_pool = "http://proxy1:8080,http://proxy2:8080"
```

### Client Fingerprinting
You can also alter Siyarix's HTTP fingerprint to mimic different browsers during OSINT and web requests:
```toml
client_profile = "desktop_chrome"
# Available Options: desktop_chrome, desktop_firefox, android_mobile, ios_safari
```

---

## 🎨 Make it Yours: Color Themes

Security tools don't have to be ugly! Siyarix ships with beautifully crafted terminal themes.

```toml
color_theme = "cyber_noir"
```

Want to see what they look like? Run `siyarix themes` to preview them all!
*Available themes: `cyber_noir`, `matrix`, `bloodmoon`, `arctic`, `synthwave`, `neon`, and more.*

---

## 💻 CLI Configuration Commands

You don't *have* to open the `settings.toml` file manually. Siyarix provides handy CLI commands to manage your config directly from the terminal:

```bash
siyarix config list               # Show all settings beautifully formatted
siyarix config get <key>          # Get a single value (e.g., `siyarix config get color_theme`)
siyarix config set <key> <value>  # Set a value 
siyarix config reset              # Reset everything back to factory defaults
siyarix config edit               # Automatically open settings.toml in your default $EDITOR
```

---

## 🔑 Credential Management Refresher

Just a quick reminder on how to securely manage your API keys via the encrypted vault:

```bash
siyarix auth set-key <provider>    # Securely store a new API key
siyarix auth show                  # See which providers are active
siyarix creds list                 # List all stored credentials
siyarix creds rotate               # Rotate the AES encryption key securing the vault
```

---

## ⏭️ Next Steps

- **[Troubleshooting](getting-started-troubleshooting)** — Having issues? Let's get them fixed.
- **[CLI Commands](../user/cli-commands.md)** — See all the commands you can run!
