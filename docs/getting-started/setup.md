# ⚙️ Setup & Configuration

Once you have installed Siyarix, the next step is connecting it to your preferred AI provider and tweaking the workspace to fit your style. 

We have designed the setup process to be as straightforward and secure as possible.

---

## 🧙‍♂️ The First-Run Wizard (Recommended)

The absolute easiest way to configure Siyarix is to just let the platform do it for you! 

When you launch Siyarix for the very first time, an interactive, 11-step wizard will run automatically. It asks you a few simple questions, detects your environment, and configures everything.

```bash
# Just run this command and follow the prompts!
siyarix
```

*Want to change your setup later? You can re-run the wizard from scratch at any time:*
```bash
siyarix init --force
```

---

## 🔑 Managing API Keys

If you are using a cloud-based AI provider (like OpenAI or Anthropic), Siyarix needs an API key to communicate with them. You have two main ways to provide these keys:

### 1. Environment Variables
You can temporarily or permanently export them in your terminal session:

```bash
export OPENAI_API_KEY="sk-..."           # OpenAI
export GEMINI_API_KEY="..."              # Google Gemini
export ANTHROPIC_API_KEY="sk-ant-..."    # Anthropic Claude
```

### 2. The `.env` File
For a more permanent solution, simply create a file named `.env` in your project folder, or in your central Siyarix directory (`~/.siyarix/.env`).

```env
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
ANTHROPIC_API_KEY=sk-ant-...
```
*Siyarix loads this file automatically on startup. Check out `.env.example` in the repository root for a complete template!*

---

## 🛡️ The Encrypted Credential Vault

We take security seriously. You shouldn't have API keys lying around in plain text. Siyarix includes an integrated **Credential Vault** that stores your API keys and secrets using robust **AES-256-GCM** encryption, directly integrated with your operating system's native keyring.

Here is how you use the vault from the CLI:

```bash
# Securely prompt for and store your OpenAI key (input is hidden!)
siyarix auth set-key openai          

# List which providers you have configured
siyarix auth show                    

# Store a custom credential for a specific security tool
siyarix creds set <provider_or_tool> <key>   

# Rotate your master encryption key for maximum security
siyarix creds rotate                 
```

**Why our Vault is Secure:**
- **Key Storage:** Uses your OS system keyring (Keychain on macOS, Credential Manager on Windows) as the primary storage.
- **Key Derivation:** We use PBKDF2 with SHA-256 and 600,000 iterations (meeting OWASP recommendations).
- **capable Ready:** Supports AWS KMS envelope encryption (`SIYARIX_KMS_PROVIDER=aws`).
- **Memory Safe:** Credentials are automatically cleared from memory the moment your session ends.
- **Zero Hardcoding:** Keys are *never* written to source code, plain config files, logs, or debug outputs.

---

## 🛠️ Managing Your Settings

Beyond API keys, Siyarix has a wide array of settings (like color themes, output formats, and default models). These are saved in a central file: `~/.siyarix/settings.toml`.

You can manage these settings easily through the CLI:

```bash
siyarix config list                  # View every setting
siyarix config get model_provider    # See what AI provider is currently active
siyarix config set model_provider gemini  # Change the active AI provider
siyarix config edit                  # Open the settings file in your favorite text editor
siyarix config reset                 # Messed something up? Restore the factory defaults!
```

---

## 🎛️ Key Settings Reference

Here are some of the most important settings you might want to tweak:

| Setting Name | Default Value | What It Does |
|---------|---------|-------------|
| `model_provider` | `auto` | The active AI engine. Options: `auto`, `openai`, `gemini`, `anthropic`, `ollama`, etc. |
| `default_output_format` | `table` | How results are displayed. Options: `table`, `json`, `yaml`, `csv`, `html`, `markdown`, `raw`, `quiet`. |
| `color_theme` | `default` | Change the terminal vibe! Options: `cyber_noir`, `matrix`, `bloodmoon`, `arctic`, `synthwave`, `neon`, etc. |
| `stealth_mode` | `false` | Enable strict OPSEC features (like TOR routing, request jitter, and proxy rotation). |
| `persona` | `auto` | Set the AI's "mindset". Options: `redteam`, `blueteam`, `dfir`, `appsec`, `osint`, `cloud`, etc. |
| `default_parallel` | `3` | The maximum number of security tools Siyarix can run at the exact same time. |
| `max_waves` | `25` | How many "plan-execute-measure" cycles the autonomous agent can run before giving up. |
| `auto_save_session` | `false` | Should we save your session logs on exit? (Defaults to `false` to leave zero footprint). |

---

## ⏭️ Next Steps

Your workspace is configured and ready to go!

- **[Your First Run](first-run.md)** — Let's execute your very first automated security workflow.
- **[Configuration Deep-Dive](configuration.md)** — Want to see *every* possible setting? Check out the full reference.
