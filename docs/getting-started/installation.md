# Installation

Siyarix requires Python 3.11+ and is distributed via PyPI, Homebrew, npm, and Winget.

## Requirements

- **Python**: 3.11 or later
- **OS**: Windows, macOS, Linux (including WSL2)
- **RAM**: 512 MB minimum; 4 GB+ recommended for AI features
- **Disk**: ~500 MB for tool dependencies

## Install from PyPI

```bash
pip install siyarix
```

### Optional extras

```bash
# Install with AI provider SDKs
pip install "siyarix[openai,gemini,anthropic]"

# Install with CLI enhancements
pip install "siyarix[cli]"

# Install with SIEM connectors
pip install "siyarix[siem]"

# Install everything
pip install "siyarix[all]"
```

### Available extras groups

| Extra | Includes |
|-------|----------|
| `openai` | OpenAI Python SDK |
| `gemini` | Google Generative AI SDK |
| `anthropic` | Anthropic SDK |
| `groq` | Groq SDK |
| `together` | Together AI SDK |
| `ollama` | Ollama Python library |
| `lmstudio` | LM Studio API support |
| `cli` | Rich-enhanced CLI experience |
| `siem` | Splunk/ELK SIEM forwarders |
| `all` | All of the above |

## Platform-specific installs

### macOS (Homebrew)

```bash
brew install mufthakherul/siyarix/siyarix
```

### Windows (Winget)

```bash
winget install Mufthakherul.Siyarix
```

### npm (launcher)

```bash
npx @mufthakherul/siyarix --help
```

## Install from source

```bash
git clone https://github.com/mufthakherul/siyarix.git
cd siyarix
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .\.venv\Scripts\Activate.ps1  # Windows
pip install -e ".[all,cli,siem]"
```

## Verify installation

```bash
siyarix --version
siyarix --help
```

## Next steps

- [Setup & Configuration](setup.md) — API keys, environment, first-run wizard
- [First Run](first-run.md) — run your first commands
