# Installation

### Standard Installation

Install the core package from PyPI:

```bash
pip install nexsec
```

### Installation from Source

For development or testing the latest features:

```bash
git clone https://github.com/CosmicSec-Lab/nexsec.git
cd nexsec
pip install -e .
```

### CLI Entry Points

The following commands are registered upon installation:
- **`nexsec`**: The primary command-line interface.
- **`nexsec-agent`**: Enterprise-branded alias.

Running `nexsec` with no subcommand launches the interactive assistant shell with a richer landing screen, quick actions, and built-in theme/model/key controls.

### Requirements & Extras

- **Python Version**: Requires Python >= 3.11.
- **Autonomous Features**: Install `nexsec[autonomous]` for model provider integrations (e.g., OpenAI).
- **Gemini Support**: Install `nexsec[autonomous]` for Gemini planning support as well as OpenAI/Ollama.
- **Interactive Enhancements**: Install `prompt_toolkit` for an improved experience in the command palette and chat mode.
- **External Tools**: Ensure security tools like `nmap`, `nuclei`, or `ffuf` are in your system PATH for full functionality.

### Environment & Secrets

- A repo-root `.env` file is created/used automatically for local API keys.
- Use `nexsec auth set-key <provider> --key <value>` or the chat `/key` command to store keys in the credential vault and sync them to `.env`.
- Supported providers include OpenAI, Gemini, Anthropic, and NexSec Cloud.
