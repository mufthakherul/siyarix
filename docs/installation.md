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

### Requirements & Extras

- **Python Version**: Requires Python >= 3.11.
- **Autonomous Features**: Install `nexsec[autonomous]` for model provider integrations (e.g., OpenAI).
- **Interactive Enhancements**: Install `prompt_toolkit` for an improved experience in the command palette and chat mode.
- **External Tools**: Ensure security tools like `nmap`, `nuclei`, or `ffuf` are in your system PATH for full functionality.
