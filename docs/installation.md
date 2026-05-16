# Installation

### Standard Installation

Install the core package from PyPI:

```bash
pip install siyarix
```

### Installation from Source

For development or testing the latest features:

```bash
git clone https://github.com/CosmicSec-Lab/siyarix.git
cd siyarix
pip install -e .
```

### CLI Entry Points

The following commands are registered upon installation:
- **`siyarix`**: The primary command-line interface.
- **`siyarix-agent`**: Enterprise-branded alias.

### Requirements & Extras

- **Python Version**: Requires Python >= 3.11.
- **Autonomous Features**: Install `siyarix[autonomous]` for model provider integrations (e.g., OpenAI).
- **External Tools**: Ensure security tools like `nmap`, `nuclei`, or `ffuf` are in your system PATH for full functionality.
