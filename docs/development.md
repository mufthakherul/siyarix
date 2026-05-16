# Development Guide

Developer quickstart:

```bash
git clone https://github.com/CosmicSec-Lab/nexsec.git
cd nexsec
python -m venv .venv
source .venv/bin/activate   # or .\.venv\Scripts\activate.ps1 on Windows
pip install -e '.[all]'
pytest -q
```

Conventions:
- Use Black and Ruff for formatting/linting.
- Keep public APIs stable; add new parser adapters under `src/cosmicsec_agent/parsers`.
- Tests live under `tests/` and use pytest with asyncio support.

Packaging:
- Build wheel with `python -m build` (hatchling backend) or `pip wheel .`
