# Lockfile policy

This project uses **uv** (`uv.lock`) as the single source of truth for locked dependencies.
CI installs with `uv pip` / hatchling from `pyproject.toml`.

The legacy `poetry.lock` was removed to stop dual-lock drift (cryptography and other
packages had diverged between Poetry and uv). Do not reintroduce Poetry locks unless
Poetry becomes a supported install path again.
