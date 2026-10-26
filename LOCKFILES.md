# Lockfile policy

This project uses **uv** (`uv.lock`) as the single source of truth for locked dependencies.

Primary CI jobs (`ci.yml` lint/test/production-check/security-audit/compatibility,
`coverage.yml`) install with `uv sync --locked` (plus `--extra dev` or `--extra security`
where needed), then run tools via `uv run`. A few CI-only tools that are not in
`[project.optional-dependencies]` (`pytest-xdist`, `pytest-timeout`,
`check-wheel-contents`, pinned `ruff==0.15.20`) are installed with `uv pip install`
into the project env after sync.

The legacy `poetry.lock` was removed to stop dual-lock drift (cryptography and other
packages had diverged between Poetry and uv). Do not reintroduce Poetry locks unless
Poetry becomes a supported install path again.
