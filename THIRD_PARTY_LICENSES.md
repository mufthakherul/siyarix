# Third-Party Licenses

Siyarix depends on open-source libraries listed in `pyproject.toml` / `uv.lock`.
This document mirrors those declared dependencies only — do not treat historical or
planned packages as shipped. Siyarix uses AGPL-3.0-or-later; listed licenses are
believed compatible for distribution as dependencies.

Source of truth for package names and extras: `pyproject.toml` (locked in `uv.lock`).

---

## Core Runtime Dependencies

Installed with the base `siyarix` package (`project.dependencies`):

| Package | License | SPDX Identifier |
|---------|---------|-----------------|
| cryptography | Apache-2.0 / BSD-3-Clause | (Apache-2.0 OR BSD-3-Clause) |
| defusedxml | Python-2.0 | Python-2.0 |
| httpx | BSD-3-Clause | BSD-3-Clause |
| jinja2 | BSD-3-Clause | BSD-3-Clause |
| keyring | MIT | MIT |
| prompt-toolkit | BSD-3-Clause | BSD-3-Clause |
| psutil | BSD-3-Clause | BSD-3-Clause |
| pydantic | MIT | MIT |
| pyyaml | MIT | MIT |
| rich | MIT | MIT |
| typer | MIT | MIT |

---

## Optional Dependencies

Installed only when the named extra is selected. `siyarix[all]` expands to
`cli`, `siem`, `autonomous`, `security`, `mobile`, and `windows` — it deliberately
**omits** the reserved `api` extra (see FEAT-02 / `pyproject.toml`).

| Package | Extra(s) | License | Notes |
|---------|----------|---------|-------|
| anthropic | anthropic, autonomous | MIT | Anthropic API client |
| openai | openai, autonomous, dev | Apache-2.0 | OpenAI API client |
| textual | cli, terminal, mobile, windows | MIT | Terminal UI |
| colorama | cli, terminal, windows | BSD-3-Clause | Windows console colors (`sys_platform==win32`) |
| pywin32 | cli, terminal, windows | PSF-2.0 | Windows APIs (`sys_platform==win32`) |
| bandit | security, dev | Apache-2.0 | Security linter |
| pip-audit | security, dev | Apache-2.0 | Dependency vulnerability audit |
| fastapi | api | MIT | Reserved packaging stub only — **not** in `[all]` |
| uvicorn | api | BSD-3-Clause | Reserved packaging stub only — **not** in `[all]` |
| pyjwt | api | MIT | Reserved packaging stub only — **not** in `[all]` |

`siyarix[gemini]` is a documented no-op extra (Gemini uses native REST via `httpx`).
`siyarix[siem]` / `siyarix[mobile]` re-export core or nested extras without new PyPI names beyond the table above.

---

## Not shipped / not declared

These names previously appeared in docs or plans but are **not** in
`pyproject.toml` / `uv.lock` as Siyarix dependencies. Do not treat them as part of
a Siyarix distribution:

| Package | Status |
|---------|--------|
| aiofiles | NOT SHIPPED — not declared |
| tenacity | NOT SHIPPED — not declared |
| google-generativeai | Ghost removed (MOD-P0) — Gemini uses httpx; `siyarix[gemini]` is a no-op |
| redis | NOT SHIPPED — not declared |
| websockets | NOT SHIPPED as a direct dep (may appear only as a transitive of `uvicorn` if `api` is installed) |
| aiohttp | NOT SHIPPED — not declared |
| docker | NOT SHIPPED — not declared |
| kubernetes | NOT SHIPPED — not declared |
| boto3 | NOT SHIPPED — not declared |
| azure-identity | NOT SHIPPED — not declared |
| google-cloud-resource-manager | NOT SHIPPED — not declared |
| stix2 | NOT SHIPPED / planned — not declared |
| mispylib | NOT SHIPPED / planned — not declared |
| opentelemetry-api | NOT SHIPPED — not declared |
| opentelemetry-sdk | NOT SHIPPED — not declared |
| opentelemetry-exporter-otlp | NOT SHIPPED — not declared |
| tox | NOT SHIPPED — not a declared project dependency |

---

## Development Dependencies

From `optional-dependencies.dev` (and nested `terminal`):

| Package | License | SPDX Identifier |
|---------|---------|-----------------|
| bandit | Apache-2.0 | Apache-2.0 |
| build | MIT | MIT |
| click | BSD-3-Clause | BSD-3-Clause |
| hypothesis | MPL-2.0 | MPL-2.0 |
| mypy | MIT | MIT |
| openai | Apache-2.0 | Apache-2.0 |
| pip-audit | Apache-2.0 | Apache-2.0 |
| pre-commit | MIT | MIT |
| pytest | MIT | MIT |
| pytest-asyncio | Apache-2.0 | Apache-2.0 |
| pytest-cov | MIT | MIT |
| respx | MIT | MIT |
| ruff | MIT | MIT |
| twine | Apache-2.0 | Apache-2.0 |
| types-psutil / types-psycopg2 / types-pyperclip / types-pyyaml / types-redis | Apache-2.0 | Apache-2.0 |
| textual / prompt-toolkit / rich / colorama / pywin32 | (see Optional) | via `siyarix[terminal]` |

---

## AI Models & Providers

Siyarix **does not bundle any AI models**. AI capabilities are provided through:

- **Cloud API Providers**: OpenAI, Google Gemini, Anthropic, Groq, Together AI, OpenRouter, DeepSeek, xAI, Mistral AI, Perplexity, Cerebras, Fireworks AI, Z.AI, MiniMax, Moonshot, NVIDIA, Hugging Face, Azure OpenAI, OpenCode Zen — each subject to their respective terms of service, privacy policies, and data processing agreements

- **Local Model Runtimes**: Ollama, LM Studio, llama.cpp, vLLM, LocalAI — these run entirely on the user's machine and are subject to the licenses of the individual models loaded (typically permissive licenses for open-weight models such as Llama, Mistral, Gemma, Phi, etc.)

---

## License Compatibility

The AGPL-3.0-or-later license used by Siyarix is compatible with:

| License | Compatibility | Notes |
|---------|---------------|-------|
| Apache-2.0 | Compatible | Compatible with additional permissions |
| MIT | Compatible | Fully compatible |
| BSD-2-Clause | Compatible | Fully compatible |
| BSD-3-Clause | Compatible | Fully compatible |
| Python-2.0 | Compatible | Fully compatible |
| ISC | Compatible | Fully compatible |
| MPL-2.0 | Compatible | File-level copyleft; dependency use is fine |
| Unlicense / CC0 | Compatible | Public domain equivalent |

**Incompatibility Notice**: AGPL-3.0 is generally **not** compatible with GPL-2.0-only (not "or later"). If you are combining Siyarix with GPL-2.0-only licensed code, consult a qualified legal professional. AGPL-3.0 is compatible with GPL-3.0.

---

## Notice for Distributors

If you distribute Siyarix (or a modified version), whether as source code, compiled binaries, container images, or as part of a network service, you must:

1. Include a copy of the AGPL-3.0-or-later license text
2. Include this third-party license notice (or a reference to it)
3. Preserve all original copyright notices, attributions, and license texts from all included components
4. Provide complete corresponding source code as required by AGPL-3.0 Sections 6 and 13
5. Document any modifications made to the original Siyarix source code
6. Ensure that any additional dependencies you add are licensed under terms compatible with AGPL-3.0-or-later

---

## Attribution

This document is maintained manually against `pyproject.toml` / `uv.lock`. If you
believe a license is missing, incorrect, or has changed, please open an issue or
submit a pull request to correct the record.

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
