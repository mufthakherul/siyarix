# Third-Party Licenses

Siyarix depends on several open-source libraries and components. This document lists all known third-party dependencies and their respective licenses.

---

## Core Runtime Dependencies

| Package | License | SPDX |
|---------|---------|------|
| aiofiles | Apache-2.0 | Apache-2.0 |
| cryptography | Apache-2.0 / BSD-3-Clause | Apache-2.0 OR BSD-3-Clause |
| defusedxml | Python-2.0 | Python-2.0 |
| google-generativeai | Apache-2.0 | Apache-2.0 |
| httpx | BSD-3-Clause | BSD-3-Clause |
| keyring | MIT | MIT |
| psutil | BSD-3-Clause | BSD-3-Clause |
| pydantic | MIT | MIT |
| rich | MIT | MIT |
| tenacity | Apache-2.0 | Apache-2.0 |
| typer | MIT | MIT |

---

## Optional Dependencies

| Package | License | Notes |
|---------|---------|-------|
| openai | Apache-2.0 | AI provider |
| anthropic | MIT | AI provider |
| jinja2 | BSD-3-Clause | Template rendering |
| prompt-toolkit | BSD-3-Clause | Enhanced REPL |
| redis | MIT | Distributed backend |
| websockets | BSD-3-Clause | Dashboard live updates |
| uvicorn | BSD-3-Clause | Dashboard server |
| fastapi | MIT | Dashboard API |
| aiohttp | Apache-2.0 | Async HTTP |
| docker | Apache-2.0 | Docker integration |
| kubernetes | Apache-2.0 | K8s scanning |
| boto3 | Apache-2.0 | AWS scanning |
| azure-identity | MIT | Azure scanning |
| google-cloud-resource-manager | Apache-2.0 | GCP scanning |
| stix2 | Apache-2.0 | Threat intel STIX parsing |
| mispylib | MIT | MISP integration |

---

## Development Dependencies

| Package | License |
|---------|---------|
| pytest | MIT |
| pytest-asyncio | Apache-2.0 |
| pytest-cov | MIT |
| ruff | MIT |
| mypy | MIT |
| pre-commit | MIT |
| bandit | Apache-2.0 |
| pip-audit | Apache-2.0 |
| types-* (stubs) | Apache-2.0 |

---

## AI Models & Providers

Siyarix does not bundle any AI models. AI capabilities are provided through:

- **Cloud APIs**: OpenAI, Google Gemini, Anthropic, Groq, Together — subject to their respective terms of service and privacy policies.
- **Local Models**: Ollama, LM Studio — run locally; subject to individual model licenses (typically permissive for open-weight models).

---

## License Compatibility

AGPL-3.0-or-later is compatible with:

- Apache-2.0 (compatible with additional permissions)
- MIT (compatible)
- BSD-2-Clause / BSD-3-Clause (compatible)
- Python-2.0 (compatible)

**Note**: AGPL-3.0 is generally **not** compatible with GPL-2.0-only. If you are combining Siyarix with GPL-2.0-only licensed code, consult a legal professional.

---

## Notice for Distributors

If you distribute Siyarix (or a modified version), you must:

1. Include a copy of the AGPL-3.0 license
2. Include this third-party license notice
3. Preserve all original copyright notices
4. Provide source code access as required by AGPL-3.0 Section 6 and Section 13

---

*This document is maintained manually. If you believe a license is missing or incorrect, please open an issue or pull request.*

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
