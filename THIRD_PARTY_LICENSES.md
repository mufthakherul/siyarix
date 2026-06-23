# Third-Party Licenses

Siyarix depends on several open-source libraries and components. This document lists all known third-party dependencies and their respective licenses. Siyarix is committed to using only permissively-licensed or copyleft-licensed dependencies that are compatible with the project's AGPL-3.0-or-later license.

---

## Core Runtime Dependencies

These dependencies are installed with the base `siyarix` package:

| Package | License | SPDX Identifier |
|---------|---------|-----------------|
| aiofiles | Apache-2.0 | Apache-2.0 |
| cryptography | Apache-2.0 / BSD-3-Clause | (Apache-2.0 OR BSD-3-Clause) |
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

These dependencies are installed when specific extras are selected (e.g., `siyarix[all]`, `siyarix[openai]`, `siyarix[cloud]`):

| Package | License | Notes |
|---------|---------|-------|
| openai | Apache-2.0 | OpenAI API client |
| anthropic | MIT | Anthropic API client |
| jinja2 | BSD-3-Clause | Template rendering engine |
| prompt-toolkit | BSD-3-Clause | Enhanced interactive REPL |
| redis | MIT | Distributed caching and task queue backend |
| websockets | BSD-3-Clause | WebSocket server for real-time updates |
| uvicorn | BSD-3-Clause | ASGI server for REST API |
| fastapi | MIT | REST API framework |
| aiohttp | Apache-2.0 | Asynchronous HTTP client/server |
| docker | Apache-2.0 | Docker Engine API client |
| kubernetes | Apache-2.0 | Kubernetes API client |
| boto3 | Apache-2.0 | AWS SDK for cloud scanning |
| azure-identity | MIT | Azure SDK authentication |
| google-cloud-resource-manager | Apache-2.0 | GCP resource management API |
| stix2 | Apache-2.0 | STIX 2.x threat intelligence parsing |
| mispylib | MIT | MISP (Malware Information Sharing Platform) integration |
| opentelemetry-api | Apache-2.0 | Distributed tracing and observability |
| opentelemetry-sdk | Apache-2.0 | OpenTelemetry SDK |
| opentelemetry-exporter-otlp | Apache-2.0 | OTLP exporter |

---

## Development Dependencies

These dependencies are used for development, testing, and CI/CD:

| Package | License | SPDX Identifier |
|---------|---------|-----------------|
| pytest | MIT | MIT |
| pytest-asyncio | Apache-2.0 | Apache-2.0 |
| pytest-cov | MIT | MIT |
| ruff | MIT | MIT |
| mypy | MIT | MIT |
| pre-commit | MIT | MIT |
| bandit | Apache-2.0 | Apache-2.0 |
| pip-audit | Apache-2.0 | Apache-2.0 |
| types-* (stubs) | Apache-2.0 | Apache-2.0 |
| tox | MIT | MIT |

---

## AI Models & Providers

Siyarix **does not bundle any AI models**. AI capabilities are provided through:

- **Cloud API Providers**: OpenAI, Google Gemini, Anthropic, Groq, Together AI, OpenRouter, DeepSeek, xAI, Mistral AI, Perplexity, Cerebras, Fireworks AI, Z.AI, MiniMax, Moonshot, NVIDIA, Hugging Face, Azure OpenAI, OpenCode Zen -- each subject to their respective terms of service, privacy policies, and data processing agreements

- **Local Model Runtimes**: Ollama, LM Studio, llama.cpp, vLLM, LocalAI -- these run entirely on the user's machine and are subject to the licenses of the individual models loaded (typically permissive licenses for open-weight models such as Llama, Mistral, Gemma, Phi, etc.)

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

This document is maintained manually. If you believe a license is missing, incorrect, or has changed, please open an issue or submit a pull request to correct the record.

---

*SPDX-License-Identifier: AGPL-3.0-or-later*
