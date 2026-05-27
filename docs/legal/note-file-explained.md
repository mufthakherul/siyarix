# NOTICE File Explained

The [NOTICE](../../NOTICE) file at the project root serves specific legal functions required by the AGPL-3.0 license.

## Purpose

The NOTICE file provides:

1. **Project identity**: Name, description, and home page
2. **Copyright notice**: Who holds the copyright
3. **License reference**: How the project is licensed
4. **Third-party attributions**: Other software included with different licenses
5. **AI provider documentation**: Architectural description of multi-provider AI system
6. **Disclaimer of affiliation**: The project is not affiliated with any AI provider company

## NOTICE vs LICENSE

| File | Purpose |
|------|---------|
| LICENSE | The full AGPL-3.0 legal text (unmodified from gnu.org) |
| NOTICE | Project-specific notices required by AGPL-3.0 Section 5(a) |

AGPL-3.0 Section 5(a) requires that the NOTICE file be preserved in all distributions. The LICENSE file must also be preserved, but cannot be modified.

## NOTICE sections

### (a) Project Identity

Basic project metadata: name, description, homepage, license, SPDX identifier.

### (b) Copyright Notice

Copyright held by MD MUFTHAKHERUL ISLAM MIRAZ and contributors.

### (c) License Reference

How to find the license, what AGPL-3.0-or-later means.

### (d) Third-Party Dependencies

A table listing:

- Direct runtime dependencies with their licenses
- Each entry includes: Package, Version, License, SPDX
- Dependencies listed include: typer, rich, httpx, pydantic, cryptography, keyring, etc.

### (e) AI Model Provider Architecture

Documents the AI provider abstraction layer:

- Provider-agnostic design
- 10 registered providers
- Dynamic selection and failover
- No hard SDK dependency (providers are optional extras)
- Local/offline operation capability

### (f) Disclaimer of Affiliation

Explicitly disclaims affiliation with:

- Google (Gemini)
- OpenAI (GPT)
- Anthropic (Claude)
- Groq
- Together AI
- Meta (Llama)
- Mistral AI
- Any other provider

### (g) Project Homepage

Source code URL, issue tracker, distribution channels.

## SPDX header

The NOTICE file ends with:

```
SPDX-License-Identifier: AGPL-3.0-or-later
```

## Why this matters

The NOTICE file satisfies AGPL-3.0 requirements and ensures:

1. **Legal compliance**: Meets attribution and notice requirements
2. **Third-party respect**: Properly credits other open-source projects
3. **Transparency**: Clearly documents the AI provider architecture
4. **No confusion**: Disclaims any affiliation with provider companies
