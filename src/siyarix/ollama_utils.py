# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ollama-specific utilities: model pull, enrichment, and discovery.

Patterns adapted from OpenClaw (Apache 2.0):
  - pullOllamaModelCore() / api/pull streaming
  - enrichOllamaModelsWithContext() / api/show per-model enrichment
  - buildOllamaModelDefinition() with capability detection
"""

from __future__ import annotations

__all__ = [
    "resolve_ollama_url",
    "fetch_ollama_models",
    "fetch_ollama_model_info",
    "enrich_model_context",
    "enrich_ollama_models",
    "build_model_definition",
    "is_reasoning_model",
    "pull_ollama_model",
    "ensure_model_pulled",
    "discover_provider_models",
    "_is_safe_url",
    "_safe_http_get",
    "_safe_http_post",
]

import json
import logging
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)

OLLAMA_DEFAULT_URL = "http://localhost:11434"
OLLAMA_PULL_RESPONSE_TIMEOUT = 30.0
OLLAMA_PULL_STREAM_IDLE_TIMEOUT = 300.0
OLLAMA_SHOW_TIMEOUT = 5.0
OLLAMA_TAGS_TIMEOUT = 5.0
OLLAMA_SHOW_CONCURRENCY = 8
OLLAMA_CONTEXT_ENRICH_LIMIT = 200
OLLAMA_DEFAULT_CONTEXT_WINDOW = 128_000
OLLAMA_DEFAULT_MAX_TOKENS = 8192


def resolve_ollama_url(base_url: str | None = None) -> str:
    url = (base_url or "").strip()
    if not url:
        url = OLLAMA_DEFAULT_URL
    return url.rstrip("/")


def _safe_http_get(url: str, timeout: float = 10.0) -> dict[str, Any] | list[Any] | None:
    """SSRF-safe HTTP GET — only allows localhost/private IPs."""
    if not _is_safe_url(url):
        logger.warning("Blocked unsafe URL: %s", url)
        return None
    import httpx
    try:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("HTTP GET failed for %s: %s", url, exc)
        return None


def _safe_http_post(
    url: str, payload: dict[str, Any], timeout: float = 10.0
) -> httpx.Response | None:
    """SSRF-safe HTTP POST — validates URL, returns response or None."""
    if not _is_safe_url(url):
        logger.warning("Blocked unsafe POST URL: %s", url)
        return None
    import httpx
    try:
        resp = httpx.post(url, json=payload, timeout=timeout)
        return resp
    except Exception as exc:
        logger.debug("HTTP POST failed for %s: %s", url, exc)
        return None


def _is_safe_url(url: str) -> bool:
    """Allow only http://localhost, http://127.0.0.1, http://[::1], and private IPs.

    OpenClaw pattern: hostname allowlist + private network allowance.
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname or ""
        if host in ("localhost", "127.0.0.1", "::1", "[::1]"):
            return True
        if host.startswith("127."):
            return True
        if host == "[::1]" or host == "::1":
            return True
        import ipaddress
        try:
            addr = ipaddress.ip_address(host)
            return addr.is_private or addr.is_loopback
        except ValueError:
            return False
    except Exception:
        return False


def fetch_ollama_models(
    base_url: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch available models from Ollama via GET /api/tags.

    Returns list of model dicts with 'name', 'digest', 'modified_at'.
    Returns empty list on error.
    """
    url = f"{resolve_ollama_url(base_url)}/api/tags"
    data = _safe_http_get(url, timeout=OLLAMA_TAGS_TIMEOUT)
    if not data or not isinstance(data, dict):
        return []
    return data.get("models", [])


def fetch_ollama_model_info(
    model_name: str, base_url: str | None = None
) -> dict[str, Any]:
    """Get model info from Ollama via POST /api/show.

    Returns dict with 'model_info', 'capabilities', 'parameters', 'modelfile'.
    OpenClaw pattern: queryOllamaModelShowInfo().
    """
    url = f"{resolve_ollama_url(base_url)}/api/show"
    resp = _safe_http_post(url, {"name": model_name}, timeout=OLLAMA_SHOW_TIMEOUT)
    if resp is None:
        return {}
    try:
        return resp.json()
    except Exception:
        return {}


def enrich_model_context(
    model_name: str, base_url: str | None = None
) -> tuple[int | None, list[str] | None]:
    """Enrich a single model with context window and capabilities.

    OpenClaw pattern: extracts context_length from model_info.*.context_length
    and capabilities array from /api/show response.
    """
    info = fetch_ollama_model_info(model_name, base_url)
    if not info:
        return None, None

    context_window: int | None = None
    model_info = info.get("model_info") or {}

    for key, value in model_info.items():
        if key.endswith(".context_length") and isinstance(value, (int, float)):
            ctx = int(value)
            if ctx > 0:
                context_window = ctx
                break

    param_ctx = _parse_num_ctx(info.get("parameters"))
    if param_ctx is not None and (context_window is None or param_ctx > context_window):
        context_window = param_ctx

    capabilities_raw = info.get("capabilities")
    capabilities: list[str] | None = None
    if isinstance(capabilities_raw, list):
        capabilities = [str(c) for c in capabilities_raw if isinstance(c, str)]

    return context_window, capabilities


def _parse_num_ctx(parameters: Any) -> int | None:
    """Extract num_ctx from Modelfile parameters string.

    OpenClaw pattern: parseOllamaNumCtxParameter().
    """
    if not isinstance(parameters, str) or not parameters.strip():
        return None
    last_value: int | None = None
    for line in parameters.splitlines():
        m = __import__("re").match(r"num_ctx\s+(\d+)", line.strip())
        if m:
            val = int(m.group(1))
            if val > 0:
                last_value = val
    return last_value


def is_reasoning_model(model_name: str) -> bool:
    """Heuristic: detect reasoning models by name.

    OpenClaw pattern: isReasoningModelHeuristic().
    """
    import re
    return bool(re.search(r"r1|reasoning|think|reason", model_name, re.IGNORECASE))


def build_model_definition(
    model_name: str,
    context_window: int | None = None,
    capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """Build a model definition dict matching ProviderManager expectations.

    OpenClaw pattern: buildOllamaModelDefinition().
    """
    has_vision = capabilities is not None and "vision" in capabilities
    reasoning = is_reasoning_model(model_name)
    if capabilities is not None:
        reasoning = reasoning or "thinking" in capabilities
    supports_tools = capabilities is None or "tools" in capabilities
    return {
        "name": model_name,
        "supports_vision": has_vision,
        "supports_tools": supports_tools,
        "context_window": context_window or OLLAMA_DEFAULT_CONTEXT_WINDOW,
        "max_tokens": OLLAMA_DEFAULT_MAX_TOKENS,
        "reasoning": reasoning,
    }


def enrich_ollama_models(
    models: list[dict[str, Any]], base_url: str | None = None
) -> list[dict[str, Any]]:
    """Enrich a list of Ollama models with context window and capabilities.

    Processes in batches of OLLAMA_SHOW_CONCURRENCY.
    OpenClaw pattern: enrichOllamaModelsWithContext().
    """
    import asyncio

    base = resolve_ollama_url(base_url)
    enriched: list[dict[str, Any]] = []
    limit = OLLAMA_CONTEXT_ENRICH_LIMIT

    async def _enrich_one(m: dict[str, Any]) -> dict[str, Any]:
        name = m.get("name", "")
        ctx, caps = enrich_model_context(name, base)
        defn = build_model_definition(name, ctx, caps)
        return {**m, **defn}

    async def _run() -> None:
        batch: list[Any] = []
        for idx, m in enumerate(models):
            if idx >= limit:
                break
            batch.append(_enrich_one(m))
            if len(batch) >= OLLAMA_SHOW_CONCURRENCY:
                results = await asyncio.gather(*batch, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict):
                        enriched.append(r)
                batch = []
        if batch:
            results = await asyncio.gather(*batch, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    enriched.append(r)

    try:
        asyncio.run(_run())
    except Exception as exc:
        logger.debug("Model enrichment error: %s", exc)

    return enriched


def pull_ollama_model(
    model_name: str,
    base_url: str | None = None,
    on_status: Callable[[str, int | None], None] | None = None,
) -> tuple[bool, str]:
    """Pull an Ollama model via POST /api/pull with streaming NDJSON response.

    OpenClaw pattern: pullOllamaModelCore() with streaming progress.

    Returns (ok: bool, message: str).
    """
    import httpx

    url = f"{resolve_ollama_url(base_url)}/api/pull"
    if not _is_safe_url(url):
        return False, f"Blocked unsafe URL: {url}"

    try:
        with httpx.Client(timeout=httpx.Timeout(OLLAMA_PULL_STREAM_IDLE_TIMEOUT)) as client:
            resp = client.post(url, json={"name": model_name}, timeout=OLLAMA_PULL_RESPONSE_TIMEOUT)
            if not resp.is_success:
                return False, f"Failed to download {model_name} (HTTP {resp.status_code})"

            layers: dict[str, dict[str, int]] = {}
            buffer = ""

            for chunk in resp.iter_bytes():
                buffer += chunk.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if data.get("error"):
                        return False, f"Download failed: {data['error']}"
                    status = data.get("status", "")
                    if not status:
                        continue
                    total = data.get("total")
                    completed = data.get("completed")
                    if total is not None and completed is not None:
                        layers[status] = {"total": int(total), "completed": int(completed)}
                        total_sum = sum(v["total"] for v in layers.values())
                        completed_sum = sum(v["completed"] for v in layers.values())
                        pct = round(completed_sum / total_sum * 100) if total_sum > 0 else None
                        if on_status:
                            on_status(status, pct)
                    else:
                        if on_status:
                            on_status(status, None)

            if buffer.strip():
                try:
                    data = json.loads(buffer.strip())
                    if data.get("error"):
                        return False, f"Download failed: {data['error']}"
                except json.JSONDecodeError:
                    pass

            return True, f"Downloaded {model_name}"

    except httpx.TimeoutException:
        return False, f"Timed out pulling {model_name}"
    except Exception as exc:
        return False, f"Failed to pull {model_name}: {exc}"


def ensure_model_pulled(
    model_name: str,
    base_url: str | None = None,
    console: Any = None,
) -> bool:
    """Check if a model exists in Ollama; pull it if missing.

    OpenClaw pattern: ensureOllamaModelPulled().
    Returns True if model is available (already present or successfully pulled).
    """
    models = fetch_ollama_models(base_url)
    installed = [m.get("name", "") for m in models]
    check = model_name if ":" in model_name else f"{model_name}:latest"
    if check in installed or model_name in installed:
        return True

    if console:
        console.print(f"[dim]Model {model_name} not found locally — pulling...[/dim]")

    def _on_status(status: str, pct: int | None) -> None:
        if console and pct is not None:
            console.print(f"\r[dim]  {status} — {pct}%[/dim]", end="")
        elif console:
            console.print(f"\r[dim]  {status}[/dim]", end="")

    ok, msg = pull_ollama_model(model_name, base_url, on_status=_on_status)
    if console:
        if ok:
            console.print(f"\r[green]✓ {msg}[/green]")
        else:
            console.print(f"\r[red]✗ {msg}[/red]")
    return ok


def discover_provider_models(
    base_url: str | None = None,
    enrich: bool = True,
) -> list[dict[str, Any]]:
    """Discover all Ollama models, optionally enriched with context/capabilities.

    OpenClaw pattern: buildOllamaProvider().
    Returns list of model definition dicts compatible with ProviderProfile.models.
    """
    models = fetch_ollama_models(base_url)
    if not models:
        return []
    if enrich:
        enriched = enrich_ollama_models(models, base_url)
        if enriched:
            return enriched
    return [
        build_model_definition(m.get("name", ""))
        for m in models
    ]
