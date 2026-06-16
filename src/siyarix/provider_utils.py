# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generic local provider utilities: model listing, enrichment, pull.

Supports all local providers (ollama, lmstudio, llamacpp, vllm, localai)
with a unified interface. Patterns adapted from OpenClaw (Apache 2.0):
  - Provider-specific model listing + enrichment
  - On-demand model pull (Ollama only)
  - SSRF-safe HTTP helpers
"""

from __future__ import annotations

import json
import logging
import re
import httpx
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────────

DEFAULT_CONTEXT_WINDOW = 128_000
DEFAULT_MAX_TOKENS = 8192

PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "ollama": {
        "url": "http://localhost:11434",
        "models_endpoint": "/api/tags",
        "models_list_key": "models",
        "model_id_key": "name",
        "info_endpoint": "/api/show",
        "info_method": "POST",
        "info_payload_key": "name",
        "pull_endpoint": "/api/pull",
        "supports_pull": True,
        "health_endpoint": "/api/tags",
    },
    "lmstudio": {
        "url": "http://localhost:1234",
        "models_endpoint": "/v1/models",
        "models_list_key": "data",
        "model_id_key": "id",
        "info_endpoint": None,
        "supports_pull": False,
        "health_endpoint": "/v1/models",
    },
    "llamacpp": {
        "url": "http://localhost:18080",
        "models_endpoint": "/v1/models",
        "models_list_key": "data",
        "model_id_key": "id",
        "info_endpoint": None,
        "supports_pull": False,
        "health_endpoint": "/health",
    },
    "vllm": {
        "url": "http://localhost:8000",
        "models_endpoint": "/v1/models",
        "models_list_key": "data",
        "model_id_key": "id",
        "info_endpoint": None,
        "supports_pull": False,
        "health_endpoint": "/health",
    },
    "localai": {
        "url": "http://localhost:8080",
        "models_endpoint": "/v1/models",
        "models_list_key": "data",
        "model_id_key": "id",
        "info_endpoint": None,
        "supports_pull": False,
        "health_endpoint": "/readyz",
    },
}


# ── SSRF-safe HTTP helpers ───────────────────────────────────────────────


def _is_safe_url(url: str) -> bool:
    """Allow only http://localhost, 127.0.0.1, ::1, and private IPs.

    OpenClaw pattern: hostname allowlist + private network allowance.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1", "[::1]"):
            return True
        if host.startswith("127."):
            return True
        import ipaddress

        try:
            addr = ipaddress.ip_address(host)
            return bool(addr.is_private or addr.is_loopback)
        except ValueError:
            return False
    except Exception as exc:
        logger.debug("URL safety check failed for %s: %s", url, exc)
        return False


def safe_http_get(url: str, timeout: float = 10.0) -> Any:
    """SSRF-safe HTTP GET — only allows localhost/private IPs."""
    if not _is_safe_url(url):
        logger.warning("Blocked unsafe GET: %s", url)
        return None
    try:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("HTTP GET failed for %s: %s", url, exc)
        return None


def safe_http_post(
    url: str, payload: dict[str, Any], timeout: float = 10.0
) -> httpx.Response | None:
    """SSRF-safe HTTP POST."""
    if not _is_safe_url(url):
        logger.warning("Blocked unsafe POST: %s", url)
        return None
    try:
        return httpx.post(url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.debug("HTTP POST failed for %s: %s", url, exc)
        return None


def safe_http_get_raw(url: str, timeout: float = 10.0) -> httpx.Response | None:
    """SSRF-safe HTTP GET returning raw response."""
    if not _is_safe_url(url):
        logger.warning("Blocked unsafe GET: %s", url)
        return None
    try:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp
    except Exception as exc:
        logger.debug("HTTP GET failed for %s: %s", url, exc)
        return None


# ── Shared helpers ───────────────────────────────────────────────────────


def resolve_provider_url(provider: str, base_url: str | None = None) -> str:
    cfg = PROVIDER_DEFAULTS.get(provider)
    if not cfg:
        return base_url or ""
    url = (base_url or "").strip()
    if not url:
        url = cfg["url"]
    return url.rstrip("/")


def is_reasoning_model(model_name: str) -> bool:
    """Detect reasoning models by name heuristic.

    OpenClaw pattern: isReasoningModelHeuristic().
    """
    return bool(re.search(r"r1|qwq|reasoning|think|reason", model_name, re.IGNORECASE))


def build_model_definition(
    model_name: str,
    context_window: int | None = None,
    capabilities: list[str] | None = None,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Build a model definition dict matching ProviderManager expectations."""
    has_vision = capabilities is not None and "vision" in capabilities
    reasoning = is_reasoning_model(model_name)
    if capabilities is not None:
        reasoning = reasoning or "thinking" in capabilities
    supports_tools = capabilities is None or "tools" in capabilities
    return {
        "name": model_name,
        "supports_vision": has_vision,
        "supports_tools": supports_tools,
        "context_window": context_window or DEFAULT_CONTEXT_WINDOW,
        "max_tokens": max_tokens or DEFAULT_MAX_TOKENS,
        "reasoning": reasoning,
    }


# ── Provider-specific model listing ──────────────────────────────────────


def _list_ollama_models(base_url: str) -> list[dict[str, Any]]:
    """GET /api/tags."""
    url = f"{base_url}/api/tags"
    data = safe_http_get(url, timeout=5.0)
    if not data or not isinstance(data, dict):
        return []
    return data.get("models", [])


def _list_openai_compat_models(base_url: str, timeout: float = 5.0) -> list[dict[str, Any]]:
    """GET /v1/models for OpenAI-compatible providers."""
    url = f"{base_url}/v1/models"
    data = safe_http_get(url, timeout=timeout)
    if not data or not isinstance(data, dict):
        return []
    raw = data.get("data") or data.get("models") or []
    return raw if isinstance(raw, list) else []


def list_provider_models(provider: str, base_url: str | None = None) -> list[dict[str, Any]]:
    """List available models for any local provider.

    Returns list of dicts with at least {'name': '<model_id>'}.
    """
    resolved = resolve_provider_url(provider, base_url)
    provider = provider.lower()

    if provider == "ollama":
        models = _list_ollama_models(resolved)
        return [{"name": m.get("name", ""), **m} for m in models]

    if provider in ("lmstudio", "llamacpp", "vllm", "localai"):
        models = _list_openai_compat_models(resolved)
        return [{"name": m.get("id", ""), **m} for m in models]

    return []


# ── Provider-specific model enrichment ───────────────────────────────────


def _enrich_ollama_model(
    model_name: str, base_url: str
) -> tuple[int | None, list[str] | None, int | None]:
    """POST /api/show and extract context_length + capabilities."""
    url = f"{base_url}/api/show"
    resp = safe_http_post(url, {"name": model_name}, timeout=5.0)
    if resp is None:
        return None, None, None
    try:
        info = resp.json()
    except Exception as exc:
        logger.debug("Failed to parse Ollama model info for %s: %s", model_name, exc)
        return None, None, None

    ctx: int | None = None
    mi = info.get("model_info") or {}
    for key, value in mi.items():
        if key.endswith(".context_length") and isinstance(value, (int, float)):
            v = int(value)
            if v > 0:
                ctx = v
                break

    param_ctx = _parse_num_ctx(info.get("parameters"))
    if param_ctx is not None and (ctx is None or param_ctx > ctx):
        ctx = param_ctx

    caps_raw = info.get("capabilities")
    caps: list[str] | None = None
    if isinstance(caps_raw, list):
        caps = [str(c) for c in caps_raw if isinstance(c, str)]

    mi_max_tokens = None
    for key, value in mi.items():
        if key.endswith(".max_tokens") and isinstance(value, (int, float)):
            mi_max_tokens = int(value)
            break

    return ctx, caps, mi_max_tokens


def _enrich_lmstudio_model(
    model_entry: dict[str, Any],
) -> tuple[int | None, list[str] | None, int | None]:
    """Extract context window and capabilities from LM Studio model metadata."""
    ctx: int | None = None
    caps: list[str] | None = None
    max_tok: int | None = None

    for file_info in model_entry.get("loaded_instances", []):
        if file_info.get("context_length"):
            ctx_file = file_info["context_length"]
            if isinstance(ctx_file, (int, float)) and ctx_file > 0:
                ctx = int(ctx_file)

    meta = model_entry.get("metadata") or {}
    if meta.get("vision"):
        caps = (caps or []) + ["vision"]
    if meta.get("reasoning"):
        caps = (caps or []) + ["thinking"]
    if meta.get("tools"):
        caps = (caps or []) + ["tools"]

    if meta.get("max_tokens"):
        mt = meta["max_tokens"]
        if isinstance(mt, (int, float)) and mt > 0:
            max_tok = int(mt)

    return ctx, caps, max_tok


def _enrich_vllm_model(
    model_entry: dict[str, Any],
) -> tuple[int | None, list[str] | None, int | None]:
    """Extract context window from vLLM model metadata (max_model_len)."""
    ctx: int | None = None
    max_tok: int | None = None
    for key, value in model_entry.items():
        if key.endswith("max_model_len") and isinstance(value, (int, float)):
            v = int(value)
            if v > 0:
                ctx = v
                break
    return ctx, None, max_tok


def enrich_model(
    provider: str,
    model_name: str,
    model_entry: dict[str, Any] | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Enrich a single model with context window and capabilities.

    Returns a model definition dict.
    """
    ctx: int | None = None
    caps: list[str] | None = None
    max_tok: int | None = None

    provider = provider.lower()
    resolved = resolve_provider_url(provider, base_url)

    if provider == "ollama":
        ctx, caps, max_tok = _enrich_ollama_model(model_name, resolved)
    elif provider == "lmstudio" and model_entry:
        ctx, caps, max_tok = _enrich_lmstudio_model(model_entry)
    elif provider == "vllm" and model_entry:
        ctx, caps, max_tok = _enrich_vllm_model(model_entry)
    elif provider in ("llamacpp", "localai") and model_entry:
        for key, value in model_entry.items():
            if key.endswith("context_length") and isinstance(value, (int, float)):
                ctx = int(value)
                break

    return build_model_definition(model_name, ctx, caps, max_tok)


def enrich_all_models(
    provider: str,
    models: list[dict[str, Any]],
    base_url: str | None = None,
    concurrency: int = 8,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Enrich all models for a provider with context window + capabilities.

    Ollama uses batched /api/show calls; others read metadata from listing.
    """
    provider = provider.lower()

    if provider == "ollama":
        return _enrich_ollama_models_batch(models, base_url, concurrency, limit)

    enriched: list[dict[str, Any]] = []
    for idx, m in enumerate(models):
        if idx >= limit:
            break
        name = m.get("name", "")
        if not name:
            continue
        defn = enrich_model(provider, name, m, base_url)
        enriched.append({**m, **defn})
    return enriched


def _enrich_ollama_models_batch(
    models: list[dict[str, Any]],
    base_url: str | None = None,
    concurrency: int = 8,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Batch-enrich Ollama models with concurrent /api/show calls."""
    import asyncio

    base = resolve_provider_url("ollama", base_url)
    enriched: list[dict[str, Any]] = []

    async def _enrich_one(m: dict[str, Any]) -> dict[str, Any]:
        name = m.get("name", "")
        ctx, caps, max_tok = _enrich_ollama_model(name, base)
        defn = build_model_definition(name, ctx, caps, max_tok)
        return {**m, **defn}

    async def _run() -> None:
        batch: list[Any] = []
        for idx, m in enumerate(models):
            if idx >= limit:
                break
            batch.append(_enrich_one(m))
            if len(batch) >= concurrency:
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
        asyncio.get_running_loop()
        logger.debug("Ollama batch enrichment skipped (already in async context)")
    except RuntimeError:
        try:
            asyncio.run(_run())
        except Exception as exc:
            logger.debug("Ollama batch enrichment error: %s", exc)

    return enriched


# ── Provider discovery ───────────────────────────────────────────────────


def discover_provider_models(
    provider: str,
    base_url: str | None = None,
    enrich: bool = True,
) -> list[dict[str, Any]]:
    """Discover and optionally enrich all models for a provider.

    Returns list of model definition dicts compatible with ProviderProfile.models.
    """
    models = list_provider_models(provider, base_url)
    if not models:
        return []
    if enrich:
        enriched = enrich_all_models(provider, models, base_url)
        if enriched:
            return enriched
    return [build_model_definition(m.get("name", "")) for m in models]


# ── Model pulling (Ollama only) ──────────────────────────────────────────


def _parse_num_ctx(parameters: Any) -> int | None:
    """Extract num_ctx from Modelfile parameters string.

    OpenClaw pattern: parseOllamaNumCtxParameter().
    """
    if not isinstance(parameters, str) or not parameters.strip():
        return None
    last_value: int | None = None
    for line in parameters.splitlines():
        m = re.match(r"num_ctx\s+(\d+)", line.strip())
        if m:
            val = int(m.group(1))
            if val > 0:
                last_value = val
    return last_value


def pull_model(
    provider: str,
    model_name: str,
    base_url: str | None = None,
    on_status: Callable[[str, int | None], None] | None = None,
) -> tuple[bool, str]:
    """Pull a model for providers that support it (Ollama only for now).

    OpenClaw pattern: pullOllamaModelCore() with streaming NDJSON.

    Returns (ok: bool, message: str).
    """
    provider = provider.lower()
    if provider != "ollama":
        return False, f"Model pull not supported for {provider}"

    resolved = resolve_provider_url(provider, base_url)
    url = f"{resolved}/api/pull"
    if not _is_safe_url(url):
        return False, f"Blocked unsafe URL: {url}"

    try:
        with httpx.Client(timeout=httpx.Timeout(300.0)) as client:
            resp = client.post(url, json={"name": model_name}, timeout=30.0)
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
    provider: str,
    model_name: str,
    base_url: str | None = None,
    console: Any = None,
) -> bool:
    """Check if model exists; pull if missing (Ollama only).

    OpenClaw pattern: ensureOllamaModelPulled().
    Returns True if model is available.
    """
    provider = provider.lower()
    models = list_provider_models(provider, base_url)
    installed = [m.get("name", "") for m in models]
    check = model_name if ":" in model_name else f"{model_name}:latest"
    if check in installed or model_name in installed:
        return True

    if provider != "ollama":
        if console:
            console.print(
                f"[yellow]⚠ Model '{model_name}' not found — cannot auto-pull for {provider}[/yellow]"
            )
        return False

    if console:
        console.print(f"[dim]Model {model_name} not found locally — pulling...[/dim]")

    def _on_status(status: str, pct: int | None) -> None:
        if console and pct is not None:
            console.print(f"\r[dim]  {status} — {pct}%[/dim]", end="")
        elif console:
            console.print(f"\r[dim]  {status}[/dim]", end="")

    ok, msg = pull_model(provider, model_name, base_url, on_status=_on_status)
    if console:
        if ok:
            console.print(f"\r[green]✓ {msg}[/green]")
        else:
            console.print(f"\r[red]✗ {msg}[/red]")
    return ok


# ── Health check ─────────────────────────────────────────────────────────


def check_provider_health(provider: str, base_url: str | None = None) -> bool:
    """Check if a provider is reachable via its health endpoint."""
    provider = provider.lower()
    resolved = resolve_provider_url(provider, base_url)
    cfg = PROVIDER_DEFAULTS.get(provider)
    if not cfg:
        return False

    endpoint = cfg["health_endpoint"]
    url = f"{resolved}{endpoint}"
    resp = safe_http_get_raw(url, timeout=5.0)
    return resp is not None


__all__ = [
    "DEFAULT_CONTEXT_WINDOW",
    "DEFAULT_MAX_TOKENS",
    "safe_http_get",
    "safe_http_post",
    "safe_http_get_raw",
    "resolve_provider_url",
    "is_reasoning_model",
    "build_model_definition",
    "list_provider_models",
    "enrich_model",
    "enrich_all_models",
    "discover_provider_models",
    "pull_model",
    "ensure_model_pulled",
    "check_provider_health",
]
