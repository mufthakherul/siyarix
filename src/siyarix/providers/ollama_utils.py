from __future__ import annotations

import logging
import os
import shutil
import subprocess

import httpx

logger = logging.getLogger(__name__)


def ensure_ollama_running() -> None:
    """Start Ollama in background if configured and not already running."""
    try:
        from ..config import SettingsStore

        settings = SettingsStore()
        provider = settings.get("model_provider") or ""
        should_start = settings.get("_start_ollama_on_launch", False) or provider == "ollama"
        if not should_start:
            return

        ollama_url = settings.get("ollama_url") or "http://localhost:11434"
        from ..provider_utils import _is_safe_url

        if not _is_safe_url(str(ollama_url)):
            logger.warning("Refusing unsafe ollama_url for auto-start probe: %s", ollama_url)
            return

        try:
            r = httpx.get(
                f"{str(ollama_url).rstrip('/')}/api/tags",
                timeout=3,
                follow_redirects=False,
            )
            if r.status_code < 500:
                return
        except Exception:
            logger.debug("Ollama not reachable at %s (launching background service)", ollama_url)

        if shutil.which("ollama"):
            kwargs: dict = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            subprocess.Popen(["ollama", "serve"], **kwargs)
    except Exception as e:
        logger.debug("Failed to lazy-start ollama: %s", e)


__all__ = [
    "ensure_ollama_running",
]
