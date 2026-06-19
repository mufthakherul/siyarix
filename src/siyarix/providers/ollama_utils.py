import os
import shutil
import subprocess

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
        import httpx
        
        try:
            r = httpx.get(f"{ollama_url}/api/tags", timeout=3)
            if r.status_code < 500:
                return
        except Exception:
            from rich.console import Console
            Console().print(f"[yellow]⚠ Ollama not reachable at {ollama_url} (launching background service)[/yellow]")
            
        if shutil.which("ollama"):
            if os.name == "nt":
                subprocess.Popen(
                    ["ollama", "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
    except Exception as e:
        import logging
        logging.getLogger(__name__).debug("Failed to lazy-start ollama: %s", e)
