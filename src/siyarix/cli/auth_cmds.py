# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authentication / API-key CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import os

import typer
from rich.console import Console
from rich.table import Table

from siyarix.cli.credentials import get_creds, store_key

console = Console()

auth_app = typer.Typer(help="🔑 Authentication & API keys")


@auth_app.command("set-key")
def auth_set_key(
    provider: str = typer.Argument(help="Provider: openai | gemini | anthropic | custom"),
    api_key: str = typer.Option(..., "--key", "-k", help="API key value", hide_input=True),
) -> None:
    """Store an API key for a model provider.

    Examples:
      siyarix auth set-key openai --key sk-...
      siyarix auth set-key gemini --key AIz...
      siyarix auth set-key anthropic --key sk-ant-...
    """
    store_key(provider, api_key)
    console.print(f"[green]✓ API key stored for provider: {provider}[/green]")
    console.print("[dim]Key is stored in the encrypted CredentialStore.[/dim]")


@auth_app.command("show")
def auth_show() -> None:
    """Show configured API key providers."""
    try:
        from siyarix.providers import ProviderManager

        pm = ProviderManager.get_instance()
        providers = pm.list_providers()
    except Exception:
        providers = ["openai", "gemini", "anthropic", "groq", "openrouter"]

    table = Table(title="Configured API Keys", show_header=True, header_style="bold green")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Source")

    for prov in providers:
        from siyarix.providers import get_provider_env_var

        env_key = get_provider_env_var(prov)
        from_env = bool(os.getenv(env_key))
        cs = get_creds()
        from_creds = bool(cs.retrieve(prov, "api_key")) if cs else False
        if from_env:
            status, source = "✓ Set", "Environment variable"
        elif from_creds:
            status, source = "✓ Set", "CredentialStore"
        else:
            status, source = "✗ Not set", "—"
        table.add_row(prov, status, source)

    console.print(table)
