#!/usr/bin/env python3
"""Siyarix initialization wizard — sets up credential store and configuration.

Usage:
  python init_siyarix.py                          # interactive setup
  python init_siyarix.py --provider gemini --key <key>  # quick setup
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path


def ensure_config_dir() -> Path:
    config_dir = Path.home() / ".siyarix"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def initialize_interactive() -> int:
    from siyarix.credential_store import CredentialStore

    print("=== Siyarix Initialization Wizard ===\n")

    master_pass = getpass.getpass("Enter a master password for credential store: ")
    if not master_pass:
        print("Error: Master password cannot be empty.", file=sys.stderr)
        return 1

    confirm = getpass.getpass("Confirm master password: ")
    if master_pass != confirm:
        print("Error: Passwords do not match.", file=sys.stderr)
        return 1

    store = CredentialStore(master_password=master_pass)

    provider = (
        input("AI provider to configure (e.g., openai, gemini, anthropic) [openai]: ").strip()
        or "openai"
    )
    api_key = getpass.getpass(f"Enter your {provider} API key: ")
    if api_key:
        store.store(provider, api_key, "api_key")
        print(f"  ✓ {provider} API key stored securely")
    else:
        print("  - Skipped API key (can be configured later)")

    print(f"\n✓ Siyarix initialized at {ensure_config_dir()}")
    print("  Run 'siyarix --help' to get started.")
    return 0


def initialize_quick(provider: str, api_key: str) -> int:
    from siyarix.credential_store import CredentialStore

    master_pass = os.environ.get("SIYARIX_MASTER_PASSWORD") or provider + "_master"
    store = CredentialStore(master_password=master_pass)
    store.store(provider, api_key, "api_key")
    print(f"✓ {provider} API key stored")
    print("✓ Siyarix initialized successfully")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Siyarix initialization wizard")
    parser.add_argument("--provider", help="AI provider name for quick setup")
    parser.add_argument("--key", help="API key for quick setup")
    args = parser.parse_args()

    if args.provider and args.key:
        return initialize_quick(args.provider, args.key)
    elif args.provider or args.key:
        print("Error: Both --provider and --key are required together.", file=sys.stderr)
        return 1
    else:
        return initialize_interactive()


if __name__ == "__main__":
    sys.exit(main())
