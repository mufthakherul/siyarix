"""NexSec package shim — re-export from cosmicsec_agent for backwards compatibility.

This allows `import nexsec` while the current implementation lives in
`src/cosmicsec_agent`.
"""
from __future__ import annotations

from cosmicsec_agent import *  # noqa: F401,F403

__all__ = getattr(__import__("cosmicsec_agent"), "__all__", [])
