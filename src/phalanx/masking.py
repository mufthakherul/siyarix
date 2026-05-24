"""Session-scoped masking engine for bidirectional data masking.

Provides simple, deterministic masking and unmasking for sensitive
tokens (domains, IPs, API keys) used by planners and LLM providers.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple


@dataclass
class MaskRule:
    name: str
    pattern: Pattern[str]
    replacement: str | None = None


class MaskingEngine:
    """Simple session-scoped masking engine.

    Usage:
        me = MaskingEngine()
        me.add_rule("domain", r"(?P<domain>[a-z0-9.-]+\.[a-z]{2,})")
        masked = me.mask("scan xyz.com and api.xyz.com")
        unmasked = me.unmask(masked)
    """

    def __init__(self) -> None:
        self._rules: List[MaskRule] = []
        # deterministic maps for this session
        self._orig_to_token: Dict[str, str] = {}
        self._token_to_orig: Dict[str, str] = {}
        self._counter = 0

    def add_rule(self, name: str, regex: str, replacement: str | None = None) -> None:
        compiled = re.compile(regex, flags=re.IGNORECASE)
        self._rules.append(MaskRule(name=name, pattern=compiled, replacement=replacement))

    def _new_token(self) -> str:
        # stable-looking token per session
        self._counter += 1
        return f"__PHX_MASK_{self._counter:04d}__"

    def mask(self, text: str) -> str:
        """Return a masked version of `text` and record mappings."""
        if not text:
            return text

        # For each rule, replace matches with deterministic tokens
        def _replacer(match: re.Match, rule: MaskRule) -> str:
            orig = match.group(0)
            if orig in self._orig_to_token:
                return self._orig_to_token[orig]
            token = self._new_token()
            self._orig_to_token[orig] = token
            self._token_to_orig[token] = orig
            return token

        result = text
        for rule in self._rules:
            # Use callable replacement to capture each match
            result = rule.pattern.sub(lambda m, r=rule: _replacer(m, r), result)
        return result

    def unmask(self, text: str) -> str:
        """Reverse masking by replacing tokens with original values."""
        if not text:
            return text
        # Replace tokens with original values; tokens are safe ASCII
        def _token_replacer(match: re.Match) -> str:
            token = match.group(0)
            return self._token_to_orig.get(token, token)

        # Build token regex based on current mapping
        if not self._token_to_orig:
            return text
        token_pattern = re.compile("(" + "|".join(re.escape(t) for t in self._token_to_orig) + ")")
        return token_pattern.sub(_token_replacer, text)

    def reset(self) -> None:
        """Clear all session mappings and rules."""
        self._rules.clear()
        self._orig_to_token.clear()
        self._token_to_orig.clear()
        self._counter = 0

    def export_map(self) -> Dict[str, str]:
        """Return the mapping token -> original for persistence or auditing."""
        return dict(self._token_to_orig)


__all__ = ["MaskingEngine"]
