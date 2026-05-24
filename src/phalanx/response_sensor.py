"""Response sensor utilities: masking before model calls, unmasking and redaction after."""
from __future__ import annotations

from typing import Any, Dict

from .masking import MaskingEngine
from .security_hardening import SecretRedactor, danger_analyzer


class ResponseSensor:
    """Helper that encapsulates masking/unmasking and redaction logic.

    Typical usage:
        rs = ResponseSensor()
        masked_text = rs.mask_for_model(text)
        raw = provider.plan(masked_text, masked_context)
        safe = rs.unmask_and_redact(raw)
    """

    def __init__(self) -> None:
        self._redactor = SecretRedactor()

    def mask_for_model(self, text: str | None, *, rules: Dict[str, str] | None = None) -> tuple[str, MaskingEngine]:
        """Return (masked_text, mask_engine)."""
        me = MaskingEngine()
        # Default rules: domain, ip, api keys
        me.add_rule("domain", r"[a-z0-9.-]+\.[a-z]{2,}")
        me.add_rule("ip", r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        me.add_rule("apikey", r"sk-[A-Za-z0-9]{24,}")
        # Additional rules can be supplied
        if rules:
            for name, regex in rules.items():
                me.add_rule(name, regex)

        masked = me.mask(text or "")
        return masked, me

    def unmask_and_redact(self, payload: Any, mask: MaskingEngine | None = None) -> Any:
        """Unmask tokens in `payload` (recursively) and redact secrets before returning."""
        def _unmask_obj(o: Any) -> Any:
            if isinstance(o, str):
                s = mask.unmask(o) if mask else o
                return self._redactor.redact(s)
            if isinstance(o, dict):
                return {k: _unmask_obj(v) for k, v in o.items()}
            if isinstance(o, list):
                return [_unmask_obj(i) for i in o]
            return o

        return _unmask_obj(payload)


__all__ = ["ResponseSensor"]
