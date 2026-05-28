# SPDX-License-Identifier: AGPL-3.0-or-later

"""Optional Rust acceleration hooks (CA-10.3).

This module is intentionally lightweight: if the extension module is absent,
all callers transparently fall back to pure Python implementations.
"""

from __future__ import annotations

from typing import Any

try:
    import siyarix_rust_parsers as _rust  # pyright: ignore[reportMissingImports]
except Exception as exc:
    import logging

    logger = logging.getLogger(__name__)
    logger.debug("Rust extension not available: %s", exc)
    _rust = None


def rust_available() -> bool:
    return _rust is not None


def parse_nmap_xml(xml_output: str) -> list[dict[str, Any]] | None:
    if _rust is None:
        return None
    try:
        parsed = _rust.parse_nmap_xml(xml_output)
    except Exception as exc:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Rust parser failed: %s", exc)
        return None
    if isinstance(parsed, list):
        normalized: list[dict[str, Any]] = []
        for item in parsed:
            if isinstance(item, dict):
                normalized.append(item)
        return normalized
    return None
