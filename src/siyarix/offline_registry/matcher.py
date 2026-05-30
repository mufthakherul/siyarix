# SPDX-License-Identifier: AGPL-3.0-or-later

"""Trigger matching for offline responses — exact, fuzzy, and regex."""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .registry import ResponseEntry

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLD: float = 0.75


def _best_fuzzy_score(query: str, candidates: list[str]) -> float:
    best = 0.0
    q_lower = query.lower()
    for c in candidates:
        c_lower = c.lower()
        score = SequenceMatcher(None, q_lower, c_lower).ratio()
        if score > best:
            best = score
    return best


def match_entry(
    query: str,
    entry: ResponseEntry,
    threshold: float = _DEFAULT_THRESHOLD,
) -> float:
    """Return a match score (0.0 – 1.0) for *query* against *entry*.

    Checks in order:
      1. Exact trigger match       → 1.0
      2. Regex pattern match       → 1.0
      3. Fuzzy trigger match       → SequenceMatcher ratio (clamped)
    Returns 0.0 if nothing matched.
    """
    q_lower = query.lower().strip()

    # 1. Exact match against any trigger
    for t in entry.triggers:
        if q_lower == t.lower():
            return 1.0

    # 2. Regex pattern match
    for pat in entry.patterns:
        try:
            if re.search(pat, q_lower):
                return 1.0
        except re.error as exc:
            logger.debug("Invalid regex pattern %r: %s", pat, exc)

    # 3. Fuzzy match against triggers
    score = _best_fuzzy_score(q_lower, entry.triggers)
    if score >= threshold:
        return score

    return 0.0


def best_match(
    query: str,
    entries: list[ResponseEntry],
    threshold: float = _DEFAULT_THRESHOLD,
) -> ResponseEntry | None:
    """Return the highest-scoring entry for *query*, or ``None``."""
    best: tuple[float, ResponseEntry | None] = (0.0, None)
    for entry in entries:
        score = match_entry(query, entry, threshold=threshold)
        if score > best[0] or (
            score == best[0]
            and best[1] is not None
            and entry.priority > best[1].priority
        ):
            best = (score, entry)
    return best[1]
