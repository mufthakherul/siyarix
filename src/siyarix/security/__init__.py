# SPDX-License-Identifier: AGPL-3.0-or-later

"""Security subsystem — attack path analysis, RBAC, compliance."""

from .attack_path import AttackPathAnalyzer

__all__ = [
    "AttackPathAnalyzer",
]
