# SPDX-License-Identifier: AGPL-3.0-or-later

"""Backward-compatible re-exports for ``siyarix.main``.

All functionality moved to ``siyarix/cli/``. This stub will be removed in v3.0.
"""

import warnings

from .cli import app  # noqa: F401, E402

warnings.warn(
    "siyarix.main is deprecated. Import from siyarix.cli directly.",
    DeprecationWarning,
    stacklevel=2,
)
