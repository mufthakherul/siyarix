# SPDX-License-Identifier: AGPL-3.0-or-later
"""SX-012: webhook destination URL must reject SSRF-prone targets."""

from __future__ import annotations

import pytest

from siyarix.webhooks import _validate_url


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.slack.com/services/T00/B00/xxx",
        "https://discord.com/api/webhooks/1/token",
        "http://alerts.example.com/hook",
    ],
)
def test_validate_url_allows_public_https_hosts(url: str) -> None:
    _validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/hook",
        "http://192.168.1.1/hook",
        "https://10.0.0.5/x",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/hooks",
        "https://0.0.0.0/x",
        "https://localhost/hook",
        "https://metadata.google.internal/computeMetadata/v1/",
        "ftp://hooks.example.com/x",
        "https:///nohost",
    ],
)
def test_validate_url_rejects_ssrf_targets(url: str) -> None:
    with pytest.raises(ValueError):
        _validate_url(url)
