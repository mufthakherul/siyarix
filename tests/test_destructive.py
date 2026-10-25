"""Shared destructive command hard-blocks."""

from __future__ import annotations

import pytest

from siyarix.destructive import assert_command_not_destructive
from siyarix.exceptions import PermissionDeniedError
from siyarix.executor import BaseExecutor


@pytest.mark.parametrize(
    "command",
    [
        "echo hello",
        "dd if=/dev/zero of=/dev/null bs=1 count=1",
        "dd if=/dev/zero of=/tmp/out.img bs=1M count=1",
        "rm -rf /tmp/scratch",
        "rm -rf /important",  # non-system path; gate patterns may still flag
        "rm -rf /homebrew",  # must not match /home prefix
        "nmap -sV example.com",
    ],
)
def test_assert_allows_safe_commands(command: str) -> None:
    assert_command_not_destructive(command)


@pytest.mark.parametrize(
    "command",
    [
        ":(){ :|:& };:",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "dd of=/dev/null of=/dev/nvme0n1",  # last of= wins
        "sudo fdisk /dev/sda",
        "mkfs.ext4 /dev/sdb1",
        "parted /dev/sda mklabel gpt",
        "mkswap /dev/sda2",
        "rm -rf /",
        "rm -fr /etc",
        "rm --recursive --force /var",
    ],
)
def test_assert_blocks_destructive_commands(command: str) -> None:
    with pytest.raises(PermissionDeniedError):
        assert_command_not_destructive(command)


def test_base_executor_delegates_to_shared_helper() -> None:
    ex = BaseExecutor()
    with pytest.raises(PermissionDeniedError, match="block devices"):
        ex.check_destructive("dd of=/dev/sda if=/dev/zero")
    with pytest.raises(PermissionDeniedError, match="Formatting"):
        ex.check_destructive("fdisk /dev/sda")
