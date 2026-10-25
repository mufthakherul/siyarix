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
        "find /tmp -delete",
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
        "rm -rf /.",
        'rm -rf "/"',
        "rm -rf //",
        "rm -rf /./",
        "rm -rf /boot",
        "rm -rf /root",
        "rm -rf /opt",
        "find / -delete",
        "find /etc -name '*' -delete",
        "find / -exec rm -rf {} +",
        "cp /dev/zero /dev/sda",
        "tee /dev/sda < /dev/zero",
        "wipefs -a /dev/sda",
        "sgdisk --zap-all /dev/sda",
        "blkdiscard /dev/sda",
        "shred -n 1 /dev/sdb",
        "python -c \"import shutil; shutil.rmtree('/')\"",
        "python -c 'import shutil; shutil.rmtree(\"/etc\")'",
        "truncate -s 0 /dev/sda",
        "install /dev/zero /dev/sda",
        "openssl enc -in /dev/zero -out /dev/sda",
        "perl -e \"unlink q(/etc/passwd)\"",
        "ruby -e \"FileUtils.rm_rf '/'\"",
        "node -e \"require('fs').rmSync('/',{recursive:true})\"",
        "chmod -R 777 /",
        "chmod -R 777 /*",
        "chmod -R 777 /.",
        "chmod --recursive 755 /./",
        "chown -R nobody: /",
        "chown -R root:root /*",
        "hdparm --security-erase NULL /dev/sda",
        "nvme format /dev/nvme0n1",
        "cryptsetup luksErase /dev/sda",
        "sfdisk /dev/sda",
        "gdisk /dev/sda",
        "cfdisk /dev/sda",
        "tar -cvf /dev/sda /tmp",
        "dc3dd if=/dev/zero of=/dev/sda",
        "badblocks -w /dev/sda",
        "fio --filename=/dev/sda --rw=write",
        "rsync -a /dev/zero /dev/sda",
        "rsync -a /tmp/x /dev/nvme0n1",
        "ntfsformat /dev/sda",
        "mkntfs /dev/sda1",
        "newfs /dev/sda1",
        "newfs_msdos /dev/sda1",
        "python -c \"open('/dev/sda','wb').write(b'x')\"",
        "ruby -e \"File.write('/dev/sda','x')\"",
        "node -e \"require('fs').writeFileSync('/dev/sda','x')\"",
        "php -r \"file_put_contents('/dev/sda','x');\"",
        "m'k'fs.ext4 /dev/sda",
        "zpool destroy tank",
        "zfs destroy -r tank/ds",
        "lvremove -f /dev/mapper/vg-lv",
        "mdadm --zero-superblock /dev/sda",
        "btrfs subvolume delete /",
        "pvremove /dev/sda",
        "dmsetup remove_all",
        "xfs_repair -L /dev/sda1",
        "debugfs -w /dev/sda1 -R rm",
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
    with pytest.raises(PermissionDeniedError, match="find -delete"):
        ex.check_destructive("find / -delete")
