# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared hard-blocks for destructive shell payloads.

Used by the executor, ToolRegistry, PermissionGate patterns, and subprocess
last-line validation so registry/playbook/deep-scan paths cannot bypass
``BaseExecutor.check_destructive``.
"""

from __future__ import annotations

import re

from siyarix.exceptions import PermissionDeniedError

_FORK_BOMB_MARKERS = (":(){", "::&")
_ALLOWED_DD_OF = frozenset({"/dev/null", "/dev/zero"})
_RM_DESTRUCTIVE_RE = re.compile(
    r"\brm\b[\s]+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s*)+|\brm\b\s+--(?:recursive|force)",
    re.IGNORECASE,
)
_SYSTEM_RM_ROOTS = frozenset(
    {
        "/etc",
        "/var",
        "/bin",
        "/sbin",
        "/usr",
        "/home",
        "/boot",
        "/root",
        "/opt",
        "/lib",
        "/lib64",
    }
)
_ROOT_EQUIV = frozenset({"/", "/*", "/.", "/./", "//", "///"})
_PARTITION_RE = re.compile(
    r"\b(mkfs(?:\.\w+)?|fdisk|sfdisk|cfdisk|gdisk|sgdisk|parted|mkswap|"
    r"ntfsformat|mkntfs|newfs(?:_\w+)?)\b",
    re.IGNORECASE,
)
_DD_OF_RE = re.compile(r"\bof=(\S+)", re.IGNORECASE)
_DD_WORD_RE = re.compile(r"\b(?:dd|dc3dd|ddrescue)\b", re.IGNORECASE)

# Block-device node paths (sd / nvme / vd / xvd / hd / loop / dm / mapper).
_BLOCK_DEV_RE = re.compile(
    r"/dev/(?:sd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|vd[a-z]\d*|xvd[a-z]\d*|hd[a-z]\d*"
    r"|loop\d+|dm-\d+|mapper/\S+)",
    re.IGNORECASE,
)
_BLOCK_WIPE_TOOLS_RE = re.compile(
    r"\b(wipefs|sgdisk|blkdiscard|shred|truncate|openssl|install|"
    r"hdparm|nvme|cryptsetup|sg_format|sg_sanitize)\b",
    re.IGNORECASE,
)
_CP_TEE_TO_BLOCK_RE = re.compile(
    r"\b(?:cp|tee|cat|dd|dc3dd|ddrescue|install|pv|openssl|tar|badblocks|fio|rsync)\b"
    r"[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_REDIRECT_TO_BLOCK_RE = re.compile(
    r">\s*" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_FIND_DELETE_RE = re.compile(
    r"\bfind\b[\s\S]{0,400}(?:-delete\b|-exec\s+rm\b)",
    re.IGNORECASE,
)
# Matched after quote-stripping, so paths appear as bare ``/`` (not ``'/'``).
_INTERPRETER_WIPE_RE = re.compile(
    r"(?:"
    r"shutil\s*\.\s*rmtree\s*\(\s*/"
    r"|os\s*\.\s*(?:remove|unlink|rmdir)\s*\(\s*/"
    r"|Path\s*\(\s*/?\s*\)\s*\.\s*(?:unlink|rmdir)"
    r"|pathlib\s*\.\s*Path\s*\(\s*/?\s*\)\s*\.\s*(?:unlink|rmdir)"
    r"|FileUtils\s*\.\s*rm_rf\s*\(?\s*/"
    r"|unlink\s+(?:q(?:w)?\()?\s*/"  # perl unlink /… or unlink q(/…)
    r"|rmSync\s*\(\s*/"
    r"|fs\s*\.\s*(?:rmSync|rmdirSync|unlinkSync)\s*\(\s*/"
    r")",
    re.IGNORECASE,
)
_INTERPRETER_DEV_WRITE_RE = re.compile(
    r"(?:"
    r"open\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"|File\.write\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"|IO\.write\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"|writeFile(?:Sync)?\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"|file_put_contents\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"|Path\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"[\s\S]{0,80}\.write_(?:bytes|text)\s*\("
    r"|pathlib\s*\.\s*Path\s*\(\s*/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)"
    r"[\s\S]{0,80}\.write_(?:bytes|text)\s*\("
    r")",
    re.IGNORECASE,
)
_RSYNC_DELETE_RE = re.compile(
    r"\brsync\b[\s\S]{0,200}--delete(?:-\w+)?\b",
    re.IGNORECASE,
)
_QEMU_IMG_BLOCK_RE = re.compile(
    r"\bqemu-img\b[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_MV_SYSTEM_RE = re.compile(
    r"\bmv\b\s+(?:-[^\s]+\s+)*(\S+)\s+(\S+)",
    re.IGNORECASE,
)
# Recursive flag may appear before or after mode/owner (``chmod -R … /``,
# ``chmod … -R /``, combined ``-Rf``).
_CHMOD_CHOWN_CMD_RE = re.compile(r"\b(?:chmod|chown|chgrp)\b", re.IGNORECASE)
_RECURSE_FLAG_RE = re.compile(
    r"(?:-[a-zA-Z]*R[a-zA-Z]*\b|--recursive\b)",
    re.IGNORECASE,
)
_DOWNLOAD_TO_BLOCK_RE = re.compile(
    r"\b(?:curl|wget|busybox|fetch|aria2c)\b[\s\S]{0,220}"
    r"(?:-o|--output(?:-document)?|-O)(?:=|\s+)"
    + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_AUTH_FILE_RE = re.compile(r"/etc/(?:passwd|shadow|sudoers|group)\b", re.IGNORECASE)
_LN_NULL_AUTH_RE = re.compile(
    r"\bln\b[\s\S]{0,80}/dev/null[\s\S]{0,80}" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_CP_TO_AUTH_RE = re.compile(
    r"\bcp\b\s+(?:-[^\s]+\s+)*\S+\s+" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_REDIRECT_TO_AUTH_RE = re.compile(
    r"(?:(?:>{1,2}|\btee\b)\s*" + _AUTH_FILE_RE.pattern + r")"
    r"|(?:\b(?:truncate|shred|install)\b[\s\S]{0,80}" + _AUTH_FILE_RE.pattern + r")",
    re.IGNORECASE,
)
_VOLUME_DESTROY_RE = re.compile(
    r"(?:"
    r"\bzpool\s+destroy\b"
    r"|\bzfs\s+destroy\b"
    r"|\blvremove\b"
    r"|\bvgremove\b"
    r"|\bpvremove\b"
    r"|\bdmsetup\s+remove(?:_all)?\b"
    r"|\bmdadm\b[\s\S]{0,80}--zero-superblock\b"
    r"|\bbtrfs\s+(?:subvolume\s+delete|filesystem\s+resize)\b"
    r"|\bxfs_repair\s+[^\n]*-L\b"
    r"|\bdebugfs\s+-w\b"
    r")",
    re.IGNORECASE,
)


def _strip_shell_quotes(text: str) -> str:
    """Remove ``'`` / ``"`` so ``m'k'fs`` collapses to ``mkfs`` before matching."""
    return text.replace("'", "").replace('"', "")


def _normalize_path_token(tok: str) -> str:
    """Strip quotes and collapse trivial root equivalents."""
    t = tok.strip().strip("'\"")
    # Collapse repeated slashes and trailing "/." noise for root checks.
    while "//" in t:
        t = t.replace("//", "/")
    if t.endswith("/.") and t != "/.":
        t = t[:-2] or "/"
    if t in _ROOT_EQUIV or t in {"/.", "/./", "//", "///"}:
        return "/"
    # "/." and "/./" already covered; bare "." after strip of leading slash
    if t in {".", "./"}:
        return t
    return t


def _targets_system_path(cmd_clean: str) -> bool:
    """True when *cmd_clean* names ``/``, ``/*``, or a critical system root.

    Uses token boundaries so ``/tmp`` is not treated as ``/`` (substring trap).
    """
    for raw in cmd_clean.split():
        if raw.startswith("-") or raw in {"rm", "sudo", "doas", "--", "find"}:
            continue
        tok = _normalize_path_token(raw)
        if tok in {"/", "/*"} or tok in _ROOT_EQUIV:
            return True
        for root in _SYSTEM_RM_ROOTS:
            if tok == root or tok.startswith(root + "/"):
                return True
    return False


def _targets_block_device(cmd_clean: str) -> bool:
    return bool(_BLOCK_DEV_RE.search(cmd_clean))


def assert_command_not_destructive(command: str) -> None:
    """Raise :class:`PermissionDeniedError` for fork bombs, disk wipes, and mkfs/fdisk."""
    raw = (command or "").strip().lower()
    if not raw:
        return
    # Collapse shell quote-splitting evasion (m'k'fs → mkfs) before matching.
    cmd_clean = _strip_shell_quotes(raw)

    if any(marker in cmd_clean for marker in _FORK_BOMB_MARKERS):
        raise PermissionDeniedError(
            "Destructive command detected: Fork bomb execution is blocked."
        )

    if _DD_WORD_RE.search(cmd_clean):
        of_matches = _DD_OF_RE.findall(cmd_clean)
        if of_matches:
            of_target = _normalize_path_token(of_matches[-1])  # last ``of=`` wins
            if of_target.startswith("/dev/") and of_target not in _ALLOWED_DD_OF:
                raise PermissionDeniedError(
                    "Destructive command detected: Overwriting block devices is blocked."
                )

    # Non-dd block-device wipes / copies / redirects onto disks.
    if _targets_block_device(cmd_clean) and (
        _BLOCK_WIPE_TOOLS_RE.search(cmd_clean)
        or _CP_TEE_TO_BLOCK_RE.search(cmd_clean)
        or _REDIRECT_TO_BLOCK_RE.search(cmd_clean)
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )

    if _FIND_DELETE_RE.search(cmd_clean) and _targets_system_path(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: find -delete on system paths is blocked."
        )

    if _RM_DESTRUCTIVE_RE.search(cmd_clean) and _targets_system_path(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Deleting system directory is blocked."
        )

    if _INTERPRETER_WIPE_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Interpreter wipe of system paths is blocked."
        )

    if _INTERPRETER_DEV_WRITE_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Interpreter write to block devices is blocked."
        )

    if _QEMU_IMG_BLOCK_RE.search(cmd_clean) or _DOWNLOAD_TO_BLOCK_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )

    if _RSYNC_DELETE_RE.search(cmd_clean) and _targets_system_path(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: rsync --delete on system paths is blocked."
        )

    mv_match = _MV_SYSTEM_RE.search(cmd_clean)
    if mv_match:
        src = _normalize_path_token(mv_match.group(1))
        system_src = src in {"/", "/*"} or src in _ROOT_EQUIV or src in _SYSTEM_RM_ROOTS
        if not system_src:
            system_src = any(
                src == root or src.startswith(root + "/") for root in _SYSTEM_RM_ROOTS
            )
        if system_src:
            raise PermissionDeniedError(
                "Destructive command detected: Moving system directories is blocked."
            )

    if (
        _LN_NULL_AUTH_RE.search(cmd_clean)
        or _CP_TO_AUTH_RE.search(cmd_clean)
        or _REDIRECT_TO_AUTH_RE.search(cmd_clean)
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting auth files is blocked."
        )

    if _CHMOD_CHOWN_CMD_RE.search(cmd_clean) and _RECURSE_FLAG_RE.search(cmd_clean):
        for raw in cmd_clean.split():
            if raw.startswith("-"):
                continue
            path_tok = _normalize_path_token(raw)
            if path_tok in {"/", "/*"} or path_tok in _ROOT_EQUIV:
                raise PermissionDeniedError(
                    "Destructive command detected: Recursive chmod/chown on / is blocked."
                )

    if _VOLUME_DESTROY_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Volume/array destroy is blocked."
        )

    if _PARTITION_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Formatting storage devices is blocked."
        )


__all__ = ["assert_command_not_destructive"]
