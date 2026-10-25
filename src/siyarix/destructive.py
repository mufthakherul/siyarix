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
_DD_WORD_RE = re.compile(
    r"\b(?:dd|dc3dd|ddrescue|dcfldd|gddrescue)\b",
    re.IGNORECASE,
)

# Block-device node paths (Linux + macOS + RAID/flash/virt).
_BLOCK_DEV_RE = re.compile(
    r"/dev/(?:sd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|vd[a-z]\d*|xvd[a-z]\d*|hd[a-z]\d*"
    r"|loop\d+|dm-\d+|mapper/\S+|disk/\S+|disk\d+(?:s\d+)?|rdisk\d+(?:s\d+)?"
    r"|block/\S+|root\b|sg\d+|nbd\d+|mmcblk\d+(?:p\d+)?|md\d+|md/\S+"
    r"|zram\d+|ram\d+|fd\d+|mtdblock\d+|mtd\d+|pmem\d+|drbd\d+|rbd\d+"
    r"|dasd[a-z]\d*|cciss/\S+)",
    re.IGNORECASE,
)
_BLOCK_WIPE_TOOLS_RE = re.compile(
    r"\b(wipefs|sgdisk|blkdiscard|shred|truncate|openssl|install|"
    r"hdparm|nvme|cryptsetup|sg_format|sg_sanitize|nwipe|scrub|sg_unmap|"
    r"dwipe|mop)\b",
    re.IGNORECASE,
)
_FILE_WIPE_TOOLS_RE = re.compile(r"\b(?:srm|wipe|bcwipe)\b", re.IGNORECASE)
_OS_SYSTEM_WIPE_RE = re.compile(
    r"(?:os\s*\.\s*(?:system|popen)|subprocess\s*\.\s*(?:call|run|Popen|check_call))"
    r"\s*\([^)]*(?:\brm\b|\bdd\b|\bmkfs\b|/dev/(?:sd|nvme|disk/)|rmtree)",
    re.IGNORECASE,
)
_CP_TEE_TO_BLOCK_RE = re.compile(
    r"\b(?:cp|tee|cat|dd|dc3dd|ddrescue|dcfldd|gddrescue|install|pv|openssl|"
    r"tar|badblocks|fio|rsync)\b"
    r"[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_REDIRECT_TO_BLOCK_RE = re.compile(
    r">\s*" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_FIND_DELETE_RE = re.compile(
    r"\bfind\b[\s\S]{0,400}"
    r"(?:-delete\b|-exec\s+(?:rm|shred|wipe|srm|dd|bcwipe|nwipe|unlink)\b|"
    r"-ok\s+(?:rm|unlink)\b)",
    re.IGNORECASE,
)
# Matched after quote-stripping, so paths appear as bare ``/`` (not ``'/'``).
_INTERPRETER_WIPE_RE = re.compile(
    r"(?:"
    r"(?:shutil\s*\.\s*)?rmtree\s*\(\s*/"
    r"|os\s*\.\s*(?:remove|unlink|rmdir)\s*\(\s*/"
    r"|Path\s*\(\s*/(?:etc|var|usr|home|boot|root|opt|lib(?:64)?|bin|sbin)?/?\s*\)"
    r"\s*\.\s*(?:unlink|rmdir|rmtree)"
    r"|pathlib\s*\.\s*Path\s*\(\s*/(?:etc|var|usr|home|boot|root|opt|lib(?:64)?|"
    r"bin|sbin)?/?\s*\)\s*\.\s*(?:unlink|rmdir|rmtree)"
    r"|FileUtils\s*\.\s*rm_rf\s*\(?\s*/"
    r"|unlink\s+(?:q(?:w)?\()?\s*/"  # perl unlink /… or unlink q(/…)
    r"|rmSync\s*\(\s*/"
    r"|fs\s*\.\s*(?:rmSync|rmdirSync|unlinkSync)\s*\(\s*/"
    r")",
    re.IGNORECASE,
)
_INTERPRETER_DEV_WRITE_RE = re.compile(
    r"(?:"
    r"open\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"|File\.write\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"|IO\.write\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"|writeFile(?:Sync)?\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"|file_put_contents\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"|urlretrieve\s*\([^)]*" + _BLOCK_DEV_RE.pattern
    + r"|Path\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"[\s\S]{0,80}\.write_(?:bytes|text)\s*\("
    + r"|pathlib\s*\.\s*Path\s*\(\s*" + _BLOCK_DEV_RE.pattern
    + r"[\s\S]{0,80}\.write_(?:bytes|text)\s*\("
    + r")",
    re.IGNORECASE,
)
_GPG_OPENSSL_OUT_BLOCK_RE = re.compile(
    r"\b(?:gpg|openssl)\b[\s\S]{0,160}(?:--output|-out)\s*"
    + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_OPENSSL_OUT_AUTH_RE = re.compile(
    r"\bopenssl\b[\s\S]{0,160}(?:-out|--out)\s*" + r"/etc/(?:passwd|shadow|sudoers|group)\b",
    re.IGNORECASE,
)
# Capture extract destinations; normalize before comparing to ``/``.
# Long options first; ``\b`` after short flags so ``-C`` does not match inside ``--chdir``.
_EXTRACT_DEST_RE = re.compile(
    r"(?:"
    r"\b(?:tar|bsdtar|star)\b[\s\S]{0,160}"
    r"(?:--directory|--chdir|--cd|-C)\b(?:=|\s*)(\S+)"
    r"|\bunzip\b[\s\S]{0,100}(?:--directory|-d)\b(?:=|\s*)(\S+)"
    r"|\b(?:7z|7za|7zr|7zz)\b[\s\S]{0,100}-o(\S*)"
    r"|\bcpio\b[\s\S]{0,100}(?:--directory|-D)\b(?:=|\s*)(\S+)"
    r")",
    re.IGNORECASE,
)
_UNRAR_CMD_RE = re.compile(r"\b(?:unrar|unar|rar)\b", re.IGNORECASE)
_RSYNC_DELETE_RE = re.compile(
    r"\brsync\b[\s\S]{0,200}(?:--delete(?:-\w+)?|--remove-source-files)\b",
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
    r"(?:"
    r"\b(?:curl|wget|busybox|fetch|aria2c|axel|http|httpie|yt-dlp|youtube-dl|lftp)\b"
    r"[\s\S]{0,220}"
    r"(?:-o|--output(?:-document)?|--out|--index-out|-O)(?:=|\s*)(?:\d+=)?"
    + _BLOCK_DEV_RE.pattern
    + r"|\blwp-download\b[\s\S]{0,200}"
    + _BLOCK_DEV_RE.pattern
    + r"|\brclone\b[\s\S]{0,200}"
    + _BLOCK_DEV_RE.pattern
    + r"|\b(?:scp|sftp)\b[\s\S]{0,200}"
    + _BLOCK_DEV_RE.pattern
    + r"|\b(?:zstd|pzstd|lz4|xz)\b[\s\S]{0,100}(?:-o|--output)(?:=|\s*)"
    + _BLOCK_DEV_RE.pattern
    + r"|\b(?:split|csplit)\b[\s\S]{0,100}(?:-f|--prefix)(?:=|\s*)"
    + _BLOCK_DEV_RE.pattern
    + r"|\bsplit\b[\s\S]{0,160}\s"
    + _BLOCK_DEV_RE.pattern
    + r"(?:\s|$)"
    + r")",
    re.IGNORECASE,
)
_CMAKE_COPY_BLOCK_RE = re.compile(
    r"\bcmake\b[\s\S]{0,80}-E\s+copy(?:_if_different)?\b[\s\S]{0,200}"
    + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
# curl/wget/aria2c writing under /dev via separate --dir / -o filename.
_DOWNLOAD_DIR_DEV_RE = re.compile(
    r"\b(?:curl|wget|aria2c)\b[\s\S]{0,220}"
    r"(?:--output-dir|--directory-prefix|--dir|-d)(?:=|\s+)/dev(?:/|\s|$)",
    re.IGNORECASE,
)
_SOCAT_BLOCK_RE = re.compile(
    r"\bsocat\b[\s\S]{0,220}(?:OPEN|CREATE):" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_WINDOWS_WIPE_RE = re.compile(
    r"(?:"
    r"\\\\\.\\physicaldrive\d+"
    r"|\bof=\\\\\.\\physicaldrive"
    r"|\bformat\s+[a-z]\s*:"
    r"|\bclear-disk\b"
    r"|\bclear-partition\b"
    r"|\bformat-volume\b"
    r"|\binitialize-disk\b"
    r"|\bremove-partition\b"
    r"|\breset-physicaldisk\b"
    r"|\bremove-physicaldisk\b"
    r"|\bsdelete(?:64)?\b"
    r"|\bcipher\b[\s\S]{0,60}/w"
    r")",
    re.IGNORECASE,
)
_DISKUTIL_WIPE_RE = re.compile(
    r"\bdiskutil\b[\s\S]{0,100}"
    r"(?:erasedisk|erasevolume|secureerase|zerodisk|partitiondisk|"
    r"apfs\s+delete(?:container|volume))",
    re.IGNORECASE,
)
_ASR_ERASE_RE = re.compile(
    r"\basr\b[\s\S]{0,220}(?:--erase\b|" + _BLOCK_DEV_RE.pattern + r")",
    re.IGNORECASE,
)
_HDIUTIL_BLOCK_RE = re.compile(
    r"\bhdiutil\b[\s\S]{0,160}" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_WMIC_FORMAT_RE = re.compile(
    r"\bwmic\b[\s\S]{0,100}(?:diskdrive|volume|logicaldisk)[\s\S]{0,80}format",
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
_DD_OF_AUTH_RE = re.compile(
    r"\b(?:dd|dc3dd|ddrescue)\b[\s\S]{0,120}\bof=" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_INTERPRETER_AUTH_WRITE_RE = re.compile(
    r"(?:"
    r"open\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|File\.write\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|IO\.write\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|writeFile(?:Sync)?\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|file_put_contents\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|File\.open\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|urlretrieve\s*\([^)]*" + _AUTH_FILE_RE.pattern
    + r")",
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
    """Strip quotes, resolve ``..``/``.`` lexically, collapse root equivalents."""
    t = tok.strip().strip("'\"")
    # Drop trailing shell punctuation glued after quote-strip
    # (e.g. ``system(rm -rf /)`` → token ``/)``).
    t = t.rstrip(")]}',\";:")
    # Collapse repeated slashes before segment walk.
    while "//" in t:
        t = t.replace("//", "/")
    if t.endswith("/.") and t != "/.":
        t = t[:-2] or "/"
    # Lexical ``..`` / ``.`` resolution so ``/tmp/../`` and ``/etc/..`` → ``/``.
    if "/" in t or t in {".", ".."}:
        abs_path = t.startswith("/")
        parts: list[str] = []
        for seg in t.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        if abs_path:
            t = "/" + "/".join(parts) if parts else "/"
        else:
            t = "/".join(parts) if parts else "."
    if t in _ROOT_EQUIV or t in {"/.", "/./", "//", "///"}:
        return "/"
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


def _is_dangerous_extract_dest(tok: str, *, absolute_any: bool = False) -> bool:
    """True for ``/``, root aliases, system roots, or (7z) any absolute path."""
    norm = _normalize_path_token(tok)
    if norm in {"/", "/*"} or norm in _ROOT_EQUIV:
        return True
    if absolute_any and norm.startswith("/"):
        return True
    if norm in _SYSTEM_RM_ROOTS:
        return True
    return any(norm.startswith(root + "/") for root in _SYSTEM_RM_ROOTS)


def _is_extract_to_root(cmd_clean: str) -> bool:
    """True when an archiver targets ``/`` (incl. ``/tmp/../``, ``/.``, ``//``)."""
    for match in _EXTRACT_DEST_RE.finditer(cmd_clean):
        groups = match.groups()
        dest = next((g for g in groups if g is not None), None)
        if dest is None:
            continue
        # groups[2] is the 7-Zip ``-o`` destination — block any absolute path.
        seven_zip = groups[2] is not None
        if _is_dangerous_extract_dest(dest, absolute_any=seven_zip):
            return True
    if _UNRAR_CMD_RE.search(cmd_clean):
        for raw in reversed(cmd_clean.split()[1:]):
            if raw.startswith("-"):
                continue
            return _is_dangerous_extract_dest(raw)
    return False


def assert_command_not_destructive(command: str) -> None:
    """Raise :class:`PermissionDeniedError` for fork bombs, disk wipes, and mkfs/fdisk."""
    raw = (command or "").strip().lower()
    if not raw:
        return
    # Collapse shell quote-splitting evasion (m'k'fs → mkfs) before matching.
    quoted_clean = _strip_shell_quotes(raw)
    # Windows device paths use backslashes — probe them before stripping.
    if _WINDOWS_WIPE_RE.search(quoted_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )
    # Strip remaining escapes (``\/`` → ``/``) so ``exec(...rmtree(\"/\")`` matches.
    # Normalize list-argv commas (``['rm','-rf','/']`` → ``rm -rf /``).
    cmd_clean = re.sub(r"\s*,\s*", " ", quoted_clean.replace("\\", ""))

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
            if _AUTH_FILE_RE.search(of_target):
                raise PermissionDeniedError(
                    "Destructive command detected: Overwriting auth files is blocked."
                )

    # Non-dd block-device wipes / copies / redirects onto disks.
    if _targets_block_device(cmd_clean) and (
        _BLOCK_WIPE_TOOLS_RE.search(cmd_clean)
        or _CP_TEE_TO_BLOCK_RE.search(cmd_clean)
        or _REDIRECT_TO_BLOCK_RE.search(cmd_clean)
        or _FILE_WIPE_TOOLS_RE.search(cmd_clean)
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )

    if _FIND_DELETE_RE.search(cmd_clean) and _targets_system_path(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: find -delete on system paths is blocked."
        )

    if (
        _RM_DESTRUCTIVE_RE.search(cmd_clean) or _FILE_WIPE_TOOLS_RE.search(cmd_clean)
    ) and _targets_system_path(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Deleting system directory is blocked."
        )

    if _INTERPRETER_WIPE_RE.search(cmd_clean) or _OS_SYSTEM_WIPE_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Interpreter wipe of system paths is blocked."
        )

    if _INTERPRETER_DEV_WRITE_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Interpreter write to block devices is blocked."
        )

    if (
        _QEMU_IMG_BLOCK_RE.search(cmd_clean)
        or _DOWNLOAD_TO_BLOCK_RE.search(cmd_clean)
        or _DOWNLOAD_DIR_DEV_RE.search(cmd_clean)
        or _CMAKE_COPY_BLOCK_RE.search(cmd_clean)
        or _GPG_OPENSSL_OUT_BLOCK_RE.search(cmd_clean)
        or _SOCAT_BLOCK_RE.search(cmd_clean)
        or _DISKUTIL_WIPE_RE.search(cmd_clean)
        or _ASR_ERASE_RE.search(cmd_clean)
        or _HDIUTIL_BLOCK_RE.search(cmd_clean)
        or _WMIC_FORMAT_RE.search(cmd_clean)
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )

    if _is_extract_to_root(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Extracting archives onto / is blocked."
        )

    if _RSYNC_DELETE_RE.search(cmd_clean) and _targets_system_path(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: rsync delete/remove on system paths is blocked."
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
        or _DD_OF_AUTH_RE.search(cmd_clean)
        or _INTERPRETER_AUTH_WRITE_RE.search(cmd_clean)
        or _OPENSSL_OUT_AUTH_RE.search(cmd_clean)
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
