# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator-safety hard-blocks for destructive shell payloads.

Siyarix accelerates authorized security research. These guards stop *accidental*
damage to the operator's own machine (disk wipe, auth-file clobber, fork bombs)
when an LLM/playbook emits a dangerous command. They do not block normal
research tooling (nmap, ssh, sqlmap, …).

Used by the executor, ToolRegistry, PermissionGate patterns, and subprocess
last-line validation so registry/playbook/deep-scan paths cannot bypass
``BaseExecutor.check_destructive``.
"""

from __future__ import annotations

import re

from siyarix.exceptions import PermissionDeniedError

_FORK_BOMB_RE = re.compile(
    r"(?:"
    r":\s*\(\s*\)\s*\{"  # classic :(){
    r"|::\s*&"
    # recursive ``bomb(){ bomb|bomb &};bomb``
    r"|\b(\w+)\s*\(\s*\)\s*\{[^}]{0,120}\b\1\s*\|\s*\1\s*&"
    r")",
    re.IGNORECASE,
)
_ALLOWED_DD_OF = frozenset({"/dev/null", "/dev/zero"})
_RM_WORD_RE = re.compile(r"\brm\b", re.IGNORECASE)
_RM_RECURSIVE_FLAG_RE = re.compile(
    r"(?:-[a-zA-Z]*r[a-zA-Z]*\b|--recursive\b)",
    re.IGNORECASE,
)
_RM_FORCE_FLAG_RE = re.compile(
    r"(?:-[a-zA-Z]*f[a-zA-Z]*\b|--force\b)",
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
    r"\b(mkfs(?:\.\w+)?|mke2fs|mkdosfs|fdisk|sfdisk|cfdisk|gdisk|sgdisk|parted|mkswap|"
    r"ntfsformat|mkntfs|newfs(?:_\w+)?)\b",
    re.IGNORECASE,
)
_DD_OF_RE = re.compile(r"\bof=(\S+)", re.IGNORECASE)
_DD_WORD_RE = re.compile(
    r"\b(?:g?dd|dc3dd|dd_?rescue|dcfldd|gddrescue|ddr|sg_dd)\b",
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
    r"\b(wipefs|sgdisk|blkdiscard|shred|truncate|openssl|g?install|"
    r"hdparm|nvme|cryptsetup|integritysetup|veritysetup|"
    r"sg_format|sg_sanitize|sg_write_same|sg_write_buffer|nwipe|scrub|sg_unmap|"
    r"dwipe|mop|partclone(?:\.\w+)?|ntfsclone|fsarchiver|e2image|partimage|"
    r"flashcp|ubiformat|make_ext4fs|flash_eraseall)\b",
    re.IGNORECASE,
)
_FILE_WIPE_TOOLS_RE = re.compile(r"\b(?:srm|wipe|bcwipe)\b", re.IGNORECASE)
_OS_SYSTEM_WIPE_RE = re.compile(
    r"(?:os\s*\.\s*(?:system|popen)|subprocess\s*\.\s*(?:call|run|Popen|check_call))"
    r"\s*\([^)]*(?:\brm\b|\bdd\b|\bmkfs\b|/dev/(?:sd|nvme|disk/)|rmtree)",
    re.IGNORECASE,
)
_CP_TEE_TO_BLOCK_RE = re.compile(
    r"\b(?:cp|tee|cat|g?dd|dc3dd|dd_?rescue|dcfldd|gddrescue|ddr|sg_dd|sg_write_same|"
    r"sg_write_buffer|g?install|pv|openssl|"
    r"tar|badblocks|fio|rsync|simg2img|bmaptool|partclone(?:\.\w+)?|ntfsclone|"
    r"fsarchiver|e2image|partimage|flashcp|ubiformat|make_ext4fs)\b"
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
    r"\b(?:gpg|openssl)\b[\s\S]{0,160}(?:--output|-out|-o)(?:=|\s*)"
    + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
_MISC_WRITE_BLOCK_RE = re.compile(
    r"(?:"
    r"\b(?:base64|brotli|unzstd|lz4|xz|gzip|gunzip|pigz|bzip2|lzop|lzma|lzip|plzip|lrzip)\b"
    r"[\s\S]{0,120}(?:-o|--output)(?:=|\s*)" + _BLOCK_DEV_RE.pattern
    + r"|\b(?:xxd|fallocate|flash_erase|nandwrite|ddrescue|uudecode|objcopy)\b"
    r"[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern
    + r"|\b(?:iconv|ffmpeg|convert|magick)\b[\s\S]{0,220}"
    + _BLOCK_DEV_RE.pattern
    + r"|\bgs\b[\s\S]{0,160}-sOutputFile=" + _BLOCK_DEV_RE.pattern
    + r"|\bsocat\b[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern
    # ``mksquashfs src /dev/sda`` — last positional block dest (RH-27).
    + r"|\bmksquashfs\b[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern
    + r")",
    re.IGNORECASE,
)
# Capture extract destinations; normalize before comparing to ``/``.
# Long options first; ``\b`` after short flags so ``-C`` does not match inside ``--chdir``.
_EXTRACT_DEST_RE = re.compile(
    r"(?:"
    r"\b(?:tar|gtar|bsdtar|star|pax)\b[\s\S]{0,160}"
    r"(?:--directory|--chdir|--cd|-C)\b(?:=|\s*)(\S+)"
    # ``-d DIR``, ``-d/``, ``--directory=DIR``, and glued ``-od /`` (overwrite+directory).
    # ``(?![a-zA-Z])`` after ``d`` prevents matching inside ``--directory``.
    r"|\bunzip\b[\s\S]{0,100}(?:--directory(?:=|\s*)|-[a-zA-Z]*d(?![a-zA-Z])(?:=|\s*))(\S+)"
    r"|\b(?:7z|7za|7zr|7zz)\b[\s\S]{0,100}-o(\S*)"
    r"|\bcpio\b[\s\S]{0,100}(?:--directory|-D)\b(?:=|\s*)(\S+)"
    # zipfile/tarfile: ``-e archive dest`` — capture dest (last path), not archive.
    r"|\bpython(?:\d+(?:\.\d+)?)?\s+-m\s+(?:zipfile|tarfile)\b"
    r"[\s\S]{0,100}(?:-e|--extract|\bextract\b)\s+\S+\s+(\S+)"
    r"|\bcabextract\b[\s\S]{0,100}(?:-d|--directory)(?:=|\s*)(\S+)"
    r"|\bjar\b[\s\S]{0,120}(?:-C|--directory)(?:=|\s*)(\S+)"
    r"|\b(?:dpkg-deb|dpkg)\b[\s\S]{0,120}(?:-x|--extract)\b[\s\S]{0,80}(\S+)\s+(\S+)"
    r"|\bunsquashfs\b[\s\S]{0,100}(?:--dest|-dest|-d)\b(?:=|\s*)(\S+)"
    r"|\b(?:unar|unrar|rar)\b[\s\S]{0,140}(?:-op|-o|-d)(?:=|\s*)(\S+)"
    # ``ar x a.a --output /`` / ``ar -O /`` (RH-27). Avoid matching ``-O`` inside ``--output``.
    r"|\bar\b[\s\S]{0,160}(?:--output(?:=|\s*)|(?<![-\w])-O(?:=|\s*))(\S+)"
    # ``gem unpack/install/i … --target|--install-dir|-i /`` / ``aunpack -X /`` (RH-35/41).
    # Long opts first; short ``-i`` must not match inside ``--install-dir``.
    r"|\bgem\b[\s\S]{0,160}(?:unpack|install|\bi)\b[\s\S]{0,140}"
    r"(?:(?:--target|--install-dir)(?:=|\s*)|(?<![-\w])-i(?:=|\s*))(\S+)"
    r"|\b(?:aunpack|atool)\b[\s\S]{0,100}(?:-X|--extract-to)(?:=|\s*)(\S+)"
    # ``patool extract --outdir /`` (RH-41). Avoid ``-O`` matching inside ``--outdir``.
    r"|\bpatool\b[\s\S]{0,140}(?:extract|x)\b[\s\S]{0,120}"
    r"(?:(?:--outdir|--out-dir)(?:=|\s*)|(?<![-\w])-O(?:=|\s*))(\S+)"
    r")",
    re.IGNORECASE,
)
_UNRAR_CMD_RE = re.compile(r"\b(?:unrar|unar|rar)\b", re.IGNORECASE)
_PKG_ROOT_RE = re.compile(
    # Non-greedy span so ``-r`` inside ``--root`` is not preferred over ``--root=``.
    # ``pip install --target=/`` / ``cargo install --root=/`` (RH-38 / RH-41).
    r"\b(?:rpm|apk|dnf|yum|zypper|pacman|opkg|pip|pip3|npm|yarn|pnpm|cargo|uv)\b"
    r"[\s\S]{0,160}?"
    r"(?:--installroot|--offline-root|--root|--prefix|--target|(?<![\w-])-r)"
    r"(?:=|\s*)(\S+)",
    re.IGNORECASE,
)
# OpenWrt opkg also uses ``-o`` / ``--offline-root`` for the install root.
_OPKG_ROOT_RE = re.compile(
    r"\bopkg\b[\s\S]{0,160}?(?:--offline-root|--root|(?<![\w-])-o)(?:=|\s*)(\S+)",
    re.IGNORECASE,
)
_GIT_SEPARATE_DIR_RE = re.compile(
    r"\bgit\b[\s\S]{0,160}--separate-git-dir(?:=|\s+)(\S+)",
    re.IGNORECASE,
)
# Alpine apk also uses ``-p`` / ``--root`` for the install root.
_APK_ROOT_RE = re.compile(
    r"\bapk\b[\s\S]{0,160}?(?:--root|-p)(?:=|\s*)(\S+)",
    re.IGNORECASE,
)
# Bootstrap/installers that take a root filesystem path as a positional arg.
_BOOTSTRAP_ROOT_RE = re.compile(
    r"\b(?:debootstrap|pacstrap)\b[\s\S]{0,200}?((?:/|\./|\.\./)\S*)",
    re.IGNORECASE,
)
_DD_RESCUE_POS_RE = re.compile(
    r"\b(?:dd_rescue|ddr)\b[\s\S]{0,200}" + _BLOCK_DEV_RE.pattern,
    re.IGNORECASE,
)
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
    + r"|\b(?:zstd|pzstd|lz4|xz|lzip|plzip|lrzip|gzip|gunzip|pigz)\b"
    r"[\s\S]{0,100}(?:-o|--output)(?:=|\s*)"
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
# Auth + persistence paths that must not be overwritten / linked over.
_AUTH_FILE_RE = re.compile(
    r"(?:"
    r"/etc/(?:passwd|shadow|sudoers(?:\.d(?:/\S*)?)?|group|ld\.so\.preload|crontab|rc\.local)\b"
    r"|/etc/cron\.(?:d|daily|hourly|weekly|monthly)(?:/\S*)?"
    r"|/etc/systemd/(?:system|user)(?:/\S*)?"
    # Vendor unit dirs (RH-41) — persistence outside /etc/systemd.
    r"|/(?:usr/)?lib/systemd/(?:system|user)(?:/\S*)?"
    r"|/(?:root|home/[^/\s]+)/\.ssh/authorized_keys\b"
    r")",
    re.IGNORECASE,
)
_OPENSSL_OUT_AUTH_RE = re.compile(
    r"\b(?:gpg|openssl)\b[\s\S]{0,160}(?:--output|-out|-o)(?:=|\s*)"
    + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
# Compressed auth paths: ``gunzip /etc/passwd.gz`` clobbers ``/etc/passwd``.
_AUTH_COMPRESSED_RE = re.compile(
    _AUTH_FILE_RE.pattern
    + r"(?:\.(?:gz|bz2|xz|lzma|lz|lzo|zst|Z|zz|zip|br|sz))?\b",
    re.IGNORECASE,
)
_MISC_WRITE_AUTH_RE = re.compile(
    r"(?:"
    r"\b(?:base64|brotli|unzstd|lz4|xz|gzip|gunzip|pigz|bzip2|bunzip2|pbzip2|lbzip2|"
    r"lzop|lzma|unlzma|unxz|pixz|lzip|plzip|lrzip|zstd|pzstd|snzip|compress|uncompress|"
    r"age|rage)\b"
    r"[\s\S]{0,120}(?:-o|--output)(?:=|\s*)" + _AUTH_FILE_RE.pattern
    # Positional decompress dest: ``lz4 -d x.lz4 /etc/passwd``, ``zstd -d x /etc/passwd``.
    + r"|\b(?:lz4|lzop|zstd|pzstd|unzstd|lzip|plzip|lrzip|brotli|snzip|pixz)\b[\s\S]{0,120}"
    r"(?:-d|--decompress)\b[\s\S]{0,160}" + _AUTH_FILE_RE.pattern
    # In-place decompress of compressed auth files (``gunzip /etc/passwd.gz``).
    + r"|\b(?:gzip|gunzip|pigz|bzip2|bunzip2|pbzip2|lbzip2|xz|unxz|pixz|lzma|unlzma|"
    r"lzip|plzip|lrzip|lz4|lzop|zstd|pzstd|unzstd|brotli|snzip|compress|uncompress)\b"
    r"[\s\S]{0,160}" + _AUTH_COMPRESSED_RE.pattern
    + r"|\b(?:xxd|fallocate|flash_erase|nandwrite|uudecode|objcopy)\b"
    r"[\s\S]{0,200}" + _AUTH_FILE_RE.pattern
    + r"|\b(?:iconv|ffmpeg|convert|magick)\b[\s\S]{0,220}"
    + _AUTH_FILE_RE.pattern
    + r"|\bgs\b[\s\S]{0,160}-sOutputFile=" + _AUTH_FILE_RE.pattern
    + r"|\buudecode\b[\s\S]{0,100}(?:-o|--output-file)(?:=|\s*)"
    + _AUTH_FILE_RE.pattern
    + r")",
    re.IGNORECASE,
)
_RM_AUTH_RE = re.compile(
    r"\brm\b[\s\S]{0,160}" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_INTERPRETER_AUTH_DELETE_RE = re.compile(
    r"(?:"
    r"File\.delete\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|FileUtils\s*\.\s*rm(?:_r|_rf)?\s*\(?\s*" + _AUTH_FILE_RE.pattern
    + r"|os\s*\)?\s*\.\s*(?:remove|unlink)\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|Path\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"[\s\S]{0,40}\.unlink\s*\("
    + r"|pathlib\s*\.\s*Path\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"[\s\S]{0,40}\.unlink\s*\("
    + r"|unlink(?:Sync)?\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|unlink\s+(?:q(?:w)?\()?\s*" + _AUTH_FILE_RE.pattern
    + r"|rmSync\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r")",
    re.IGNORECASE,
)
_AUTH_DIR_RE = re.compile(
    r"(?:"
    r"/etc/sudoers\.d\b"
    r"|/etc/cron\.(?:d|daily|hourly|weekly|monthly)\b"
    r"|/etc/systemd/(?:system|user)\b"
    r"|/(?:usr/)?lib/systemd/(?:system|user)\b"
    r")",
    re.IGNORECASE,
)
_LN_NULL_AUTH_RE = re.compile(
    r"\bln\b[\s\S]{0,80}/dev/null[\s\S]{0,80}" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_LN_TO_AUTH_RE = re.compile(
    r"(?:"
    r"\bln\b[\s\S]{0,200}" + _AUTH_FILE_RE.pattern
    + r"|\blink\b[\s\S]{0,160}" + _AUTH_FILE_RE.pattern
    + r"|os\s*\)?\s*\.\s*(?:link|symlink)\s*\([^)]*" + _AUTH_FILE_RE.pattern
    + r"|symlink(?:Sync)?\s*\([^)]*" + _AUTH_FILE_RE.pattern
    + r")",
    re.IGNORECASE,
)
_CP_TO_AUTH_RE = re.compile(
    r"\b(?:cp|mv|rsync|g?install)\b\s+(?:-[^\s]+\s+)*\S+\s+" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_CP_TARGET_DIR_AUTH_RE = re.compile(
    r"\b(?:cp|mv|g?install)\b[\s\S]{0,180}"
    # ``-t /path``, ``-t=/path``, glued ``-t/path`` / ``--target-directory/path``.
    r"(?:(?:-t|--target-directory)(?:=|\s+)|-t(?=/)|--target-directory(?=/))"
    + _AUTH_DIR_RE.pattern,
    re.IGNORECASE,
)
_MV_RSYNC_TO_AUTH_RE = re.compile(
    r"\b(?:mv|rsync)\b[\s\S]{0,220}" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_REDIRECT_TO_AUTH_RE = re.compile(
    r"(?:"
    r"(?:>{1,2})\s*" + _AUTH_FILE_RE.pattern
    + r"|\btee\b(?:\s+-[^\s]+|\s+--[^\s=]+(?:=\S*)?)*\s+"
    + _AUTH_FILE_RE.pattern
    + r"|\b(?:truncate|shred|g?install)\b[\s\S]{0,80}"
    + _AUTH_FILE_RE.pattern
    + r")",
    re.IGNORECASE,
)
_PROCFS_HIJACK_RE = re.compile(
    r"(?:"
    r"(?:>{1,2}|\btee\b(?:\s+\S+)*)\s*"
    r"/proc/sys/kernel/(?:core_pattern|modprobe|hotplug)\b"
    r"|(?:>{1,2}|\btee\b(?:\s+\S+)*)\s*/proc/sys/fs/binfmt_misc/register\b"
    r"|\bsysctl\b[\s\S]{0,80}"
    r"(?:kernel\.(?:core_pattern|modprobe|hotplug)|fs\.binfmt_misc\.register)"
    r")",
    re.IGNORECASE,
)
_MOUNT_BIND_AUTH_RE = re.compile(
    # Match before and after comma→space scrub (``-o rw,bind`` / ``-o rw bind``).
    # Also block bind onto ``/`` / ``/etc`` (RH-41) — hides/clobbers auth trees.
    r"\bmount\b[\s\S]{0,160}"
    r"(?:--bind\b|-B\b|-o(?:=|\s+)\S*bind\b|-o(?:=|\s+)\S*\s+bind\b)"
    r"(?=[\s\S]{0,200}(?:"
    + _AUTH_FILE_RE.pattern
    + r"|/etc\b|(?:\s)/(?:\s*)$"
    r"))",
    re.IGNORECASE,
)
_TAR_ABSOLUTE_NAMES_RE = re.compile(
    # ``-P``, clustered ``-xPf`` / ``-xPvf``, or ``--absolute-names``.
    r"\b(?:tar|gtar|bsdtar|star|pax)\b[\s\S]{0,160}"
    r"(?:--absolute-names\b|-[a-zA-Z]*P[a-zA-Z]*\b)",
    re.IGNORECASE,
)
_SHUF_OUT_AUTH_RE = re.compile(
    r"\bshuf\b[\s\S]{0,100}(?:-o|--output)(?:=|\s*)" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_GIT_ROOT_WRITE_RE = re.compile(
    r"(?:"
    r"\bgit\b[\s\S]{0,160}(?:--prefix|--work-tree)(?:=|\s+)/"
    r"|\bgit\b[\s\S]{0,80}checkout-index\b[\s\S]{0,120}--prefix(?:=|\s*)/"
    r")",
    re.IGNORECASE,
)
_DOWNLOAD_TO_AUTH_RE = re.compile(
    r"(?:"
    r"\b(?:curl|wget|busybox|fetch|aria2c|axel|http|httpie|yt-dlp|youtube-dl|lftp)\b"
    r"[\s\S]{0,220}"
    r"(?:-o|--output(?:-document)?|--out|--index-out|-O)(?:=|\s*)(?:\d+=)?"
    + _AUTH_FILE_RE.pattern
    + r"|\blwp-download\b[\s\S]{0,200}"
    + _AUTH_FILE_RE.pattern
    + r"|\brclone\b[\s\S]{0,200}"
    + _AUTH_FILE_RE.pattern
    + r"|\b(?:scp|sftp)\b[\s\S]{0,200}"
    + _AUTH_FILE_RE.pattern
    + r"|\b(?:base64|brotli)\b[\s\S]{0,120}(?:-o|--output)(?:=|\s*)"
    + _AUTH_FILE_RE.pattern
    + r"|\b(?:zstd|pzstd|unzstd|lz4|xz|gzip|gunzip|lzop|lzma)\b[\s\S]{0,100}"
    r"(?:-o|--output)(?:=|\s*)"
    + _AUTH_FILE_RE.pattern
    + r"|\b(?:split|csplit)\b[\s\S]{0,100}(?:-f|--prefix)(?:=|\s*)"
    + _AUTH_FILE_RE.pattern
    # ``split -b1 /dev/urandom /etc/passwd`` — last positional is the prefix.
    + r"|\bsplit\b[\s\S]{0,160}\s"
    + _AUTH_FILE_RE.pattern
    + r"(?:\s|$)"
    + r")",
    re.IGNORECASE,
)
_SOCAT_AUTH_RE = re.compile(
    r"\bsocat\b[\s\S]{0,220}(?:OPEN|CREATE|APPEND):" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_DOWNLOAD_DIR_AUTH_RE = re.compile(
    r"\b(?:curl|wget|aria2c)\b[\s\S]{0,220}"
    r"(?:--output-dir|--directory-prefix|--dir|-d)(?:=|\s*)/etc(?:/|\s|$)",
    re.IGNORECASE,
)
_CMAKE_COPY_AUTH_RE = re.compile(
    r"\bcmake\b[\s\S]{0,80}-E\s+copy(?:_if_different)?\b[\s\S]{0,200}"
    + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_INPLACE_AUTH_RE = re.compile(
    r"(?:"
    # Leading ``-i`` / clustered ``-pi`` / ``-ri`` / ``-npi`` inplace edits.
    r"\b(?:sed|perl|ruby)\b[\s\S]{0,100}"
    r"(?:-i\S*|-[a-zA-Z]*i[a-zA-Z]*)\b[\s\S]{0,160}"
    + _AUTH_FILE_RE.pattern
    # ``-i``, ``-inplace``, glued ``-iinplace``.
    + r"|\b(?:g?awk)\b[\s\S]{0,80}(?:-iinplace\b|-i(?:nplace)?\b)[\s\S]{0,160}"
    + _AUTH_FILE_RE.pattern
    + r"|\bsponge\b\s+"
    + _AUTH_FILE_RE.pattern
    + r")",
    re.IGNORECASE,
)
_CHMOD_AUTH_RE = re.compile(
    r"\b(?:chmod|chown|chgrp|setfacl|getfacl|chattr|lsattr|setfattr|getfattr)\b"
    r"[\s\S]{0,160}"
    + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_SETUID_SYSTEM_RE = re.compile(
    r"(?:"
    # Setuid (4) / setgid (2) / combined (6,7) / sticky+set* (3,5) — not sticky-only (1).
    r"\bchmod\b[\s\S]{0,100}"
    r"(?:[ug]*\+s|\+s|[0-7]*[2-7][0-7]{3})\b[\s\S]{0,100}"
    r"/(?:bin|sbin|usr/(?:s?bin|local/(?:s?bin)))/\S*"
    # Glued ``-m4755`` / ``ginstall`` as well as spaced/``=`` forms.
    r"|\bg?install\b[\s\S]{0,120}"
    r"(?:-m|--mode)(?:=|\s*)(?:[0-7]*[2-7][0-7]{3}|[ug]*\+s|\+s)\b"
    r"[\s\S]{0,160}/(?:bin|sbin|usr/(?:s?bin|local/(?:s?bin)))/\S*"
    # ``setcap`` dangerous capabilities on system binaries (RH-27).
    r"|\bsetcap\b[\s\S]{0,120}"
    r"cap_(?:set(?:uid|gid)|sys_admin|sys_rawio|sys_module|dac_override|dac_read_search)"
    r"\b[\s\S]{0,80}/(?:bin|sbin|usr/(?:s?bin|local/(?:s?bin)))/\S*"
    r")",
    re.IGNORECASE,
)
_DD_OF_AUTH_RE = re.compile(
    r"\b(?:dd|dc3dd|ddrescue)\b[\s\S]{0,120}\bof=" + _AUTH_FILE_RE.pattern,
    re.IGNORECASE,
)
_DD_RESCUE_AUTH_RE = re.compile(
    r"\b(?:dd_?rescue|ddr|gddrescue)\b[\s\S]{0,200}" + _AUTH_FILE_RE.pattern,
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
    + r"|Path\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"[\s\S]{0,80}\.write_(?:bytes|text)\s*\("
    + r"|pathlib\s*\.\s*Path\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"[\s\S]{0,80}\.write_(?:bytes|text)\s*\("
    # ``__import__('shutil').copy`` → ``shutil).copy`` after quote-strip.
    + r"|shutil\s*\)?\s*\.\s*(?:copy|copy2|copyfile|move)\s*\([^)]*"
    + _AUTH_FILE_RE.pattern
    + r"|os\s*\)?\s*\.\s*(?:rename|replace|link|symlink)\s*\([^)]*"
    + _AUTH_FILE_RE.pattern
    + r"|appendFile(?:Sync)?\s*\(\s*" + _AUTH_FILE_RE.pattern
    + r"|symlink(?:Sync)?\s*\([^)]*" + _AUTH_FILE_RE.pattern
    + r"|extractall\s*\(\s*/"
    + r"|ZipFile\s*\([^)]*\)[\s\S]{0,80}\.extract(?:all)?\s*\(\s*/"
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
    r"|\bbtrfs\s+(?:subvolume\s+delete|filesystem\s+resize|receive)\b"
    r"|\bxfs_repair\s+[^\n]*-L\b"
    r"|\bdebugfs\s+-w\b"
    # dump/restore family writing onto ``/`` (operator root clobber).
    r"|\b(?:restore|xfsrestore|star)\b[\s\S]{0,160}(?:-C|--directory)(?:=|\s*)/"
    r"|\b(?:restore|xfsrestore)\b[\s\S]{0,200}\s/\s*$"
    r")",
    re.IGNORECASE,
)
# Create-on-device siblings of destroy (RH-41) — wipe existing data via new pool/RAID/LVM.
_VOLUME_CREATE_RE = re.compile(
    r"(?:"
    r"\bzpool\s+create\b[\s\S]{0,220}"
    + _BLOCK_DEV_RE.pattern
    + r"|\bmdadm\b[\s\S]{0,160}--create\b[\s\S]{0,220}"
    + _BLOCK_DEV_RE.pattern
    + r"|\bpvcreate\b[\s\S]{0,160}"
    + _BLOCK_DEV_RE.pattern
    + r"|\bvgcreate\b[\s\S]{0,200}"
    + _BLOCK_DEV_RE.pattern
    + r"|\blvcreate\b[\s\S]{0,200}"
    + _BLOCK_DEV_RE.pattern
    + r")",
    re.IGNORECASE,
)


def _strip_shell_quotes(text: str) -> str:
    """Remove ``'`` / ``"`` so ``m'k'fs`` collapses to ``mkfs`` before matching."""
    return text.replace("'", "").replace('"', "")


def _expand_ansi_c_quotes(text: str) -> str:
    """Expand ANSI-C quotes ``$'/'`` / ``$'\\x2f'`` before ordinary quote-strip."""

    def _repl(match: re.Match[str]) -> str:
        body = match.group(1)
        out: list[str] = []
        i = 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                simple = {
                    "n": "\n",
                    "t": "\t",
                    "r": "\r",
                    "\\": "\\",
                    "'": "'",
                    '"': '"',
                    "a": "\a",
                    "b": "\b",
                    "f": "\f",
                    "v": "\v",
                }
                if nxt in simple:
                    out.append(simple[nxt])
                    i += 2
                    continue
                if nxt == "x" and i + 3 < len(body):
                    try:
                        out.append(chr(int(body[i + 2 : i + 4], 16)))
                        i += 4
                        continue
                    except ValueError:
                        pass
                # Bash octal ``\nnn`` / ``\0nnn`` (e.g. ``$'\057'`` → ``/``).
                if nxt in "01234567":
                    j = i + 1
                    while j < len(body) and j < i + 4 and body[j] in "01234567":
                        j += 1
                    out.append(chr(int(body[i + 1 : j], 8) & 0xFF))
                    i = j
                    continue
            out.append(body[i])
            i += 1
        return "".join(out)

    return re.sub(r"\$'([^']*)'", _repl, text)


def _scrub_ifs(text: str) -> str:
    """Replace ``$IFS`` / ``${IFS}`` with spaces so ``rm$IFS-rf$IFS/`` tokenizes.

    Case-insensitive: callers may lowercase the command before scrubbing.
    """
    return re.sub(r"\$\{?IFS\}?", " ", text, flags=re.IGNORECASE)


def _expand_brace_paths(text: str) -> str:
    """Expand absolute brace paths so system-root checks see each alt.

    Handles ``/{etc,var}``, mid-segment ``/et{c,}`` → ``/etc``,
    suffix forms ``/{e,}tc`` → ``/etc``, and ``/usr{,/local}`` → ``/usr /usr/local``.
    """

    def _repl(match: re.Match[str]) -> str:
        prefix, body, suffix = match.group(1), match.group(2), match.group(3)
        # Keep empty alts (``/et{c,}`` → ``/etc`` + ``/et``).
        return " ".join(prefix + part + suffix for part in body.split(","))

    # Absolute path with optional suffix after ``}`` (``/{e,}tc``, ``/de{v,}/sda``).
    expanded = text
    for _ in range(4):  # nested / multi-brace safety bound
        nxt = re.sub(r"(?<![\w{])(/[^\s{]*)\{([^{}]+)\}([^\s]*)", _repl, expanded)
        if nxt == expanded:
            break
        expanded = nxt
    return expanded


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


# Absolute paths (and of=/… assignments) so lexical evasion cannot bypass
# auth/block regexes that match canonical ``/etc/passwd`` / ``/dev/sda``.
_ABS_PATH_IN_CMD_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(/(?:[^\s;|&<>'\"`()]+))",
)
_OF_ABS_PATH_RE = re.compile(r"(\bof=)(/(?:[^\s;|&<>'\"`()]+))", re.IGNORECASE)
# Relative auth-like paths reconstructed under ``/`` via ``cp --parents`` /
# ``rsync -R`` / ``--relative``.
_REL_AUTH_PATH_RE = re.compile(
    r"(?:^|[\s=])"
    r"(?:etc/(?:passwd|shadow|sudoers(?:\.d(?:/\S*)?)?|group|ld\.so\.preload|"
    r"crontab|rc\.local)|"
    r"etc/cron\.(?:d|daily|hourly|weekly|monthly)(?:/\S*)?|"
    r"etc/systemd/(?:system|user)(?:/\S*)?|"
    r"(?:root|home/[^/\s]+)/\.ssh/authorized_keys)"
    r"(?:\s|$)",
    re.IGNORECASE,
)
_CP_PARENTS_FLAG_RE = re.compile(r"--parents\b", re.IGNORECASE)
_RSYNC_RELATIVE_FLAG_RE = re.compile(
    r"(?:--relative\b|(?<![-\w])-[^\s]*R[^\s]*)",
    re.IGNORECASE,
)


def _normalize_abs_paths_in_command(cmd: str) -> str:
    """Replace absolute path tokens with lexically normalized forms.

    Closes ``/tmp/../etc/passwd``, ``/./dev/sda``, ``/etc/./shadow`` evasions
    that otherwise miss ``_AUTH_FILE_RE`` / ``_BLOCK_DEV_RE`` literal matches.
    """

    def _of_repl(match: re.Match[str]) -> str:
        return match.group(1) + _normalize_path_token(match.group(2))

    def _path_repl(match: re.Match[str]) -> str:
        return _normalize_path_token(match.group(1))

    out = _OF_ABS_PATH_RE.sub(_of_repl, cmd)
    return _ABS_PATH_IN_CMD_RE.sub(_path_repl, out)


def _token_is_rel_auth_path(tok: str) -> bool:
    """True when a (possibly ``./`` / ``etc/./``) relative token is an auth path."""
    norm = _normalize_path_token(tok)
    if not norm or norm.startswith("/"):
        return False
    # Probe with surrounding whitespace so ``_REL_AUTH_PATH_RE`` anchors match.
    return bool(_REL_AUTH_PATH_RE.search(f" {norm} ") or _REL_AUTH_PATH_RE.search(f"={norm}"))


def _parents_reconstructs_auth(cmd_clean: str) -> bool:
    """True when ``cp --parents`` / ``rsync -R`` would materialize auth under ``/``."""
    has_cp_parents = bool(
        re.search(r"\bcp\b", cmd_clean, re.IGNORECASE)
        and _CP_PARENTS_FLAG_RE.search(cmd_clean)
    )
    has_rsync_rel = bool(
        re.search(r"\brsync\b", cmd_clean, re.IGNORECASE)
        and _RSYNC_RELATIVE_FLAG_RE.search(cmd_clean)
    )
    if not (has_cp_parents or has_rsync_rel):
        return False
    has_rel_auth = bool(_REL_AUTH_PATH_RE.search(cmd_clean))
    has_root_dest = False
    for raw in cmd_clean.split():
        if raw.startswith("-"):
            continue
        tok = _normalize_path_token(raw)
        if tok in {"/", "/*"} or tok in _ROOT_EQUIV:
            has_root_dest = True
            continue
        if _token_is_rel_auth_path(raw):
            has_rel_auth = True
    return has_rel_auth and has_root_dest


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


def _rm_is_destructive(cmd_clean: str) -> bool:
    """True when ``rm`` has recursive+force flags in any option order."""
    if not _RM_WORD_RE.search(cmd_clean):
        return False
    return bool(
        _RM_RECURSIVE_FLAG_RE.search(cmd_clean) and _RM_FORCE_FLAG_RE.search(cmd_clean)
    )


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
        # groups[2] is the 7-Zip ``-o`` destination — block any absolute path.
        seven_zip = groups[2] is not None
        for dest in groups:
            if dest is None:
                continue
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
    # ``$IFS`` / ``${IFS}`` before quote/ANSI expand so ``rm$IFS-rf$IFS/`` matches.
    raw = _scrub_ifs(raw)
    # ANSI-C quotes before ordinary quote-strip (``$'/'`` → ``/``).
    ansi_clean = _expand_ansi_c_quotes(raw)
    # Collapse shell quote-splitting evasion (m'k'fs → mkfs) before matching.
    quoted_clean = _strip_shell_quotes(ansi_clean)
    # Windows device paths use backslashes — probe them before stripping.
    if _WINDOWS_WIPE_RE.search(quoted_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )
    # Strip remaining escapes (``\/`` → ``/``) so ``exec(...rmtree(\"/\")`` matches.
    # Keep a pre-comma form for mount ``-o rw,bind`` (comma scrub would hide ``bind``).
    cmd_esc = quoted_clean.replace("\\", "")
    # Expand ``/{etc,var}`` before comma scrub (commas inside braces are alts).
    cmd_braced = _expand_brace_paths(cmd_esc)
    # Normalize list-argv commas (``['rm','-rf','/']`` → ``rm -rf /``).
    cmd_clean = re.sub(r"\s*,\s*", " ", cmd_braced)
    # Lexical path normalize so ``/tmp/../etc/passwd`` / ``/./dev/sda`` hit
    # the canonical auth/block regexes (RH-01 / RH-02).
    cmd_clean = _normalize_abs_paths_in_command(cmd_clean)

    if _FORK_BOMB_RE.search(cmd_clean):
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
        _rm_is_destructive(cmd_clean) or _FILE_WIPE_TOOLS_RE.search(cmd_clean)
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
        or _MISC_WRITE_BLOCK_RE.search(cmd_clean)
        or _SOCAT_BLOCK_RE.search(cmd_clean)
        or _DISKUTIL_WIPE_RE.search(cmd_clean)
        or _ASR_ERASE_RE.search(cmd_clean)
        or _HDIUTIL_BLOCK_RE.search(cmd_clean)
        or _WMIC_FORMAT_RE.search(cmd_clean)
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )

    if _is_extract_to_root(cmd_clean) or _TAR_ABSOLUTE_NAMES_RE.search(cmd_clean):
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
        or _LN_TO_AUTH_RE.search(cmd_clean)
        or _CP_TO_AUTH_RE.search(cmd_clean)
        or _CP_TARGET_DIR_AUTH_RE.search(cmd_clean)
        or _MV_RSYNC_TO_AUTH_RE.search(cmd_clean)
        or _REDIRECT_TO_AUTH_RE.search(cmd_clean)
        or _DD_OF_AUTH_RE.search(cmd_clean)
        or _INTERPRETER_AUTH_WRITE_RE.search(cmd_clean)
        or _OPENSSL_OUT_AUTH_RE.search(cmd_clean)
        or _MISC_WRITE_AUTH_RE.search(cmd_clean)
        or _RM_AUTH_RE.search(cmd_clean)
        or _INTERPRETER_AUTH_DELETE_RE.search(cmd_clean)
        or _DOWNLOAD_TO_AUTH_RE.search(cmd_clean)
        or _DOWNLOAD_DIR_AUTH_RE.search(cmd_clean)
        or _CMAKE_COPY_AUTH_RE.search(cmd_clean)
        or _INPLACE_AUTH_RE.search(cmd_clean)
        or _CHMOD_AUTH_RE.search(cmd_clean)
        or _MOUNT_BIND_AUTH_RE.search(cmd_esc)
        or _MOUNT_BIND_AUTH_RE.search(cmd_clean)
        or _SHUF_OUT_AUTH_RE.search(cmd_clean)
        or _DD_RESCUE_AUTH_RE.search(cmd_clean)
        or _PROCFS_HIJACK_RE.search(cmd_clean)
        or _SOCAT_AUTH_RE.search(cmd_clean)
        or _parents_reconstructs_auth(cmd_clean)
    ):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting auth files is blocked."
        )

    for sep_dir in _GIT_SEPARATE_DIR_RE.finditer(cmd_clean):
        dest = _normalize_path_token(sep_dir.group(1))
        if _AUTH_FILE_RE.search(dest) or _is_dangerous_extract_dest(dest):
            raise PermissionDeniedError(
                "Destructive command detected: Overwriting auth files is blocked."
            )

    for pkg_root in (
        *_PKG_ROOT_RE.finditer(cmd_clean),
        *_APK_ROOT_RE.finditer(cmd_clean),
        *_OPKG_ROOT_RE.finditer(cmd_clean),
    ):
        if _is_dangerous_extract_dest(pkg_root.group(1)):
            raise PermissionDeniedError(
                "Destructive command detected: Package install onto / is blocked."
            )

    for boot_root in _BOOTSTRAP_ROOT_RE.finditer(cmd_clean):
        if _is_dangerous_extract_dest(boot_root.group(1)):
            raise PermissionDeniedError(
                "Destructive command detected: Bootstrap install onto / is blocked."
            )

    if _DD_RESCUE_POS_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Overwriting block devices is blocked."
        )

    if _GIT_ROOT_WRITE_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Git write onto / is blocked."
        )

    if _SETUID_SYSTEM_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Setuid on system binaries is blocked."
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

    if _VOLUME_CREATE_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Volume/array create on block devices is blocked."
        )

    if _PARTITION_RE.search(cmd_clean):
        raise PermissionDeniedError(
            "Destructive command detected: Formatting storage devices is blocked."
        )


__all__ = ["assert_command_not_destructive"]
