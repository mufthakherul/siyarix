# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-platform system clipboard integration for Siyarix.

Provides robust, zero-dependency copy and paste capabilities across
Windows, macOS, Linux (X11 & Wayland), and Android (Termux).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)


def copy_to_clipboard(text: str) -> bool:
    """Copy the given text to the system clipboard.

    Returns True if successfully copied, False otherwise.
    """
    if not text:
        return False

    # 1. Try pyperclip if installed
    try:
        import pyperclip

        pyperclip.copy(text)
        return True
    except Exception:
        pass

    # 2. Windows: clip.exe or PowerShell Set-Clipboard
    if sys.platform == "win32":
        try:
            # clip.exe expects utf-16le encoded input on Windows
            proc = subprocess.run(
                ["clip.exe"],
                input=text.encode("utf-16le"),
                check=False,
                capture_output=True,
            )
            if proc.returncode == 0:
                return True
        except Exception as exc:
            logger.debug("clip.exe failed: %s", exc)

        # Fallback to PowerShell Set-Clipboard
        try:
            proc = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Set-Clipboard -Value $input",
                ],
                input=text.encode("utf-8"),
                check=False,
                capture_output=True,
            )
            if proc.returncode == 0:
                return True
        except Exception as exc:
            logger.debug("powershell Set-Clipboard failed: %s", exc)

    # 3. macOS: pbcopy
    elif sys.platform == "darwin":
        if shutil.which("pbcopy"):
            try:
                proc = subprocess.run(
                    ["pbcopy"],
                    input=text.encode("utf-8"),
                    check=False,
                    capture_output=True,
                )
                if proc.returncode == 0:
                    return True
            except Exception as exc:
                logger.debug("pbcopy failed: %s", exc)

    # 4. Linux / BSD / Android
    else:
        # Termux on Android
        if shutil.which("termux-clipboard-set"):
            try:
                proc = subprocess.run(
                    ["termux-clipboard-set"],
                    input=text.encode("utf-8"),
                    check=False,
                    capture_output=True,
                )
                if proc.returncode == 0:
                    return True
            except Exception as exc:
                logger.debug("termux-clipboard-set failed: %s", exc)

        # Wayland: wl-copy
        if shutil.which("wl-copy"):
            try:
                proc = subprocess.run(
                    ["wl-copy"],
                    input=text.encode("utf-8"),
                    check=False,
                    capture_output=True,
                )
                if proc.returncode == 0:
                    return True
            except Exception as exc:
                logger.debug("wl-copy failed: %s", exc)

        # X11: xclip
        if shutil.which("xclip"):
            try:
                proc = subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text.encode("utf-8"),
                    check=False,
                    capture_output=True,
                )
                if proc.returncode == 0:
                    return True
            except Exception as exc:
                logger.debug("xclip failed: %s", exc)

        # X11: xsel
        if shutil.which("xsel"):
            try:
                proc = subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode("utf-8"),
                    check=False,
                    capture_output=True,
                )
                if proc.returncode == 0:
                    return True
            except Exception as exc:
                logger.debug("xsel failed: %s", exc)

    return False


def get_from_clipboard() -> str:
    """Read the current string from the system clipboard."""
    try:
        import pyperclip

        return str(pyperclip.paste() or "")
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard"],
                capture_output=True,
                check=False,
            )
            if proc.returncode == 0:
                return proc.stdout.decode("utf-8", errors="replace").rstrip("\r\n")
        except Exception:
            pass
    elif sys.platform == "darwin":
        if shutil.which("pbpaste"):
            try:
                proc = subprocess.run(["pbpaste"], capture_output=True, check=False)
                if proc.returncode == 0:
                    return proc.stdout.decode("utf-8", errors="replace")
            except Exception:
                pass
    else:
        if shutil.which("termux-clipboard-get"):
            try:
                proc = subprocess.run(["termux-clipboard-get"], capture_output=True, check=False)
                if proc.returncode == 0:
                    return proc.stdout.decode("utf-8", errors="replace")
            except Exception:
                pass
        if shutil.which("wl-paste"):
            try:
                proc = subprocess.run(
                    ["wl-paste", "--no-newline"], capture_output=True, check=False
                )
                if proc.returncode == 0:
                    return proc.stdout.decode("utf-8", errors="replace")
            except Exception:
                pass
        if shutil.which("xclip"):
            try:
                proc = subprocess.run(
                    ["xclip", "-selection", "clipboard", "-o"], capture_output=True, check=False
                )
                if proc.returncode == 0:
                    return proc.stdout.decode("utf-8", errors="replace")
            except Exception:
                pass

    return ""
