"""Phalanx PTY Support — Pseudo-terminal wrapper for interactive tool execution.

Provides:
  • **PTYSession** — Launch tools in a pseudo-terminal for full interactive I/O
  • **PTYManager** — Manage multiple concurrent PTY sessions
  • **OutputCapture** — Capture and stream PTY output with ANSI handling

On Windows, uses ConPTY (via subprocess). On Unix, uses the pty module.
Falls back gracefully to subprocess if PTY is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "PTYSession",
    "PTYManager",
    "PTYCapabilities",
]

logger = logging.getLogger(__name__)

# Platform detection
_IS_WINDOWS = sys.platform == "win32"
_HAS_PTY = False
if not _IS_WINDOWS:
    try:
        import pty as _pty_mod


        _HAS_PTY = True
    except ImportError:
        pass


class PTYCapabilities(StrEnum):
    """Available PTY backends."""

    NATIVE_PTY = "native_pty"  # Unix pty module
    CONPTY = "conpty"  # Windows ConPTY
    SUBPROCESS = "subprocess"  # Fallback: plain subprocess


def detect_pty_backend() -> PTYCapabilities:
    """Detect the best available PTY backend for the current platform."""
    if _IS_WINDOWS:
        # Windows 10+ has ConPTY support
        try:
            ver = sys.getwindowsversion()
            if ver.major >= 10 and ver.build >= 17763:
                return PTYCapabilities.CONPTY
        except AttributeError:
            pass
        return PTYCapabilities.SUBPROCESS
    elif _HAS_PTY:
        return PTYCapabilities.NATIVE_PTY
    else:
        return PTYCapabilities.SUBPROCESS


@dataclass
class PTYOutput:
    """A chunk of captured PTY output."""

    data: str
    timestamp: float = field(default_factory=time.monotonic)
    is_stderr: bool = False
    raw_bytes: bytes = b""


class PTYSession:
    """A pseudo-terminal session wrapping a subprocess.

    Supports:
    - Interactive I/O (send input, read output)
    - Window resize
    - Signal forwarding
    - Timeout and graceful cleanup
    """

    def __init__(
        self,
        command: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        rows: int = 24,
        cols: int = 80,
        timeout: float = 300.0,
    ) -> None:
        self.command = command
        self.cwd = cwd
        self.env = {**os.environ, **(env or {})}
        self.rows = rows
        self.cols = cols
        self.timeout = timeout
        self.session_id = f"pty_{id(self):x}"

        self._process: subprocess.Popen[bytes] | None = None
        self._master_fd: int | None = None
        self._backend = detect_pty_backend()
        self._output_buffer: list[PTYOutput] = []
        self._running = False
        self._exit_code: int | None = None

    @property
    def is_running(self) -> bool:
        if self._process:
            return self._process.poll() is None
        return self._running

    @property
    def exit_code(self) -> int | None:
        if self._process:
            return self._process.poll()
        return self._exit_code

    @property
    def backend(self) -> PTYCapabilities:
        return self._backend

    async def start(self) -> None:
        """Start the PTY session."""
        if self._backend == PTYCapabilities.NATIVE_PTY and _HAS_PTY:
            await self._start_pty()
        else:
            await self._start_subprocess()
        self._running = True
        logger.info(
            "PTY session started: %s (backend=%s)",
            " ".join(self.command),
            self._backend.value,
        )

    async def _start_pty(self) -> None:
        """Start using native Unix PTY."""
        import struct
        import fcntl
        import termios

        master_fd, slave_fd = _pty_mod.openpty()  # type: ignore[attr-defined]
        self._master_fd = master_fd

        # Set terminal size
        if _HAS_PTY:
            winsize = struct.pack("HHHH", self.rows, self.cols, 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)  # type: ignore[attr-defined]

        self._process = subprocess.Popen(
            self.command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=self.cwd,
            env=self.env,
            close_fds=True,
        )
        os.close(slave_fd)

    async def _start_subprocess(self) -> None:
        """Fallback: start as regular subprocess with pipes."""
        self._process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=self.env,
        )

    async def send_input(self, data: str) -> None:
        """Send input to the PTY session."""
        if not self._process:
            return

        encoded = data.encode("utf-8")

        if self._master_fd is not None:
            os.write(self._master_fd, encoded)
        elif self._process.stdin:
            self._process.stdin.write(encoded)
            self._process.stdin.flush()

    async def read_output(self, timeout: float = 0.5) -> str:
        """Read available output from the PTY session."""
        if not self._process:
            return ""

        if self._master_fd is not None:
            # Non-blocking read from PTY master
            loop = asyncio.get_event_loop()
            try:
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: os.read(self._master_fd, 4096)),  # type: ignore
                    timeout=timeout,
                )
                decoded = data.decode("utf-8", errors="replace")
                self._output_buffer.append(PTYOutput(data=decoded, raw_bytes=data))
                return decoded
            except (asyncio.TimeoutError, OSError):
                return ""
        elif self._process.stdout:
            try:
                data = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self._process.stdout.read(4096),  # type: ignore
                    ),
                    timeout=timeout,
                )
                if data:
                    decoded = data.decode("utf-8", errors="replace")
                    self._output_buffer.append(PTYOutput(data=decoded, raw_bytes=data))
                    return decoded
            except (asyncio.TimeoutError, OSError):
                pass
        return ""

    async def read_all(self) -> str:
        """Read all output until the process exits or timeout."""
        chunks: list[str] = []
        deadline = time.monotonic() + self.timeout

        while self.is_running and time.monotonic() < deadline:
            chunk = await self.read_output(timeout=0.5)
            if chunk:
                chunks.append(chunk)
            else:
                await asyncio.sleep(0.1)

        # Final read
        chunk = await self.read_output(timeout=0.2)
        if chunk:
            chunks.append(chunk)

        return "".join(chunks)

    async def resize(self, rows: int, cols: int) -> None:
        """Resize the PTY window."""
        self.rows = rows
        self.cols = cols
        if self._master_fd is not None and _HAS_PTY:
            import struct
            import fcntl
            import termios

            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)  # type: ignore[attr-defined]

    async def send_signal(self, sig: int) -> None:
        """Send a signal to the process."""
        if self._process:
            try:
                self._process.send_signal(sig)
            except (ProcessLookupError, OSError):
                pass

    async def terminate(self) -> int:
        """Terminate the PTY session gracefully."""
        if not self._process:
            return self._exit_code or -1

        if self.is_running:
            try:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=2)
            except (ProcessLookupError, OSError):
                pass

        self._exit_code = self._process.returncode
        self._running = False

        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None

        logger.info("PTY session terminated: exit_code=%s", self._exit_code)
        return self._exit_code or -1

    def get_output_history(self) -> str:
        """Get all captured output as a single string."""
        return "".join(o.data for o in self._output_buffer)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "command": self.command,
            "backend": self._backend.value,
            "running": self.is_running,
            "exit_code": self.exit_code,
            "output_chunks": len(self._output_buffer),
        }


class PTYManager:
    """Manage multiple concurrent PTY sessions.

    Usage::

        mgr = PTYManager()
        session = await mgr.create(["nmap", "-sV", "target.com"])
        output = await session.read_all()
        await mgr.terminate(session.session_id)
    """

    def __init__(self, max_sessions: int = 10) -> None:
        self._sessions: dict[str, PTYSession] = {}
        self._max_sessions = max_sessions
        self._backend = detect_pty_backend()

    @property
    def backend(self) -> PTYCapabilities:
        return self._backend

    async def create(
        self,
        command: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 300.0,
    ) -> PTYSession:
        """Create and start a new PTY session."""
        if len(self._sessions) >= self._max_sessions:
            # Clean up finished sessions
            finished = [sid for sid, s in self._sessions.items() if not s.is_running]
            for sid in finished:
                del self._sessions[sid]

            if len(self._sessions) >= self._max_sessions:
                raise RuntimeError(f"Max PTY sessions ({self._max_sessions}) reached")

        session = PTYSession(
            command=command,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
        await session.start()
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> PTYSession | None:
        return self._sessions.get(session_id)

    async def terminate(self, session_id: str) -> int:
        """Terminate a specific session."""
        session = self._sessions.get(session_id)
        if not session:
            return -1
        code = await session.terminate()
        del self._sessions[session_id]
        return code

    async def terminate_all(self) -> None:
        """Terminate all active sessions."""
        for session in list(self._sessions.values()):
            await session.terminate()
        self._sessions.clear()

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all active sessions."""
        return [s.to_dict() for s in self._sessions.values()]

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s.is_running)
