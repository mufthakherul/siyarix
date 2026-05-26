"""Smart Autocomplete System for Phalanx.

Provides three-tier autocompletion (static, context-aware, and AI/MITRE-predicted)
for interactive prompt prompts. Works seamlessly with prompt_toolkit when available,
and provides standard completion helpers when used as a fallback.
"""

from __future__ import annotations

import glob
import os
import re
from typing import Any, Iterable

try:
    from prompt_toolkit.completion import Completer as PromptCompleter
    from prompt_toolkit.completion import Completion as PromptCompletion

    Completer = PromptCompleter
    Completion = PromptCompletion
except ImportError:
    # Resilient fallback mock classes if prompt_toolkit is not installed
    class Completer:  # type: ignore[no-redef]
        """Fallback Completer class."""

        pass

    class Completion:  # type: ignore[no-redef]
        """Fallback Completion class."""

        def __init__(
            self, text: str, start_position: int = 0, display_meta: str = ""
        ) -> None:
            self.text = text
            self.start_position = start_position
            self.display_meta = display_meta


class SmartAutocomplete(Completer):
    """Tiered Smart Autocomplete system.

    Tier 1: Static completions (subcommands, options, tool names).
    Tier 2: Context-aware completions (recent targets, directories, files).
    Tier 3: AI-predicted completions (MITRE ATT&CK progression based on state).
    """

    def __init__(self, session: Any = None, xi: Any = None) -> None:
        self._session = session
        self._xi = xi
        self._registry_tools = [
            "nmap",
            "nuclei",
            "gobuster",
            "sqlmap",
            "hydra",
            "subfinder",
            "nikto",
            "amass",
            "dnsx",
            "theHarvester",
            "whois",
            "ffuf",
            "feroxbuster",
            "httpx",
            "wpscan",
            "john",
            "hashcat",
            "msfconsole",
            "trufflehog",
            "gitleaks",
            "aws",
            "podman",
            "docker",
        ]
        self._main_commands = {
            "run": "Run a security command or instruction",
            "chat": "Enter interactive AI conversational loop",
            "scan": "Quick security scan on target",
            "explain": "Explain security command payload",
            "workflow": "Manage and run automation workflows",
            "wizard": "Guided onboarding wizard setup",
            "dashboard": "Launch interactive TUI SOC Dashboard",

            "serve": "Start headless API mode",
            "alias": "Manage custom command aliases",
            "macro": "Manage execution macros",
            "config": "Get/set environment configuration",
            "auth": "Manage encrypted credentials",
            "audit": "View compliance and tamper-evident logs",
            "help": "Display interactive usage guide",
        }
        self._slash_commands = {
            "/1": "Switch to Mode 1: Interactive Shell",
            "/2": "Switch to Mode 2: AI Conversational",
            "/3": "Switch to Mode 3: Direct Command",
            "/4": "Switch to Mode 4: Autonomous Agent",
            "/5": "Switch to Mode 5: Workflow Automation",
            "/6": "Switch to Mode 6: TUI Dashboard",
            "/modes": "Display Nine Interaction Modes table",
            "/split": "Toggle Split Pane visualization view",
            "/help": "Display chat helper",
            "/quit": "Exit application",
            "/exit": "Exit application",
        }

    def get_completions(
        self, document: Any, complete_event: Any = None
    ) -> Iterable[Completion]:
        """Generate autocompletions dynamically based on cursor position."""
        text = document.text_before_cursor
        word_before = document.get_word_before_cursor()
        start_pos = -len(word_before) if word_before else 0

        # Slash Command Trigger
        if text.startswith("/"):
            for slash_cmd, desc in self._slash_commands.items():
                if slash_cmd.startswith(text):
                    yield Completion(
                        slash_cmd, start_position=-len(text), display_meta=desc
                    )
            return

        # Main command matching (First word completion)
        words = text.strip().split()
        if not words or (len(words) == 1 and not text.endswith(" ")):
            for cmd, desc in self._main_commands.items():
                if cmd.startswith(word_before):
                    yield Completion(cmd, start_position=start_pos, display_meta=desc)
            return

        # If inside 'run' or 'scan' arguments
        main_cmd = words[0]

        # Tier 2 Context Injection: Auto-complete files & directories
        if len(words) > 1 and (
            word_before.startswith(".")
            or "/" in word_before
            or "\\" in word_before
            or word_before == ""
        ):
            # File completions
            path_part = word_before
            for path_match in self._get_file_completions(path_part):
                # Ensure we calculate clean start position for path completions
                yield Completion(
                    path_match, start_position=start_pos, display_meta="Local File/Path"
                )

        # Tier 1 Static Tool Names
        if main_cmd in {"run", "scan"}:
            # Offer targets or tool names
            for tool in self._registry_tools:
                if tool.startswith(word_before):
                    yield Completion(
                        tool, start_position=start_pos, display_meta="Security Tool"
                    )

            # Common command-line options
            options = [
                "--target",
                "--help",
                "--verbose",
                "--dry-run",
                "--theme",
                "--parallel",
                "--resume",
            ]
            for opt in options:
                if opt.startswith(word_before):
                    yield Completion(
                        opt, start_position=start_pos, display_meta="Flag Options"
                    )

        # Tier 2 Session-Aware Targets completion
        if self._session and hasattr(self._session, "operations"):
            recent_targets = set()
            for op in self._session.operations:
                # heuristic to extract targets from past instructions
                matches = re.findall(
                    r"(?:https?://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}",
                    op.instruction,
                )
                recent_targets.update(matches)

            for target in recent_targets:
                if target.startswith(word_before):
                    yield Completion(
                        target, start_position=start_pos, display_meta="Recent Target"
                    )

        # Tier 3 AI / MITRE ATT&CK progression completions
        # If user recently ran nmap, suggest gobuster, nuclei, whois
        if len(words) > 1:
            if word_before:
                prev_tools = [w for w in words[:-1] if w in self._registry_tools]
            else:
                prev_tools = [w for w in words if w in self._registry_tools]
            if prev_tools:
                last_tool = prev_tools[-1]
                predictions = self._predict_next_based_on_tool(last_tool)
                for pred, desc in predictions:
                    if pred.startswith(word_before):
                        yield Completion(
                            pred,
                            start_position=start_pos,
                            display_meta=f"AI Suggestion: {desc}",
                        )

    def _get_file_completions(self, path_part: str) -> list[str]:
        """Scan current directory for matching files/directories."""
        try:
            # Support wildcard scanning for current pattern
            search_pattern = path_part + "*" if path_part else "*"
            results = glob.glob(search_pattern)
            completions = []
            for r in results:
                # Add trailing slash if it's a directory
                if os.path.isdir(r):
                    completions.append(r + "/")
                else:
                    completions.append(r)
            return completions[:15]
        except Exception:
            return []

    def _predict_next_based_on_tool(self, tool: str) -> list[tuple[str, str]]:
        """MITRE ATT&CK & progression-aware action predictions."""
        progression = {
            "nmap": [
                ("nuclei", "Vulnerability scanning based on open ports"),
                ("gobuster", "Brute-force directories/files on discovered web ports"),
                ("nikto", "Web server scanner check for general misconfigurations"),
                ("httpx", "Probe discovered hosts for live HTTP/HTTPS services"),
            ],
            "subfinder": [
                ("dnsx", "Perform fast DNS resolution of found subdomains"),
                ("httpx", "Filter out live web servers from subdomain list"),
                ("nmap", "Port scan live subdomains discovered"),
            ],
            "httpx": [
                ("nuclei", "Scan web interface with custom CVE templates"),
                ("gobuster", "Enumerate directories for hidden endpoints"),
                ("nikto", "Verify web server configuration flags and SSL details"),
            ],
            "nuclei": [
                ("sqlmap", "Scan detected SQL Injection parameters for database dump"),
                ("hydra", "Brute force authentication portals found in scan"),
                (
                    "msfconsole",
                    "Trigger exploitation modules for verified vulnerabilities",
                ),
            ],
        }
        return progression.get(tool.lower(), [])
