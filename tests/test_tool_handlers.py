# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for tool handler factory functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.tool_handlers import (
    _empty_target_result,
    _make_result,
    _run,
    make_brute_handler,
    make_crypto_handler,
    make_curl_handler,
    make_dns_handler,
    make_generic_handler,
    make_nmap_handler,
    make_network_handler,
    make_portscan_handler,
    make_recon_handler,
    make_web_handler,
    make_whois_handler,
)


@pytest.fixture(autouse=True)
def _patch_input_validator():
    """Prevent injection detection in all handler tests by default."""
    with patch("siyarix.security_hardening.InputValidator") as mock_cls:
        validator = MagicMock()
        validator.check_args_injection.return_value = (False, None)
        validator.sanitize_args.side_effect = lambda x: x
        mock_cls.return_value = validator
        yield


def _mock_result(exit_code=0, stdout="out", stderr=""):
    m = MagicMock()
    m.exit_code = exit_code
    m.stdout = stdout
    m.stderr = stderr
    return m


# ── Internal helpers ────────────────────────────────────────────────────────


class TestEmptyTargetResult:
    def test_returns_error_dict(self):
        result = _empty_target_result("nmap")
        assert result == {
            "status": "error",
            "error": "No target specified",
            "tool": "nmap",
        }


class TestRun:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.security_hardening.InputValidator")
    async def test_with_valid_cmd(self, MockValidator, mock_safe_run):
        mock_validator = MagicMock()
        mock_validator.check_args_injection.return_value = (False, None)
        mock_validator.sanitize_args.side_effect = lambda x: x
        MockValidator.return_value = mock_validator
        mock_safe_run.return_value = _mock_result(exit_code=0, stdout="ok")
        result = await _run("nmap", ["nmap", "target"])
        assert result.stdout == "ok"

    @patch("siyarix.security_hardening.InputValidator")
    async def test_with_command_injection(self, MockValidator):
        mock_validator = MagicMock()
        mock_validator.check_args_injection.return_value = (True, "shell_meta")
        MockValidator.return_value = mock_validator
        result = _run("nmap", ["nmap", "target; rm -rf /"])
        assert result.exit_code == 1
        assert "Security error" in result.stderr
        assert "shell_meta" in result.stderr

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.security_hardening.InputValidator", side_effect=ImportError("no module"))
    async def test_with_exception_in_validator(self, mock_validator_cls, mock_safe_run):
        mock_safe_run.return_value = _mock_result(exit_code=0, stdout="fallback")
        result = await _run("nmap", ["nmap", "target"])
        assert result.stdout == "fallback"


class TestMakeResult:
    def test_success_result(self):
        result = _make_result("nmap", _mock_result(exit_code=0, stdout="output", stderr=""))
        assert result["status"] == "success"
        assert result["output"] == "output"
        assert result["error"] == ""
        assert result["exit_code"] == 0
        assert result["tool"] == "nmap"

    def test_error_result(self):
        result = _make_result("nmap", _mock_result(exit_code=1, stdout="", stderr="error msg"))
        assert result["status"] == "error"
        assert result["output"] == ""
        assert result["error"] == "error msg"
        assert result["exit_code"] == 1


# ── Nmap Handler ────────────────────────────────────────────────────────────


class TestMakeNmapHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result(exit_code=0, stdout="nmap output")
        handler = make_nmap_handler("nmap")
        result = await handler(target="10.0.0.1")
        assert result["status"] == "success"
        assert result["output"] == "nmap output"
        mock_safe_run.assert_called_once()
        args, _ = mock_safe_run.call_args
        assert "10.0.0.1" in args[0]

    async def test_without_target(self):
        handler = make_nmap_handler("nmap")
        result = await handler()
        assert result["status"] == "error"
        assert result["error"] == "No target specified"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_custom_flags(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_nmap_handler("nmap")
        await handler(target="t", flags="-sV -p 22,80")
        args, _ = mock_safe_run.call_args
        assert "-sV" in args[0]
        assert "-p" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_custom_timeout(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_nmap_handler("nmap")
        await handler(target="t", timeout=300)
        assert mock_safe_run.call_args[1]["timeout"] == 300


# ── Web Handler ─────────────────────────────────────────────────────────────


class TestMakeWebHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def _run_web(self, tool_name, mock_safe_run, **kwargs):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler(tool_name)
        return await handler(**kwargs), mock_safe_run

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_nikto_flag(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("nikto")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert "-h" in args[0]
        assert "example.com" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_nuclei_flag(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("nuclei")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert "-duc" in args[0]
        assert "-u" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_gobuster_flag(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("gobuster")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert "-u" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_ffuf_flag(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("ffuf")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert "-u" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_wpscan_flag(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("wpscan")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert "--url" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_sqlmap_flag(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("sqlmap")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert "-u" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_without_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result(exit_code=0, stdout="help text")
        handler = make_web_handler("nikto")
        result = await handler()
        assert result["status"] == "success"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_extra_args_as_string(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("gobuster")
        await handler(target="example.com", args="-w wordlist.txt")
        args, _ = mock_safe_run.call_args
        assert "-w" in args[0]
        assert "wordlist.txt" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_extra_args_as_list(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("gobuster")
        await handler(target="example.com", args=["-w", "wordlist.txt"])
        args, _ = mock_safe_run.call_args
        assert "-w" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_unknown_tool_appends_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("unknown_tool")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["unknown_tool", "example.com"]

    @patch.dict("os.environ", {"SIYARIX_STEALTH": "1"})
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.stealth.StealthEngine")
    @patch("urllib.request.urlopen")
    @patch("urllib.request.Request")
    async def test_stealth_mode(self, mock_urllib_req, mock_urllib_open, MockStealth, mock_safe_run):
        mock_engine = MagicMock()
        mock_engine.get_decoy_requests.return_value = [
            {"url": "http://example.com/decoy", "method": "GET", "user_agent": "Mozilla"},
        ]
        MockStealth.return_value = mock_engine
        mock_safe_run.return_value = _mock_result()

        handler = make_web_handler("nuclei")
        await handler(target="example.com", stealth={"rotate_user_agents": True})
        mock_engine.set_config.assert_called_once_with(rotate_user_agents=True)
        mock_engine.get_decoy_requests.assert_called_once_with("example.com")

    @patch.dict("os.environ", {"SIYARIX_STEALTH": "1"})
    @patch("urllib.request.Request")
    @patch("urllib.request.urlopen", side_effect=Exception("Connection refused"))
    @patch("siyarix.stealth.StealthEngine")
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_stealth_mode_decoy_fail(self, mock_safe_run, MockStealth, mock_urllib_open, mock_urllib_req):
        mock_engine = MagicMock()
        mock_engine.get_decoy_requests.return_value = [
            {"url": "http://example.com/decoy", "method": "GET", "user_agent": "Mozilla"},
        ]
        MockStealth.return_value = mock_engine
        mock_safe_run.return_value = _mock_result()

        handler = make_web_handler("nuclei")
        result = await handler(target="example.com")
        assert result["status"] == "success"
        mock_engine.get_decoy_requests.assert_called_once_with("example.com")

    @patch.dict("os.environ", {"SIYARIX_STEALTH": "1"})
    @patch("urllib.request.Request")
    @patch("urllib.request.urlopen")
    @patch("siyarix.stealth.StealthEngine")
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_stealth_mode_no_stealth_kwarg(self, mock_safe_run, MockStealth, mock_urllib_open, mock_urllib_req):
        mock_engine = MagicMock()
        mock_engine.get_decoy_requests.return_value = []
        MockStealth.return_value = mock_engine
        mock_safe_run.return_value = _mock_result()

        handler = make_web_handler("nuclei")
        await handler(target="example.com")
        mock_engine.set_config.assert_not_called()

    @patch.dict("os.environ", {"SIYARIX_STEALTH": "1"})
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.stealth.StealthEngine", side_effect=ImportError("no module"))
    async def test_stealth_import_fail(self, MockStealth, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_web_handler("nuclei")
        result = await handler(target="example.com")
        assert result["status"] == "success"


# ── Portscan Handler ────────────────────────────────────────────────────────


class TestMakePortscanHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_portscan_handler("masscan")
        result = await handler(target="10.0.0.0/24")
        assert result["status"] == "success"

    async def test_without_target(self):
        handler = make_portscan_handler("masscan")
        result = await handler()
        assert result["status"] == "error"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_custom_flags(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_portscan_handler("masscan")
        await handler(target="t", flags="-p 80,443 --rate 100")
        args, _ = mock_safe_run.call_args
        assert "-p" in args[0]
        assert "--rate" in args[0]


# ── Recon Handler ───────────────────────────────────────────────────────────


class TestMakeReconHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_amass_enum(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("amass")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["amass", "enum", "-d", "example.com"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_amass_no_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("amass")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["amass", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_subfinder(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("subfinder")
        await handler(target="example.com")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["subfinder", "-d", "example.com"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_subfinder_no_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("subfinder")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["subfinder", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_shodan_info(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("shodan")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["shodan", "info"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_shodan_host(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("shodan")
        await handler(target="1.1.1.1")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["shodan", "host", "1.1.1.1"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_shodan_target_starts_with_dash(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("shodan")
        await handler(target="--help")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["shodan", "info"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_other_tool(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_recon_handler("sherlock")
        await handler(target="user")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["sherlock", "--help"]


# ── Brute Handler ───────────────────────────────────────────────────────────


class TestMakeBruteHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_brute_handler("hydra")
        result = await handler(target="10.0.0.1")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert "ssh://10.0.0.1" in args[0]

    async def test_without_target(self):
        handler = make_brute_handler("hydra")
        result = await handler()
        assert result["status"] == "error"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_custom_service_username_wordlist(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_brute_handler("hydra")
        await handler(target="10.0.0.1", service="rdp", username="admin", wordlist="/tmp/custom.txt")
        args, _ = mock_safe_run.call_args
        assert "rdp://10.0.0.1" in args[0]
        assert "-l" in args[0]
        assert "admin" in args[0]
        assert "/tmp/custom.txt" in args[0]


# ── Network Handler ─────────────────────────────────────────────────────────


class TestMakeNetworkHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_bettercap(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("bettercap")
        await handler(target="10.0.0.0/24")
        args, _ = mock_safe_run.call_args
        assert "bettercap" in args[0]
        assert any("arp.spoof" in a for a in args[0])

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_ettercap(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("ettercap")
        await handler(target="10.0.0.1")
        args, _ = mock_safe_run.call_args
        assert "ettercap" in args[0]
        assert "/10.0.0.1//" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_aircrack_capture(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("aircrack-ng")
        await handler(target="wlan0mon", mode="capture")
        args, _ = mock_safe_run.call_args
        assert "aircrack-ng" in args[0]
        assert "-c" in args[0]
        assert "wlan0mon" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_aircrack_capture_no_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("aircrack-ng")
        await handler(mode="capture")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["aircrack-ng", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_aircrack_crack(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("aircrack-ng")
        await handler(mode="crack", pcap="capture.pcap", wordlist="/tmp/wl.txt")
        args, _ = mock_safe_run.call_args
        assert "aircrack-ng" in args[0]
        assert "-w" in args[0]
        assert "capture.pcap" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_aircrack_crack_no_pcap(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("aircrack-ng")
        await handler(mode="crack")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["aircrack-ng", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_aircrack_no_mode(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("aircrack-ng")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["aircrack-ng", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_aircrack_invalid_mode(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("aircrack-ng")
        await handler(mode="invalid")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["aircrack-ng", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_other_network_tool(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_network_handler("netcat")
        await handler(target="10.0.0.1")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["netcat", "--help"]


# ── Crypto Handler ──────────────────────────────────────────────────────────


class TestMakeCryptoHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_hashcat_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_crypto_handler("hashcat")
        result = await handler(target="hash.txt")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert "-m" in args[0]
        assert "-a" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_hashcat_with_hashfile(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_crypto_handler("hashcat")
        await handler(target="t", hashfile="custom.hash", mode="1000")
        args, _ = mock_safe_run.call_args
        assert "custom.hash" in args[0]
        assert "1000" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_john_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_crypto_handler("john")
        result = await handler(target="hash.txt")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert args[0] == ["john", "hash.txt"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_hashcat_no_target_shows_help(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_crypto_handler("hashcat")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["hashcat", "--help"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_john_no_target_shows_help(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_crypto_handler("john")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["john", "--help"]


# ── Curl Handler ────────────────────────────────────────────────────────────


class TestMakeCurlHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_curl_handler("curl")
        result = await handler(target="https://example.com")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert "https://example.com" in args[0]

    async def test_without_target(self):
        handler = make_curl_handler("curl")
        result = await handler()
        assert result["status"] == "error"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_custom_flags(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_curl_handler("curl")
        await handler(target="https://example.com", flags="-k -v")
        args, _ = mock_safe_run.call_args
        assert "-k" in args[0]
        assert "-v" in args[0]


# ── DNS Handler ─────────────────────────────────────────────────────────────


class TestMakeDnsHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_dns_handler("dnsrecon")
        result = await handler(target="example.com")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert "example.com" in args[0]

    async def test_without_target(self):
        handler = make_dns_handler("dnsrecon")
        result = await handler()
        assert result["status"] == "error"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_custom_flags(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_dns_handler("dnsrecon")
        await handler(target="example.com", flags="-t axfr")
        args, _ = mock_safe_run.call_args
        assert "-t" in args[0]
        assert "axfr" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_no_flags(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_dns_handler("dnsrecon")
        await handler(target="example.com", flags="")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["dnsrecon", "example.com"]


# ── Whois Handler ───────────────────────────────────────────────────────────


class TestMakeWhoisHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_with_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_whois_handler("whois")
        result = await handler(target="example.com")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert args[0] == ["whois", "example.com"]

    async def test_without_target(self):
        handler = make_whois_handler("whois")
        result = await handler()
        assert result["status"] == "error"


# ── Generic Handler ─────────────────────────────────────────────────────────


class TestMakeGenericHandler:
    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.validators.validate_target")
    async def test_with_args_as_string(self, mock_validate, mock_safe_run):
        mock_validate.return_value = {"type": "hostname", "normalized": "example.com"}
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        result = await handler(target="example.com", args="-v -o output.txt")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert "-v" in args[0]
        assert "-o" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.validators.validate_target")
    async def test_with_args_as_list(self, mock_validate, mock_safe_run):
        mock_validate.return_value = {"type": "hostname", "normalized": "example.com"}
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        await handler(target="example.com", args=["-v", "-o", "output.txt"])
        args, _ = mock_safe_run.call_args
        assert "-v" in args[0]
        assert "-o" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_no_args(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        await handler()
        args, _ = mock_safe_run.call_args
        assert args[0] == ["mytool"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.validators.validate_target")
    async def test_with_flags(self, mock_validate, mock_safe_run):
        mock_validate.return_value = {"type": "hostname", "normalized": "example.com"}
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        await handler(target="example.com", flags="--debug --verbose")
        args, _ = mock_safe_run.call_args
        assert "--debug" in args[0]
        assert "--verbose" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_valid_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        result = await handler(target="example.com")
        assert result["status"] == "success"
        args, _ = mock_safe_run.call_args
        assert "example.com" in args[0]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_invalid_target(self, mock_safe_run):
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        result = await handler(target="bad input")
        assert result["status"] == "success"

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    async def test_exception_handling(self, mock_safe_run):
        mock_safe_run.side_effect = RuntimeError("Something broke")
        handler = make_generic_handler("mytool")
        result = await handler()
        assert result["status"] == "error"
        assert "Something broke" in result["error"]

    @patch("siyarix.subprocess_utils.safe_run_async", new_callable=AsyncMock)
    @patch("siyarix.validators.validate_target")
    async def test_with_target_and_all_options(self, mock_validate, mock_safe_run):
        mock_validate.return_value = {"type": "hostname", "normalized": "example.com"}
        mock_safe_run.return_value = _mock_result()
        handler = make_generic_handler("mytool")
        await handler(target="example.com", args=["-x"], flags="-z")
        args, _ = mock_safe_run.call_args
        assert args[0] == ["mytool", "-x", "-z", "example.com"]
