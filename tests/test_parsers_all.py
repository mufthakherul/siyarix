"""Comprehensive tests for all tool output parsers."""

from __future__ import annotations

from phalanx.parsers.aircrack_parser import AircrackParser
from phalanx.parsers.amass_parser import AmassParser
from phalanx.parsers.bettercap_parser import BettercapParser
from phalanx.parsers.burpsuite_parser import BurpsuiteParser
from phalanx.parsers.ettercap_parser import EttercapParser
from phalanx.parsers.ffuf_parser import FfufParser
from phalanx.parsers.gobuster_parser import GobusterParser
from phalanx.parsers.hashcat_parser import HashcatParser
from phalanx.parsers.hydra_parser import HydraParser
from phalanx.parsers.impacket_parser import ImpacketParser
from phalanx.parsers.john_parser import JohnParser
from phalanx.parsers.masscan_parser import MasscanParser
from phalanx.parsers.metasploit_parser import MetasploitParser
from phalanx.parsers.nikto_parser import NiktoParser
from phalanx.parsers.nmap_parser import NmapParser
from phalanx.parsers.nuclei_parser import NucleiParser
from phalanx.parsers.shodan_parser import ShodanParser
from phalanx.parsers.sqlmap_parser import SqlmapParser
from phalanx.parsers.subfinder_parser import SubfinderParser
from phalanx.parsers.wpscan_parser import WpscanParser
from phalanx.parsers.zaproxy_parser import ZaproxyParser


def _check_finding(finding, expected_tool, min_fields=None):
    """Validate a finding dict has required structure."""
    min_fields = min_fields or {
        "title",
        "severity",
        "description",
        "evidence",
        "tool",
        "target",
        "timestamp",
    }
    for field in min_fields:
        assert field in finding, f"Missing field {field} in {expected_tool} finding"
    assert finding["tool"] == expected_tool
    assert finding["severity"] in ("critical", "high", "medium", "low", "info")


class TestNmapParser:
    def test_basic_parse(self):
        p = NmapParser()
        xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames><hostname name="test.local" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports>
</host></nmaprun>"""
        findings = p.parse(xml)
        assert len(findings) >= 2
        for f in findings:
            _check_finding(f, "nmap")

    def test_empty_output(self):
        p = NmapParser()
        assert p.parse("") == []


class TestNucleiParser:
    def test_basic_parse(self):
        p = NucleiParser()
        output = '{"template-id":"CVE-2023-1234","info":{"name":"Test Vuln","severity":"high"},"host":"example.com","matched-at":"example.com/admin"}\n'
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "nuclei")

    def test_empty_output(self):
        p = NucleiParser()
        assert p.parse("") == []


class TestGobusterParser:
    def test_basic_parse(self):
        p = GobusterParser()
        output = "Url: http://example.com\n/admin (Status: 200) [Size: 1234]\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "gobuster")

    def test_empty_output(self):
        p = GobusterParser()
        assert p.parse("") == []


class TestNiktoParser:
    def test_basic_parse(self):
        p = NiktoParser()
        output = "+ /admin: OSVDB-1234: Admin login page found.\n+ Server: Apache/2.4.7\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        for f in findings:
            _check_finding(f, "nikto")

    def test_empty_output(self):
        p = NiktoParser()
        assert p.parse("") == []


class TestFfufParser:
    def test_basic_parse(self):
        p = FfufParser()
        output = "admin                  [Status: 200, Size: 1234, Words: 100, Lines: 20]\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "ffuf")

    def test_empty_output(self):
        p = FfufParser()
        assert p.parse("") == []


class TestAmassParser:
    def test_basic_parse(self):
        p = AmassParser()
        output = (
            '{"name":"sub.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}\n'
        )
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "amass")

    def test_empty_output(self):
        p = AmassParser()
        assert p.parse("") == []


class TestSqlmapParser:
    def test_basic_parse(self):
        p = SqlmapParser()
        output = "[INFO] target URL appears to be 'http://example.com'\n[WARNING] parameter id is vulnerable\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "sqlmap")

    def test_empty_output(self):
        p = SqlmapParser()
        assert p.parse("") == []


class TestHydraParser:
    def test_basic_parse(self):
        p = HydraParser()
        output = "[22][ssh] host: 192.168.1.1 login: root password: admin123\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "hydra")
        assert findings[0]["severity"] == "critical"

    def test_empty_output(self):
        p = HydraParser()
        assert p.parse("") == []


class TestMasscanParser:
    def test_basic_parse(self):
        p = MasscanParser()
        output = "Discovered open port 80/tcp on 192.168.1.1\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "masscan")

    def test_empty_output(self):
        p = MasscanParser()
        assert p.parse("") == []


class TestMetasploitParser:
    def test_meterpreter_session(self):
        p = MetasploitParser()
        output = "[*] Meterpreter session 1 opened (1.2.3.4:4444 -> 5.6.7.8:12345)\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "metasploit")

    def test_empty_output(self):
        p = MetasploitParser()
        assert p.parse("") == []


class TestSubfinderParser:
    def test_basic_parse(self):
        p = SubfinderParser()
        output = "sub.example.com\nanother.example.com\n"
        findings = p.parse(output)
        assert len(findings) == 2
        _check_finding(findings[0], "subfinder")

    def test_empty_output(self):
        p = SubfinderParser()
        assert p.parse("") == []


class TestWpscanParser:
    def test_basic_parse(self):
        p = WpscanParser()
        output = "[+] URL: http://example.com\n[!] WordPress version 5.8 identified (vulnerable)\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "wpscan")

    def test_empty_output(self):
        p = WpscanParser()
        assert p.parse("") == []


class TestZaproxyParser:
    def test_basic_parse(self):
        p = ZaproxyParser()
        output = "[HIGH] Cross Site Scripting (Reflected) found at http://example.com/search\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "zaproxy")

    def test_empty_output(self):
        p = ZaproxyParser()
        assert p.parse("") == []


class TestShodanParser:
    def test_basic_parse(self):
        p = ShodanParser()
        output = '{"ip_str":"1.2.3.4","org":"Test Corp","os":"Linux","ports":[80,443],"vulns":["CVE-2023-1234"]}\n'
        findings = p.parse(output)
        assert len(findings) >= 2  # host summary + vulnerability
        _check_finding(findings[0], "shodan")

    def test_empty_output(self):
        p = ShodanParser()
        assert p.parse("") == []


class TestHashcatParser:
    def test_basic_parse(self):
        p = HashcatParser()
        output = "hash123:plaintext\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "hashcat")

    def test_empty_output(self):
        p = HashcatParser()
        assert p.parse("") == []


class TestJohnParser:
    def test_basic_parse(self):
        p = JohnParser()
        output = "admin:password123\n"
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "john")

    def test_empty_output(self):
        p = JohnParser()
        assert p.parse("") == []


class TestBurpsuiteParser:
    def test_basic_parse(self):
        p = BurpsuiteParser()
        output = "Issue: SQL Injection\nSeverity: High\nConfidence: Certain\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "burpsuite")

    def test_empty_output(self):
        p = BurpsuiteParser()
        assert p.parse("") == []


class TestBettercapParser:
    def test_basic_parse(self):
        p = BettercapParser()
        output = "[12:34:56] [sys.log] [mitm] spoofing detected on 192.168.1.1\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "bettercap")

    def test_empty_output(self):
        p = BettercapParser()
        assert p.parse("") == []


class TestEttercapParser:
    def test_basic_parse(self):
        p = EttercapParser()
        output = "Host 192.168.1.1 added to targets list\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "ettercap")

    def test_empty_output(self):
        p = EttercapParser()
        assert p.parse("") == []


class TestAircrackParser:
    def test_basic_parse(self):
        p = AircrackParser()
        output = "KEY FOUND! [ testpassword ]\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "aircrack-ng")

    def test_empty_output(self):
        p = AircrackParser()
        assert p.parse("") == []


class TestImpacketParser:
    def test_basic_parse(self):
        p = ImpacketParser()
        output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "impacket")

    def test_empty_output(self):
        p = ImpacketParser()
        assert p.parse("") == []


class TestParserEdgeCases:
    """Test edge cases across parsers."""

    def test_malformed_input(self):
        p = NucleiParser()
        assert p.parse("not json at all {{{") == []

    def test_unicode_input(self):
        p = SubfinderParser()
        result = p.parse("über.example.com\n")
        assert len(result) >= 1

    def test_very_long_output(self):
        p = MasscanParser()
        lines = [f"Discovered open port {p}/tcp on 10.0.0.1" for p in range(1, 1000)]
        result = p.parse("\n".join(lines))
        assert len(result) == 999

    def test_mixed_content(self):
        p = GobusterParser()
        output = "Url: http://example.com\nsome noise here\n/admin (Status: 200)\n[Footer]\n"
        findings = p.parse(output)
        assert len(findings) >= 1
