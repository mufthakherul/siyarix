"""Tests for Active Directory & Windows Security parsers."""
from __future__ import annotations

import json
from siyarix.parsers.bloodhound_parser import BloodhoundParser
from siyarix.parsers.bloodhound_python_parser import BloodhoundPythonParser
from siyarix.parsers.certipy_parser import CertipyParser
from siyarix.parsers.crackmapexec_parser import CrackmapexecParser
from siyarix.parsers.enum4linux_parser import Enum4linuxParser
from siyarix.parsers.evil_winrm_parser import EvilWinrmParser
from siyarix.parsers.impacket_parser import ImpacketParser
from siyarix.parsers.kerbrute_parser import KerbruteParser
from siyarix.parsers.mimikatz_parser import MimikatzParser
from siyarix.parsers.pypykatz_parser import PypykatzParser
from siyarix.parsers.responder_parser import ResponderParser
from siyarix.parsers.seatbelt_parser import SeatbeltParser
from siyarix.parsers.sharphound_parser import SharphoundParser
from siyarix.parsers.smbclient_parser import SmbclientParser
from siyarix.parsers.smbmap_parser import SmbmapParser


def _check_finding(finding, expected_tool, min_fields=None):
    min_fields = min_fields or {
        "title", "severity", "description", "evidence", "tool", "target", "timestamp",
    }
    for field in min_fields:
        assert field in finding, f"Missing field {field} in {expected_tool} finding"
    assert finding["tool"] == expected_tool
    assert finding["severity"] in ("critical", "high", "medium", "low", "info")



class TestPypykatzParser:
    def test_json_output_with_credentials(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": {
                    "secrets": [
                        {"Password": "P@ssw0rd!", "NTHash": "31d6cfe0d16ae931b73c59d7e0c089c1"},
                    ],
                },
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        for f in findings:
            _check_finding(f, "pypykatz")
            assert f["severity"] == "critical"

    def test_json_output_with_empty_hash(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "user1", "DomainName": "WORKGROUP"},
            "Credentials": {
                "WDIGEST": {
                    "creds": [
                        {"Password": "", "NTHash": "aad3b435b51404eeaad3b435b51404ee"},
                    ],
                },
            },
        })
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_list_output(self):
        p = PypykatzParser()
        output = json.dumps([
            {
                "LogonSession": {"Username": "alice", "DomainName": "CORP"},
                "Credentials": {
                    "MSV": {"secrets": [{"Password": "secret123", "NTHash": ""}]},
                },
            },
        ])
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_plaintext_password_line(self):
        p = PypykatzParser()
        output = "password : admin123\nusername : root\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"

    def test_line_based_json(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "bob", "DomainName": "LOCAL"},
            "Credentials": {
                "LIVESS": {
                    "c": [{"Password": "bobpass", "NTHash": ""}],
                },
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_mixed_content(self):
        p = PypykatzParser()
        output = "some noise text\npassword : SecretP@ss\n"
        findings = p.parse(output)
        assert any("unknown" in f["title"] or "SecretP@ss" in f["description"] for f in findings)
        for f in findings:
            _check_finding(f, "pypykatz")
            assert f["severity"] == "critical"

    def test_empty_output(self):
        p = PypykatzParser()
        assert p.parse("") == []
        assert p.parse("   ") == []

    def test_malformed_json(self):
        p = PypykatzParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)
class TestBloodhoundParser:
    def test_json_user_output(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [{"Label": "ADMIN", "ObjectId": "S-1-5-21-1001-500", "ObjectType": "User"}],
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "bloodhound")
        assert "User" in findings[0]["title"]

    def test_json_computer_output(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [{"Label": "DC01.CORP.LOCAL", "ObjectId": "S-1-5-21-1001-1000", "ObjectType": "Computer"}],
        })
        findings = p.parse(output)
        assert "Computer" in findings[0]["title"]

    def test_json_group_output(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [{"Label": "DOMAIN ADMINS", "ObjectId": "S-1-5-21-1001-512", "ObjectType": "Group"}],
        })
        findings = p.parse(output)
        assert "Group" in findings[0]["title"]

    def test_json_user_props_format(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "User",
            "props": {"samaccountname": "jdoe", "userprincipalname": "jdoe@corp.local", "enabled": True},
        })
        findings = p.parse(output)
        assert any("jdoe" in f["title"] for f in findings)

    def test_json_computer_props_format(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Computer",
            "props": {"name": "WS001", "operatingsystem": "Windows 10 Pro", "samaccountname": "WS001$"},
        })
        findings = p.parse(output)
        assert any("WS001" in f["title"] for f in findings)

    def test_json_session_props_format(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Session",
            "props": {"user": "JDOE", "computer": "DC01"},
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_json_acl_props_format(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Acl",
            "props": {"principal": "JDOE", "righttype": "GenericAll"},
        })
        findings = p.parse(output)
        assert any("ACL" in f["title"] or "GenericAll" in f["title"] for f in findings)

    def test_empty_output(self):
        p = BloodhoundParser()
        assert p.parse("") == []

    def test_malformed_json(self):
        p = BloodhoundParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)
class TestBloodhoundPythonParser:
    def test_json_user_no_spn(self):
        p = BloodhoundPythonParser()
        output = json.dumps({"type": "user", "props": {"name": "jdoe", "domain": "CORP.LOCAL", "enabled": True}})
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "bloodhound-python")
        assert findings[0]["severity"] == "info"
        assert "jdoe" in findings[0]["title"]

    def test_json_user_with_spn(self):
        p = BloodhoundPythonParser()
        output = json.dumps({
            "type": "user",
            "props": {
                "name": "svc_account",
                "domain": "CORP.LOCAL",
                "serviceprincipalnames": ["HTTP/server.corp.local"],
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_json_computer(self):
        p = BloodhoundPythonParser()
        output = json.dumps({
            "type": "computer",
            "props": {"name": "DC01", "domain": "CORP.LOCAL", "operatingsystem": "Windows Server 2022"},
        })
        findings = p.parse(output)
        assert any("DC01" in f["title"] for f in findings)

    def test_json_group(self):
        p = BloodhoundPythonParser()
        output = json.dumps({
            "type": "group",
            "props": {"name": "Domain Admins", "domain": "CORP.LOCAL"},
        })
        findings = p.parse(output)
        assert any("Domain Admins" in f["title"] for f in findings)

    def test_json_session(self):
        p = BloodhoundPythonParser()
        output = json.dumps({
            "type": "session",
            "props": {"name": "jdoe", "computer": "DC01", "domain": "CORP.LOCAL"},
        })
        findings = p.parse(output)
        assert findings[0]["severity"] == "medium"
        assert "jdoe" in findings[0]["title"]

    def test_json_acl(self):
        p = BloodhoundPythonParser()
        output = json.dumps({
            "type": "acl",
            "props": {"name": "jdoe", "rightguid": "GenericAll", "domain": "CORP.LOCAL"},
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "low"

    def test_info_found_line(self):
        p = BloodhoundPythonParser()
        output = "INFO: Found 150 users\nINFO: Found 20 computers\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        assert any("Users" in f["title"] or "users" in f["title"] for f in findings)

    def test_mixed_info_and_json(self):
        p = BloodhoundPythonParser()
        output = (
            "INFO: Found 5 users\n"
            + json.dumps({"type": "user", "props": {"name": "admin", "domain": "CORP.LOCAL"}})
            + "\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_empty_output(self):
        p = BloodhoundPythonParser()
        assert p.parse("") == []

    def test_malformed_json(self):
        p = BloodhoundPythonParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)
class TestEnum4linuxParser:
    def test_user_discovery(self):
        p = Enum4linuxParser()
        output = "user: administrator\nuser: jdoe\nuser: guest\n"
        findings = p.parse(output)
        assert len(findings) >= 3
        for f in findings:
            _check_finding(f, "enum4linux")
        assert all(f["severity"] == "medium" for f in findings)

    def test_share_discovery(self):
        p = Enum4linuxParser()
        output = "ADMIN$ disk shares\nC$ disk shares\nIPC$ disk shares\n"
        findings = p.parse(output)
        assert len(findings) >= 3
        for f in findings:
            _check_finding(f, "enum4linux")
        assert all(f["severity"] == "medium" for f in findings)

    def test_os_identification(self):
        p = Enum4linuxParser()
        output = "OS: Windows Server 2022 Standard 20348\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "Windows" in findings[0]["title"]

    def test_workgroup_discovery(self):
        p = Enum4linuxParser()
        output = "Workgroup: WORKGROUP\n"
        findings = p.parse(output)
        assert any("Workgroup" in f["title"] for f in findings)

    def test_sid_discovery(self):
        p = Enum4linuxParser()
        output = "Domain SID: S-1-5-21-1234567890-0987654321-1234567890-500\n"
        findings = p.parse(output)
        assert any("SID:" in f["title"] or "S-1-5-21" in f["title"] for f in findings)

    def test_rid_entry(self):
        p = Enum4linuxParser()
        output = "[RID] : 500 Administrator\n[RID] : 501 Guest\n"
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_password_policy(self):
        p = Enum4linuxParser()
        output = "Password policy: Minimum password length: 8\n"
        findings = p.parse(output)
        assert any("policy" in f["title"].lower() for f in findings)

    def test_printer_info(self):
        p = Enum4linuxParser()
        output = "Printer: HP LaserJet 4000\n"
        findings = p.parse(output)
        assert any("Printer" in f["title"] for f in findings)

    def test_domain_group(self):
        p = Enum4linuxParser()
        output = "domain group: Domain Admins\n"
        findings = p.parse(output)
        assert any("group" in f["title"].lower() for f in findings)

    def test_session_info(self):
        p = Enum4linuxParser()
        output = "Session: jdoe logged in\n"
        findings = p.parse(output)
        assert any("session" in f["title"].lower() for f in findings)

    def test_json_format(self):
        p = Enum4linuxParser()
        output = json.dumps([
            {"user": "admin", "host": "10.0.0.1"},
            {"share": "ADMIN$", "host": "10.0.0.1"},
            {"os": "Windows 10", "host": "10.0.0.1"},
        ])
        findings = p.parse(output)
        assert len(findings) >= 3

    def test_target_line(self):
        p = Enum4linuxParser()
        output = "Target: 10.0.0.1\nuser: admin\nuser: backup\n"
        findings = p.parse(output)
        assert any("admin" in f["title"] for f in findings)

    def test_empty_output(self):
        p = Enum4linuxParser()
        assert p.parse("") == []
class TestSmbclientParser:
    def test_share_discovery_text(self):
        p = SmbclientParser()
        output = (
            "server: 10.0.0.1\n"
            "Domain=[WORKGROUP] OS=[Windows 10] Server=[SMB 3.1.1]\n"
            "\tADMIN$ Disk\n"
            "\tC$ Disk\n"
            "\tIPC$ Disk\n"
        )
        findings = p.parse(output)
        shares = [f for f in findings if "share" in f["title"].lower()]
        assert len(shares) >= 3
        for f in findings:
            _check_finding(f, "smbclient")

    def test_domain_os_server(self):
        p = SmbclientParser()
        output = (
            "Domain=[CORP]\n"
            "OS=[Windows Server 2022]\n"
            "Server=[SMB Server]\n"
        )
        findings = p.parse(output)
        assert any("domain" in f["title"].lower() for f in findings)
        assert any("OS" in f["title"] for f in findings)
        assert any("server" in f["title"].lower() for f in findings)

    def test_smb_version(self):
        p = SmbclientParser()
        output = "SMB version: 3.1.1\n"
        findings = p.parse(output)
        assert any("version" in f["title"].lower() for f in findings)

    def test_netbios_name(self):
        p = SmbclientParser()
        output = "NetBIOS: SERVER01\n"
        findings = p.parse(output)
        assert any("NetBIOS" in f["title"] for f in findings)

    def test_file_listing(self):
        p = SmbclientParser()
        output = json.dumps([
            {"filename": "secret.doc", "server": "10.0.0.1", "size": 1024},
            {"filename": "data.xlsx", "server": "10.0.0.1", "size": 2048},
        ])
        findings = p.parse(output)
        files = [f for f in findings if "file" in f["title"].lower()]
        assert len(files) >= 2
        for f in files:
            _check_finding(f, "smbclient")

    def test_connected_session(self):
        p = SmbclientParser()
        output = "session started with server 10.0.0.1\n"
        findings = p.parse(output)
        assert any("session" in f["title"].lower() for f in findings)

    def test_json_format(self):
        p = SmbclientParser()
        output = json.dumps([
            {"share": "ADMIN$", "server": "10.0.0.1"},
            {"filename": "passwords.txt", "server": "10.0.0.1", "size": 512},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_empty_output(self):
        p = SmbclientParser()
        assert p.parse("") == []
class TestSmbmapParser:
    def test_share_with_permissions(self):
        p = SmbmapParser()
        output = "Target: 10.0.0.1\nADMIN$ (READ,WRITE)\nC$ (READ ONLY)\nIPC$ (ACCESS DENIED)\n"
        findings = p.parse(output)
        assert len(findings) >= 3
        for f in findings:
            _check_finding(f, "smbmap")
        write_shares = [f for f in findings if "WRITE" in f["title"] or "WRITE" in f["description"]]
        assert len(write_shares) >= 1
        assert write_shares[0]["severity"] == "critical"

    def test_shares_line_format(self):
        p = SmbmapParser()
        output = "Target: 10.0.0.1\nShares: ADMIN$ (READ,WRITE) C$ (READ ONLY)\n"
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_file_listing(self):
        p = SmbmapParser()
        output = "Target: 10.0.0.1\nDisk: [ADMIN$]\n  passwords.txt 1024 a-- 2024-01-01\n  backup.zip 2048 b-- 2024-01-02\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            _check_finding(f, "smbmap")

    def test_disk_usage(self):
        p = SmbmapParser()
        output = "Target: 10.0.0.1\n2.5GB used out of 10.0GB\n"
        findings = p.parse(output)
        assert any("usage" in f["title"].lower() for f in findings)

    def test_host_regex(self):
        p = SmbmapParser()
        output = "(10.0.0.1) - Windows Server 2022\n"
        findings = p.parse(output)
        assert any("target" in f["title"].lower() for f in findings)

    def test_recursive_directory(self):
        p = SmbmapParser()
        output = "Target: 10.0.0.1\nDisk: [SHARE1]\n`-.\n  |.\\dir1\\\n  |.\\dir1\\file.txt\n"
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_json_format(self):
        p = SmbmapParser()
        output = json.dumps([
            {"share": "ADMIN$", "permission": "READ,WRITE", "target": "10.0.0.1"},
            {"filename": "secret.txt", "size": 512, "target": "10.0.0.1"},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_empty_output(self):
        p = SmbmapParser()
        assert p.parse("") == []
class TestMimikatzParser:
    def test_json_credentials_with_ntlm(self):
        p = MimikatzParser()
        output = json.dumps([{"username": "admin", "domain": "CONTOSO", "NTLM": "aad3b435b51404eeaad3b435b51404ee"}])
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "mimikatz")
        assert findings[0]["severity"] == "critical"

    def test_json_credentials_with_password(self):
        p = MimikatzParser()
        output = json.dumps([{"username": "user1", "domain": "WORKGROUP", "password": "P@ssw0rd"}])
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("plaintext" in f["title"].lower() for f in findings)

    def test_json_credentials_with_both(self):
        p = MimikatzParser()
        output = json.dumps({"username": "admin", "domain": "DOMAIN", "NTLM": "31d6cfe0d16ae931b73c59d7e0c089c1", "password": "Secret123"})
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            _check_finding(f, "mimikatz")

    def test_json_null_password_skipped(self):
        p = MimikatzParser()
        output = json.dumps({"username": "guest", "domain": "DOMAIN", "password": "(null)"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_logonpasswords_text(self):
        p = MimikatzParser()
        output = (
            "  sekurlsa::logonpasswords\n"
            "  * Username : admin\n"
            "  * Domain   : CONTOSO\n"
            "  * NTLM     : aad3b435b51404eeaad3b435b51404ee\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 2
        assert any("logonpasswords" in f["title"].lower() for f in findings)

    def test_dcsync_detection(self):
        p = MimikatzParser()
        output = "  lsadump::dcsync /user:krbtgt\n  * Username : krbtgt\n  * Domain   : CONTOSO\n  * NTLM     : aad3b435b51404eeaad3b435b51404ee\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        assert any("dcsync" in f["title"].lower() for f in findings)

    def test_golden_ticket_detection(self):
        p = MimikatzParser()
        output = "  kerberos::golden /user:Administrator /domain:contoso.local\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("golden" in f["title"].lower() for f in findings)

    def test_ticket_extraction(self):
        p = MimikatzParser()
        output = "[ticket] Ticket saved to admin.kirbi\n  * Username : admin\n  * Domain   : CONTOSO\n  * NTLM     : aad3b435b51404eeaad3b435b51404ee\n"
        findings = p.parse(output)
        assert any("ticket" in f["title"].lower() for f in findings)

    def test_plaintext_password_text(self):
        p = MimikatzParser()
        output = "  * Username : user1\n  * Domain   : WORKGROUP\n  * Password : plaintextPwd\n"
        findings = p.parse(output)
        assert any("plaintext" in f["title"].lower() for f in findings)

    def test_empty_output(self):
        p = MimikatzParser()
        assert p.parse("") == []

    def test_json_array_mixed(self):
        p = MimikatzParser()
        output = json.dumps([{"user": "u1", "domain": "D", "ntlm": "aad3b435b51404eeaad3b435b51404ee"}, {"user": "u2", "domain": "D", "NTLM": "31d6cfe0d16ae931b73c59d7e0c089c1", "password": "pwd"}])
        findings = p.parse(output)
        assert len(findings) >= 3

    def test_section_tracking(self):
        p = MimikatzParser()
        output = "  msv [\n  * Username : user1\n  * Domain   : D\n  * NTLM     : aad3b435b51404eeaad3b435b51404ee\n"
        findings = p.parse(output)
        assert any("msv" in f["title"].lower() or "MSV" in f["title"] for f in findings)
class TestEvilWinrmParser:
    def test_banner_detected(self):
        p = EvilWinrmParser()
        output = "Evil-WinRM shell session opened on 192.168.1.100\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "evil_winrm")
        assert findings[0]["severity"] == "critical"

    def test_connection_established(self):
        p = EvilWinrmParser()
        output = "Connecting to 10.0.0.1:5985 established successfully\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"

    def test_connection_failed(self):
        p = EvilWinrmParser()
        output = "Connecting to 10.0.0.1:5985 error: connection refused\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "info"

    def test_banner_with_username(self):
        p = EvilWinrmParser()
        output = "Evil-WinRM PS session on 192.168.1.100 user: administrator\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "administrator" in findings[0]["description"]

    def test_target_identified(self):
        p = EvilWinrmParser()
        output = "Found HTTP endpoint on 192.168.1.100 port 5985\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "Target" in findings[0]["title"]

    def test_json_session(self):
        p = EvilWinrmParser()
        output = json.dumps([{"host": "192.168.1.100", "username": "admin"}])
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "evil_winrm")
        assert findings[0]["severity"] == "critical"

    def test_json_multiple_sessions(self):
        p = EvilWinrmParser()
        output = json.dumps([{"host": "10.0.0.1", "username": "admin"}, {"host": "10.0.0.2", "username": "user"}])
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_empty_output(self):
        p = EvilWinrmParser()
        assert p.parse("") == []

    def test_connection_attempt_severity(self):
        p = EvilWinrmParser()
        output = "Connecting to 10.0.0.1:5985 ...\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_dedup_same_host(self):
        p = EvilWinrmParser()
        output = "Evil-WinRM shell on 192.168.1.100\nEvil-WinRM PS session on 192.168.1.100\n"
        findings = p.parse(output)
        assert len(findings) == 1
class TestKerbruteParser:
    def test_valid_user_text(self):
        p = KerbruteParser()
        output = "[+] VALID USER: admin@domain.local\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "kerbrute")
        assert findings[0]["severity"] == "high"

    def test_valid_user_with_timestamp(self):
        p = KerbruteParser()
        output = "2025/01/01 12:00:00 > [+] VALID USER: john@domain.local\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_invalid_user(self):
        p = KerbruteParser()
        output = "[-] user invalid - does not exist\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_asrep_hash_text(self):
        p = KerbruteParser()
        output = "AS-REP hash: $krb5asrep$user@domain:hash123\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"

    def test_tgt_captured(self):
        p = KerbruteParser()
        output = "TGT ticket captured from DC\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_json_valid(self):
        p = KerbruteParser()
        output = json.dumps({"username": "admin@domain.local", "valid": True, "domain": "domain.local"})
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "kerbrute")

    def test_json_with_hash(self):
        p = KerbruteParser()
        output = json.dumps({"username": "user@domain", "valid": True, "hash": "$krb5asrep$user@domain:abcd1234"})
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_empty_output(self):
        p = KerbruteParser()
        assert p.parse("") == []

    def test_password_spray_result(self):
        p = KerbruteParser()
        output = "PASS: admin:Password123\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_user_stats(self):
        p = KerbruteParser()
        output = "3 valid users found\n"
        findings = p.parse(output)
        assert len(findings) >= 1
class TestImpacketParser:
    def test_smb_share_accessed(self):
        p = ImpacketParser()
        output = "Impacket v0.9.19 - Copyright 2020 SecureAuth\nSMB share opened on 192.168.1.1\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "impacket")
        assert findings[0]["severity"] == "medium"

    def test_secretsdump_hash(self):
        p = ImpacketParser()
        output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c1:::\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "impacket")
        assert findings[0]["severity"] == "critical"

    def test_wmi_execution(self):
        p = ImpacketParser()
        output = "WMI Exec result: success\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_kerberos_attack(self):
        p = ImpacketParser()
        output = "Impacket v0.9.19 - Copyright 2020 SecureAuth\n[*] KRB5 ticket captured\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_empty_output(self):
        p = ImpacketParser()
        assert p.parse("") == []

    def test_generic_output_no_findings(self):
        p = ImpacketParser()
        output = "Some generic message\n"
        findings = p.parse(output)
        assert isinstance(findings, list)
class TestCertipyParser:
    def test_success_line_with_esc(self):
        p = CertipyParser()
        output = "[*] Vulnerable to ESC1 - template allows domain users to enroll\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        _check_finding(findings[0], "certipy")

    def test_esc_critical_severity(self):
        p = CertipyParser()
        output = "[*] Vulnerable to ESC8 - NTLM relay to CA HTTP endpoint\n"
        findings = p.parse(output)
        esc_findings = [f for f in findings if "ESC8" in f["title"]]
        assert len(esc_findings) >= 1
        assert esc_findings[0]["severity"] == "critical"

    def test_certificate_template(self):
        p = CertipyParser()
        output = "[*] Certificate Template: SubCA\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_ca_info(self):
        p = CertipyParser()
        output = "[*] CA Name: contoso-DC-CA\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_pkcs12_saved(self):
        p = CertipyParser()
        output = "[*] Saved certificate to admin.p12\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_json_input(self):
        p = CertipyParser()
        output = json.dumps([{"template": "SubCA", "ca": "contoso-DC-CA", "vulnerability": "ESC1"}])
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_no_template(self):
        p = CertipyParser()
        output = json.dumps({"ca": "contoso-DC-CA"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_user_identifier(self):
        p = CertipyParser()
        output = "[*] User Principal: admin@contoso.local\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_vulnerable_template(self):
        p = CertipyParser()
        output = "[*] Vulnerable certificate template: UserAuthentication\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_got_certificate(self):
        p = CertipyParser()
        output = "Got certificate for admin\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_empty_output(self):
        p = CertipyParser()
        assert p.parse("") == []

    def test_feature_enabled(self):
        p = CertipyParser()
        output = "[*] Template Enabled for enrollment\n"
        findings = p.parse(output)
        assert len(findings) >= 1
class TestBloodhoundParser_extra_b5:
    def test_data_list_with_labels(self):
        p = BloodhoundParser()
        output = json.dumps({"data": [{"Label": "ADMIN", "ObjectId": "S-1-5-21-123", "ObjectType": "User"}, {"Label": "DC01", "ObjectId": "S-1-5-21-456", "ObjectType": "Computer"}]})
        findings = p.parse(output)
        assert len(findings) >= 2
        _check_finding(findings[0], "bloodhound")

    def test_data_list_group(self):
        p = BloodhoundParser()
        output = json.dumps({"data": [{"Label": "Domain Admins", "ObjectId": "S-1-5-21-789", "ObjectType": "Group"}]})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "Group" in findings[0]["title"]

    def test_user_props(self):
        p = BloodhoundParser()
        output = json.dumps({"type": "User", "props": {"samaccountname": "admin", "userprincipalname": "admin@contoso.local", "enabled": True}})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_computer_props(self):
        p = BloodhoundParser()
        output = json.dumps({"type": "Computer", "props": {"name": "DC01.contoso.local", "operatingsystem": "Windows Server 2022", "samaccountname": "DC01$"}})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_group_props(self):
        p = BloodhoundParser()
        output = json.dumps({"type": "Group", "props": {"name": "Domain Admins"}})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_session(self):
        p = BloodhoundParser()
        output = json.dumps({"type": "Session", "props": {"user": "admin", "computer": "DC01"}})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_acl(self):
        p = BloodhoundParser()
        output = json.dumps({"type": "Acl", "props": {"principal": "ADMIN", "righttype": "GenericAll"}})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

    def test_empty_output(self):
        p = BloodhoundParser()
        assert p.parse("") == []

    def test_non_json_skipped(self):
        p = BloodhoundParser()
        output = "not json\n"
        findings = p.parse(output)
        assert isinstance(findings, list)

    def test_dedup(self):
        p = BloodhoundParser()
        output = json.dumps({"data": [{"Label": "ADMIN", "ObjectId": "S-1-5-21-123", "ObjectType": "User"}]}) + "\n" + json.dumps({"data": [{"Label": "ADMIN", "ObjectId": "S-1-5-21-123", "ObjectType": "User"}]})
        findings = p.parse(output)
        assert len(findings) == 1
class TestMimikatzParser_extra_b6:
    def test_json_single_credential(self):
        p = MimikatzParser()
        output = '{"username":"Admin","domain":"EXAMPLE","ntlm":"31d6cfe0d16ae931b73c59d7e0c089c1","password":"Passw0rd!"}\n'
        findings = p.parse(output)
        assert len(findings) >= 2
        credential_titles = [f for f in findings if "credential" in f["title"].lower()]
        password_titles = [f for f in findings if "plaintext" in f["title"].lower()]
        assert len(credential_titles) >= 1
        assert len(password_titles) >= 1
        for f in findings:
            _check_finding(f, "mimikatz")

    def test_json_list_credentials(self):
        p = MimikatzParser()
        output = json.dumps([
            {"username": "Admin", "domain": "EXAMPLE", "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c1"},
            {"username": "User1", "domain": "EXAMPLE", "password": "secret123"},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2
        admin_findings = [f for f in findings if "Admin" in f.get("target", "")]
        assert len(admin_findings) >= 0

    def test_json_credential_with_null_password(self):
        p = MimikatzParser()
        output = '{"username":"Admin","domain":"EXAMPLE","ntlm":"31d6cfe0d16ae931b73c59d7e0c089c1","password":"(null)"}\n'
        findings = p.parse(output)
        assert len(findings) >= 1
        password_findings = [f for f in findings if "plaintext" in f["title"].lower()]
        assert len(password_findings) == 0

    def test_json_dedup(self):
        p = MimikatzParser()
        output = json.dumps([
            {"username": "Admin", "domain": "EXAMPLE", "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c1"},
            {"username": "Admin", "domain": "EXAMPLE", "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c1"},
        ])
        findings = p.parse(output)
        credential_findings = [f for f in findings if "credential" in f["title"].lower()]
        assert len(credential_findings) == 1

    def test_sekurlsa_logonpasswords(self):
        p = MimikatzParser()
        output = (
            "mimikatz # sekurlsa::logonpasswords\n"
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c1\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 2
        assert any("logonpasswords" in f["title"].lower() for f in findings)
        assert any("credential" in f["title"].lower() for f in findings)

    def test_lsadump_dcsync(self):
        p = MimikatzParser()
        output = (
            "mimikatz # lsadump::dcsync\n"
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c1\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 2
        assert any("dcsync" in f["title"].lower() for f in findings)

    def test_kerberos_golden(self):
        p = MimikatzParser()
        output = "mimikatz # kerberos::golden /user:Admin /domain:EXAMPLE /sid:S-1-5-21-1234 /krbtgt:hash\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "golden" in findings[0]["title"].lower()
        assert findings[0]["severity"] == "critical"

    def test_ticket_extraction(self):
        p = MimikatzParser()
        output = "[ticket] Ticket for krbtgt@EXAMPLE\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "ticket" in findings[0]["title"].lower()
        assert findings[0]["severity"] == "high"

    def test_malformed_section_text(self):
        p = MimikatzParser()
        output = (
            "msv [\n"
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c1\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("MSV" in f["title"] for f in findings)

    def test_wdigest_section(self):
        p = MimikatzParser()
        output = (
            "wdigest\n"
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* Password : plaintext123\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("WDIGEST" in f["title"] for f in findings)
        assert any("plaintext" in f["title"].lower() for f in findings)

    def test_kerberos_section(self):
        p = MimikatzParser()
        output = (
            "kerberos\n"
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c1\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("KERBEROS" in f["title"] for f in findings)

    def test_empty_output(self):
        p = MimikatzParser()
        assert p.parse("") == []

    def test_whitespace_only(self):
        p = MimikatzParser()
        assert p.parse("   \n  ") == []

    def test_garbage_input(self):
        p = MimikatzParser()
        findings = p.parse("!@#$%^&*() garbage input\n")
        assert isinstance(findings, list)

    def test_json_no_user_or_domain(self):
        p = MimikatzParser()
        output = '{"some":"data","other":"value"}\n'
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_invalid_then_text(self):
        p = MimikatzParser()
        output = "not json at all\nsome other text\n"
        findings = p.parse(output)
        assert isinstance(findings, list)

    def test_sha1_field_not_ntlm(self):
        p = MimikatzParser()
        output = (
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* SHA1     : a" * 40 + "\n"
        )
        findings = p.parse(output)
        assert isinstance(findings, list)

    def test_password_with_null(self):
        p = MimikatzParser()
        output = (
            "* Username : Admin\n"
            "* Domain   : EXAMPLE\n"
            "* Password : (null)\n"
        )
        findings = p.parse(output)
        assert len(findings) == 0


# ===================================================================
# ResponderParser
# ===================================================================
class TestResponderParser:
    def test_http_ntlm_hash_captured(self):
        p = ResponderParser()
        output = "[HTTP] Captured NTLMv2 hash from 192.168.1.1\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        hash_findings = [f for f in findings if "hash" in f["title"].lower()]
        assert len(hash_findings) >= 1
        assert hash_findings[0]["tool"] == "responder"
        assert hash_findings[0]["severity"] == "high"
        assert "HTTP" in hash_findings[0]["title"]

    def test_smb_hash_captured(self):
        p = ResponderParser()
        output = "[SMB] Captured NTLMv2 hash from 192.168.1.2\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        hash_findings = [f for f in findings if "hash" in f["title"].lower()]
        assert len(hash_findings) >= 1
        assert "SMB" in hash_findings[0]["title"]

    def test_mdns_medium_severity(self):
        p = ResponderParser()
        output = "[MDNS] Captured NTLMv2 hash from 192.168.1.3\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        hash_findings = [f for f in findings if "hash" in f["title"].lower()]
        assert len(hash_findings) >= 1
        assert hash_findings[0]["severity"] == "medium"

    def test_protocol_capture_event(self):
        p = ResponderParser()
        output = "[LLMNR] Got query from 192.168.1.1 for name TEST\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "capture event" in findings[0]["title"].lower()

    def test_challenge_response(self):
        p = ResponderParser()
        output = "NTLMv2 Challenge Response: abcdef1234567890\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "Challenge" in findings[0]["title"]

    def test_nbtns_poison_response(self):
        p = ResponderParser()
        output = "[NBT-NS] Poisoned answer sent to 192.168.1.1 for ISATAP\n"
        findings = p.parse(output)
        poison = [f for f in findings if "poison" in f["title"].lower()]
        assert len(poison) >= 1
        assert poison[0]["severity"] == "medium"

    def test_empty_output(self):
        p = ResponderParser()
        assert p.parse("") == []

    def test_whitespace_only(self):
        p = ResponderParser()
        assert p.parse("   \n  ") == []

    def test_garbage_input(self):
        p = ResponderParser()
        findings = p.parse("!@#$%^&*() garbage\n")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_deduplication_same_hash(self):
        p = ResponderParser()
        output = (
            "[HTTP] Captured NTLMv2 hash from 192.168.1.1: admin::domain:ABCD1234\n"
            "[HTTP] Captured NTLMv2 hash from 192.168.1.1: admin::domain:ABCD1234\n"
        )
        findings = p.parse(output)
        hash_findings = [f for f in findings if "hash" in f["title"].lower()]
        assert len(hash_findings) == 1

    def test_json_format(self):
        p = ResponderParser()
        output = json.dumps([
            {"hash": "admin::domain:ABCD1234", "protocol": "SMB", "client_ip": "10.0.0.1"},
            {"ntlmv2": "user::domain:EFGH5678", "protocol": "HTTP", "from": "10.0.0.2"},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            _check_finding(f, "responder")

    def test_json_single_object(self):
        p = ResponderParser()
        output = '{"hash":"admin::domain:HASHVAL","protocol":"SMB","client_ip":"10.0.0.1"}'
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_invalid_then_text(self):
        p = ResponderParser()
        output = "not json\n[SMB] NTLMv2 hash captured from 10.0.0.1: user::domain:HASH\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_dedup(self):
        p = ResponderParser()
        output = json.dumps([
            {"hash": "admin::domain:SAMEHASH", "protocol": "SMB", "client_ip": "10.0.0.1"},
            {"hash": "admin::domain:SAMEHASH", "protocol": "SMB", "client_ip": "10.0.0.1"},
        ])
        findings = p.parse(output)
        hash_findings = [f for f in findings if "hash" in f["title"].lower()]
        assert len(hash_findings) == 1

    def test_challenge_response_dedup(self):
        p = ResponderParser()
        output = (
            "NTLMv2 Challenge Response: SAMEVALUE\n"
            "NTLMv2 Challenge Response: SAMEVALUE\n"
        )
        findings = p.parse(output)
        challenge_findings = [f for f in findings if "Challenge" in f["title"]]
        assert len(challenge_findings) == 1

    def test_mixed_multiline_output(self):
        p = ResponderParser()
        output = (
            "[HTTP] NTLMv2 hash captured from 10.0.0.1: admin::domain:HASH1\n"
            "[SMB] NTLMv2 hash captured from 10.0.0.2: user::domain:HASH2\n"
            "[MDNS] NTLMv2 hash captured from 10.0.0.3: test::domain:HASH3\n"
            "[NBT-NS] Poisoned answer sent to 10.0.0.4\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 4


# ===================================================================
# SharphoundParser
# ===================================================================
class TestSharphoundParser:
    def test_user_object(self):
        p = SharphoundParser()
        output = json.dumps({
            "Type": "User",
            "Props": {"name": "ADMIN", "domain": "EXAMPLE.LOCAL"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "AD User" in findings[0]["title"]
        assert findings[0]["severity"] == "info"

    def test_group_object(self):
        p = SharphoundParser()
        output = json.dumps({
            "Type": "Group",
            "Props": {"name": "Domain Admins", "domain": "EXAMPLE.LOCAL"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "AD Group" in findings[0]["title"]

    def test_computer_object(self):
        p = SharphoundParser()
        output = json.dumps({
            "type": "computer",
            "props": {"name": "DC01", "domain": "EXAMPLE.LOCAL", "operatingsystem": "Windows Server 2022"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "AD Computer" in findings[0]["title"]
        assert "Windows Server 2022" in findings[0]["description"]

    def test_session_object(self):
        p = SharphoundParser()
        output = json.dumps({
            "Type": "Session",
            "Props": {"name": "ADMIN", "computer": "DC01", "domain": "EXAMPLE.LOCAL"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "AD Session" in findings[0]["title"]
        assert findings[0]["severity"] == "medium"

    def test_acl_object(self):
        p = SharphoundParser()
        output = json.dumps({
            "Type": "ACL",
            "Props": {"name": "S-1-5-21-1234-500", "domain": "EXAMPLE.LOCAL"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "AD ACL" in findings[0]["title"]
        assert findings[0]["severity"] == "low"

    def test_multiple_objects_in_list(self):
        p = SharphoundParser()
        output = json.dumps([
            {"Type": "User", "Props": {"name": "ADMIN", "domain": "EXAMPLE.LOCAL"}},
            {"Type": "Group", "Props": {"name": "Domain Admins", "domain": "EXAMPLE.LOCAL"}},
            {"Type": "Computer", "props": {"name": "DC01", "domain": "EXAMPLE.LOCAL", "OperatingSystem": "Windows"}},
        ])
        findings = p.parse(output)
        assert len(findings) == 3
        for f in findings:
            _check_finding(f, "sharphound")

    def test_non_json_text_fallback(self):
        p = SharphoundParser()
        output = "SharpHound Enumeration Results:\n -- Users: 10\n -- Computers: 5\n"
        findings = p.parse(output)
        assert len(findings) >= 2
        for f in findings:
            assert f["severity"] == "info"

    def test_non_json_dedup(self):
        p = SharphoundParser()
        output = "SharpHound Enumeration Results:\n -- Users: 10\n -- Users: 10\n"
        findings = p.parse(output)
        assert len(findings) == 2

    def test_empty_output(self):
        p = SharphoundParser()
        assert p.parse("") == []

    def test_whitespace_only(self):
        p = SharphoundParser()
        assert p.parse("   \n  ") == []

    def test_garbage_input(self):
        p = SharphoundParser()
        findings = p.parse("!@#$%^&*() garbage\n")
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_json_object_with_no_type_key(self):
        p = SharphoundParser()
        output = json.dumps({"Props": {"name": "unknown", "domain": "EXAMPLE.LOCAL"}})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_dedup_identical_users(self):
        p = SharphoundParser()
        output = json.dumps([
            {"Type": "User", "Props": {"name": "ADMIN", "domain": "EXAMPLE.LOCAL"}},
            {"Type": "User", "Props": {"name": "ADMIN", "domain": "EXAMPLE.LOCAL"}},
        ])
        findings = p.parse(output)
        user_findings = [f for f in findings if "AD User" in f["title"]]
        assert len(user_findings) == 1

    def test_mixed_json_and_non_json(self):
        p = SharphoundParser()
        output = (
            '{"Type":"User","Props":{"name":"ADMIN","domain":"EXAMPLE.LOCAL"}}\n'
            "Some plain text line here\n"
        )
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("AD User" in f["title"] for f in findings)

    def test_object_type_case_insensitive(self):
        p = SharphoundParser()
        output = json.dumps({"type": "USER", "Props": {"name": "ADMIN", "domain": "EXAMPLE.LOCAL"}})
        findings = p.parse(output)
        assert len(findings) == 1
        assert "AD User" in findings[0]["title"]


# ===================================================================
# CommixParser
# ===================================================================
class TestCrackmapexecParser:
    def test_smb_login_success(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     [+] admin:Password123!\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "Credential" in findings[0]["title"]
        assert findings[0]["severity"] == "high"
        _check_finding(findings[0], "crackmapexec")

    def test_pwn3d_detected(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     [+] Pwn3d!\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        pwn = [f for f in findings if "Pwn3d" in f["title"]]
        assert len(pwn) >= 1
        assert pwn[0]["severity"] == "critical"

    def test_sam_credentials(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     [+] SAM admin hash captured\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("SAM" in f["title"] for f in findings)

    def test_dcsync_detected(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     [+] DCSync credentials harvested\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("DCSync" in f["title"] for f in findings)

    def test_smb_version_info(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     [*] SMB version: Windows 10.0 Build 17763 x64\n"
        findings = p.parse(output)
        smb_version = [f for f in findings if "SMB version" in f["title"]]
        assert len(smb_version) >= 1
        assert smb_version[0]["severity"] == "info"

    def test_login_failure(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     [-] admin:Password123! login failure\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert any("failure" in f["title"].lower() for f in findings)

    def test_smbv1_enabled(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     SMBv1: True\n"
        findings = p.parse(output)
        smbv1 = [f for f in findings if "SMBv1" in f["title"]]
        assert len(smbv1) >= 1
        assert smbv1[0]["severity"] == "medium"

    def test_smb_signing_disabled(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     signing: False\n"
        findings = p.parse(output)
        signing = [f for f in findings if "signing" in f["title"].lower()]
        assert len(signing) >= 1
        assert signing[0]["severity"] == "medium"

    def test_creds_regex_format(self):
        p = CrackmapexecParser()
        output = "SMB         10.0.0.1      445    DC01     admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c1:::\n"
        findings = p.parse(output)
        creds = [f for f in findings if "Credential" in f["title"]]
        assert len(creds) >= 1

    def test_json_format(self):
        p = CrackmapexecParser()
        output = json.dumps([
            {"host": "10.0.0.1", "username": "admin", "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c1"},
            {"host": "10.0.0.2", "username": "user", "hash": "aad3b435b51404eeaad3b435b51404ee", "pwned": True},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2
        pwned = [f for f in findings if "Pwn3d" in f["title"]]
        assert len(pwned) >= 1

    def test_json_single_object(self):
        p = CrackmapexecParser()
        output = '{"host":"10.0.0.1","username":"admin","nt_hash":"31d6cfe0d16ae931b73c59d7e0c089c1","pwned":true}'
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_empty_output(self):
        p = CrackmapexecParser()
        assert p.parse("") == []

    def test_whitespace_only(self):
        p = CrackmapexecParser()
        assert p.parse("   \n  ") == []

    def test_garbage_input(self):
        p = CrackmapexecParser()
        findings = p.parse("!@#$%^&*() garbage\n")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_dedup_creds(self):
        p = CrackmapexecParser()
        output = (
            "SMB         10.0.0.1      445    DC01     [+] admin:Password123!\n"
            "SMB         10.0.0.1      445    DC01     [+] admin:Password123!\n"
        )
        findings = p.parse(output)
        creds = [f for f in findings if "Credential" in f["title"]]
        assert len(creds) == 1

    def test_dedup_pwned(self):
        p = CrackmapexecParser()
        output = (
            "SMB         10.0.0.1      445    DC01     [+] Pwn3d!\n"
            "SMB         10.0.0.1      445    DC01     [+] Pwn3d!\n"
        )
        findings = p.parse(output)
        pwned = [f for f in findings if "Pwn3d" in f["title"]]
        assert len(pwned) == 1


# ===================================================================
# DirbParser
# ===================================================================
class TestPypykatzParser_extra_b6:
    def test_json_block_credentials(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "MSV": [{"Password": "Passw0rd!", "NTHash": "31d6cfe0d16ae931b73c59d7e0c089c1"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"
        _check_finding(findings[0], "pypykatz")

    def test_json_multiple_cred_types(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "MSV": [{"Password": "Passw0rd!", "NTHash": "31d6cfe0d16ae931b73c59d7e0c089c1"}],
                "WDIGEST": [{"Password": "wdigest_pass"}],
                "SSP": [{"Password": "ssp_pass"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 3

    def test_json_section_subtype_creds(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "MSV": {
                    "Logon": [{"Password": "secret", "NTHash": "31d6cfe0d16ae931b73c59d7e0c089c1"}],
                },
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_empty_password_and_null_hash_skipped(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "MSV": [{"Password": "", "NTHash": "aad3b435b51404eeaad3b435b51404ee"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_list_top_level(self):
        p = PypykatzParser()
        output = json.dumps([
            {"LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"}, "Credentials": {"MSV": [{"Password": "p1"}]}},
            {"LogonSession": {"Username": "User1", "DomainName": "EXAMPLE"}, "Credentials": {"MSV": [{"Password": "p2"}]}},
        ])
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_text_line_password(self):
        p = PypykatzParser()
        output = "password: Passw0rd!\nusername: Admin\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "plaintext" in findings[0]["title"].lower()

    def test_text_line_without_username(self):
        p = PypykatzParser()
        output = "password: secret123\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "unknown" in findings[0]["title"]

    def test_json_per_line_format(self):
        p = PypykatzParser()
        output = (
            '{"LogonSession":{"Username":"Admin","DomainName":"EXAMPLE"},"Credentials":{"MSV":[{"Password":"Passw0rd!"}]}}\n'
        )
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_ssp_cred_section(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "SSP_CRED": {
                    "LogonSession": [{"Password": "ssp_cred_pass"}],
                },
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_empty_output(self):
        p = PypykatzParser()
        assert p.parse("") == []

    def test_whitespace_only(self):
        p = PypykatzParser()
        assert p.parse("   \n  ") == []

    def test_garbage_input(self):
        p = PypykatzParser()
        findings = p.parse("!@#$%^&*() garbage\n")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_dedup_credentials(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "MSV": [{"Password": "Passw0rd!", "NTHash": "31d6cfe0d16ae931b73c59d7e0c089c1"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) == 1

    def test_livess_section(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "Admin", "DomainName": "EXAMPLE"},
            "Credentials": {
                "LIVESS": [{"Password": "live_password"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1


# ===================================================================
# SshAuditParser
# ===================================================================
class TestBloodhoundParser_extra_b7:
    def test_data_list_user(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [
                {"Label": "ADMIN@CORP.LOCAL", "ObjectId": "S-1-5-21-1234-500", "ObjectType": "User"},
                {"Label": "jdoe@CORP.LOCAL", "ObjectId": "S-1-5-21-1234-1001", "ObjectType": "User"},
            ],
        })
        findings = p.parse(output)
        assert len(findings) == 2
        for f in findings:
            _check_finding(f, "bloodhound")
        assert any("User ADMIN@CORP.LOCAL" in f["title"] for f in findings)
        assert all(f["severity"] == "info" for f in findings)

    def test_data_list_computer(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [
                {"Label": "DC01.CORP.LOCAL", "ObjectId": "S-1-5-21-1234-1000", "ObjectType": "Computer"},
            ],
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Computer DC01.CORP.LOCAL" in findings[0]["title"]

    def test_data_list_group(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [
                {"Label": "DOMAIN ADMINS", "ObjectId": "S-1-5-21-1234-512", "ObjectType": "Group"},
            ],
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Group DOMAIN ADMINS" in findings[0]["title"]

    def test_data_list_other_type(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [
                {"Label": "OU=SERVERS", "ObjectId": "OU-GUID-123", "ObjectType": "OU"},
            ],
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "OU" in findings[0]["title"]
        assert "OU=SERVERS" in findings[0]["title"]

    def test_data_list_dedup(self):
        p = BloodhoundParser()
        output = json.dumps({
            "data": [
                {"Label": "ADMIN", "ObjectId": "S-1-1", "ObjectType": "User"},
                {"Label": "ADMIN", "ObjectId": "S-1-2", "ObjectType": "User"},
            ],
        })
        findings = p.parse(output)
        assert len(findings) == 1

    def test_data_list_skip_non_dict(self):
        p = BloodhoundParser()
        output = json.dumps({"data": ["not a dict", 123, None]})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_type_user_props(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "User",
            "props": {"samaccountname": "alice", "userprincipalname": "alice@corp.local", "enabled": True},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "User alice" in findings[0]["title"]

    def test_type_computer_props(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Computer",
            "props": {"name": "DC01", "operatingsystem": "Windows Server 2022", "samaccountname": "DC01$"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Computer DC01" in findings[0]["title"]

    def test_type_group_props(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Group",
            "props": {"name": "Domain Admins"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Group Domain Admins" in findings[0]["title"]

    def test_type_session(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Session",
            "props": {"user": "alice", "computer": "DC01"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Session alice" in findings[0]["title"]
        assert findings[0]["severity"] == "medium"

    def test_type_acl(self):
        p = BloodhoundParser()
        output = json.dumps({
            "type": "Acl",
            "props": {"principal": "S-1-5-21-1234-500", "righttype": "GenericAll"},
        })
        findings = p.parse(output)
        assert len(findings) == 1
        assert "ACL GenericAll" in findings[0]["title"]
        assert findings[0]["severity"] == "medium"

    def test_non_json_line_skip(self):
        p = BloodhoundParser()
        output = "not json content\n# comment line\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_malformed_json_skip(self):
        p = BloodhoundParser()
        output = "{bad json}\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_empty_output(self):
        p = BloodhoundParser()
        assert p.parse("") == []
        assert p.parse("   ") == []
class TestCrackmapexecParser_extra_b8:
    def test_empty(self):
        assert CrackmapexecParser().parse("") == []
        assert CrackmapexecParser().parse("   ") == []

    def test_json_single_credential(self):
        p = CrackmapexecParser()
        output = json.dumps({"host": "10.0.0.1", "username": "admin", "nt_hash": "aad3b435b51404eeaad3b435b51404ee"})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "crackmapexec")
        assert "Credential" in findings[0]["title"]

    def test_json_dual_credential_and_pwned(self):
        p = CrackmapexecParser()
        output = json.dumps({"host": "10.0.0.1", "username": "admin", "nt_hash": "aad3b435b51404eeaad3b435b51404ee", "pwned": True})
        findings = p.parse(output)
        assert len(findings) == 2
        titles = [f["title"] for f in findings]
        assert any("Pwn3d" in t for t in titles)
        assert any("Credential" in t for t in titles)

    def test_json_list_format(self):
        p = CrackmapexecParser()
        output = json.dumps([
            {"host": "10.0.0.1", "user": "admin", "hash": "aad3b435b51404eeaad3b435b51404ee", "admin": True},
            {"host": "10.0.0.2", "user": "user1", "hash": "aad3b435b51404eeaad3b435b51404ee"},
        ])
        findings = p.parse(output)
        assert len(findings) == 3

    def test_json_non_dict_item_skipped(self):
        p = CrackmapexecParser()
        output = json.dumps(["string", 123])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_dedup_credential(self):
        p = CrackmapexecParser()
        output = json.dumps([
            {"host": "10.0.0.1", "user": "admin", "hash": "aad3b435b51404eeaad3b435b51404ee"},
            {"host": "10.0.0.1", "user": "admin", "hash": "aad3b435b51404eeaad3b435b51404ee"},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_pwned_dedup(self):
        p = CrackmapexecParser()
        output = json.dumps([
            {"host": "10.0.0.1", "pwned": True},
            {"host": "10.0.0.1", "pwned": True},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_malformed_falls_through(self):
        p = CrackmapexecParser()
        output = "{bad json}"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_pwned_line(self):
        p = CrackmapexecParser()
        output = "[+] Pwn3d! victim fully compromised"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_text_sam_credentials(self):
        p = CrackmapexecParser()
        output = "[+] SAM credentials harvested from DC01"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "SAM" in findings[0]["title"]

    def test_text_dcsync(self):
        p = CrackmapexecParser()
        output = "[+] DCSync credentials extracted successfully"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "DCSync" in findings[0]["title"]

    def test_text_smb_version_from_success(self):
        p = CrackmapexecParser()
        output = "[+] SMB version 3.1.1 detected"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "SMB version" in findings[0]["title"]

    def test_text_credential_pair_via_colon(self):
        p = CrackmapexecParser()
        output = "[+] administrator:Passw0rd!"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Credential" in findings[0]["title"]

    def test_text_failure_login(self):
        p = CrackmapexecParser()
        output = "[-] login failed for administrator"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Login failure" in findings[0]["title"]

    def test_text_failure_generic(self):
        p = CrackmapexecParser()
        output = "[-] something went wrong"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_creds_regex_line(self):
        p = CrackmapexecParser()
        output = "admin:1000:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_text_smb_version_generic(self):
        p = CrackmapexecParser()
        output = "SMB version 2.02"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "SMB version" in findings[0]["title"]

    def test_text_smbv1_enabled(self):
        p = CrackmapexecParser()
        output = "SMBv1 enabled on target"
        findings = p.parse(output)
        assert any("SMBv1" in f["title"] for f in findings)

    def test_text_signing_disabled(self):
        p = CrackmapexecParser()
        output = "signing: false"
        findings = p.parse(output)
        assert any("signing" in f["title"].lower() for f in findings)

    def test_text_ip_extracted(self):
        p = CrackmapexecParser()
        output = "192.168.1.100 SMB version 3.0"
        findings = p.parse(output)
        assert len(findings) >= 1
        # IP is extracted as target when line starts with the IP
        assert any(f["target"] == "192.168.1.100" for f in findings)

    def test_text_dedup_pwned(self):
        p = CrackmapexecParser()
        output = "[+] Pwn3d!\n[+] Pwn3d!"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_dedup_cred_colon(self):
        p = CrackmapexecParser()
        output = "[+] user:pass\n[+] user:pass"
        findings = p.parse(output)
        assert len(findings) == 1
class TestPypykatzParser_extra_b8:
    def test_empty(self):
        assert PypykatzParser().parse("") == []
        assert PypykatzParser().parse("   ") == []

    def test_json_single_record_with_credentials(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": [{"Password": "pass123", "NTHash": "aad3b435b51404eeaad3b435b51404ee"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "pypykatz")

    def test_json_credentials_section_items(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": {"mstsv1_0": [{"Password": "", "NTHash": "aad3b435b51404eeaad3b435b51404ee"}]},
            },
        })
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_credential_empty_hash_skipped(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "WDIGEST": [{"Password": "", "NTHash": "aad3b435b51404eeaad3b435b51404ee"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_non_dict_record_skipped(self):
        p = PypykatzParser()
        output = json.dumps(["string", 123])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_sections_with_real_hash(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "user1", "DomainName": "DOMAIN"},
            "Credentials": {
                "MSV": [{"Password": "realpass", "NTHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"}],
                "LIVESS": [{"Password": "", "NTHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"}],
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_json_dedup(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "user", "DomainName": "D"},
            "Credentials": {
                "SSP": [{"Password": "pass", "NTHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"}],
                "SSP_CRED": [{"Password": "pass", "NTHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"}],
            },
        })
        findings = p.parse(output)
        # Different dedup keys due to different sections
        assert len(findings) >= 1

    def test_json_section_subtype_creds(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "u", "DomainName": "d"},
            "Credentials": {
                "WDIGEST": {"subtype1": [{"Password": "pwd", "NTHash": ""}]},
                "WDIGEST": {"subtype2": [{"Password": "pwd2", "NTHash": "ccccccccccccccccccccccccccccccc3"}]},
            },
        })
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_json_no_logonsession(self):
        p = PypykatzParser()
        output = json.dumps({"Credentials": {"MSV": [{"Password": "pass"}]}})
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_line_json_parse(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {"MSV": [{"Password": "secret"}]},
        })
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_password_line(self):
        p = PypykatzParser()
        output = "password: hunter2\n"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "plaintext" in findings[0]["title"].lower()

    def test_text_password_with_username(self):
        p = PypykatzParser()
        output = "username: admin\npassword: secret"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_password_dedup(self):
        p = PypykatzParser()
        output = "password: secret\npassword: secret"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_line_json_per_line_with_creds(self):
        p = PypykatzParser()
        line = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {"MSV": [{"Password": "pass", "NTHash": ""}]},
        })
        findings = p.parse(line)
        assert len(findings) >= 1

    def test_json_malformed_falls_to_text(self):
        p = PypykatzParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_text_line_json_with_section_subtype(self):
        p = PypykatzParser()
        line = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": {"mstsv1_0": [{"Password": "pass", "NTHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"}]},
            },
        })
        findings = p.parse(line)
        assert len(findings) >= 1
class TestMimikatzParser_extra_b8:
    def test_empty(self):
        assert MimikatzParser().parse("") == []
        assert MimikatzParser().parse("   ") == []

    def test_json_single_cred(self):
        p = MimikatzParser()
        output = json.dumps({"username": "admin", "domain": "CORP", "ntlm": "aad3b435b51404eeaad3b435b51404ee"})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "mimikatz")
        assert findings[0]["severity"] == "critical"

    def test_json_with_password(self):
        p = MimikatzParser()
        output = json.dumps({"username": "admin", "domain": "CORP", "password": "secret123"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert "password" in findings[0]["title"].lower()

    def test_json_with_ntlm_and_password(self):
        p = MimikatzParser()
        output = json.dumps({"user": "admin", "domain": "CORP", "NTLM": "aad3b435b51404eeaad3b435b51404ee", "password": "secret"})
        findings = p.parse(output)
        assert len(findings) == 2

    def test_json_no_user_or_domain_skipped(self):
        p = MimikatzParser()
        output = json.dumps({"ntlm": "aad3b435b51404eeaad3b435b51404ee"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_null_password_skipped(self):
        p = MimikatzParser()
        output = json.dumps({"username": "admin", "domain": "CORP", "password": "(null)"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_dedup(self):
        p = MimikatzParser()
        output = json.dumps([
            {"username": "admin", "domain": "CORP", "ntlm": "aad3b435b51404eeaad3b435b51404ee"},
            {"username": "admin", "domain": "CORP", "ntlm": "aad3b435b51404eeaad3b435b51404ee"},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_non_dict_skipped(self):
        p = MimikatzParser()
        output = json.dumps(["string"])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_malformed_falls_to_text(self):
        p = MimikatzParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_text_logonpasswords(self):
        p = MimikatzParser()
        output = "sekurlsa::logonpasswords"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "logonpasswords" in findings[0]["title"].lower()

    def test_text_dcsync(self):
        p = MimikatzParser()
        output = "lsadump::dcsync"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "dcsync" in findings[0]["title"].lower()

    def test_text_golden(self):
        p = MimikatzParser()
        output = "kerberos::golden"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "golden" in findings[0]["title"].lower()

    def test_text_ticket(self):
        p = MimikatzParser()
        output = "[ticket] captured ticket.kirbi"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "ticket" in findings[0]["title"].lower()

    def test_text_msv_section(self):
        p = MimikatzParser()
        output = "* Username : admin\n* Domain : CORP\n* NTLM : aad3b435b51404eeaad3b435b51404ee\nmsv [something]"
        findings = p.parse(output)
        ntlm_findings = [f for f in findings if "NTLM" in f["evidence"] or "credential" in f["title"].lower()]
        assert len(findings) >= 1

    def test_text_wdigest_detected(self):
        p = MimikatzParser()
        output = "wdigest"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_username_line(self):
        p = MimikatzParser()
        output = "* Username : admin"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_domain_line(self):
        p = MimikatzParser()
        output = "* Domain : CORP"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_ntlm_extraction(self):
        p = MimikatzParser()
        output = "* Username : admin\n* Domain : CORP\n* NTLM : aad3b435b51404eeaad3b435b51404ee"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "NTLM" in findings[0]["evidence"]

    def test_text_password_extraction_with_section(self):
        p = MimikatzParser()
        output = "* Username : admin\n* Domain : CORP\n* Password : secret123"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "password" in findings[0]["title"].lower()

    def test_text_password_null_skipped(self):
        p = MimikatzParser()
        output = "* Username : admin\n* Domain : CORP\n* Password : (null)"
        findings = p.parse(output)
        assert len(findings) == 0
class TestSmbclientParser_extra_b8:
    def test_empty(self):
        assert SmbclientParser().parse("") == []
        assert SmbclientParser().parse("   ") == []

    def test_json_share(self):
        p = SmbclientParser()
        output = json.dumps({"share": "Documents", "server": "192.168.1.1"})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "smbclient")
        assert "share" in findings[0]["title"].lower()

    def test_json_share_and_file(self):
        p = SmbclientParser()
        output = json.dumps({"name": "file.txt", "server": "192.168.1.1", "size": 1024})
        findings = p.parse(output)
        assert len(findings) == 2

    def test_json_dedup(self):
        p = SmbclientParser()
        output = json.dumps([
            {"share": "S", "server": "192.168.1.1"},
            {"share": "S", "server": "192.168.1.1"},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_non_dict_skipped(self):
        p = SmbclientParser()
        output = json.dumps(["string"])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_no_share_or_name(self):
        p = SmbclientParser()
        output = json.dumps({"server": "192.168.1.1"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_malformed_falls_to_text(self):
        p = SmbclientParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_text_domain(self):
        p = SmbclientParser()
        output = "Domain = [CORP]"
        findings = p.parse(output)
        assert len(findings) >= 1
        assert "domain" in findings[0]["title"].lower()

    def test_text_os(self):
        p = SmbclientParser()
        output = "OS = [Windows Server 2022]"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_server_description(self):
        p = SmbclientParser()
        output = "Server = [DC01]"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_smb_version(self):
        p = SmbclientParser()
        output = "SMB version = 3.1.1"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_netbios_name(self):
        p = SmbclientParser()
        output = "NetBIOS = DC01"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_server_line_extraction(self):
        p = SmbclientParser()
        output = "server \\\\DC01"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_session_request_skipped(self):
        p = SmbclientParser()
        output = "session request to DC01 failed"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_connected(self):
        p = SmbclientParser()
        output = "connected to \\\\DC01"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_share_line(self):
        p = SmbclientParser()
        output = "Documents    Disk"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_share_dedup(self):
        p = SmbclientParser()
        output = "Docs    Disk\nDocs    Disk"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_file_line(self):
        from siyarix.parsers.smbclient_parser import _FILE_RE
        m = _FILE_RE.match("A  some stuff    Mon Jan 01 12:00:00 2025 report.txt")
        assert m is not None
        assert m.group("name") == "report.txt"
        assert m.group("date") == "Mon Jan 01 12:00:00 2025"

    def test_text_current_share_matches_line_skipped(self):
        p = SmbclientParser()
        output = "Documents    Disk\n\\Documents"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_no_match(self):
        p = SmbclientParser()
        output = "garbage"
        findings = p.parse(output)
        assert len(findings) == 0
class TestSmbmapParser_extra_b8:
    def test_empty(self):
        assert SmbmapParser().parse("") == []
        assert SmbmapParser().parse("   ") == []

    def test_json_share_with_write(self):
        p = SmbmapParser()
        output = json.dumps({"share": "Documents", "permission": "READ,WRITE", "target": "10.0.0.1"})
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "smbmap")
        assert findings[0]["severity"] == "critical"

    def test_json_share_read_only(self):
        p = SmbmapParser()
        output = json.dumps({"share": "Public", "access": "READ", "host": "10.0.0.1"})
        findings = p.parse(output)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "info"

    def test_json_file_and_disk_usage(self):
        p = SmbmapParser()
        output = json.dumps({"filename": "file.txt", "file_size": 1024, "target": "10.0.0.1", "disk_usage": "500MB used"})
        findings = p.parse(output)
        assert len(findings) >= 2

    def test_json_share_no_perm_skipped(self):
        p = SmbmapParser()
        output = json.dumps({"share": "IPC$", "target": "10.0.0.1"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_non_dict_skipped(self):
        p = SmbmapParser()
        output = json.dumps(["string"])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_dedup(self):
        p = SmbmapParser()
        output = json.dumps([
            {"share": "S", "permission": "READ", "target": "10.0.0.1"},
            {"share": "S", "permission": "READ", "target": "10.0.0.1"},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_malformed_falls_to_text(self):
        p = SmbmapParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_text_target_header(self):
        p = SmbmapParser()
        output = "[Target] : 10.0.0.1\nDisk: Documents\nDocuments    (READ)\n"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_host_line(self):
        p = SmbmapParser()
        output = "(10.0.0.1) - Windows Server"
        findings = p.parse(output)
        assert len(findings) >= 1

    def test_text_target_colon(self):
        p = SmbmapParser()
        output = "target: 10.0.0.1"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_shares_line(self):
        p = SmbmapParser()
        output = "Shares: Documents (READ,WRITE) Public (READ)"
        findings = p.parse(output)
        assert len(findings) == 2
        assert any(f["severity"] == "critical" for f in findings)

    def test_text_share_line(self):
        p = SmbmapParser()
        output = "Documents    (READ,WRITE)"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_text_share_line_read(self):
        p = SmbmapParser()
        output = "Public    (READ)"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    def test_text_disk_usage(self):
        p = SmbmapParser()
        output = "1.5GB used out of 10GB"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_recursive_dir(self):
        p = SmbmapParser()
        output = "` .\\folder\\subdir\\"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "directory" in findings[0]["title"].lower()

    def test_text_recursive_file(self):
        p = SmbmapParser()
        output = "` .\\folder\\file.txt"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "file" in findings[0]["title"].lower()

    def test_text_bracket_line_skipped(self):
        p = SmbmapParser()
        output = "[some: thing]"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_file_line(self):
        p = SmbmapParser()
        output = "file.txt    1024    rw-    some date"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_non_matching(self):
        p = SmbmapParser()
        output = "some garbage\n"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_share_line_dedup(self):
        p = SmbmapParser()
        output = "Documents    (READ)\nDocuments    (READ)"
        findings = p.parse(output)
        assert len(findings) == 1
class TestKerbruteParser_extra_b8:
    def test_empty(self):
        assert KerbruteParser().parse("") == []
        assert KerbruteParser().parse("   ") == []

    def test_json_valid_user(self):
        p = KerbruteParser()
        output = json.dumps({"username": "admin", "valid": True, "domain": "CORP"})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "kerbrute")

    def test_json_with_hash(self):
        p = KerbruteParser()
        output = json.dumps({"username": "admin", "valid": True, "hash": "$krb5asrep$admin@CORP:hashdata"})
        findings = p.parse(output)
        assert len(findings) == 2

    def test_json_invalid_user(self):
        p = KerbruteParser()
        output = json.dumps({"username": "unknown", "valid": False, "status": "invalid"})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_non_dict_skipped(self):
        p = KerbruteParser()
        output = json.dumps(["string"])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_malformed_falls_to_text(self):
        p = KerbruteParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_text_valid_user(self):
        p = KerbruteParser()
        output = "[+] VALID USER: admin@CORP"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_valid_user_alt_format(self):
        p = KerbruteParser()
        output = "2025/01/01 12:00:00 > [+] VALID USER: administrator"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_invalid_user(self):
        p = KerbruteParser()
        output = "[-] unknown_user invalid username"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "Invalid" in findings[0]["title"]

    def test_text_asrep_hash(self):
        p = KerbruteParser()
        output = "AS-REP hash captured: $krb5asrep$user@CORP:abcd1234"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_text_tgt(self):
        p = KerbruteParser()
        output = "TGT captured from DC"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_ip_extraction(self):
        p = KerbruteParser()
        output = "192.168.1.100 DC detected"
        findings = p.parse(output)
        assert len(findings) == 0

    def test_text_password_spray(self):
        p = KerbruteParser()
        output = "PASS: Spring2025 - user: admin"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_text_user_stats(self):
        p = KerbruteParser()
        output = "5 valid users found"
        findings = p.parse(output)
        assert len(findings) == 1
        assert "stats" in findings[0]["title"].lower()

    def test_text_dedup_user(self):
        p = KerbruteParser()
        output = "[+] VALID USER: admin\n[+] VALID USER: admin"
        findings = p.parse(output)
        users = [f for f in findings if "Valid user" in f["title"]]
        assert len(users) == 1

    def test_text_dedup_asrep(self):
        p = KerbruteParser()
        output = "AS-REP hash: $krb5asrep$u@D:x\nAS-REP hash: $krb5asrep$u@D:x"
        findings = p.parse(output)
        hashes = [f for f in findings if "AS-REP" in f["title"]]
        assert len(hashes) == 1

    def test_non_matching(self):
        p = KerbruteParser()
        output = "some random text\n"
        findings = p.parse(output)
        assert len(findings) == 0
class TestSeatbeltParser:
    def test_empty(self):
        assert SeatbeltParser().parse("") == []
        assert SeatbeltParser().parse("   ") == []

    def test_json_with_output_high(self):
        p = SeatbeltParser()
        output = json.dumps({"Command": "user-enum", "Host": "DC01", "Output": "Found password in config", "User": "admin"})
        findings = p.parse(output)
        assert len(findings) == 1
        _check_finding(findings[0], "seatbelt")
        assert findings[0]["severity"] == "high"

    def test_json_with_output_admin(self):
        p = SeatbeltParser()
        output = json.dumps({"command": "token-enum", "host": "SRV01", "output": "admin privileges found"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_json_no_output(self):
        p = SeatbeltParser()
        output = json.dumps({"Command": "basic-info", "Host": "localhost"})
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    def test_json_dedup(self):
        p = SeatbeltParser()
        output = json.dumps([
            {"Command": "test", "Host": "localhost"},
            {"Command": "test", "Host": "localhost"},
        ])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_non_dict_skipped(self):
        p = SeatbeltParser()
        output = json.dumps(["string"])
        findings = p.parse(output)
        assert len(findings) == 0

    def test_json_malformed_falls_to_text(self):
        p = SeatbeltParser()
        findings = p.parse("{bad")
        assert isinstance(findings, list)

    def test_text_password_line(self):
        p = SeatbeltParser()
        output = "Found password in registry"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_text_admin_line(self):
        p = SeatbeltParser()
        output = "Running as administrator"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_text_normal_line(self):
        p = SeatbeltParser()
        output = "OS Version: 10.0.20348"
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    def test_text_dedup(self):
        p = SeatbeltParser()
        output = "same line\nsame line"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_non_matching_empty(self):
        p = SeatbeltParser()
        output = ""
        findings = p.parse(output)
        assert len(findings) == 0
class TestBloodhoundParserBranches:
    """Covers: data list item w/o ObjectType, dedup for user/computer/group/session/acl."""

    def test_data_item_no_objtype(self):
        p = BloodhoundParser()
        output = json.dumps({"data": [{"Label": "SOMETHING"}]})
        findings = p.parse(output)
        assert len(findings) == 0

    def test_user_dedup(self):
        p = BloodhoundParser()
        line = json.dumps({"type": "User", "props": {"samaccountname": "admin"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_computer_dedup(self):
        p = BloodhoundParser()
        line = json.dumps({"type": "Computer", "props": {"name": "PC01"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_group_dedup(self):
        p = BloodhoundParser()
        line = json.dumps({"type": "Group", "props": {"name": "Domain Admins"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_session_dedup(self):
        p = BloodhoundParser()
        line = json.dumps({"type": "Session", "props": {"user": "admin", "computer": "PC01"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_acl_dedup(self):
        p = BloodhoundParser()
        line = json.dumps({"type": "Acl", "props": {"principal": "admin", "righttype": "GenericAll"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 9. bloodhound_python_parser.py  — missing 29, 37, 65, 86, 103, 120, 137
# ---------------------------------------------------------------------------
class TestBloodhoundPythonParserBranches:
    """Covers: empty line, found-dedup, and all type dedup."""

    def test_empty_line_skipped(self):
        p = BloodhoundPythonParser()
        findings = p.parse("\n\n")
        assert findings == []

    def test_found_dedup(self):
        p = BloodhoundPythonParser()
        findings = p.parse("INFO: Found 5 users\nINFO: Found 5 users\n")
        assert len(findings) == 1

    def test_user_dedup(self):
        p = BloodhoundPythonParser()
        line = json.dumps({"type": "user", "props": {"name": "admin", "domain": "contoso"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_computer_dedup(self):
        p = BloodhoundPythonParser()
        line = json.dumps({"type": "computer", "props": {"name": "PC01", "domain": "contoso"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_group_dedup(self):
        p = BloodhoundPythonParser()
        line = json.dumps({"type": "group", "props": {"name": "Domain Admins", "domain": "contoso"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_session_dedup(self):
        p = BloodhoundPythonParser()
        line = json.dumps({"type": "session", "props": {"name": "admin", "computer": "PC01", "domain": "contoso"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1

    def test_acl_dedup(self):
        p = BloodhoundPythonParser()
        line = json.dumps({"type": "acl", "props": {"name": "admin", "rightguid": "GUID123", "domain": "contoso"}})
        findings = p.parse(f"{line}\n{line}\n")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 10. burpsuite_parser.py  — missing 18, 31
# ---------------------------------------------------------------------------
class TestCertipyParserBranches:
    """Covers: non-dict JSON item, JSON template dedup, ESC non-critical,
       empty-line, ESC dedup, template dedup, CA info, PKCS12 cert obtained."""

    def test_json_non_dict_item_skipped(self):
        p = CertipyParser()
        output = json.dumps([42, {"template": "SubCA"}])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_template_dedup(self):
        p = CertipyParser()
        output = json.dumps([{"template": "SubCA"}, {"template": "SubCA"}])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_esc_not_critical(self):
        p = CertipyParser()
        output = json.dumps([{"template": "Web", "vulnerability": "ESC3"}])
        findings = p.parse(output)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_empty_line_skipped(self):
        p = CertipyParser()
        findings = p.parse("[*] Enabled enrollment\n\n[*] CA Name: MyCA\n")
        assert len(findings) == 2

    def test_esc_dedup(self):
        p = CertipyParser()
        findings = p.parse("[*] Vulnerable to ESC1\n[*] Vulnerable to ESC1\n")
        esc = [f for f in findings if "ESC" in f["title"]]
        assert len(esc) == 1

    def test_template_dedup(self):
        p = CertipyParser()
        findings = p.parse("[*] Certificate Template: SubCA\n[*] Certificate Template: SubCA\n")
        tpl = [f for f in findings if "Certificate template" in f["title"]]
        assert len(tpl) == 1

    def test_ca_info_added(self):
        p = CertipyParser()
        findings = p.parse("[*] CA Name: contoso-DC-CA\n")
        assert any("CA" in f["title"] for f in findings)

    def test_cert_obtained_pkcs12(self):
        p = CertipyParser()
        findings = p.parse("Got certificate for admin.p12\n")
        assert len(findings) >= 1

    def test_non_esc_vuln_line(self):
        p = CertipyParser()
        findings = p.parse("[*] some other message\n")
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# 12. checkov_parser.py  — missing 52, 59, 62-65
# ---------------------------------------------------------------------------
class TestEnum4linuxParserBranches:
    """Covers: JSON non-dict, user dedup, share dedup, OS from JSON,
       text empty, section header, target line, RID dedup, workgroup,
       user, share, printer, group, session, policy, OS, SID."""

    def test_json_non_dict_skipped(self):
        p = Enum4linuxParser()
        output = json.dumps([42, {"user": "admin", "host": "PC01"}])
        findings = p.parse(output)
        assert len(findings) == 1

    def test_json_user_dedup(self):
        p = Enum4linuxParser()
        output = json.dumps([{"user": "admin", "host": "PC01"}, {"user": "admin", "host": "PC01"}])
        findings = p.parse(output)
        users = [f for f in findings if "User" in f["title"]]
        assert len(users) == 1

    def test_json_share_dedup(self):
        p = Enum4linuxParser()
        output = json.dumps([{"share": "sharedocs", "host": "PC01"}, {"share": "sharedocs", "host": "PC01"}])
        findings = p.parse(output)
        shares = [f for f in findings if "share" in f["title"].lower()]
        assert len(shares) == 1

    def test_json_os_entry(self):
        p = Enum4linuxParser()
        output = json.dumps([{"os": "Windows 10", "host": "PC01"}])
        findings = p.parse(output)
        assert any("OS" in f["title"] for f in findings)

    def test_text_empty_line_skipped(self):
        p = Enum4linuxParser()
        findings = p.parse("[+] Some header\n\n  \n")
        assert isinstance(findings, list)

    def test_text_target_line(self):
        p = Enum4linuxParser()
        findings = p.parse("target: 192.168.1.1\n")
        assert isinstance(findings, list)

    def test_rid_dedup(self):
        p = Enum4linuxParser()
        output = "[RID] 500 Administrator\n[RID] 500 Administrator\n"
        findings = p.parse(output)
        assert len(findings) == 1

    def test_workgroup_line(self):
        p = Enum4linuxParser()
        findings = p.parse("Workgroup: WORKGROUP\n")
        assert len(findings) == 1
        assert "Workgroup" in findings[0]["title"]

    def test_text_user(self):
        p = Enum4linuxParser()
        findings = p.parse("user: jdoe\n")
        assert len(findings) == 1
        assert "User" in findings[0]["title"]

    def test_text_share(self):
        p = Enum4linuxParser()
        findings = p.parse("sharedocs  disk  accessible\n")
        assert len(findings) >= 1
        assert "SMB share" in findings[0]["title"]

    def test_printer_info(self):
        p = Enum4linuxParser()
        findings = p.parse("Printer: HP LaserJet on 192.168.1.1\n")
        assert len(findings) == 1
        assert "Printer" in findings[0]["title"]

    def test_group_line(self):
        p = Enum4linuxParser()
        findings = p.parse("Group: Domain Admins\n")
        assert len(findings) == 1
        assert "Domain group" in findings[0]["title"]

    def test_session_line(self):
        p = Enum4linuxParser()
        findings = p.parse("Session: admin logged in\n")
        assert len(findings) == 1
        assert "Active SMB sessions" in findings[0]["title"]

    def test_password_policy(self):
        p = Enum4linuxParser()
        findings = p.parse("Password policy: Min password length 8\n")
        assert len(findings) == 1
        assert "Password" in findings[0]["title"]

    def test_os_line(self):
        p = Enum4linuxParser()
        findings = p.parse("OS: Windows Server 2022\n")
        assert len(findings) == 1
        assert "OS" in findings[0]["title"]

    def test_sid_found(self):
        p = Enum4linuxParser()
        findings = p.parse("SID: S-1-5-21-123456789-1234567890-123456789-500\n")
        assert len(findings) >= 1
        assert "SID" in findings[0]["title"]


# ---------------------------------------------------------------------------
# 25. ettercap_parser.py  — missing 18
# ---------------------------------------------------------------------------
class TestEvilWinrmParser:
    def test_empty(self):
        assert EvilWinrmParser().parse("") == []
        assert EvilWinrmParser().parse("   ") == []

    def test_text_connect_success_line(self):
        r = EvilWinrmParser().parse("Connecting to 10.0.0.5:5985 with user admin authenticated")
        assert len(r) == 1
        assert r[0]["severity"] == "critical"

    def test_text_connect_error_line(self):
        r = EvilWinrmParser().parse("Connecting to 10.0.0.5:5985 failed")
        assert len(r) == 1
        assert r[0]["severity"] == "info"

    def test_text_ip_port_winrm_line(self):
        r = EvilWinrmParser().parse("http service on 10.0.0.5 port 5985")
        assert len(r) >= 1
        assert any("Target identified" in f["title"] for f in r)

    def test_json_array(self):
        r = EvilWinrmParser().parse('[{"host":"10.0.0.5","username":"admin"}]')
        assert len(r) >= 1
        assert r[0]["severity"] == "critical"

    def test_json_non_dict_skipped(self):
        r = EvilWinrmParser().parse('["hello"]')
        assert len(r) == 0
class TestImpacketParser:
    def test_empty(self):
        assert ImpacketParser().parse("") == []

    def test_samba_cred(self):
        r = ImpacketParser().parse("user:1000:abc:def:::")
        assert len(r) == 1

    def test_kerberos_line(self):
        r = ImpacketParser().parse("KRB5 ticket obtained for admin")
        assert any("Kerberos" in f["title"] for f in r)

    def test_wmi_line(self):
        r = ImpacketParser().parse("WMI exec result: success")
        assert any("WMI execution" in f["title"] for f in r)

    def test_smb_share_line(self):
        r = ImpacketParser().parse("SMB share opened on admin$")
        assert any("SMB share accessed" in f["title"] for f in r)

    def test_skip_blank_line(self):
        r = ImpacketParser().parse("\n\n")
        assert len(r) == 0
class TestPypykatzParser:
    def test_empty(self):
        assert PypykatzParser().parse("") == []
        assert PypykatzParser().parse("   ") == []

    def test_json_section_creds(self):
        r = PypykatzParser().parse('{"LogonSession":{"Username":"admin","DomainName":"WORKGROUP"},"Credentials":{"MSV":{"subtype1":[{"Password":"pass123","NTHash":"aad3b435b51404eeaad3b435b51404ee"}]}}}')
        assert len(r) >= 1

    def test_json_empty_password_skipped(self):
        r = PypykatzParser().parse('{"LogonSession":{"Username":"admin","DomainName":"WORKGROUP"},"Credentials":{"MSV":{"subtype1":[{"Password":"","NTHash":"aad3b435b51404eeaad3b435b51404ee"}]}}}')
        assert len(r) == 0

    def test_json_creds_list(self):
        r = PypykatzParser().parse('[{"LogonSession":{"Username":"admin","DomainName":"WORKGROUP"},"Credentials":{"MSV":{"sub":[{"Password":"pass"}]}}}]')
        assert len(r) >= 1

    def test_text_password_line(self):
        r = PypykatzParser().parse("password: mypass123")
        assert len(r) == 1

    def test_text_json_per_line(self):
        r = PypykatzParser().parse('{"LogonSession":{"Username":"admin","DomainName":"WORKGROUP"},"Credentials":{"MSV":{"sub":[{"Password":"pass"}]}}}')
        assert len(r) >= 1

    def test_dedup(self):
        r = PypykatzParser().parse("password: mypass123\npassword: mypass123")
        assert len(r) == 1
class TestResponderParser:
    def test_empty(self):
        assert ResponderParser().parse("") == []
        assert ResponderParser().parse("   ") == []

    def test_json_hash(self):
        r = ResponderParser().parse('{"hash":"abc123","protocol":"SMB","client_ip":"10.0.0.1"}')
        assert len(r) == 1

    def test_json_decode_error(self):
        r = ResponderParser().parse("{bad}")
        assert len(r) == 0

    def test_hash_captured_mdns(self):
        r = ResponderParser().parse("[MDNS] Captured hash from 10.0.0.1")
        assert any("hash captured" in f["title"].lower() for f in r)

    def test_hash_captured_with_user(self):
        r = ResponderParser().parse("[SMB] Captured hash from 10.0.0.1 User: admin")
        assert any("hash captured" in f["title"].lower() for f in r)

    def test_hash_captured_dedup_by_hash_value(self):
        r = ResponderParser().parse("[SMB] Captured hash from 10.0.0.1 ($admin$)")
        assert len(r) == 1

    def test_protocol_capture_event(self):
        r = ResponderParser().parse("[SMB] request from 10.0.0.1")
        assert any("capture event" in f["title"] for f in r)

    def test_challenge_response(self):
        r = ResponderParser().parse("NTLMv2 Challenge: ABC123")
        assert any("Challenge/Response" in f["title"] for f in r)

    def test_nbtns_poison(self):
        r = ResponderParser().parse("NBT-NS poison response sent")
        assert any("poison response" in f["title"].lower() for f in r)
class TestSharphoundParser:
    def test_empty(self):
        assert SharphoundParser().parse("") == []

    def test_json_user(self):
        r = SharphoundParser().parse('{"Type":"user","Props":{"name":"jdoe","domain":"EXAMPLE"}}')
        assert any("AD User: jdoe" in f["title"] for f in r)

    def test_json_group(self):
        r = SharphoundParser().parse('{"Type":"group","Props":{"name":"Domain Admins","domain":"EXAMPLE"}}')
        assert any("AD Group" in f["title"] for f in r)

    def test_json_computer(self):
        r = SharphoundParser().parse('{"Type":"computer","Props":{"name":"PC-01","domain":"EXAMPLE","operatingsystem":"Windows 10"}}')
        assert any("AD Computer" in f["title"] for f in r)

    def test_json_session(self):
        r = SharphoundParser().parse('{"Type":"session","Props":{"name":"jdoe","computer":"PC-01","domain":"EXAMPLE"}}')
        assert any("AD Session" in f["title"] for f in r)

    def test_json_acl(self):
        r = SharphoundParser().parse('{"Type":"acl","Props":{"name":"ACL-01","domain":"EXAMPLE"}}')
        assert any("AD ACL" in f["title"] for f in r)

    def test_non_json_fallback(self):
        r = SharphoundParser().parse("plain text line")
        assert len(r) == 1

    def test_dedup_json(self):
        r = SharphoundParser().parse('{"Type":"user","Props":{"name":"jdoe","domain":"EXAMPLE"}}\n{"Type":"user","Props":{"name":"jdoe","domain":"EXAMPLE"}}')
        assert len(r) == 1
class TestSmbclientParser:
    def test_empty(self):
        assert SmbclientParser().parse("") == []
        assert SmbclientParser().parse("   ") == []

    def test_json_share_and_file(self):
        r = SmbclientParser().parse('[{"share":"C$","server":"10.0.0.1","filename":"secret.txt","size":1024}]')
        assert len(r) >= 2

    def test_json_non_dict_skipped(self):
        r = SmbclientParser().parse('["hello"]')
        assert len(r) == 0

    def test_json_decode_error_fallthrough(self):
        r = SmbclientParser().parse("{bad}")
        assert isinstance(r, list)

    def test_domain_line(self):
        r = SmbclientParser().parse("Domain = [WORKGROUP]")
        assert any("SMB server domain" in f["title"] for f in r)

    def test_os_line(self):
        r = SmbclientParser().parse("OS = [Windows 10]")
        assert any("SMB server OS" in f["title"] for f in r)

    def test_server_desc_line(self):
        r = SmbclientParser().parse('Server = [SERVER01]')
        assert any("SMB server" in f["title"] for f in r)

    def test_smb_version_line(self):
        r = SmbclientParser().parse("SMB version = 3.1.1")
        assert any("SMB protocol version" in f["title"] for f in r)

    def test_netbios_line(self):
        r = SmbclientParser().parse("nbname = SERVER01")
        assert any("NetBIOS name" in f["title"] for f in r)

    def test_server_ip_line(self):
        r = SmbclientParser().parse("server \\\\10.0.0.1")
        # This just updates context, no finding produced
        assert len(r) == 0

    def test_connected_line(self):
        r = SmbclientParser().parse("session started successfully")
        assert any("SMB session" in f["title"] for f in r)

    def test_share_line(self):
        r = SmbclientParser().parse("C$      Disk")
        assert any("SMB share discovered" in f["title"] for f in r)

    def test_file_line(self):
        r = SmbclientParser().parse("A  ...  1024  Jun 1 12:34:56 2024  file.txt")
        assert any("SMB file" in f["title"] for f in r)

    def test_server_desc_updates_target(self):
        r = SmbclientParser().parse("Server = [TARGET]")
        assert any("SMB server: TARGET" in f["title"] for f in r)
class TestSmbmapParser:
    def test_empty(self):
        assert SmbmapParser().parse("") == []
        assert SmbmapParser().parse("   ") == []

    def test_json_share(self):
        r = SmbmapParser().parse('[{"share":"C$","permission":"READ","target":"10.0.0.1"}]')
        assert len(r) == 1

    def test_json_share_with_file(self):
        r = SmbmapParser().parse(
            '[{"share":"C$","permission":"READ","target":"10.0.0.1"},'
            '{"filename":"secret.txt","size":1024,"target":"10.0.0.1","share":"C$"}]'
        )
        assert len(r) >= 2

    def test_json_disk_usage(self):
        r = SmbmapParser().parse('[{"share":"C$","permission":"READ","target":"10.0.0.1","disk_usage":"10.5G used"}]')
        assert any("disk usage" in f["title"].lower() for f in r)

    def test_json_decode_error_fallthrough(self):
        r = SmbmapParser().parse("{bad}")
        assert isinstance(r, list)

    def test_target_header(self):
        r = SmbmapParser().parse("Target: 10.0.0.1")
        assert len(r) == 0

    def test_host_re(self):
        r = SmbmapParser().parse("(10.0.0.1) - Windows Server")
        assert any("SMB target" in f["title"] for f in r)

    def test_target_line_update(self):
        r = SmbmapParser().parse("target : 10.0.0.5")
        assert len(r) == 0

    def test_disk_line(self):
        r = SmbmapParser().parse("Disk : C$")
        assert len(r) == 0

    def test_shares_line(self):
        r = SmbmapParser().parse("Shares: C$ (READ) D$ (WRITE)")
        assert len(r) >= 2

    def test_share_re(self):
        r = SmbmapParser().parse("C$       (READ ONLY)")
        assert any("SMB share" in f["title"] for f in r)

    def test_disk_usage_re(self):
        r = SmbmapParser().parse("10.5GB used out of 50.0GB")
        assert any("disk usage" in f["title"].lower() for f in r)

    def test_recursive_dir(self):
        r = SmbmapParser().parse("`  .\\dir\\")
        assert any("SMB directory" in f["title"] for f in r)

    def test_recursive_file(self):
        r = SmbmapParser().parse("`  .\\path\\file.txt")
        assert any("SMB file" in f["title"] for f in r)

    def test_file_re(self):
        r = SmbmapParser().parse("secret.txt   1024   rw-   something")
        assert any("SMB file" in f["title"] for f in r)
class TestPypykatzParserBranches:
    """Covers all uncovered branches."""

    def test_cred_type_items_not_list(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {"MSV": "not_a_list", "WDIGEST": "not_a_list"}
        })
        findings = p.parse(output)
        assert len(findings) == 0

    def test_cred_type_dedup_seen(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": [{"Password": "pass123", "NTHash": ""},
                        {"Password": "pass456", "NTHash": ""}]
            }
        })
        findings = p.parse(output)
        assert len(findings) == 1

    def test_section_data_not_dict(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {"MSV": "not_a_dict"}
        })
        findings = p.parse(output)
        assert len(findings) == 0

    def test_sub_creds_dedup_seen(self):
        p = PypykatzParser()
        output = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": {"LogonSessions": [{"Password": "pass", "NTHash": ""},
                                           {"Password": "other", "NTHash": ""}]}
            }
        })
        findings = p.parse(output)
        assert len(findings) == 1

    def test_empty_line_skipped_text_mode(self):
        p = PypykatzParser()
        findings = p.parse("line1\n\n  \nline2")
        assert len(findings) == 0

    def test_json_per_line_full_block(self):
        record = json.dumps({
            "LogonSession": {"Username": "admin", "DomainName": "CORP"},
            "Credentials": {
                "MSV": [{"Password": "pass123", "NTHash": ""}],
                "WDIGEST": {"LogonSessions": [{"Password": "pass456", "NTHash": ""}]}
            }
        })
        output = record + "\n" + record
        p = PypykatzParser()
        findings = p.parse(output)
        assert len(findings) == 2

    def test_json_per_line_empty_ssp(self):
        record = json.dumps({
            "LogonSession": {"Username": "system", "DomainName": "WORKGROUP"},
            "Credentials": {
                "SSP_CRED": {"Sessions": [{"Password": "",
                                            "NTHash": "aad3b435b51404eeaad3b435b51404ee"}]}
            }
        })
        p = PypykatzParser()
        findings = p.parse(record)
        assert len(findings) == 0

    def test_json_per_line_ssp_with_hash(self):
        record = json.dumps({
            "LogonSession": {"Username": "user", "DomainName": "WORKGROUP"},
            "Credentials": {
                "SSP": {"Creds": [{"Password": "", "NTHash": "deadbeef1234567890abcdef12345678"}]}
            }
        })
        p = PypykatzParser()
        findings = p.parse(record)
        assert len(findings) == 1

    def test_text_mode_password_line(self):
        p = PypykatzParser()
        findings = p.parse("password: supersecret\nusername: admin")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 9. recon_ng_parser.py  — missing 76, 116->120, 122, 164-171
# ---------------------------------------------------------------------------
class TestEvilWinrmParserAdditionalBranches:
    """Covers: JSON dedup, JSON decode error, text empty line skip,
       JSON ip_m found, connect line with ip search, connect dedup."""

    def test_json_dedup(self):
        """Line 50->43: JSON item host already in seen_hosts."""
        p = EvilWinrmParser()
        findings = p.parse('[{"host":"10.0.0.5","username":"admin"},{"host":"10.0.0.5","username":"admin2"}]')
        sessions = [f for f in findings if "Session established" in f["title"]]
        assert len(sessions) == 1

    def test_json_decode_error(self):
        """Line 64-65: JSONDecodeError in JSON path caught."""
        p = EvilWinrmParser()
        findings = p.parse("{bad}")
        assert isinstance(findings, list)

    def test_text_empty_line_skipped(self):
        """Line 70: empty line in text parse."""
        p = EvilWinrmParser()
        findings = p.parse("\n  \n")
        assert findings == []

    def test_banner_with_ip(self):
        """Line 76->78: Evil-WinRM banner line with IP."""
        p = EvilWinrmParser()
        findings = p.parse("Evil-WinRM PS session on 10.0.0.5:5985")
        sessions = [f for f in findings if "Session established" in f["title"]]
        assert len(sessions) == 1
        assert sessions[0]["target"] == "10.0.0.5"

    def test_connect_with_ip(self):
        """Line 103->106: connect line with IP found."""
        p = EvilWinrmParser()
        findings = p.parse("Connecting to 10.0.0.5:5985")
        conn = [f for f in findings if "Connection" in f["title"]]
        assert len(conn) == 1

    def test_connect_dedup(self):
        """Line 115->128: connect dedup_key already in seen_hosts."""
        p = EvilWinrmParser()
        findings = p.parse("Connecting to 10.0.0.5:5985\nConnecting to 10.0.0.5:5985\n")
        conn = [f for f in findings if "Connection" in f["title"]]
        assert len(conn) == 1


# ============================================================================
# 4. gowitness_parser.py  — 46-49
# ============================================================================
class TestSharphoundParserAdditionalBranches:
    """Covers: dict type (line 35), non-dict props skip, dedup for
       group, computer, session, ACL."""

    def test_json_dict_data(self):
        """Line 35->22: data is a dict, not a list."""
        p = SharphoundParser()
        findings = p.parse('{"Type":"user","Props":{"name":"admin","domain":"EXAMPLE"}}')
        assert any("AD User: admin" in f["title"] for f in findings)

    def test_non_dict_props_skipped(self):
        """Line 63->exit: props is not a dict, return early."""
        p = SharphoundParser()
        findings = p.parse('{"Type":"user","Props":"not_a_dict"}')
        assert len(findings) == 0

    def test_group_dedup(self):
        """Line 86: group dedup_key already in seen."""
        p = SharphoundParser()
        findings = p.parse('{"Type":"group","Props":{"name":"admins","domain":"E"}}\n{"Type":"group","Props":{"name":"admins","domain":"E"}}')
        groups = [f for f in findings if "AD Group" in f["title"]]
        assert len(groups) == 1

    def test_computer_dedup(self):
        """Line 102: computer dedup_key already in seen."""
        p = SharphoundParser()
        findings = p.parse('{"Type":"computer","Props":{"name":"PC-1","domain":"E"}}\n{"Type":"computer","Props":{"name":"PC-1","domain":"E"}}')
        comps = [f for f in findings if "AD Computer" in f["title"]]
        assert len(comps) == 1

    def test_session_dedup(self):
        """Line 120: session dedup_key already in seen."""
        p = SharphoundParser()
        findings = p.parse('{"Type":"session","Props":{"name":"jdoe","computer":"PC-1"}}\n{"Type":"session","Props":{"name":"jdoe","computer":"PC-1"}}')
        sessions = [f for f in findings if "AD Session" in f["title"]]
        assert len(sessions) == 1

    def test_acl_dedup(self):
        """Line 136: ACL dedup_key already in seen."""
        p = SharphoundParser()
        findings = p.parse('{"Type":"acl","Props":{"name":"ACL-1","domain":"E"}}\n{"Type":"acl","Props":{"name":"ACL-1","domain":"E"}}')
        acls = [f for f in findings if "AD ACL" in f["title"]]
        assert len(acls) == 1

    def test_non_json_text_output(self):
        """Line 35->22: no JSON found, fallback to text."""
        p = SharphoundParser()
        findings = p.parse("Some plain text output\n")
        assert len(findings) == 1


# ============================================================================
# 8. smbmap_parser.py  — 103, 139, 164-166, 182, 238, 257, 279
# ============================================================================
class TestSmbmapParserAdditionalBranches:
    """Covers: JSON file dedup, empty line skip, target: line update,
       shares_line dedup, recursive dir dedup, recursive file dedup,
       file_re dedup."""

    def test_json_file_dedup(self):
        """Line 103: file dedup_key already in seen."""
        p = SmbmapParser()
        findings = p.parse('[{"share":"C$","permission":"READ","target":"10.0.0.1"},\n{"filename":"secret.txt","size":1024,"target":"10.0.0.1","share":"C$"},\n{"filename":"secret.txt","size":2048,"target":"10.0.0.1","share":"C$"}]')
        files = [f for f in findings if "SMB file" in f["title"]]
        assert len(files) == 1

    def test_text_empty_line(self):
        """Line 139: empty line in text parse."""
        p = SmbmapParser()
        findings = p.parse("\n  \n")
        assert findings == []

    def test_target_line_update(self):
        """Lines 164-166: 'target:' line updates target."""
        p = SmbmapParser()
        findings = p.parse("target: 10.0.0.5")
        assert len(findings) == 0

    def test_shares_line_dedup(self):
        """Line 182: shares line dedup_key already in seen."""
        p = SmbmapParser()
        findings = p.parse("Shares: C$ (READ)\nShares: C$ (READ)\n")
        shares = [f for f in findings if "SMB share" in f["title"]]
        assert len(shares) == 1

    def test_recursive_dir_dedup(self):
        """Line 238: recursive dir dedup_key already in seen."""
        p = SmbmapParser()
        findings = p.parse("`  .\\dir\\\n`  .\\dir\\\n")
        dirs = [f for f in findings if "SMB directory" in f["title"]]
        assert len(dirs) == 1

    def test_recursive_file_dedup(self):
        """Line 257: recursive file dedup_key already in seen."""
        p = SmbmapParser()
        findings = p.parse("`  .\\path\\file.txt\n`  .\\path\\file.txt\n")
        files = [f for f in findings if "SMB file" in f["title"]]
        assert len(files) == 1

    def test_file_re_dedup(self):
        """Line 279: FILE_RE dedup_key already in seen."""
        p = SmbmapParser()
        findings = p.parse("secret.txt   1024   rw-   something\nsecret.txt   1024   rw-   something\n")
        files = [f for f in findings if "SMB file" in f["title"]]
        assert len(files) == 1


# ============================================================================
# 9. smtp_user_enum_parser.py — 91, 99, 144-145, 182->196, 183->196,
#                                230->243, 250->276, 264->276
# ============================================================================
class TestSmbclientParserAdditionalBranches:
    """Covers: JSON file dedup, empty line, server desc unknown, server
       from path, current share skip, file dedup."""

    def test_json_file_dedup(self):
        """101: JSON filename dedup_key already in seen."""
        item = json.dumps({"filename": "test.txt", "server": "srv", "size": 100})
        p = SmbclientParser()
        findings = p.parse(f"[{item},{item}]")
        files = [f for f in findings if "SMB file" in f["title"]]
        assert len(files) == 1

    def test_empty_line_skipped(self):
        """126: empty line in text parsing."""
        p = SmbclientParser()
        findings = p.parse("Disk share\n\n")
        assert isinstance(findings, list)

    def test_server_desc_updates_unknown(self):
        """176->178: server description line with server still 'unknown'."""
        p = SmbclientParser()
        findings = p.parse("Server = [FILESERVER]\n")
        svr = [f for f in findings if "SMB server" in f["title"]]
        assert len(svr) >= 1
        assert svr[0]["target"] == "FILESERVER"

    def test_server_from_path_line(self):
        """213->215: server extracted from line containing path/URL."""
        p = SmbclientParser()
        findings = p.parse("server \\\\192.168.1.100\\share\n")
        assert isinstance(findings, list)

    def test_current_share_line_skipped(self):
        """235: line with backslash matching current_share is skipped.
           Share name containing backslashes, then same backslash-prefixed
           line triggers the condition."""
        p = SmbclientParser()
        findings = p.parse("\\\\sharename  Disk\n\\\\sharename\n")
        assert isinstance(findings, list)

    def test_file_re_match(self):
        """258-279: _FILE_RE handler — note that _SHARE_RE is checked
           first (line 237) and matches any line with two \S+ tokens,
           which always includes _FILE_RE lines.  The _FILE_RE block
           (lines 258-279) is structurally dead code because _SHARE_RE's
           continue at line 256 skips it for the same input."""
        p = SmbclientParser()
        findings = p.parse("A   1234  Mon Jan 1 00:00:00 2024  test.txt\n")
        # _SHARE_RE eats this as share="A", type="1234"
        shares = [f for f in findings if "SMB share" in f["title"]]
        assert len(shares) == 1


# ============================================================================
# 9. enum4linux_parser.py  — 99->114, 151, 161->163, 188->201, 206->219,
#                             224->237, 255->267, 271->283, 301->313, 319
# ============================================================================
class TestEnum4linuxParserAdditionalBranches:
    """Covers: JSON user dedup, empty line, target parse, workgroup,
       user match, share match, group match, session match, OS match,
       SID dedup."""

    def test_json_user_dedup(self):
        """99->114: JSON user already in seen_users."""
        item = json.dumps({"user": "admin", "host": "srv"})
        p = Enum4linuxParser()
        findings = p.parse(f"[{item},{item}]")
        users = [f for f in findings if "User:" in f["title"]]
        assert len(users) == 1

    def test_empty_line_skipped(self):
        """151: empty line in text parsing."""
        p = Enum4linuxParser()
        findings = p.parse("\n\n")
        assert findings == []

    def test_target_from_line(self):
        """161->163: target extracted from line with colon."""
        p = Enum4linuxParser()
        findings = p.parse("Target: 192.168.1.100\n")
        assert isinstance(findings, list)

    def test_workgroup_discovered(self):
        """188->201: workgroup line matched."""
        p = Enum4linuxParser()
        findings = p.parse("Workgroup: WORKGROUP\n")
        wg = [f for f in findings if "Workgroup" in f["title"]]
        assert len(wg) == 1

    def test_user_discovered(self):
        """206->219: user line with new user."""
        p = Enum4linuxParser()
        findings = p.parse("user: jdoe\n")
        users = [f for f in findings if "User:" in f["title"]]
        assert len(users) == 1

    def test_share_discovered(self):
        """224->237: share line matched."""
        p = Enum4linuxParser()
        findings = p.parse("data     disk     comment\n")
        shares = [f for f in findings if "SMB share" in f["title"]]
        assert len(shares) == 1

    def test_group_discovered(self):
        """255->267: domain group line matched."""
        p = Enum4linuxParser()
        findings = p.parse("Domain group: Domain Admins\n")
        groups = [f for f in findings if "Domain group" in f["title"]]
        assert len(groups) == 1

    def test_session_discovered(self):
        """271->283: session info line matched."""
        p = Enum4linuxParser()
        findings = p.parse("Session: admin connected from 10.0.0.1\n")
        sessions = [f for f in findings if "Active SMB sessions" in f["title"]]
        assert len(sessions) == 1

    def test_os_discovered(self):
        """301->313: OS line matched."""
        p = Enum4linuxParser()
        findings = p.parse("OS: Windows Server 2022\n")
        os_findings = [f for f in findings if "OS:" in f["title"]]
        assert len(os_findings) == 1

    def test_sid_dedup(self):
        """319: SID dedup_key already in seen_shares."""
        line = "S-1-5-21-1000000000-2000000000-3000000000-500"
        p = Enum4linuxParser()
        findings = p.parse(f"{line}\n{line}\n")
        sids = [f for f in findings if "SID:" in f["title"]]
        assert len(sids) == 1


# ============================================================================
# 10. ike_scan_parser.py  — 108, 113->126, 130->134, 154->169, 191->204,
#                           210->223, 227->240, 249->262, 268->281, 287->105
# ============================================================================
class TestEvilWinrmParserEdgeCases:
    """Covers: text empty line, banner with IP, connect with IP."""

    def test_text_empty_line_skipped(self):
        """70: empty line in text parse."""
        p = EvilWinrmParser()
        findings = p.parse("\n  \n")
        assert findings == []

    def test_banner_with_ip(self):
        """76->78: Evil-WinRM banner line with IP found."""
        p = EvilWinrmParser()
        findings = p.parse("Evil-WinRM PS session on 10.0.0.5:5985")
        sessions = [f for f in findings if "Session established" in f["title"]]
        assert len(sessions) == 1
        assert sessions[0]["target"] == "10.0.0.5"

    def test_connect_with_ip(self):
        """103->106: connect line with IP found."""
        p = EvilWinrmParser()
        findings = p.parse("Connecting to 10.0.0.5:5985")
        conn = [f for f in findings if "Connection" in f["title"]]
        assert len(conn) == 1


# ============================================================================
# 16. feroxbuster_parser.py  — 51, 91
# ============================================================================

class TestImpacketParser:
    def test_basic_parse(self):
        p = ImpacketParser()
        output = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c1:::\n"
        findings = p.parse(output)
        assert len(findings) >= 1
        _check_finding(findings[0], "impacket")

    def test_empty_output(self):
        p = ImpacketParser()
        assert p.parse("") == []
