# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.parsers.nmap_parser import NmapParser

def test_nmap_parser_text():
    sample = """
Nmap scan report for 192.168.1.5
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
445/tcp open  microsoft-ds
"""
    p = NmapParser()
    findings = p.parse(sample)
    assert isinstance(findings, list)
    assert len(findings) == 3
    assert any(f.get("tool") == "nmap" for f in findings)
    
    ssh_finding = next(f for f in findings if "22" in f["title"])
    assert ssh_finding["severity"] == "low"
    
    smb_finding = next(f for f in findings if "445" in f["title"])
    assert smb_finding["severity"] == "high"

def test_nmap_parser_xml():
    xml_sample = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    p = NmapParser()
    findings = p.parse(xml_sample)
    assert len(findings) == 1
    assert "22" in findings[0]["title"]
    assert "OpenSSH" in findings[0]["description"]
    assert findings[0]["severity"] == "low"
    assert findings[0]["target"] == "10.0.0.1"
