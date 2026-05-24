from phalanx.parsers.nmap_parser import NmapParser


def test_nmap_parser_text():
    sample = '''
Nmap scan report for 192.168.1.5
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
'''
    p = NmapParser()
    findings = p.parse(sample)
    assert isinstance(findings, list)
    assert any(f.get("tool") == "nmap" for f in findings)
    assert any("22" in f.get("title", "") for f in findings)
