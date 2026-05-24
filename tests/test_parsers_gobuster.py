from phalanx.parsers.gobuster_parser import GobusterParser


def test_gobuster_parser_basic():
    output = '''
Url: http://example.com
/admin (Status: 200) [Size: 1234]
/login (Status: 302) [Size: 0]
'''
    p = GobusterParser()
    findings = p.parse(output)
    assert isinstance(findings, list)
    assert any("/admin" in f.get("title", "") for f in findings)
    assert any(f.get("tool") == "gobuster" for f in findings)
