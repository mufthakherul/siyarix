# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.parsers.gobuster_parser import GobusterParser

def test_gobuster_parser_basic():
    output = """
Url: http://example.com
/admin (Status: 200) [Size: 1234]
/login (Status: 302) [Size: 0]
"""
    p = GobusterParser()
    findings = p.parse(output)
    assert isinstance(findings, list)
    assert len(findings) == 2
    assert findings[0]["severity"] == "info"
    assert findings[0]["target"] == "http://example.com"
    assert "/admin" in findings[0]["title"]
    assert findings[1]["severity"] == "info"

def test_gobuster_parser_severities():
    output = """
Url: http://example.com
/secret (Status: 401)
/forbidden (Status: 403)
/error (Status: 500)
"""
    p = GobusterParser()
    findings = p.parse(output)
    assert findings[0]["severity"] == "low"
    assert findings[1]["severity"] == "low"
    assert findings[2]["severity"] == "medium"

def test_gobuster_parser_malformed():
    output = """
Url: http://example.com
Just some random line
/valid (Status: 200)
"""
    p = GobusterParser()
    findings = p.parse(output)
    assert len(findings) == 1
    assert "/valid" in findings[0]["title"]
