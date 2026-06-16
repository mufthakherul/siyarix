# SPDX-License-Identifier: AGPL-3.0-or-later
from siyarix.nlp_engine import NaturalLanguageParser

def test_nlp_target_extraction():
    nlp = NaturalLanguageParser()
    
    url, ttype = nlp.extract_entities("scan https://example.com please")
    assert url == "https://example.com"
    
    ip, ttype = nlp.extract_entities("check 192.168.1.5 fast")
    assert ip == "192.168.1.5"

def test_nlp_parameter_extraction():
    nlp = NaturalLanguageParser()
    params = nlp.extract_parameters("scan port 80,443 very fast with timeout 5m and critical vulnerabilities json")
    
    assert params.get("ports") == "80,443"
    assert params.get("speed") == "fast"
    assert params.get("timeout") == "5m"
    assert params.get("severity") == "critical"
    assert params.get("format") == "json"

def test_nlp_fuzzy_matching():
    nlp = NaturalLanguageParser()
    assert nlp.fuzzy_match("vulnaribility", ["vulnerability"]) is True
    assert nlp.fuzzy_match("direcotry", ["directory"]) is True
    assert nlp.fuzzy_match("abc", ["vulnerability"]) is False

def test_nlp_stemming_and_synonyms():
    nlp = NaturalLanguageParser()
    # default synonym for 'bug' is 'vuln' -> stem of vuln is 'vuln'
    assert nlp.tokenize("scanning bugs") == ["scan", "vuln", "scan_vuln"]
    
def test_nlp_scoring():
    nlp = NaturalLanguageParser()
    nlp.train_tools([
        {"name": "nmap", "description": "network port scanner"},
        {"name": "sqlmap", "description": "sql injection vulnerabilities"}
    ])
    
    intent = nlp.parse("run a network port scan")
    assert intent.tool_name == "nmap"
    
    intent2 = nlp.parse("find sql injection bugs")
    assert intent2.tool_name == "sqlmap"
