# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from siyarix.nlp_engine import NaturalLanguageParser

def test_nlp_target_extraction():
    nlp = NaturalLanguageParser()
    
    # Extract URL
    url, ttype = nlp.extract_entities("scan https://example.com please")
    assert url == "https://example.com"
    assert ttype == "url"
    
    # Extract IP
    ip, ttype = nlp.extract_entities("check 192.168.1.5 fast")
    assert ip == "192.168.1.5"
    assert ttype == "ipv4"
    
    # Extract Domain
    domain, ttype = nlp.extract_entities("what about google.com")
    assert domain == "google.com"
    assert ttype == "domain"

def test_nlp_parameter_extraction():
    nlp = NaturalLanguageParser()
    
    params = nlp.extract_parameters("scan port 80,443 very fast and stealthy")
    assert params.get("ports") == "80,443"
    assert params.get("speed") == "fast"
    
    # Let's test just fast
    params2 = nlp.extract_parameters("scan fast all ports")
    assert params2.get("speed") == "fast"
    assert params2.get("ports") == "all"

def test_nlp_scoring():
    nlp = NaturalLanguageParser()
    nlp.train_tools([
        {"name": "nmap", "description": "network scanner port scanner"},
        {"name": "sqlmap", "description": "sql injection vulnerability scanner"}
    ])
    
    intent = nlp.parse("run a network port scan")
    assert intent.tool_name == "nmap"
    
    intent2 = nlp.parse("find sql injection vulnerabilities")
    assert intent2.tool_name == "sqlmap"
