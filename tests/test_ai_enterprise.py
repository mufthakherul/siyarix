# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive tests for Siyarix Enterprise AI Engine.

Covers:
- Semantic Tool Pruning (SemanticToolSelector)
- Multi-format Tool Call Repair & Parsing (repair_plan_payload, repair_json)
- Anti-Hallucination Evidence Grounding (GroundingVerifier)
- Plan & Response Semantic Caching (CacheManager)
- Anti-Looping Guard & Multi-Wave Loop Control
- Tool Dependency Fallbacks & Auto-Install
- Strategic Thought Reasoning & Enterprise Reporting
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from siyarix.cache_manager import CacheManager
from siyarix.chat.engine import LLMEngineMixin
from siyarix.chat.grounding import GroundingResult, GroundingVerifier
from siyarix.models import PlanStep
from siyarix.planner_autonomous import SemanticToolSelector
from siyarix.response import ResponseGenerator
from siyarix.tool_call_repair import parse_markdown_code_blocks, repair_json, repair_plan_payload


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Semantic Tool Selector Tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_semantic_tool_selector_web_target():
    schemas = [
        {"name": "nmap", "description": "Port scanner", "category": "recon", "tags": ["port"]},
        {"name": "httpx", "description": "HTTP probe", "category": "web", "tags": ["web"]},
        {"name": "nikto", "description": "Web scanner", "category": "web", "tags": ["web"]},
        {
            "name": "nuclei",
            "description": "Vulnerability templates",
            "category": "vuln",
            "tags": ["vuln"],
        },
        {
            "name": "volatility",
            "description": "Memory forensics",
            "category": "forensic",
            "tags": ["memory"],
        },
        {
            "name": "aircrack-ng",
            "description": "WiFi security",
            "category": "wireless",
            "tags": ["wifi"],
        },
        {"name": "hydra", "description": "Brute force", "category": "bruteforce", "tags": ["auth"]},
    ]
    pruned = SemanticToolSelector.prune_schemas(
        schemas, goal="audit web vulnerabilities on https://example.com/login"
    )
    pruned_names = {s["name"] for s in pruned}
    # Web and vulnerability tools must be included
    assert "httpx" in pruned_names
    assert "nikto" in pruned_names
    assert "nuclei" in pruned_names
    # Unrelated tools should be pruned
    assert "volatility" not in pruned_names
    assert "aircrack-ng" not in pruned_names


def test_semantic_tool_selector_forensic_target():
    schemas = [
        {
            "name": "volatility",
            "description": "Memory dump forensics",
            "category": "forensic",
            "tags": ["memory"],
        },
        {
            "name": "binwalk",
            "description": "Firmware analysis",
            "category": "forensic",
            "tags": ["carve"],
        },
        {"name": "nikto", "description": "Web scanner", "category": "web", "tags": ["web"]},
        {"name": "sqlmap", "description": "SQL injection", "category": "exploit", "tags": ["sql"]},
    ]
    pruned = SemanticToolSelector.prune_schemas(
        schemas, goal="analyze memory dump memory.raw with volatility"
    )
    pruned_names = {s["name"] for s in pruned}
    assert "volatility" in pruned_names
    assert "nikto" not in pruned_names


def test_semantic_tool_selector_fallback_on_empty():
    schemas = [{"name": "toolA", "description": "descA"}, {"name": "toolB", "description": "descB"}]
    pruned = SemanticToolSelector.prune_schemas(schemas, goal="xyz123 unusual request")
    # When no keyword matches, it preserves schemas up to max_tools
    assert len(pruned) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Tool Call Repair Tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_repair_json_dirty_strings():
    # Markdown fence + single quotes + trailing comma
    dirty = "```json\n{'goal': 'recon', 'needs_tools': true, 'steps': [{'command': 'nmap -sT 127.0.0.1',}],}\n```"
    fixed = repair_json(dirty)
    assert fixed is not None
    assert fixed.get("goal") == "recon"
    assert len(fixed.get("steps", [])) == 1


def test_parse_markdown_code_blocks():
    text = "Here is the plan:\n```bash\nnmap -sV target.local\ncurl -I https://target.local\n```"
    cmds = parse_markdown_code_blocks(text)
    cmd_strings = [s["command"] for s in cmds]
    assert "nmap -sV target.local" in cmd_strings
    assert "curl -I https://target.local" in cmd_strings


def test_repair_plan_payload_yaml_and_bracket():
    # Test YAML fallback
    yaml_text = "goal: web audit\nneeds_tools: true\nsteps:\n  - command: whatweb example.com\n    tool: whatweb"
    res = repair_plan_payload(yaml_text)
    assert res is not None
    assert res.get("goal") == "web audit"
    assert len(res.get("steps", [])) == 1
    assert res.get("steps")[0]["command"] == "whatweb example.com"

    # Test bracket fallback [nmap -sV target]
    bracket_text = "I recommend running:\n[nmap -sS target.com]\n[nikto -h target.com]"
    res_b = repair_plan_payload(bracket_text)
    assert res_b is not None
    assert len(res_b.get("steps", [])) == 2
    assert res_b.get("steps")[0]["command"] == "nmap -sS target.com"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Anti-Hallucination Grounding Verifier Tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_grounding_verifier_valid_evidence():
    raw_outputs = [
        "Nmap scan report for 192.168.1.50\nPORT 80/tcp open http\nPORT 443/tcp open ssl/https\nPORT 22/tcp open ssh",
        "Nuclei found [CVE-2021-44228] Log4j Remote Code Execution on https://192.168.1.50",
    ]
    findings = [{"title": "Log4j RCE", "cve": "CVE-2021-44228", "port": 80}]

    response = (
        "Assessment completed for 192.168.1.50. Found open ports: port 80 and port 443. "
        "Critical vulnerability CVE-2021-44228 (Log4j) was verified on the target."
    )

    result = GroundingVerifier.verify(response, raw_outputs, findings)
    assert result.is_grounded is True
    assert result.score >= 0.8
    assert "CVE-2021-44228" in result.verified_cves
    assert len(result.unverified_cves) == 0
    assert 80 in result.verified_ports
    assert len(result.unverified_ports) == 0


def test_grounding_verifier_detects_hallucinations():
    raw_outputs = [
        "Nmap scan report for 10.0.0.5\nPORT 22/tcp open ssh",
    ]
    # Response falsely claims port 3389 is open and claims CVE-2023-99999
    response = "Target 10.0.0.5 has open port 3389 (RDP) and is vulnerable to critical exploit CVE-2023-99999."

    result = GroundingVerifier.verify(response, raw_outputs, [])
    assert result.is_grounded is False
    assert "CVE-2023-99999" in result.unverified_cves
    assert 3389 in result.unverified_ports
    assert len(result.advisories) >= 2


def test_grounding_verifier_append_audit():
    res = GroundingResult(
        score=1.0,
        verified_cves=["CVE-2021-44228"],
        verified_ports=[80],
        citations=["✓ CVE-2021-44228 confirmed", "✓ Port 80 confirmed"],
    )
    annotated = GroundingVerifier.append_audit_to_response("Target analysis complete.", res)
    assert "### 🛡 Grounding Verification Audit" in annotated
    assert "[VERIFIED]" in annotated
    assert "CVE-2021-44228" in annotated


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Cache Manager AI Plan & Response Tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_cache_manager_ai_plan():
    cm = CacheManager()
    goal = "scan subdomains on example.com"
    target = "example.com"
    plan_data = {
        "goal": goal,
        "steps": [{"id": "s1", "tool": "sublist3r", "command": "sublist3r -d example.com"}],
        "reasoning": "DNS enumeration phase",
    }

    cm.set_ai_plan(goal, plan_data, target=target)
    retrieved = cm.get_ai_plan(goal, target=target)
    assert retrieved is not None
    assert retrieved["goal"] == goal
    assert len(retrieved["steps"]) == 1
    assert retrieved["steps"][0]["command"] == "sublist3r -d example.com"


def test_cache_manager_ai_response():
    cm = CacheManager()
    instruction = "what is siyarix"
    cm.set_ai_response(instruction, "Siyarix is an advanced security intelligence engine.")
    cached_resp = cm.get_ai_response(instruction)
    assert cached_resp == "Siyarix is an advanced security intelligence engine."


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Response Generator Thought & Enterprise Report Tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_response_generator_thought_rendering():
    console_mock = MagicMock()
    gen = ResponseGenerator(console_mock)
    gen.render_thought("Analyzing nmap output. Port 80 is open, recommending nikto next.")
    assert console_mock.print.called


def test_response_generator_grounding_audit_rendering():
    console_mock = MagicMock()
    gen = ResponseGenerator(console_mock)
    gr = GroundingResult(
        score=0.9,
        verified_cves=["CVE-2022-1234"],
        verified_ports=[443],
        citations=["✓ Port 443 confirmed"],
    )
    gen.render_grounding_audit(gr)
    assert console_mock.print.called


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Tool Fallback & Anti-Looping Tests
# ═══════════════════════════════════════════════════════════════════════════════


class FakeChatSession:
    def __init__(self):
        self.session_id = "test-session"
        self.messages = []
        self.mode = "autonomous"
        self.target = "127.0.0.1"
        self.context = {}

    def add_message(self, role, content, **metadata):
        class Msg:
            def __init__(self, r, c):
                self.role = r
                self.content = c

        msg = Msg(role, content)
        self.messages.append(msg)
        return msg


class EngineTestMock(LLMEngineMixin):
    def __init__(self):
        self._settings = MagicMock()
        self._settings.get.return_value = False
        self._session = FakeChatSession()
        self._mode = "autonomous"
        self._llm_calls = 0


def test_tool_fallback_rewrite():
    eng = EngineTestMock()
    step = PlanStep(id="s1", tool="dig", command="dig +short example.com")

    # With nslookup installed and dig missing, it should rewrite dig to nslookup
    with patch("shutil.which", side_effect=lambda x: True if x == "nslookup" else None):
        eng._resolve_tool_fallback_and_install(step)
        assert "nslookup" in step.command
        assert "dig" not in step.command
