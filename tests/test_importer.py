"""Tests for siyarix.importer — security tool data import."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siyarix.importer import (
    ImportResult,
    ImportedFinding,
    SEVERITY_MAP,
    SecurityImporter,
    security_importer,
)


@pytest.fixture
def importer() -> SecurityImporter:
    return SecurityImporter()


# ── ImportedFinding ────────────────────────────────────────────────────

class TestImportedFinding:
    def test_defaults(self) -> None:
        f = ImportedFinding()
        assert f.source == ""
        assert f.severity == "info"
        assert f.cvss_score == 0.0
        assert f.port == 0
        assert f.references == []
        assert f.raw_data == {}


# ── ImportResult ───────────────────────────────────────────────────────

class TestImportResult:
    def test_summary_empty(self) -> None:
        r = ImportResult()
        assert r.summary == {}

    def test_summary_with_findings(self) -> None:
        r = ImportResult(findings=[
            ImportedFinding(severity="high"),
            ImportedFinding(severity="high"),
            ImportedFinding(severity="low"),
        ])
        assert r.summary == {"high": 2, "low": 1}

    def test_summary_property(self) -> None:
        r = ImportResult(source_format="nessus", total_imported=0)
        assert r.source_format == "nessus"

    @property
    def summary(self):
        return self.summary


# ── SEVERITY_MAP ───────────────────────────────────────────────────────

class TestSeverityMap:
    def test_all_mappings(self) -> None:
        assert SEVERITY_MAP[0] == "info"
        assert SEVERITY_MAP[4] == "critical"
        assert SEVERITY_MAP["none"] == "info"
        assert SEVERITY_MAP["critical"] == "critical"
        assert SEVERITY_MAP["informational"] == "info"
        assert SEVERITY_MAP["high severity"] == "high"


# ── Nessus ─────────────────────────────────────────────────────────────

class TestImportNessus:
    NESSUS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="192.168.1.1">
      <ReportItem port="22" severity="medium" protocol="tcp" pluginID="12345">
        <pluginName>SSH Server</pluginName>
        <description>SSH service detected</description>
        <cve>CVE-2024-0001</cve>
        <solution>Update SSH</solution>
        <see_also>https://example.com</see_also>
      </ReportItem>
      <ReportItem port="80" severity="0" protocol="tcp" pluginID="67890">
        <pluginName>HTTP Server</pluginName>
        <description/>
        <cve/>
        <cvss3_base_score>5.5</cvss3_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

    def test_parse_valid(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "test.nessus"
        f.write_text(self.NESSUS_XML, encoding="utf-8")
        result = importer.import_nessus(f)
        assert result.source_format == "nessus"
        assert result.total_imported == 2
        assert result.errors == []
        assert result.findings[0].host == "192.168.1.1"
        assert result.findings[0].port == 22
        assert result.findings[0].severity == "medium"
        assert result.findings[0].cve == "CVE-2024-0001"
        assert result.findings[1].cvss_score == 5.5

    def test_file_not_found(self, importer: SecurityImporter) -> None:
        result = importer.import_nessus("/nonexistent/file.nessus")
        assert result.total_imported == 0
        assert len(result.errors) == 1
        assert "File not found" in result.errors[0]

    def test_parse_error(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "bad.nessus"
        f.write_text("not xml", encoding="utf-8")
        result = importer.import_nessus(f)
        assert result.total_imported == 0
        assert len(result.errors) == 1
        assert "Nessus parse error" in result.errors[0]


# ── Burp Suite ─────────────────────────────────────────────────────────

class TestImportBurp:
    BURP_XML = """<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>111</serialNumber>
    <name>SQL Injection</name>
    <severity>high</severity>
    <cwe>89</cwe>
    <host>https://example.com</host>
    <port>443</port>
    <issueBackground>SQL injection background</issueBackground>
    <remediationBackground>Fix input validation</remediationBackground>
    <reference>https://owasp.org</reference>
  </issue>
</issues>"""

    def test_parse_valid(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "burp.xml"
        f.write_text(self.BURP_XML, encoding="utf-8")
        result = importer.import_burp(f)
        assert result.source_format == "burp"
        assert result.total_imported == 1
        assert result.findings[0].title == "SQL Injection"
        assert result.findings[0].severity == "high"
        assert result.findings[0].port == 443

    def test_file_not_found(self, importer: SecurityImporter) -> None:
        result = importer.import_burp("/nonexistent/burp.xml")
        assert result.total_imported == 0
        assert "File not found" in result.errors[0]

    def test_parse_error(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "bad_burp.xml"
        f.write_text("invalid", encoding="utf-8")
        result = importer.import_burp(f)
        assert result.total_imported == 0
        assert "Burp parse error" in result.errors[0]

    def test_uses_issue_detail_fallback(self, importer: SecurityImporter, tmp_path: Path) -> None:
        xml = """<?xml version="1.0"?><issues><issue>
            <name>Test</name><severity>medium</severity>
            <issueDetail>Direct detail text</issueDetail>
            <port>80</port></issue></issues>"""
        f = tmp_path / "burp2.xml"
        f.write_text(xml, encoding="utf-8")
        result = importer.import_burp(f)
        assert result.findings[0].description == "Direct detail text"


# ── Metasploit ─────────────────────────────────────────────────────────

class TestImportMetasploit:
    def test_parse_valid(self, importer: SecurityImporter, tmp_path: Path) -> None:
        data = [{"address": "10.0.0.1", "vulns": [{"name": "MS17-010", "severity": "high", "cve": "CVE-2017-0143"}]}]
        f = tmp_path / "msf.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        result = importer.import_metasploit(f)
        assert result.source_format == "metasploit"
        assert result.total_imported == 1
        assert result.findings[0].title == "MS17-010"
        assert result.findings[0].cve == "CVE-2017-0143"

    def test_parse_with_hosts_key(self, importer: SecurityImporter, tmp_path: Path) -> None:
        data = {"hosts": [{"address": "10.0.0.2", "findings": [{"title": "Port Scan", "severity": "medium"}]}]}
        f = tmp_path / "msf2.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        result = importer.import_metasploit(f)
        assert result.total_imported == 1

    def test_file_not_found(self, importer: SecurityImporter) -> None:
        result = importer.import_metasploit("/nonexistent/msf.json")
        assert result.total_imported == 0
        assert "File not found" in result.errors[0]

    def test_parse_error(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "bad_msf.json"
        f.write_text("not json", encoding="utf-8")
        result = importer.import_metasploit(f)
        assert result.total_imported == 0
        assert "Metasploit parse error" in result.errors[0]


# ── STIX ───────────────────────────────────────────────────────────────

class TestImportStix:
    def test_parse_valid(self, importer: SecurityImporter, tmp_path: Path) -> None:
        data = {"objects": [
            {"type": "vulnerability", "id": "vuln--1", "name": "CVE-2024-0001", "severity": "critical",
             "external_references": [{"external_id": "CVE-2024-0001"}]},
            {"type": "indicator", "id": "ind--1", "name": "Malicious IP", "severity": "high"},
            {"type": "malware", "id": "mal--1", "name": "Ransomware"},
            {"type": "attack-pattern", "id": "ap--1", "name": "Phishing"},
            {"type": "not-relevant", "id": "other--1", "name": "Skip"},
        ]}
        f = tmp_path / "stix.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        result = importer.import_stix(f)
        assert result.source_format == "stix"
        assert result.total_imported == 4

    def test_parse_list_root(self, importer: SecurityImporter, tmp_path: Path) -> None:
        data = [{"type": "vulnerability", "name": "Test", "external_references": [{"external_id": "CVE-2024-0002"}]}]
        f = tmp_path / "stix_list.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        result = importer.import_stix(f)
        assert result.total_imported == 1

    def test_file_not_found(self, importer: SecurityImporter) -> None:
        result = importer.import_stix("/nonexistent/stix.json")
        assert result.total_imported == 0
        assert "File not found" in result.errors[0]

    def test_parse_error(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "bad_stix.json"
        f.write_text("not json", encoding="utf-8")
        result = importer.import_stix(f)
        assert result.total_imported == 0
        assert "STIX parse error" in result.errors[0]


# ── OpenIOC ────────────────────────────────────────────────────────────

class TestImportOpenIoc:
    IOC_XML = """<?xml version="1.0"?>
<IOC>
  <Indicator id="ioc-1" severity="high">
    <Title>Malicious File</Title>
    <Description>Detects a known malware hash</Description>
  </Indicator>
  <Indicator id="ioc-2" severity="medium">
    <Description>No Title Here</Description>
  </Indicator>
</IOC>"""

    def test_parse_valid(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "ioc.xml"
        f.write_text(self.IOC_XML, encoding="utf-8")
        result = importer.import_openioc(f)
        assert result.source_format == "openioc"
        assert result.total_imported == 2
        assert result.findings[0].title == "Malicious File"
        assert result.findings[1].title == ""  # No Title element, indicator description used

    def test_file_not_found(self, importer: SecurityImporter) -> None:
        result = importer.import_openioc("/nonexistent/ioc.xml")
        assert result.total_imported == 0
        assert "File not found" in result.errors[0]

    def test_parse_error(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "bad_ioc.xml"
        f.write_text("invalid", encoding="utf-8")
        result = importer.import_openioc(f)
        assert result.total_imported == 0
        assert "OpenIOC parse error" in result.errors[0]


# ── Auto Import ────────────────────────────────────────────────────────

class TestAutoImport:
    def test_file_not_found(self, importer: SecurityImporter) -> None:
        result = importer.auto_import("/nonexistent/file")
        assert result.source_format == "unknown"
        assert "File not found" in result.errors[0]

    def test_detect_nessus_by_extension(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "scan.nessus"
        f.write_text("<NessusClientData_v2><Report><ReportHost name='x'><ReportItem port='80' severity='0' protocol='tcp' pluginID='1'/></ReportHost></Report></NessusClientData_v2>", encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "nessus"

    def test_detect_burp_by_name(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "burp_report.xml"
        f.write_text("<?xml version='1.0'?><issues><issue><name>T</name><severity>info</severity><port>80</port></issue></issues>", encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "burp"

    def test_detect_metasploit_by_name(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "msf_export.json"
        f.write_text(json.dumps([{"address": "10.0.0.1", "vulns": [{"name": "Test"}]}]), encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "metasploit"

    def test_detect_stix_by_name(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "stix_report.json"
        f.write_text(json.dumps({"objects": [{"type": "vulnerability", "name": "CVE-1"}]}), encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "stix"

    def test_detect_openioc_by_name(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "ioc_indicators.xml"
        f.write_text("<?xml version='1.0'?><IOC><Indicator id='1'><Title>T</Title></Indicator></IOC>", encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "openioc"

    def test_detect_nessus_by_xml_pattern(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "some_nessus_output.xml"
        f.write_text("<NessusClientData_v2><Report><ReportHost name='x'><ReportItem port='80' severity='0' protocol='tcp' pluginID='1'/></ReportHost></Report></NessusClientData_v2>", encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "nessus"

    def test_detect_json_fallback(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "unknown.json"
        f.write_text(json.dumps([{"address": "10.0.0.1", "vulns": [{"name": "Test"}]}]), encoding="utf-8")
        result = importer.auto_import(f)
        assert result.source_format == "metasploit"

    def test_last_resort_try_all(self, importer: SecurityImporter, tmp_path: Path) -> None:
        f = tmp_path / "unknown.txt"
        f.write_text("random content", encoding="utf-8")
        result = importer.auto_import(f)
        assert result.total_imported == 0


# ── to_siyarix_findings ────────────────────────────────────────────────

class TestToSiyarixFindings:
    def test_conversion(self, importer: SecurityImporter) -> None:
        result = ImportResult(findings=[
            ImportedFinding(source="nessus", title="Test Finding", severity="high", cve="CVE-2024-0001", host="10.0.0.1", port=443),
        ])
        converted = importer.to_siyarix_findings(result)
        assert len(converted) == 1
        assert converted[0]["source"] == "nessus"
        assert converted[0]["title"] == "Test Finding"
        assert converted[0]["severity"] == "high"

    def test_empty(self, importer: SecurityImporter) -> None:
        result = ImportResult()
        assert importer.to_siyarix_findings(result) == []


# ── Singleton ──────────────────────────────────────────────────────────

def test_singleton_exists() -> None:
    assert security_importer is not None
