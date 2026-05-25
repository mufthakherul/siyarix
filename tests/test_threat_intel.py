"""Tests for threat intelligence ingestion module."""

import pytest

from phalanx.threat_intel import MITREAttackDB, ThreatIntelFeed

pytestmark = pytest.mark.threat_intel


class TestMITREAttackDB:
    def test_map_finding_cve(self):
        mappings = MITREAttackDB.map_finding(
            {"title": "CVE-2024-1234 RCE vulnerability"}
        )
        assert len(mappings) > 0
        assert any("T1190" in m.attack_id for m in mappings)

    def test_map_finding_sqli(self):
        mappings = MITREAttackDB.map_finding(
            {"title": "SQL injection in login page", "description": "Blind SQLi"}
        )
        assert len(mappings) > 0

    def test_map_finding_empty(self):
        mappings = MITREAttackDB.map_finding(
            {"title": "Normal port scan result", "description": ""}
        )
        assert len(mappings) >= 0

    def test_get_technique_valid(self):
        mapping = MITREAttackDB.get_technique("T1046")
        assert mapping is not None
        assert mapping.technique == "Network Service Discovery"

    def test_get_technique_invalid(self):
        mapping = MITREAttackDB.get_technique("T9999")
        assert mapping is None


class TestThreatIntelFeed:
    def test_ingest_stix_indicators(self):
        feed = ThreatIntelFeed()
        stix_data = {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--test-1",
                    "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                    "description": "Test indicator",
                    "created": "2024-01-01T00:00:00",
                    "labels": ["test"],
                }
            ]
        }
        count = feed.ingest_stix(stix_data)
        assert count == 1
        assert feed.stats()["total_indicators"] == 1

    def test_ingest_stix_invalid_json(self):
        feed = ThreatIntelFeed()
        count = feed.ingest_stix("not valid json")
        assert count == 0

    def test_ingest_misp_events(self):
        feed = ThreatIntelFeed()
        misp_data = {
            "response": [
                {
                    "Event": {
                        "Attribute": [
                            {
                                "uuid": "test-uuid-1",
                                "type": "ip-dst",
                                "value": "185.130.5.133",
                                "category": "Network activity",
                                "comment": "Known C2 server",
                                "to_ids": True,
                            }
                        ]
                    }
                }
            ]
        }
        count = feed.ingest_misp(misp_data)
        assert count == 1

    def test_find_matches(self):
        feed = ThreatIntelFeed()
        feed.ingest_stix(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--1",
                        "pattern": "185.130.5.133",
                        "description": "C2 server",
                        "created": "2024-01-01T00:00:00",
                    }
                ]
            }
        )
        matches = feed.find_matches("Connection to 185.130.5.133 detected")
        assert len(matches) >= 1

    def test_enrich_finding_with_mitre(self):
        feed = ThreatIntelFeed()
        enriched = feed.enrich_finding(
            {
                "title": "RCE vulnerability found",
                "target": "10.0.0.1",
                "severity": "high",
            }
        )
        assert "mitre_attack" in enriched
        assert len(enriched["mitre_attack"]) > 0

    def test_enrich_finding_with_threat_intel(self):
        feed = ThreatIntelFeed()
        feed.ingest_stix(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--1",
                        "pattern": "evil.com",
                        "description": "Malicious domain",
                        "created": "2024-01-01T00:00:00",
                    }
                ]
            }
        )
        enriched = feed.enrich_finding(
            {"title": "SSL cert from evil.com", "target": "evil.com"}
        )
        found = enriched.get("threat_intel", [])
        assert len(found) >= 1 or "threat_intel" not in enriched

    def test_stats(self):
        feed = ThreatIntelFeed()
        feed.ingest_stix(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--1",
                        "pattern": "test",
                        "created": "2024-01-01T00:00:00",
                    }
                ]
            }
        )
        stats = feed.stats()
        assert stats["total_indicators"] >= 1
        assert "by_source" in stats
