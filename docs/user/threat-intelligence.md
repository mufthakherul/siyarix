# Threat Intelligence

Siyarix can enrich targets with a small set of **live** lookups and a larger set of **offline** catalogs. This page describes what actually ships today — not a roadmap of unimplemented feeds.

---

## Active integrations (live network)

### AlienVault OTX

IPv4 reputation lookup against the Open Threat Exchange API.

```python
from siyarix.threat_intel import AlienVaultOTX

otx = AlienVaultOTX()
result = await otx.lookup_ip("8.8.8.8")
# Returns: pulse_count, reputation, source (or error)
```

Set `ALIENVAULT_API_KEY` for authenticated requests. Lookups are IPv4-only.

### National Vulnerability Database (NVD)

CVE details via the NVD API 2.0.

```python
from siyarix.threat_intel import NVDDatabase

nvd = NVDDatabase()
result = await nvd.lookup_cve("CVE-2021-44228")
# Returns: description, base_score (CVSS v3.1 when present), source
```

### ThreatIntelManager facade

Routes a single target string to OTX (IP) or NVD (CVE-…).

```python
from siyarix.threat_intel import ThreatIntelManager

manager = ThreatIntelManager()
await manager.analyze_target("8.8.8.8")       # → OTX
await manager.analyze_target("CVE-2021-44228")  # → NVD
```

---

## Offline catalogs (no network)

### MITRE ATT&CK (`MITREAttackDB`)

A curated offline subset of Enterprise tactics and techniques, plus keyword `map_finding()` helpers for correlating text to technique IDs.

```python
from siyarix.threat_intel import MITREAttackDB

db = MITREAttackDB()
db.query_technique("T1059")
db.search("phishing")
db.map_finding("PowerShell encoded command execution")
```

### Offline CVE cache (`ThreatIntelFeed`)

`ThreatIntelFeed.query_cve()` / `search()` hit a small built-in `KNOWN_CVES` table (e.g. Log4Shell, MOVEit). This is **not** a full NVD mirror.

`list_feeds()` also advertises **CISA KEV** with status `planned` — Siyarix does **not** download the KEV catalog yet. Treat KEV as roadmap only; use the offline CVE cache or live NVD for vulnerability data.

---

## CLI: MITRE reference map

```bash
siyarix security mitre-coverage
```

This command lists the offline `MITREAttackDB` catalog and marks techniques **Referenced** when a local hunt query technique ID or keyword-mapped incident/vulnerability text mentions them.

It is **not** a measured defensive-coverage report. It never claims “Covered / Partial / Gap” for detections or controls you have not deployed.

---

## Planned (not implemented in this module)

These are roadmap items only — do not expect working APIs yet:

- Live **CISA KEV** fetch
- **MISP** feed ingestion
- **STIX 2.x** / OpenIOC import
- Knowledge-graph linking of indicators to scan findings

---

## What you can do today

- Check IPv4 reputation via AlienVault OTX
- Pull CVE description / CVSS from NVD
- Look up or search offline MITRE techniques and map finding text to technique IDs
- Query the small offline CVE cache without network access
- Inspect which offline techniques are referenced by local hunt queries / mapped findings (`mitre-coverage`)
