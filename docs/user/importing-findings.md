# Importing Findings

Siyarix can import scan results from external security tools into its unified finding format.

## Supported formats

| Format | File extension | Source |
|--------|---------------|--------|
| Nessus | `.nessus` | Tenable Nessus XML |
| Burp Suite | `.xml` | Burp Suite project XML |
| Metasploit | `.json` | Metasploit DB export |
| STIX 2.x | `.json` | Threat intelligence feeds |
| OpenIOC | `.ioc` | Mandiant OpenIOC |

## Usage

```bash
# Auto-detect format from file
siyarix run "import findings from nessus_scan.nessus"
siyarix run "import results from burp_report.xml"
siyarix run "import metasploit findings from msf_export.json"
siyarix run "import threat intel from stix_feed.json"
```

## How it works

The `SecurityImporter` auto-detects the format based on:

1. **File extension**: `.nessus` → Nessus, `.ioc` → OpenIOC
2. **Content analysis**: XML root element, JSON structure
3. **Magic bytes**: STIX requires `"type": "indicator"` or `"type": "observed-data"`

### Parsing pipeline

```python
importer = SecurityImporter()
result = importer.import_file("scan.nessus")
# Returns: ImportResult with unified ImportedFinding objects
```

## Unified finding format

All imports are converted to this standard format:

```python
@dataclass
class ImportedFinding:
    source: str        # "nessus", "burp", "metasploit", "stix", "openioc"
    original_id: str   # Original finding ID from source
    title: str         # Finding title
    severity: str      # critical, high, medium, low, info
    cve: str           # CVE identifier (if applicable)
    cwe: str           # CWE identifier (if applicable)
    cvss_score: float  # CVSS score (if available)
    host: str          # Affected host
    port: int          # Affected port
    remediation: str   # Fix recommendation
```

## Use cases

- **Migration**: Import results from legacy tools into Siyarix
- **Consolidation**: Combine findings from multiple scanners into one report
- **Correlation**: Cross-reference external findings with Siyarix scans
- **Reporting**: Generate unified reports from mixed tool sources

## Verification

```bash
# After import, view findings
siyarix report generate --format json
```

Imported findings are stored in the offline store and knowledge graph alongside native scan results.
