# 📥 Finding Import Pipeline

Security teams use a lot of different tools. Siyarix wants to be your central hub! The Finding Import Pipeline will allow you to ingest scan results from external security tools, translating them into a single, unified format for easy analysis and reporting.

> [!WARNING]
> **Coming Soon**: This feature is actively being built! An initial `SecurityImporter` stub exists in the codebase, and we are working hard on the parsing, format detection, and conversion logic.

---

## 🚧 Current Status

Right now, the `SecurityImporter` is acting as a placeholder. It accepts file paths but does not yet process the data.

```python
from siyarix.chat.stubs import SecurityImporter

importer = SecurityImporter()

# This is a stub! It currently returns a result with 0 imported items.
result = importer.auto_import("scan.nessus")
```

---

## 🔮 Planned Capabilities

We want to support all your favorite tools! Here is what is on the roadmap for the import pipeline:

| Format | File Extension | Source Tool |
|--------|---------------|-------------|
| **Nessus** | `.nessus` | Tenable Nessus (XML) |
| **Burp Suite** | `.xml` | Burp Suite Project Exports |
| **Metasploit** | `.json` | Metasploit Database Exports |
| **STIX 2.x** | `.json` | Standard Threat Intelligence Feeds |
| **OpenIOC** | `.ioc` | Mandiant OpenIOC |
| **Nikto** | `.json` / `.xml` | Nikto Web Scanners |
| **Nuclei** | `.json` | ProjectDiscovery Nuclei |
| **Trivy** | `.json` | Aqua Security Trivy |

### ⚙️ How the Pipeline Will Work

When complete, the pipeline will do the heavy lifting for you:

1. **Auto-Detection**: Siyarix will automatically figure out what tool generated the file by analyzing its extension and content.
2. **Unified Format Translation**: All findings will be converted into Siyarix's standard format, normalizing Severity, CVE, CWE, and CVSS scores.
3. **Smart Deduplication**: If multiple tools find the same vulnerability, Siyarix will merge them so your reports aren't cluttered.
4. **Cross-Source Correlation**: Siyarix will enrich findings by combining data from multiple tools to give you the full picture.

---

## 🎯 Key Use Cases

Why use the import pipeline?

- **Migration**: Easily move your historical security data from legacy tools straight into Siyarix.
- **Consolidation**: Stop jumping between 5 different dashboards. View all your vulnerabilities in one place!
- **Correlation**: Cross-reference vulnerabilities found by an external scanner with data gathered natively by Siyarix.
- **Beautiful Reporting**: Generate unified, professional reports that combine findings from every tool in your arsenal.

---

## 📣 Stay Tuned!

We know how important interoperability is. The import pipeline is under active development. Keep an eye on the project repository for updates on when new formats will be supported!
