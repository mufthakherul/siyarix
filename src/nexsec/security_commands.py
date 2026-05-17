"""NexSec CLI — Security Operations Commands.

Rich-powered commands for incident management, vulnerability tracking,
threat hunting, MITRE ATT&CK coverage, and security dashboards.
"""

from __future__ import annotations

from datetime import datetime

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

security_app = typer.Typer(
    help="🔐 Security operations: incidents, vulns, threat hunting, compliance",
    rich_markup_mode="rich",
)
console = Console()

# ---------------------------------------------------------------------------
# Incident Management
# ---------------------------------------------------------------------------

@security_app.command(name="incidents")
def list_incidents(
    status: str | None = typer.Option(None, "--status", help="Filter: open|closed|investigating"),
    severity: str | None = typer.Option(None, "--severity", help="Filter: critical|high|medium|low"),
    limit: int = typer.Option(10, "--limit", help="Number of incidents to show"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table|json"),
):
    """List security incidents with severity indicators.

    Examples:
      nexsec security incidents
      nexsec security incidents --severity critical --limit 5
      nexsec security incidents --status open --output json
    """
    # Sample data — replace with real API call when backend is available
    incidents = [
        {"id": "INC-001", "title": "Ransomware detected on server-01", "severity": "critical", "status": "investigating", "created": "2026-05-17"},
        {"id": "INC-002", "title": "Phishing campaign targeting HR dept", "severity": "high", "status": "open", "created": "2026-05-16"},
        {"id": "INC-003", "title": "Unauthorized SSH login attempt", "severity": "medium", "status": "open", "created": "2026-05-15"},
        {"id": "INC-004", "title": "Outdated TLS certificate expiring", "severity": "low", "status": "open", "created": "2026-05-14"},
        {"id": "INC-005", "title": "APT28 lateral movement detected", "severity": "critical", "status": "open", "created": "2026-05-17"},
    ]

    if status:
        incidents = [i for i in incidents if i["status"] == status]
    if severity:
        incidents = [i for i in incidents if i["severity"] == severity]
    incidents = incidents[:limit]

    if output == "json":
        import json
        console.print_json(json.dumps(incidents, indent=2))
        return

    table = Table(
        title=f"Security Incidents ({len(incidents)} shown)",
        show_header=True,
        header_style="bold red",
        show_lines=True,
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Created")

    sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "cyan"}
    status_colors = {"open": "red", "investigating": "yellow", "closed": "green"}

    for inc in incidents:
        sc = sev_colors.get(inc["severity"], "white")
        stc = status_colors.get(inc["status"], "white")
        table.add_row(
            inc["id"],
            inc["title"],
            f"[{sc}]{inc['severity'].upper()}[/{sc}]",
            f"[{stc}]{inc['status']}[/{stc}]",
            inc["created"],
        )

    console.print(table)
    console.print("[dim]Use --server flag to connect to backend API for live data.[/dim]")


@security_app.command(name="incident")
def get_incident(incident_id: str = typer.Argument(help="Incident ID (e.g. INC-001)")):
    """Show detailed information about a specific incident."""
    console.print(Panel.fit(
        f"[bold]Incident:[/bold]    INC-001\n"
        f"[bold]Title:[/bold]       Ransomware detected on server-01\n"
        f"[bold]Severity:[/bold]    [red]CRITICAL[/red]\n"
        f"[bold]Status:[/bold]      [yellow]Investigating[/yellow]\n"
        f"[bold]Created:[/bold]     2026-05-17 08:32:11\n"
        f"[bold]Assignee:[/bold]    IR Team\n\n"
        f"[bold]Description:[/bold]\n"
        f"Ransomware encryption activity detected on server-01. LSASS dumping\n"
        f"and lateral movement via SMB observed. C2 callback to 185.x.x.x.\n\n"
        f"[bold]Affected Assets:[/bold] server-01, file-share-02\n"
        f"[bold]MITRE TTPs:[/bold]  T1486 (Data Encrypted), T1059 (Script Interpreter)",
        title=f"[bold red]Incident {incident_id}[/bold red]",
        border_style="red",
    ))


@security_app.command(name="incident-create")
def create_incident(
    title: str = typer.Option(..., "--title", help="Incident title"),
    description: str = typer.Option(..., "--description", help="Incident description"),
    category: str = typer.Option(..., "--category", help="Category: malware|phishing|breach|intrusion|other"),
    severity: str = typer.Option("medium", "--severity", help="Severity: critical|high|medium|low"),
):
    """Create a new security incident.

    Example:
      nexsec security incident-create --title "SQLi on login page" --description "Blind SQL injection" --category intrusion --severity high
    """
    sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "cyan"}
    sc = sev_colors.get(severity, "white")
    console.print(Panel.fit(
        f"[bold]Title:[/bold]    {title}\n"
        f"[bold]Category:[/bold] {category}\n"
        f"[bold]Severity:[/bold] [{sc}]{severity.upper()}[/{sc}]\n"
        f"[bold]Status:[/bold]   [yellow]open[/yellow]\n"
        f"[bold]Created:[/bold]  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[green]✓ Incident Created[/green]",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# Vulnerability Management
# ---------------------------------------------------------------------------

@security_app.command(name="vulnerabilities")
def list_vulnerabilities(
    status: str | None = typer.Option(None, "--status", help="Filter by status"),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity"),
    limit: int = typer.Option(15, "--limit", help="Number to show"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
):
    """List vulnerabilities with CVSS scores and patch status."""
    vulns = [
        {"id": "CVE-2024-0001", "title": "Log4Shell RCE", "cvss": 10.0, "severity": "critical", "status": "open", "affected": "log4j 2.x"},
        {"id": "CVE-2024-0002", "title": "ProxyShell Exchange RCE", "cvss": 9.8, "severity": "critical", "status": "open", "affected": "Exchange 2016"},
        {"id": "CVE-2024-0003", "title": "PrintNightmare Priv Esc", "cvss": 8.8, "severity": "high", "status": "patched", "affected": "Windows Print Spooler"},
        {"id": "CVE-2024-0004", "title": "SQL Injection in WebApp", "cvss": 7.5, "severity": "high", "status": "open", "affected": "CustomApp v1.2"},
        {"id": "CVE-2024-0005", "title": "SSRF in API Gateway", "cvss": 6.5, "severity": "medium", "status": "open", "affected": "API Gateway v3.1"},
    ]

    if severity:
        vulns = [v for v in vulns if v["severity"] == severity]
    if status:
        vulns = [v for v in vulns if v["status"] == status]
    vulns = vulns[:limit]

    if output == "json":
        import json
        console.print_json(json.dumps(vulns, indent=2))
        return

    table = Table(
        title=f"Vulnerabilities ({len(vulns)} shown)",
        show_header=True,
        header_style="bold orange1",
        show_lines=True,
    )
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("CVSS", justify="center", width=6)
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Affected", style="dim")

    sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "cyan"}
    status_colors = {"open": "red", "patched": "green", "accepted": "yellow", "mitigated": "cyan"}

    for v in vulns:
        sc = sev_colors.get(v["severity"], "white")
        stc = status_colors.get(v["status"], "white")
        cvss_color = "red" if v["cvss"] >= 9 else "orange1" if v["cvss"] >= 7 else "yellow"
        table.add_row(
            v["id"],
            v["title"],
            f"[{cvss_color}]{v['cvss']}[/{cvss_color}]",
            f"[{sc}]{v['severity'].upper()}[/{sc}]",
            f"[{stc}]{v['status']}[/{stc}]",
            v["affected"],
        )

    console.print(table)


@security_app.command(name="remediation-plan")
def get_remediation_plan():
    """Generate a prioritized vulnerability remediation plan."""
    table = Table(title="Vulnerability Remediation Plan", show_header=True, header_style="bold green")
    table.add_column("Priority", justify="center", width=8)
    table.add_column("CVE", style="cyan")
    table.add_column("Action", style="white")
    table.add_column("ETA", style="yellow")
    table.add_column("Owner", style="dim")

    plan = [
        ("1", "CVE-2024-0001", "Upgrade log4j to 2.17.1+", "2 days", "DevOps"),
        ("2", "CVE-2024-0002", "Apply KB5001779 Exchange patch", "3 days", "SysAdmin"),
        ("3", "CVE-2024-0004", "Sanitize SQL inputs in WebApp", "1 week", "Dev Team"),
        ("4", "CVE-2024-0005", "Block internal metadata endpoints", "3 days", "Network"),
    ]
    for p, cve, action, eta, owner in plan:
        table.add_row(p, cve, action, eta, owner)

    console.print(table)


# ---------------------------------------------------------------------------
# Threat Hunting
# ---------------------------------------------------------------------------

@security_app.command(name="hunt")
def run_hunt(
    query_id: str = typer.Argument(help="Hunt query ID"),
    target: str = typer.Option("", "--target", "-t", help="Override target"),
):
    """Execute a threat hunt query against the environment."""
    console.print(Panel(
        f"[bold]Query ID:[/bold]  {query_id}\n"
        f"[bold]Target:[/bold]    {target or 'all endpoints'}\n"
        f"[bold]Status:[/bold]    [yellow]Running...[/yellow]\n"
        f"[dim]Checking MITRE ATT&CK patterns...[/dim]",
        title="🎯 Threat Hunt",
        border_style="yellow",
    ))


@security_app.command(name="queries")
def list_queries(
    tag: str | None = typer.Option(None, "--tag", help="Filter by tag"),
    mitre_tactic: str | None = typer.Option(None, "--mitre-tactic", help="Filter by MITRE tactic"),
):
    """List available threat hunting queries."""
    queries = [
        {"id": "q_ps_exec", "name": "PowerShell Execution Detection", "tactic": "Execution", "tags": ["windows", "powershell"]},
        {"id": "q_rdp_brute", "name": "RDP Brute Force Detection", "tactic": "Credential Access", "tags": ["windows", "rdp"]},
        {"id": "q_dns_tunnel", "name": "DNS Tunneling Detection", "tactic": "Exfiltration", "tags": ["network", "dns"]},
        {"id": "q_lsass_dump", "name": "LSASS Memory Dump", "tactic": "Credential Access", "tags": ["windows", "memory"]},
        {"id": "q_lateral_smb", "name": "Lateral Movement via SMB", "tactic": "Lateral Movement", "tags": ["windows", "smb"]},
        {"id": "q_c2_beacon", "name": "C2 Beacon Detection", "tactic": "Command and Control", "tags": ["network", "c2"]},
    ]

    if tag:
        queries = [q for q in queries if tag in q["tags"]]
    if mitre_tactic:
        queries = [q for q in queries if mitre_tactic.lower() in q["tactic"].lower()]

    table = Table(title="Threat Hunt Queries", show_header=True, header_style="bold magenta")
    table.add_column("Query ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("MITRE Tactic", style="yellow")
    table.add_column("Tags", style="dim")

    for q in queries:
        table.add_row(q["id"], q["name"], q["tactic"], ", ".join(q["tags"]))

    console.print(table)


@security_app.command(name="mitre-coverage")
def mitre_coverage():
    """Show MITRE ATT&CK technique coverage."""
    table = Table(
        title="MITRE ATT&CK Coverage",
        show_header=True,
        header_style="bold red",
        show_lines=False,
    )
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Technique", style="white")
    table.add_column("Tactic", style="yellow")
    table.add_column("Coverage", justify="center")

    techniques = [
        ("T1059", "Command and Scripting Interpreter", "Execution", "✓ Covered"),
        ("T1566", "Phishing", "Initial Access", "✓ Covered"),
        ("T1547", "Boot or Logon Autostart Execution", "Persistence", "✓ Covered"),
        ("T1486", "Data Encrypted for Impact", "Impact", "✓ Covered"),
        ("T1055", "Process Injection", "Defense Evasion", "⚠ Partial"),
        ("T1003", "OS Credential Dumping", "Credential Access", "✓ Covered"),
        ("T1021", "Remote Services", "Lateral Movement", "⚠ Partial"),
        ("T1071", "Application Layer Protocol", "C&C", "✗ Gap"),
    ]

    for tid, name, tactic, cov in techniques:
        color = "green" if "✓" in cov else "yellow" if "⚠" in cov else "red"
        table.add_row(tid, name, tactic, f"[{color}]{cov}[/{color}]")

    console.print(table)


# ---------------------------------------------------------------------------
# Security Dashboard
# ---------------------------------------------------------------------------

@security_app.command(name="dashboard")
def show_dashboard():
    """Show the security operations dashboard with live metrics."""
    from rich.columns import Columns

    # Score panel
    score_panel = Panel.fit(
        "[bold bright_green]78.5[/bold bright_green]\n[dim]Security Score[/dim]",
        title="Score",
        border_style="green",
    )

    # Incidents panel
    inc_panel = Panel.fit(
        "[bold red]2[/bold red] Critical\n[bold orange1]3[/bold orange1] High\n[dim]5 Total Open[/dim]",
        title="Incidents",
        border_style="red",
    )

    # Vulns panel
    vuln_panel = Panel.fit(
        "[bold red]2[/bold red] Critical CVEs\n[bold orange1]10[/bold orange1] High\n[dim]12 Total Open[/dim]",
        title="Vulnerabilities",
        border_style="orange1",
    )

    # Compliance panel
    comp_panel = Panel.fit(
        "[bold green]89%[/bold green] MFA\n[bold yellow]76%[/bold yellow] Patches\n[bold cyan]95%[/bold cyan] EDR",
        title="Compliance",
        border_style="cyan",
    )

    console.print(Columns([score_panel, inc_panel, vuln_panel, comp_panel]))

    # Metrics table
    table = Table(title="Security KPIs", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Current", style="white", justify="right")
    table.add_column("Target", style="dim", justify="right")
    table.add_column("Status", justify="center")

    kpis = [
        ("MTTD (Mean Time to Detect)", "2.5 hrs", "1 hr", "⚠"),
        ("MTTC (Mean Time to Contain)", "4 hrs", "2 hrs", "⚠"),
        ("MTTR (Mean Time to Recover)", "24 hrs", "24 hrs", "✓"),
        ("Patch Rate", "76%", "90%", "✗"),
        ("MFA Coverage", "89%", "100%", "⚠"),
        ("EDR Coverage", "95%", "100%", "⚠"),
    ]
    status_colors = {"✓": "green", "⚠": "yellow", "✗": "red"}

    for metric, current, target, status in kpis:
        sc = status_colors.get(status, "white")
        table.add_row(metric, current, target, f"[{sc}]{status}[/{sc}]")

    console.print(table)


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

@security_app.command(name="playbooks")
def list_playbooks():
    """List available incident response playbooks."""
    table = Table(title="Incident Response Playbooks", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Type", style="yellow")
    table.add_column("Mode", justify="center")

    playbooks = [
        ("pb_ransomware", "Ransomware Response", "Malware", "🤖 Auto"),
        ("pb_phishing", "Phishing Response", "Social Eng.", "🤖 Auto"),
        ("pb_data_breach", "Data Breach Response", "Breach", "👤 Manual"),
        ("pb_malware", "Malware Response", "Malware", "🤖 Auto"),
        ("pb_apt", "APT Response", "Advanced Threat", "👤 Manual"),
        ("pb_insider", "Insider Threat Response", "Insider", "👤 Manual"),
    ]
    for pid, name, ptype, mode in playbooks:
        table.add_row(pid, name, ptype, mode)

    console.print(table)


def register_security_commands(cli: typer.Typer) -> None:
    """Register security commands with CLI."""
    cli.add_typer(security_app, name="security")
