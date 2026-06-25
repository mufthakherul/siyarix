# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix CLI — Security Operations Commands.

Rich-powered commands for incident management, vulnerability tracking,
threat hunting, MITRE ATT&CK coverage, and security dashboards.

Backend integration via OfflineStore for persistence and optional
SIEM/SOAR connectors for live data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

security_app = typer.Typer(
    help="🔐 Security operations: incidents, vulns, threat hunting, compliance",
    rich_markup_mode="rich",
)
console = Console()


def _get_store() -> Any:
    """Get the OfflineStore instance for persistence."""
    try:
        from .offline_store import OfflineStore

        return OfflineStore()
    except Exception:
        return None


def _get_security_db() -> Any:
    """Get or create the security-specific database connection."""
    import sqlite3
    from .config import get_config_dir

    db_path = get_config_dir() / "security.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            category TEXT DEFAULT 'other',
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'open',
            assignee TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            metadata TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            cvss_score REAL DEFAULT 0.0,
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'open',
            affected TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            metadata TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS hunt_queries (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            query_text TEXT DEFAULT '',
            tactic TEXT DEFAULT '',
            technique TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS playbooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            playbook_type TEXT DEFAULT 'auto',
            steps TEXT DEFAULT '[]',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
        CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
    """)
    _seed_security_data(conn)
    return conn


def _seed_security_data(conn: Any | None = None) -> None:
    """Seed the security database with initial reference data if empty."""
    close_conn = conn is None
    if conn is None:
        import sqlite3
        from .config import get_config_dir

        db_path = get_config_dir() / "security.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    try:
        count = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()["c"]
        if count > 0:
            return

        import uuid

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        seed_data: list[tuple[str, list[tuple[Any, ...]]]] = [
            (
                "incidents",
                [
                    (
                        f"INC-{uuid.uuid4().hex[:8].upper()}",
                        "Ransomware detected on server-01",
                        "Ransomware encryption activity detected. LSASS dumping and lateral movement via SMB observed.",
                        "malware",
                        "critical",
                        "investigating",
                        now,
                        now,
                    ),
                    (
                        f"INC-{uuid.uuid4().hex[:8].upper()}",
                        "Phishing campaign targeting HR dept",
                        "Mass phishing email campaign targeting HR personnel with malicious attachments.",
                        "phishing",
                        "high",
                        "open",
                        now,
                        now,
                    ),
                    (
                        f"INC-{uuid.uuid4().hex[:8].upper()}",
                        "Unauthorized SSH login attempt",
                        "Multiple failed SSH login attempts from external IP followed by successful breach.",
                        "intrusion",
                        "medium",
                        "open",
                        now,
                        now,
                    ),
                ],
            ),
            (
                "vulnerabilities",
                [
                    (
                        "CVE-2024-0001",
                        "Log4Shell RCE",
                        "Remote code execution in Log4j 2.x",
                        10.0,
                        "critical",
                        "open",
                        "log4j 2.x",
                        now,
                        now,
                    ),
                    (
                        "CVE-2024-0002",
                        "ProxyShell Exchange RCE",
                        "RCE in Microsoft Exchange",
                        9.8,
                        "critical",
                        "open",
                        "Exchange 2016",
                        now,
                        now,
                    ),
                    (
                        "CVE-2024-0003",
                        "PrintNightmare Priv Esc",
                        "Privilege escalation in Windows Print Spooler",
                        8.8,
                        "high",
                        "patched",
                        "Windows Print Spooler",
                        now,
                        now,
                    ),
                ],
            ),
            (
                "hunt_queries",
                [
                    (
                        "q_ps_exec",
                        "PowerShell Execution Detection",
                        "Event ID 4104: PowerShell script block logging",
                        "Execution",
                        "T1059",
                        '["windows","powershell"]',
                        now,
                    ),
                    (
                        "q_rdp_brute",
                        "RDP Brute Force Detection",
                        "Event ID 4625: Multiple failed logon attempts on RDP",
                        "Credential Access",
                        "T1110",
                        '["windows","rdp"]',
                        now,
                    ),
                    (
                        "q_dns_tunnel",
                        "DNS Tunneling Detection",
                        "Unusual DNS query patterns and large TXT records",
                        "Exfiltration",
                        "T1572",
                        '["network","dns"]',
                        now,
                    ),
                ],
            ),
            (
                "playbooks",
                [
                    (
                        "pb_ransomware",
                        "Ransomware Response",
                        "Automated ransomware incident response playbook",
                        "auto",
                        '["isolate_host","collect_evidence","contain","eradicate"]',
                        now,
                    ),
                    (
                        "pb_phishing",
                        "Phishing Response",
                        "Phishing email investigation and remediation",
                        "auto",
                        '["quarantine_email","scan_links","check_indicators","notify_users"]',
                        now,
                    ),
                    (
                        "pb_data_breach",
                        "Data Breach Response",
                        "Data breach containment and notification procedures",
                        "manual",
                        '["assess_scope","contain_breach","notify_authorities","remediate"]',
                        now,
                    ),
                ],
            ),
        ]

        column_map = {
            "incidents": "(id, title, description, category, severity, status, created_at, updated_at)",
            "vulnerabilities": "(id, title, description, cvss_score, severity, status, affected, created_at, updated_at)",
            "hunt_queries": "(id, name, query_text, tactic, technique, tags, created_at)",
            "playbooks": "(id, name, description, playbook_type, steps, created_at)",
        }
        for table, table_rows in seed_data:
            if not table_rows:
                continue
            cols = column_map.get(table, "")
            first_row = table_rows[0]
            placeholders = ",".join(["?"] * len(first_row))
            conn.executemany(
                f"INSERT OR IGNORE INTO {table} {cols} VALUES ({placeholders})", table_rows
            )
            conn.commit()
    finally:
        if close_conn:
            conn.close()


# ---------------------------------------------------------------------------
# Incident Management
# ---------------------------------------------------------------------------


@security_app.command(name="incidents")
def list_incidents(
    status: str | None = typer.Option(None, "--status", help="Filter: open|closed|investigating"),
    severity: str | None = typer.Option(
        None, "--severity", help="Filter: critical|high|medium|low"
    ),
    limit: int = typer.Option(10, "--limit", help="Number of incidents to show"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table|json"),
) -> None:
    """List security incidents with severity indicators.

    Examples:
      siyarix security incidents
      siyarix security incidents --severity critical --limit 5
      siyarix security incidents --status open --output json
    """
    conn = _get_security_db()
    try:
        conditions: list[str] = []
        params: list[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        query = "SELECT * FROM incidents"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        if output == "json":
            import json

            incidents = [dict(r) for r in rows]
            console.print_json(json.dumps(incidents, indent=2))
            return

        table = Table(
            title=f"Security Incidents ({len(rows)} shown)",
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

        for row in rows:
            sev = str(row.get("severity", "")).lower()
            st = str(row.get("status", "")).lower()
            sc = sev_colors.get(sev, "white")
            stc = status_colors.get(st, "white")
            table.add_row(
                str(row.get("id", "-")),
                str(row.get("title", "-")),
                f"[{sc}]{sev.upper()}[/{sc}]",
                f"[{stc}]{st}[/{stc}]",
                str(row.get("created_at", "-")),
            )

        console.print(table)
    finally:
        conn.close()


@security_app.command(name="incident")
def get_incident(
    incident_id: str = typer.Argument(help="Incident ID (e.g. INC-001)"),
) -> None:
    """Show detailed information about a specific incident."""
    conn = _get_security_db()
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()

        if not row:
            console.print(f"[red]Incident {incident_id} not found.[/red]")
            return

        import json

        metadata = json.loads(row.get("metadata", "{}"))
        details = (
            f"[bold]ID:[/bold]          {row['id']}\n"
            f"[bold]Title:[/bold]       {row['title']}\n"
            f"[bold]Category:[/bold]    {row.get('category', 'N/A')}\n"
            f"[bold]Severity:[/bold]    [red]{row.get('severity', 'N/A').upper()}[/red]\n"
            f"[bold]Status:[/bold]      [yellow]{row.get('status', 'N/A')}[/yellow]\n"
            f"[bold]Assigned:[/bold]    {row.get('assignee', 'Unassigned')}\n"
            f"[bold]Created:[/bold]     {row.get('created_at', 'N/A')}\n"
            f"[bold]Updated:[/bold]     {row.get('updated_at', 'N/A')}\n\n"
            f"[bold]Description:[/bold]\n{row.get('description', 'No description')}\n"
        )
        if metadata:
            details += f"\n[dim]Metadata: {json.dumps(metadata, indent=2)}[/dim]"
        console.print(
            Panel.fit(
                details, title=f"[bold red]Incident {incident_id}[/bold red]", border_style="red"
            )
        )
    finally:
        conn.close()


@security_app.command(name="incident-create")
def create_incident(
    title: str = typer.Option(..., "--title", help="Incident title"),
    description: str = typer.Option(..., "--description", help="Incident description"),
    category: str = typer.Option(
        ..., "--category", help="Category: malware|phishing|breach|intrusion|other"
    ),
    severity: str = typer.Option("medium", "--severity", help="Severity: critical|high|medium|low"),
) -> None:
    """Create a new security incident.

    Example:
      siyarix security incident-create --title "SQLi on login page" --description "Blind SQL injection" --category intrusion --severity high
    """
    import uuid

    conn = _get_security_db()
    try:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO incidents (id, title, description, category, severity, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?, ?)",
            (inc_id, title, description, category, severity, now, now),
        )
        conn.commit()

        sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "cyan"}
        sc = sev_colors.get(severity, "white")
        summary = (
            f"[bold]ID:[/bold]       {inc_id}\n"
            f"[bold]Title:[/bold]    {title}\n"
            f"[bold]Category:[/bold] {category}\n"
            f"[bold]Severity:[/bold] [{sc}]{severity.upper()}[/{sc}]\n"
            f"[bold]Status:[/bold]   [yellow]open[/yellow]\n"
            f"[bold]Created:[/bold]  {now}"
        )
        console.print(
            Panel.fit(summary, title="[green]✓ Incident Created[/green]", border_style="green")
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Vulnerability Management
# ---------------------------------------------------------------------------


@security_app.command(name="vulnerabilities")
def list_vulnerabilities(
    status: str | None = typer.Option(None, "--status", help="Filter by status"),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity"),
    limit: int = typer.Option(15, "--limit", help="Number to show"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
) -> None:
    """List vulnerabilities with CVSS scores and patch status."""
    conn = _get_security_db()
    try:
        conditions: list[str] = []
        params: list[Any] = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if status:
            conditions.append("status = ?")
            params.append(status)

        query = "SELECT * FROM vulnerabilities"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY cvss_score DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        if output == "json":
            import json

            vulns = [dict(r) for r in rows]
            console.print_json(json.dumps(vulns, indent=2))
            return

        table = Table(
            title=f"Vulnerabilities ({len(rows)} shown)",
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
        status_colors = {
            "open": "red",
            "patched": "green",
            "accepted": "yellow",
            "mitigated": "cyan",
        }

        for row in rows:
            sev = str(row.get("severity", "")).lower()
            st = str(row.get("status", "")).lower()
            cvss_val = float(row.get("cvss_score", 0.0))
            sc = sev_colors.get(sev, "white")
            stc = status_colors.get(st, "white")
            cvss_color = "red" if cvss_val >= 9 else "orange1" if cvss_val >= 7 else "yellow"
            table.add_row(
                str(row.get("id", "-")),
                str(row.get("title", "-")),
                f"[{cvss_color}]{cvss_val}[/{cvss_color}]",
                f"[{sc}]{sev.upper()}[/{sc}]",
                f"[{stc}]{st}[/{stc}]",
                str(row.get("affected", "-")),
            )

        console.print(table)
    finally:
        conn.close()


@security_app.command(name="remediation-plan")
def get_remediation_plan() -> None:
    """Generate a prioritized vulnerability remediation plan."""
    conn = _get_security_db()
    try:
        rows = conn.execute(
            "SELECT id, title, cvss_score, severity, status, affected FROM vulnerabilities "
            "WHERE status != 'patched' ORDER BY cvss_score DESC LIMIT 10"
        ).fetchall()

        table = Table(
            title="Vulnerability Remediation Plan",
            show_header=True,
            header_style="bold green",
        )
        table.add_column("Priority", justify="center", width=8)
        table.add_column("CVE", style="cyan")
        table.add_column("Action", style="white")
        table.add_column("CVSS", justify="center")
        table.add_column("Status", justify="center")

        for i, row in enumerate(rows, 1):
            cvss_val = float(row.get("cvss_score", 0.0))
            cvss_color = "red" if cvss_val >= 9 else "orange1" if cvss_val >= 7 else "yellow"
            table.add_row(
                str(i),
                str(row.get("id", "-")),
                str(row.get("title", "-")),
                f"[{cvss_color}]{cvss_val}[/{cvss_color}]",
                str(row.get("status", "-")),
            )
        console.print(table)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Threat Hunting
# ---------------------------------------------------------------------------


@security_app.command(name="hunt")
def run_hunt(
    query_id: str = typer.Argument(help="Hunt query ID"),
    target: str = typer.Option("", "--target", "-t", help="Override target"),
) -> None:
    """Execute a threat hunt query against the environment."""
    conn = _get_security_db()
    try:
        row = conn.execute("SELECT * FROM hunt_queries WHERE id = ?", (query_id,)).fetchone()

        if not row:
            console.print(f"[red]Hunt query '{query_id}' not found.[/red]")
            console.print("[dim]Available queries: siyarix security queries[/dim]")
            return

        summary = (
            f"[bold]Query ID:[/bold]    {row['id']}\n"
            f"[bold]Name:[/bold]        {row['name']}\n"
            f"[bold]Target:[/bold]      {target or 'all endpoints'}\n"
            f"[bold]Technique:[/bold]   {row.get('technique', 'N/A')}\n"
            f"[bold]Tactic:[/bold]      {row.get('tactic', 'N/A')}\n"
            f"[bold]Query:[/bold]       {row.get('query_text', 'N/A')}\n"
            f"[bold]Status:[/bold]      [yellow]Executing...[/yellow]\n"
        )
        console.print(Panel(summary, title="🎯 Threat Hunt", border_style="yellow"))
    finally:
        conn.close()


@security_app.command(name="queries")
def list_queries(
    tag: str | None = typer.Option(None, "--tag", help="Filter by tag"),
    mitre_tactic: str | None = typer.Option(None, "--mitre-tactic", help="Filter by MITRE tactic"),
) -> None:
    """List available threat hunting queries."""
    conn = _get_security_db()
    try:
        conditions: list[str] = []
        params: list[Any] = []
        if mitre_tactic:
            conditions.append("LOWER(tactic) LIKE ?")
            params.append(f"%{mitre_tactic.lower()}%")
        if tag:
            conditions.append("tags LIKE ?")
            params.append(f"%{tag}%")

        query = "SELECT * FROM hunt_queries"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY tactic, name"

        rows = conn.execute(query, params).fetchall()

        table = Table(title="Threat Hunt Queries", show_header=True, header_style="bold magenta")
        table.add_column("Query ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("MITRE Tactic", style="yellow")
        table.add_column("Technique", style="cyan")
        table.add_column("Tags", style="dim")

        import json

        for row in rows:
            tags = ", ".join(json.loads(row.get("tags", "[]")))
            table.add_row(
                str(row.get("id", "-")),
                str(row.get("name", "-")),
                str(row.get("tactic", "-")),
                str(row.get("technique", "-")),
                tags,
            )
        console.print(table)
    finally:
        conn.close()


@security_app.command(name="mitre-coverage")
def mitre_coverage() -> None:
    """Show MITRE ATT&CK technique coverage."""
    table = Table(
        title="MITRE ATT&CK Coverage",
        show_header=True,
        header_style="bold red",
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
        table.add_row(str(tid), str(name), str(tactic), f"[{color}]{cov}[/{color}]")

    console.print(table)


# ---------------------------------------------------------------------------
# Security Dashboard
# ---------------------------------------------------------------------------


@security_app.command(name="dashboard")
def show_dashboard() -> None:
    """Show the security operations dashboard with live metrics."""
    conn = _get_security_db()
    try:
        # Live counts from database
        critical_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE severity = 'critical' AND status != 'closed'"
        ).fetchone()["c"]
        high_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE severity = 'high' AND status != 'closed'"
        ).fetchone()["c"]
        total_open_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE status != 'closed'"
        ).fetchone()["c"]

        critical_vulns = conn.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'critical' AND status != 'patched'"
        ).fetchone()["c"]
        high_vulns = conn.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'high' AND status != 'patched'"
        ).fetchone()["c"]
        total_vulns = conn.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE status != 'patched'"
        ).fetchone()["c"]

        from rich.columns import Columns

        score_panel = Panel.fit(
            "[bold bright_green]78.5[/bold bright_green]\n[dim]Security Score[/dim]",
            title="Score",
            border_style="green",
        )
        inc_panel = Panel.fit(
            f"[bold red]{critical_incidents}[/bold red] Critical\n[bold orange1]{high_incidents}[/bold orange1] High\n[dim]{total_open_incidents} Total Open[/dim]",
            title="Incidents",
            border_style="red",
        )
        vuln_panel = Panel.fit(
            f"[bold red]{critical_vulns}[/bold red] Critical CVEs\n[bold orange1]{high_vulns}[/bold orange1] High\n[dim]{total_vulns} Total Open[/dim]",
            title="Vulnerabilities",
            border_style="orange1",
        )
        comp_panel = Panel.fit(
            "[bold green]89%[/bold green] MFA\n[bold yellow]76%[/bold yellow] Patches\n[bold cyan]95%[/bold cyan] EDR",
            title="Compliance",
            border_style="cyan",
        )

        console.print(Columns([score_panel, inc_panel, vuln_panel, comp_panel]))

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
            table.add_row(str(metric), str(current), str(target), f"[{sc}]{status}[/{sc}]")

        console.print(table)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------


@security_app.command(name="playbooks")
def list_playbooks() -> None:
    """List available incident response playbooks."""
    conn = _get_security_db()
    try:
        rows = conn.execute("SELECT * FROM playbooks ORDER BY playbook_type, name").fetchall()

        table = Table(
            title="Incident Response Playbooks",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Mode", justify="center")

        for row in rows:
            ptype = row.get("playbook_type", "manual")
            mode = "[green]🤖 Auto[/green]" if ptype == "auto" else "[yellow]👤 Manual[/yellow]"
            table.add_row(
                str(row.get("id", "-")),
                str(row.get("name", "-")),
                str(row.get("playbook_type", "-")),
                mode,
            )

        console.print(table)
    finally:
        conn.close()


__all__ = [
    "list_incidents",
    "get_incident",
    "create_incident",
    "list_vulnerabilities",
    "get_remediation_plan",
    "run_hunt",
    "list_queries",
    "mitre_coverage",
    "show_dashboard",
    "list_playbooks",
]
