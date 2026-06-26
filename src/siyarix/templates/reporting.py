# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reporting templates for Executive and Technical formats."""

import datetime
from typing import Any

def generate_executive_report(target: str, score: str, findings_count: int, critical_count: int) -> str:
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""# Executive Security Summary

**Target:** {target}
**Date:** {date_str}

## Overview
A comprehensive security assessment was performed against {target}.
Overall Risk Score: **{score}**
Total Findings: {findings_count}
Critical Issues: {critical_count}

## Strategic Recommendations
1. Address Critical vulnerabilities immediately.
2. Review external exposure and access controls.
3. Schedule follow-up assessment in 30 days.
"""

def generate_technical_report(target: str, findings: list[dict[str, Any]], duration: float) -> str:
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    report = f"""# Technical Assessment Report

**Target:** {target}
**Date:** {date_str}
**Duration:** {duration:.2f}s

## Finding Details
"""
    if not findings:
        report += "No vulnerabilities found during the scan.\n"
        return report

    for f in findings:
        severity = f.get('severity', 'info').upper()
        title = f.get('title', f.get('cve', 'Unknown Vulnerability'))
        desc = f.get('description', '')
        report += f"### [{severity}] {title}\n"
        if desc:
            report += f"{desc}\n\n"
        
    return report
