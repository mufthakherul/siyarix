#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CI gate for Bandit / pip-audit JSON reports.

Fails closed when reports are missing or contain actionable findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::Unable to parse {path}: {exc}")
        sys.exit(1)


def gate_bandit(path: Path) -> int:
    data = _load_json(path)
    if not isinstance(data, dict):
        print("::error::Bandit report is not a JSON object")
        return 1
    results = data.get("results", []) or []
    highs = [r for r in results if str(r.get("issue_severity", "")).upper() == "HIGH"]
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "bandit"}},
                "results": [
                    {
                        "ruleId": r.get("test_id", "B000"),
                        "level": "error" if r.get("issue_severity") == "HIGH" else "warning",
                        "message": {"text": r.get("issue_text", "")},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": r.get("filename", "")},
                                    "region": {"startLine": r.get("line_number", 0)},
                                }
                            }
                        ],
                    }
                    for r in results
                    if isinstance(r, dict)
                ],
            }
        ],
    }
    path.with_suffix(".sarif").write_text(json.dumps(sarif), encoding="utf-8")
    print(f"Bandit findings: {len(results)} (high={len(highs)})")
    return 1 if highs else 0


def gate_pip_audit(path: Path) -> int:
    data = _load_json(path)
    if isinstance(data, dict):
        nested = data.get("dependencies", []) or data.get("results", []) or []
        data = nested if isinstance(nested, list) else []
    if not isinstance(data, list):
        print("::error::pip-audit report is not a dependency list")
        return 1

    vulns: list[dict] = []
    for dep in data:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name") or dep.get("package") or "?"
        for item in dep.get("vulns", []) or []:
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("package", name)
                row.setdefault("severity", "unknown")
                vulns.append(row)

    blocking = [
        v
        for v in vulns
        if str(v.get("severity", "unknown")).lower() in ("high", "critical", "unknown", "")
    ]
    if blocking:
        print(f"::error::{len(blocking)} actionable vulnerabilities found")
        for v in blocking:
            desc = str(v.get("description", ""))[:200]
            print(f"  - {v.get('package', '?')} {v.get('id', '?')}: {desc}")
        return 2
    print(f"{len(vulns)} total vulnerabilities (none actionable)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("bandit", "pip-audit"))
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    if not args.report.is_file():
        print(f"::error::Missing report file: {args.report}")
        return 1
    if args.kind == "bandit":
        return gate_bandit(args.report)
    return gate_pip_audit(args.report)


if __name__ == "__main__":
    raise SystemExit(main())
