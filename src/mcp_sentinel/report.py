from __future__ import annotations

import json as json_module
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from mcp_sentinel import __version__
from mcp_sentinel.models import Finding, Severity
from mcp_sentinel.rules import RULES

_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_table(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()

    if not findings:
        console.print("[bold green]No issues found.[/bold green]")
        return

    table = Table(title="mcp-sentinel findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Message")

    for finding in sorted(findings, key=lambda f: -f.severity.weight):
        location = finding.file
        if finding.line:
            location += f":{finding.line}"
        style = _SEVERITY_STYLE[finding.severity]
        table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
            f"{finding.rule_id} ({RULES.get(finding.rule_id, 'unknown rule')})",
            location,
            finding.message,
        )

    console.print(table)

    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity}
    summary = "  ".join(f"{sev.value}: {counts[sev]}" for sev in Severity if counts[sev])
    console.print(f"\n[bold]{len(findings)} finding(s)[/bold]  ({summary})")


def render_json(findings: list[Finding]) -> str:
    return json_module.dumps(
        [{**asdict(f), "severity": f.severity.value} for f in findings],
        indent=2,
    )


def _relative_uri(file: str, root: Path) -> str:
    try:
        return Path(file).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(file).as_posix()


def render_sarif(findings: list[Finding], root: Path) -> str:
    """Render findings as SARIF 2.1.0 — consumable by GitHub Code Scanning
    (`github/codeql-action/upload-sarif`), GitLab, and most SAST dashboards.
    """
    rule_ids_used = sorted({f.rule_id for f in findings}) or sorted(RULES.keys())
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": RULES.get(rule_id, rule_id)},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(_severity_for_rule(findings, rule_id), "warning")
            },
        }
        for rule_id in rule_ids_used
    ]

    results = []
    for f in findings:
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": _relative_uri(f.file, root)},
            }
        }
        if f.line:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [location],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/YashkantG/mcp-sentinel",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json_module.dumps(sarif, indent=2)


def _severity_for_rule(findings: list[Finding], rule_id: str) -> Severity:
    for f in findings:
        if f.rule_id == rule_id:
            return f.severity
    return Severity.MEDIUM
