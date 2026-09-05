from __future__ import annotations

import json as json_module
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from mcp_sentinel.models import Finding, Severity
from mcp_sentinel.rules import RULES

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
