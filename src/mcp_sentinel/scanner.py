from __future__ import annotations

from pathlib import Path

from mcp_sentinel.checks import code_checks, config_checks, manifest_checks, secrets_checks
from mcp_sentinel.discovery import find_source_files, iter_files
from mcp_sentinel.models import Finding


def scan(target: Path) -> list[Finding]:
    target = target.resolve()
    findings: list[Finding] = []

    if target.is_file():
        json_files = [target] if target.suffix == ".json" else []
        source_files = [target] if target.suffix in {".py", ".js", ".ts", ".mjs", ".cjs"} else []
        all_files = [target]
    else:
        all_files = list(iter_files(target))
        json_files = [p for p in all_files if p.suffix == ".json"]
        source_files = find_source_files(target)

    for manifest in json_files:
        findings.extend(manifest_checks.scan_manifest_file(manifest))
        findings.extend(config_checks.scan_config_file(manifest))

    for source in source_files:
        findings.extend(code_checks.scan_source_file(source))
        findings.extend(manifest_checks.scan_source_descriptions(source))

    for file in all_files:
        findings.extend(secrets_checks.scan_file_for_secrets(file))

    return findings
