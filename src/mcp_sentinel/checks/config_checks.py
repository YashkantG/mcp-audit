"""Checks for unsafe defaults in MCP server launch/config files."""
from __future__ import annotations

import json
from pathlib import Path

from mcp_sentinel.models import Finding, Severity

_BIND_ALL_VALUES = {"0.0.0.0", "::"}


def _walk(obj, path=""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield f"{path}.{key}" if path else key, key, value
            yield from _walk(value, f"{path}.{key}" if path else key)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _walk(item, f"{path}[{i}]")


def scan_config_file(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []

    findings: list[Finding] = []
    for json_path, key, value in _walk(data):
        lowered_key = key.lower()

        if lowered_key in {"host", "bind", "hostname"} and value in _BIND_ALL_VALUES:
            findings.append(Finding(
                rule_id="MCP301",
                severity=Severity.MEDIUM,
                file=str(path),
                message=f"'{json_path}' binds to all network interfaces ({value})",
            ))

        if lowered_key in {"trust", "trusted", "skip_auth", "disable_auth", "no_auth", "allow_all"} and value is True:
            findings.append(Finding(
                rule_id="MCP302",
                severity=Severity.HIGH,
                file=str(path),
                message=f"'{json_path}' explicitly disables an auth/trust check",
            ))

    return findings
