"""Project-level configuration: .mcptriage.toml.

Lets a team check in what "accepted risk" looks like for their repo instead
of relying purely on CLI flags or editing the source they're scanning.

    [ignore]
    rules = ["MCP003", "MCP004"]
    paths = ["tests/fixtures/**", "vendor/**"]

    [severity]
    MCP004 = "LOW"
"""
from __future__ import annotations

import fnmatch
import sys
from dataclasses import dataclass, field
from pathlib import Path

from mcp_triage.models import Severity

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_FILENAME = ".mcptriage.toml"


@dataclass
class CustomRule:
    id: str
    pattern: str
    message: str
    severity: str = "MEDIUM"
    suffixes: tuple = (".py", ".js", ".ts", ".mjs", ".cjs")


@dataclass
class Config:
    ignored_rules: set = field(default_factory=set)
    ignored_paths: list = field(default_factory=list)
    severity_overrides: dict = field(default_factory=dict)
    custom_rules: list = field(default_factory=list)

    def path_is_ignored(self, file: str) -> bool:
        normalized = file.replace("\\", "/")
        return any(fnmatch.fnmatch(normalized, pattern) for pattern in self.ignored_paths)

    def apply(self, findings: list) -> list:
        kept = []
        for finding in findings:
            if finding.rule_id in self.ignored_rules:
                continue
            if self.path_is_ignored(finding.file):
                continue
            override = self.severity_overrides.get(finding.rule_id)
            if override is not None:
                finding = _with_severity(finding, override)
            kept.append(finding)
        return kept


def _with_severity(finding, severity_name: str):
    from dataclasses import replace
    return replace(finding, severity=Severity(severity_name.upper()))


def load_config(root: Path) -> Config:
    """Load .mcptriage.toml from `root` (or its containing directory, if
    `root` is a file). Returns an empty Config if no file is present.
    """
    search_dir = root if root.is_dir() else root.parent
    config_path = search_dir / CONFIG_FILENAME
    if not config_path.is_file():
        return Config()

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    ignore = data.get("ignore", {})
    severity = data.get("severity", {})
    custom_rules = [
        CustomRule(
            id=cr["id"],
            pattern=cr["pattern"],
            message=cr["message"],
            severity=cr.get("severity", "MEDIUM"),
            suffixes=tuple(cr["suffixes"]) if "suffixes" in cr else CustomRule.suffixes,
        )
        for cr in data.get("custom_rules", [])
    ]
    return Config(
        ignored_rules=set(ignore.get("rules", [])),
        ignored_paths=list(ignore.get("paths", [])),
        severity_overrides=dict(severity),
        custom_rules=custom_rules,
    )
