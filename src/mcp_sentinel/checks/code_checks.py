"""Lightweight, regex-based static checks for dangerous patterns in MCP server
source code. This is intentionally not a full AST/taint analysis — it is a
fast first pass that flags lines worth a human look.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_sentinel.models import Finding, Severity

# (rule_id, severity, message, compiled pattern, file suffixes it applies to)
_CHECKS = [
    (
        "MCP101", Severity.HIGH, "Use of eval()/exec() on dynamic input",
        re.compile(r"\b(eval|exec)\s*\("), {".py", ".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP101", Severity.HIGH, "Dynamic Function construction (JS eval equivalent)",
        re.compile(r"\bnew\s+Function\s*\("), {".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP102", Severity.HIGH, "subprocess call with shell=True",
        re.compile(r"subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
        {".py"},
    ),
    (
        "MCP102", Severity.HIGH, "os.system() call",
        re.compile(r"\bos\.system\s*\("), {".py"},
    ),
    (
        "MCP102", Severity.HIGH, "child_process exec()/execSync() call",
        re.compile(r"\b(exec|execSync)\s*\("), {".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP103", Severity.HIGH, "pickle.loads() on potentially untrusted data",
        re.compile(r"\bpickle\.loads?\s*\("), {".py"},
    ),
    (
        "MCP103", Severity.MEDIUM, "yaml.load() without a safe loader",
        re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"), {".py"},
    ),
]


def scan_source_file(path: Path) -> list[Finding]:
    suffix = path.suffix
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule_id, severity, message, pattern, suffixes in _CHECKS:
            if suffix not in suffixes:
                continue
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    file=str(path),
                    line=lineno,
                    message=message,
                    snippet=stripped[:160],
                ))
    return findings
