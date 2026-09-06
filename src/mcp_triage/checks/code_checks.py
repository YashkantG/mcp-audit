"""Lightweight, regex-based static checks for dangerous patterns in MCP server
source code. This is intentionally not a full AST/taint analysis — it is a
fast first pass that flags lines worth a human look.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_triage.models import Finding, Severity

# (rule_id, severity, message, compiled pattern, file suffixes it applies to)
#
# The human-readable messages below necessarily contain the very constructs
# they describe, so several of them trip their own rules when mcp-triage is
# pointed at itself. Suppressed inline rather than excluded wholesale, so the
# rest of this file stays covered.
_CHECKS = [
    (
        # The negative lookbehind is load-bearing. `\b(eval|exec)\(` also matches
        # `pattern.exec(line)` — the ordinary JavaScript RegExp API — which
        # accounted for 77% of this rule's hits across 141 surveyed repositories.
        # A method call on an object is not the global eval/exec.
        "MCP101", Severity.HIGH, "Use of eval()/exec() on dynamic input",  # mcp-triage: ignore[MCP101]
        re.compile(r"(?<![.\w])(eval|exec)\s*\("), {".py", ".js", ".ts", ".mjs", ".cjs"},
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
        "MCP102", Severity.HIGH, "os.system() call",  # mcp-triage: ignore[MCP102]
        re.compile(r"\bos\.system\s*\("), {".py"},
    ),
    (
        # Same story: only a bare `exec(` (a destructured child_process import)
        # or an explicit child_process member call counts. `re.exec(s)` does not.
        "MCP102", Severity.HIGH, "child_process exec()/execSync() call",  # mcp-triage: ignore[MCP101]
        re.compile(
            r"(?<![.\w])execSync\s*\("
            r"|(?<![.\w])exec\s*\("
            r"|child_process[\"'\)\]]*\s*\.\s*exec"
            r"|\b(?:cp|childProcess|child)\s*\.\s*execSync?\s*\("
        ),
        {".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP103", Severity.HIGH, "pickle.loads() on potentially untrusted data",  # mcp-triage: ignore[MCP103]
        re.compile(r"\bpickle\.loads?\s*\("), {".py"},
    ),
    (
        "MCP103", Severity.MEDIUM, "yaml.load() without a safe loader",  # mcp-triage: ignore[MCP103]
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
