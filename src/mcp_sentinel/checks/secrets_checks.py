"""Regex-based detection of obviously hardcoded secrets/credentials."""
from __future__ import annotations

import re
from pathlib import Path

from mcp_sentinel.models import Finding, Severity

_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "Hardcoded credential assignment",
        re.compile(
            r"""(?i)\b(api[_-]?key|secret|password|token|access[_-]?key)\b["']?\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{12,}["']"""
        ),
    ),
]

_PLACEHOLDER_HINTS = ("example", "xxxx", "changeme", "your_", "<", "${", "process.env", "os.environ")

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".lock"}


def scan_file_for_secrets(path: Path) -> list[Finding]:
    if path.suffix in SKIP_SUFFIXES:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        lowered = line.lower()
        if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
            continue
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id="MCP201",
                    severity=Severity.HIGH,
                    file=str(path),
                    line=lineno,
                    message=f"Possible hardcoded secret: {label}",
                    snippet=line.strip()[:160],
                ))
                break
    return findings
