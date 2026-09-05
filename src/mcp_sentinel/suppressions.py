"""Inline suppression comments, e.g.:

    subprocess.run(cmd, shell=True)  # mcp-sentinel: ignore[MCP102]
    subprocess.run(cmd, shell=True)  # mcp-sentinel: ignore

The bracketed form suppresses only the listed rule IDs on that line; the
bare form suppresses everything mcp-sentinel would otherwise flag there.
Findings with no line number (most JSON-manifest and config findings)
aren't eligible — there's no line to attach a comment to.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_SUPPRESS_RE = re.compile(r"mcp-sentinel:\s*ignore(?:\[([A-Za-z0-9,\s]+)\])?", re.IGNORECASE)


@lru_cache(maxsize=256)
def _read_lines(path: str) -> tuple:
    try:
        return tuple(Path(path).read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return ()


def is_suppressed(file: str, line: int, rule_id: str) -> bool:
    lines = _read_lines(file)
    if not lines or not (1 <= line <= len(lines)):
        return False
    match = _SUPPRESS_RE.search(lines[line - 1])
    if not match:
        return False
    rule_list = match.group(1)
    if rule_list is None:
        return True
    ids = {r.strip().upper() for r in rule_list.split(",")}
    return rule_id in ids


def filter_suppressed(findings: list) -> list:
    return [
        f for f in findings
        if f.line is None or not is_suppressed(f.file, f.line, f.rule_id)
    ]
