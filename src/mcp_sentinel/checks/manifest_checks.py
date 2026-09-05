"""Checks that operate on MCP tool definitions (name / description / inputSchema).

Tool definitions show up in two shapes in the wild:

1. A captured `tools/list` response or an mcp.json file — plain JSON, handled
   by :func:`scan_manifest_file`.
2. A string literal inside the server's own source code (the overwhelmingly
   common case: most servers build their tool list as JS/TS/Python object
   literals, not a static JSON file) — handled by
   :func:`scan_source_descriptions`.

Both funnel into :func:`check_description`, which holds the actual rules.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from mcp_sentinel.models import Finding, Severity

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all|any|previous|prior) instructions",
    r"disregard (the|your|all) (system|previous) prompt",
    r"you must always",
    r"do not (tell|inform|mention to) the user",
    r"without (asking|confirming|telling) the user",
    r"this is (a )?system (prompt|message)",
    r"<\s*system\s*>",
    r"act as (if|though) you (are|were)",
    r"override (your|the) (rules|instructions|guidelines)",
]

INVISIBLE_CHAR_PATTERN = re.compile(
    "[​‌‍‎‏‪-‮⁠﻿]"
)

BROAD_CAPABILITY_KEYWORDS = [
    "shell", "exec", "eval", "sudo", "rm -rf", "arbitrary code",
    "any file", "all files", "entire filesystem", "root access",
    "admin access", "bypass", "delete all",
]

DESCRIPTION_LENGTH_WARN = 400
DESCRIPTION_LENGTH_HIGH = 1200


def check_description(name: str, description: str, file: str, line: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    description = description or ""

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append(Finding(
                rule_id="MCP001",
                severity=Severity.HIGH,
                file=file,
                line=line,
                message=f"Tool '{name}' description matches prompt-injection pattern: /{pattern}/",
                snippet=description[:200],
            ))
            break

    if INVISIBLE_CHAR_PATTERN.search(description):
        findings.append(Finding(
            rule_id="MCP002",
            severity=Severity.HIGH,
            file=file,
            line=line,
            message=f"Tool '{name}' description contains hidden/invisible unicode characters",
        ))

    if len(description) >= DESCRIPTION_LENGTH_HIGH:
        findings.append(Finding(
            rule_id="MCP003",
            severity=Severity.MEDIUM,
            file=file,
            line=line,
            message=f"Tool '{name}' description is unusually long ({len(description)} chars) — "
                    "could smuggle hidden instructions",
        ))
    elif len(description) >= DESCRIPTION_LENGTH_WARN:
        findings.append(Finding(
            rule_id="MCP003",
            severity=Severity.LOW,
            file=file,
            line=line,
            message=f"Tool '{name}' description is longer than typical ({len(description)} chars)",
        ))

    haystack = f"{name} {description}".lower()
    for keyword in BROAD_CAPABILITY_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", haystack):
            findings.append(Finding(
                rule_id="MCP004",
                severity=Severity.MEDIUM,
                file=file,
                line=line,
                message=f"Tool '{name}' exposes a broad capability (matched keyword: '{keyword}')",
            ))
            break

    return findings


def _check_schema(name: str, schema, file: str, line: int | None = None) -> list[Finding]:
    if isinstance(schema, dict) and schema.get("type") == "object":
        if schema.get("additionalProperties") is True:
            return [Finding(
                rule_id="MCP005",
                severity=Severity.MEDIUM,
                file=file,
                line=line,
                message=f"Tool '{name}' input schema allows additionalProperties=true "
                        "(accepts arbitrary/unvalidated fields)",
            )]
    return []


# ---------------------------------------------------------------------------
# JSON manifests (mcp.json, captured tools/list responses, ...)
# ---------------------------------------------------------------------------

def _iter_tool_like_objects(obj, path=""):
    """Recursively yield (json_path, dict) for objects that look like tool defs."""
    if isinstance(obj, dict):
        if "description" in obj and isinstance(obj.get("description"), str):
            yield path, obj
        for key, value in obj.items():
            yield from _iter_tool_like_objects(value, f"{path}.{key}" if path else key)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _iter_tool_like_objects(item, f"{path}[{i}]")


def check_tool_definition(tool: dict, file: str, json_path: str) -> list[Finding]:
    name = tool.get("name", json_path or "<unnamed tool>")
    description = tool.get("description", "") or ""
    findings = check_description(name, description, file)
    findings.extend(_check_schema(name, tool.get("inputSchema") or tool.get("input_schema"), file))
    return findings


def scan_manifest_file(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []

    findings: list[Finding] = []
    seen = set()
    for json_path, obj in _iter_tool_like_objects(data):
        key = (obj.get("name"), obj.get("description"))
        if key in seen:
            continue
        seen.add(key)
        findings.extend(check_tool_definition(obj, str(path), json_path))
    return findings


# ---------------------------------------------------------------------------
# Descriptions embedded in source code (the common real-world case: a tool
# list built as a JS/TS/Python object literal rather than a JSON file).
# ---------------------------------------------------------------------------

_DESCRIPTION_KEY_RE = re.compile(r"""\bdescription\s*[:=]\s*""")
_NAME_NEARBY_RE = re.compile(
    r"""\bname\s*[:=]\s*["'`]([^"'`]{1,80})["'`]"""
    r"""|\b(?:registerTool|register_tool|addTool|add_tool)\s*\(\s*["'`]([^"'`]{1,80})["'`]"""
)
_NAME_SEARCH_WINDOW = 300


def _read_string_literal(text: str, i: int) -> tuple[str, int]:
    """Read a single quoted/backtick string literal starting at text[i]. Returns (value, index_after)."""
    quote = text[i]
    j = i + 1
    buf = []
    while j < len(text):
        ch = text[j]
        if ch == "\\" and j + 1 < len(text):
            buf.append(text[j + 1])
            j += 2
            continue
        if ch == quote:
            return "".join(buf), j + 1
        buf.append(ch)
        j += 1
    return "".join(buf), j


def _read_description_value(text: str, i: int) -> str:
    """Read a (possibly `+`-concatenated) string value starting at text[i]."""
    parts = []
    j = i
    while j < len(text) and text[j] in " \t\r\n":
        j += 1
    while j < len(text) and text[j] in "`\"'":
        value, j = _read_string_literal(text, j)
        parts.append(value)
        k = j
        while k < len(text) and text[k] in " \t\r\n":
            k += 1
        if k < len(text) and text[k] == "+":
            k += 1
            while k < len(text) and text[k] in " \t\r\n":
                k += 1
            j = k
            continue
        break
    return "".join(parts)


def scan_source_descriptions(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    for match in _DESCRIPTION_KEY_RE.finditer(text):
        value_start = match.end()
        if value_start >= len(text) or text[value_start] not in " \t\r\n`\"'":
            continue
        description = _read_description_value(text, value_start)
        if not description:
            continue

        window_start = max(0, match.start() - _NAME_SEARCH_WINDOW)
        name_match = None
        for name_match in _NAME_NEARBY_RE.finditer(text, window_start, match.start()):
            pass  # take the last (closest preceding) match
        if name_match:
            name = name_match.group(1) or name_match.group(2)
        else:
            name = "<unnamed tool>"

        line = text.count("\n", 0, match.start()) + 1
        findings.extend(check_description(name, description, str(path), line))
    return findings
