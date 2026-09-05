"""Checks that operate on MCP tool definitions (name / description / inputSchema).

Tool definitions can come from a captured `tools/list` response, an mcp.json
file, or any JSON blob that embeds objects shaped like
``{"name": ..., "description": ..., "inputSchema": {...}}``.
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
    findings: list[Finding] = []
    name = tool.get("name", json_path or "<unnamed tool>")
    description = tool.get("description", "") or ""

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append(Finding(
                rule_id="MCP001",
                severity=Severity.HIGH,
                file=file,
                message=f"Tool '{name}' description matches prompt-injection pattern: /{pattern}/",
                snippet=description[:200],
            ))
            break

    if INVISIBLE_CHAR_PATTERN.search(description):
        findings.append(Finding(
            rule_id="MCP002",
            severity=Severity.HIGH,
            file=file,
            message=f"Tool '{name}' description contains hidden/invisible unicode characters",
        ))

    if len(description) >= DESCRIPTION_LENGTH_HIGH:
        findings.append(Finding(
            rule_id="MCP003",
            severity=Severity.MEDIUM,
            file=file,
            message=f"Tool '{name}' description is unusually long ({len(description)} chars) — "
                    "could smuggle hidden instructions",
        ))
    elif len(description) >= DESCRIPTION_LENGTH_WARN:
        findings.append(Finding(
            rule_id="MCP003",
            severity=Severity.LOW,
            file=file,
            message=f"Tool '{name}' description is longer than typical ({len(description)} chars)",
        ))

    haystack = f"{name} {description}".lower()
    for keyword in BROAD_CAPABILITY_KEYWORDS:
        if keyword in haystack:
            findings.append(Finding(
                rule_id="MCP004",
                severity=Severity.MEDIUM,
                file=file,
                message=f"Tool '{name}' exposes a broad capability (matched keyword: '{keyword}')",
            ))
            break

    schema = tool.get("inputSchema") or tool.get("input_schema")
    if isinstance(schema, dict) and schema.get("type") == "object":
        if schema.get("additionalProperties") is True:
            findings.append(Finding(
                rule_id="MCP005",
                severity=Severity.MEDIUM,
                file=file,
                message=f"Tool '{name}' input schema allows additionalProperties=true "
                        "(accepts arbitrary/unvalidated fields)",
            ))

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
