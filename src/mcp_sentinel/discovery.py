from __future__ import annotations

from pathlib import Path

MANIFEST_NAMES = {"mcp.json", "claude_desktop_config.json", "mcp_config.json"}
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for path in target.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def find_manifests(target: Path) -> list[Path]:
    return [p for p in iter_files(target) if p.name in MANIFEST_NAMES]


def find_source_files(target: Path) -> list[Path]:
    return [p for p in iter_files(target) if p.suffix in SOURCE_SUFFIXES]
