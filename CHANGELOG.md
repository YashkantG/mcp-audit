# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — plus
the additional rule-stability guarantees below, which matter if you pin rule
IDs in CI.

## Rule stability policy

Teams pin things like `--ignore-rule MCP004` and `--fail-on high` in their
pipelines, so rule identity is part of the public API, not an implementation
detail:

- **Rule IDs are never reused or renumbered.** If a rule is retired, its ID is
  retired with it.
- **A rule's default severity will not change in a patch release.** Severity
  changes ship in a minor release at the earliest, and are always listed here.
- **New rules may be added in a minor release.** This can surface new findings
  in an existing codebase, which is why `--fail-on`, `.mcpaudit.toml`, and
  (from 0.4.0) baselines exist.
- **Removing a rule, or making an existing rule meaningfully broader, is a
  breaking change** and waits for a major version.

---

## [Unreleased]

## [0.3.0] - 2026-09-05

### Added
- **SARIF 2.1.0 output** (`--format sarif`), validated against the official
  schema — findings can be uploaded to GitHub Code Scanning, GitLab, or any
  SARIF-consuming dashboard.
- **Badge output** (`--format badge`) producing a shields.io endpoint payload,
  so a scanned project can display its own posture grade.
- **Inline suppression comments**: `# mcp-audit: ignore[MCP102]` suppresses
  a specific rule on that line; a bare `# mcp-audit: ignore` suppresses all.
- **Project configuration** via `.mcpaudit.toml`: repo-wide rule and path
  ignores, per-rule severity overrides, and `[[custom_rules]]` for
  organisation-specific checks without forking.
- `--ignore-rule` (repeatable) and `--config` CLI options.
- **GitHub Action** (`action.yml`) with an `upload-sarif` path straight into
  Code Scanning.
- **pre-commit hook** definition (`.pre-commit-hooks.yaml`).
- `CONTRIBUTING.md`, `SECURITY.md`, issue forms, and a pull request template.

### Fixed
- `__version__` was still reporting `0.1.0` after the 0.2.0 release.

## [0.2.0] - 2026-09-05

### Added
- Tool descriptions are now extracted from **source code** (JS/TS/Python string
  literals, including `+`-concatenated multi-line strings), not just static
  JSON manifests. This was the flagship prompt-injection check's biggest blind
  spot: scanning the official `modelcontextprotocol/servers` reference
  implementations produced zero findings before this, because none of them ship
  a static manifest.

### Fixed
- False positive where the MCP004 broad-capability check matched `exec` as a
  substring of ordinary words like "executes". Keyword matching is now
  word-boundary aware.

## [0.1.0] - 2026-09-03

### Added
- Initial release: 11 rules across tool-description analysis (prompt injection,
  hidden unicode, over-broad capability, unvalidated schemas), dangerous code
  sinks, hardcoded secrets, and unsafe server defaults.
- `table` and `json` output, `--fail-on` severity gating for CI.

[Unreleased]: https://github.com/YashkantG/mcp-audit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/YashkantG/mcp-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/YashkantG/mcp-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/YashkantG/mcp-audit/releases/tag/v0.1.0
