# mcp-sentinel

[![CI](https://github.com/YashkantG/mcp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/YashkantG/mcp-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](pyproject.toml)

**A security scanner for MCP (Model Context Protocol) servers.**

![mcp-sentinel demo](docs/demo.gif)

MCP servers are exploding — every agent framework now connects to dozens of
them. Almost none of them get security-reviewed. `mcp-sentinel` finds the
things that quietly turn a "helpful tool" into an attack surface:

- 🧠 **Prompt-injection-prone tool descriptions** — phrasing designed to hijack
  the calling LLM ("ignore previous instructions", hidden invisible unicode,
  suspiciously long descriptions that smuggle instructions). Checked both in
  static JSON manifests **and** in the tool descriptions most servers actually
  ship: string literals inside their JS/TS/Python source.
- 🔓 **Over-broad capabilities** — tools that expose shell/exec/arbitrary file
  access, or accept unvalidated free-form input (`additionalProperties: true`).
- 💣 **Dangerous code paths** in the server implementation — `eval`,
  `subprocess(..., shell=True)`, `os.system`, `pickle.loads`, unsafe
  `yaml.load`.
- 🔑 **Hardcoded secrets** — API keys, AWS keys, GitHub/Slack tokens baked
  into source or config instead of environment variables.
- 🌐 **Unsafe defaults** — binding to `0.0.0.0`, `trust`/`skip_auth` flags left
  enabled.

Built for real pipelines, not just a terminal: SARIF output for GitHub/GitLab
code scanning, a drop-in GitHub Action, a pre-commit hook, project-level
config with inline suppression and bring-your-own custom rules, and zero
network calls — see [Use in CI](#use-in-ci) and
[Runs entirely on your machine](#runs-entirely-on-your-machine) below.

## Install

```bash
pip install mcp-sentinel-cli
```

(the PyPI distribution is named `mcp-sentinel-cli` since `mcp-sentinel` was
already taken; the installed command is still `mcp-sentinel`)

Or from source:

```bash
git clone https://github.com/YashkantG/mcp-sentinel.git
cd mcp-sentinel
pip install -e .
```

## Usage

Scan a server's project directory, a single source file, or a captured
`tools/list` / `mcp.json` manifest:

```bash
mcp-sentinel scan ./my-mcp-server
```

```
                             mcp-sentinel findings
┌──────────┬──────────────────────────────────┬─────────────────┬────────────────────────────────────────────────┐
│ Severity │ Rule                             │ Location         │ Message                                        │
├──────────┼──────────────────────────────────┼──────────────────┼─────────────────────────────────────────────────┤
│ HIGH     │ MCP001 (Prompt-injection...)     │ mcp.json         │ Tool 'run_shell' description matches...        │
│ HIGH     │ MCP102 (Shell command built...)  │ server.py:8      │ subprocess call with shell=True                │
│ HIGH     │ MCP201 (Hardcoded secret...)     │ mcp.json         │ Possible hardcoded secret: AWS Access Key ID   │
│ MEDIUM   │ MCP301 (Server bound to all...)  │ mcp.json         │ 'host' binds to all network interfaces         │
└──────────┴──────────────────────────────────┴──────────────────┴─────────────────────────────────────────────────┘

11 finding(s)  (HIGH: 8  MEDIUM: 3)
```

Use `--format json` for machine-readable output, `--format sarif` for
[SARIF](https://sarifweb.azurewebsites.net/) (native GitHub/GitLab code-scanning
ingestion), and `--fail-on` to control what severity trips a non-zero exit
code:

```bash
mcp-sentinel scan ./my-mcp-server --format json
mcp-sentinel scan ./my-mcp-server --fail-on medium   # fail CI on MEDIUM or higher
```

## Use in CI

**GitHub Action** — drop this into a workflow, no `pip install` boilerplate needed:

```yaml
- uses: YashkantG/mcp-sentinel@main
  with:
    path: ./my-mcp-server
    fail-on: high
```

**SARIF → GitHub Code Scanning**, so findings show up natively in the repo's
Security tab instead of only in build logs:

```yaml
- uses: YashkantG/mcp-sentinel@main
  with:
    path: ./my-mcp-server
    format: sarif
    upload-sarif: "true"
```

**pre-commit** — add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/YashkantG/mcp-sentinel
    rev: v0.3.0
    hooks:
      - id: mcp-sentinel
```

**Plain CLI in any CI system** works the same way — `mcp-sentinel scan . --fail-on high`
returns a non-zero exit code when it finds something at or above that severity.

## Suppressing findings

A pattern-based scanner will occasionally flag something you've already
reviewed and accepted. Three ways to tell it to stand down, from narrowest to
broadest:

**Inline comment**, right on the offending line:

```python
subprocess.run(cmd, shell=True)  # mcp-sentinel: ignore[MCP102]
subprocess.run(cmd, shell=True)  # mcp-sentinel: ignore            (suppresses every rule on this line)
```

**Project config** — a `.mcpsentinel.toml` at the scan root:

```toml
[ignore]
rules = ["MCP004"]              # never flag this rule, repo-wide
paths = ["tests/fixtures/**"]   # never scan these paths

[severity]
MCP003 = "LOW"                  # downgrade instead of ignoring outright

[[custom_rules]]                # bring your own checks — no fork required
id = "CUSTOM001"
pattern = "InternalOnlyApi\\.execute"
message = "Use of internal-only API from an MCP tool handler is banned"
severity = "HIGH"
```

**CLI flag**, for one-off or CI-specific overrides:

```bash
mcp-sentinel scan . --ignore-rule MCP004 --ignore-rule MCP301
```

## Runs entirely on your machine

`mcp-sentinel` makes zero network calls. It doesn't phone home, doesn't send
your code anywhere, and has no telemetry — the only dependencies are `typer`,
`rich`, and (on Python <3.11) `tomli`, none of which the scanner itself uses
for anything network-related. Releases are published via
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC,
no long-lived tokens), which gives you verifiable build provenance back to
the exact GitHub Actions run that produced each release. If your security
team needs to approve a new tool before it touches a private repo, that's the
whole trust story: read the source, or don't even give it network access —
it doesn't need any.

## Scanning real servers

Running `mcp-sentinel` against the [official MCP reference servers](https://github.com/modelcontextprotocol/servers)
(filesystem, git, fetch, memory, time, sequentialthinking, everything) turns
up genuine, non-hypothetical signal — nothing catastrophic here (these are
well-maintained reference implementations), but exactly the kind of thing
worth a second look before you point an agent at a *less* scrutinized server:

```
src/filesystem:
  LOW    MCP003  'read_text_file' description is longer than typical (457 chars)
  MEDIUM MCP004  'list_directory' exposes a broad capability (matched keyword: 'all files')
  MEDIUM MCP004  'list_directory_with_sizes' exposes a broad capability (matched keyword: 'all files')
  LOW    MCP003  'search_files' description is longer than typical (424 chars)

src/sequentialthinking:
  MEDIUM MCP003  'sequentialthinking' description is unusually long (2781 chars)
```

None of these are bugs in those servers — a filesystem tool legitimately
needs to describe listing "all files" — but they're exactly the kind of
capability/length signal you'd want flagged automatically before granting an
agent access to a server you didn't write.

## Rules

| ID | Check |
|----|-------|
| MCP001 | Prompt-injection phrasing in tool description |
| MCP002 | Hidden/invisible unicode characters in tool description |
| MCP003 | Suspiciously long tool description (payload smuggling risk) |
| MCP004 | Over-broad capability exposed by tool name/description |
| MCP005 | Tool schema accepts arbitrary/unvalidated input |
| MCP101 | Dangerous code execution sink (`eval`, `exec`, `new Function`) |
| MCP102 | Shell command built from untrusted input |
| MCP103 | Unsafe deserialization (`pickle.loads`, unsafe `yaml.load`) |
| MCP201 | Hardcoded secret or credential |
| MCP301 | Server bound to all network interfaces |
| MCP302 | Authentication / trust check disabled |

## Why this exists

The MCP ecosystem grew faster than its security tooling. A malicious or
careless MCP server can manipulate the LLM that's using it (via crafted tool
descriptions) or simply be a badly-secured piece of software with shell
access. `mcp-sentinel` is a fast, dependency-light first pass you can run
locally or in CI before trusting a new server.

It's intentionally simple — pattern/regex-based checks rather than a full
taint-tracking analyzer — so it's fast, has no false-negative-hiding
complexity, and is easy to extend. Contributions adding new rules are very
welcome.

## Contributing

Issues and PRs welcome — especially new rules, language support (only
Python/JS/TS source checks exist today), and real-world MCP servers to test
against. See the `tests/fixtures/` directory for the pattern used to add a
new check with a positive and negative fixture. A few
[good first issues](https://github.com/YashkantG/mcp-sentinel/labels/good%20first%20issue)
are tagged if you want a concrete starting point.

## License

MIT — see [LICENSE](LICENSE).
