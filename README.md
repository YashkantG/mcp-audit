# mcp-sentinel

[![CI](https://github.com/YashkantG/mcp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/YashkantG/mcp-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](pyproject.toml)

**A security scanner for MCP (Model Context Protocol) servers.**

MCP servers are exploding — every agent framework now connects to dozens of
them. Almost none of them get security-reviewed. `mcp-sentinel` finds the
things that quietly turn a "helpful tool" into an attack surface:

- 🧠 **Prompt-injection-prone tool descriptions** — phrasing designed to hijack
  the calling LLM ("ignore previous instructions", hidden invisible unicode,
  suspiciously long descriptions that smuggle instructions).
- 🔓 **Over-broad capabilities** — tools that expose shell/exec/arbitrary file
  access, or accept unvalidated free-form input (`additionalProperties: true`).
- 💣 **Dangerous code paths** in the server implementation — `eval`,
  `subprocess(..., shell=True)`, `os.system`, `pickle.loads`, unsafe
  `yaml.load`.
- 🔑 **Hardcoded secrets** — API keys, AWS keys, GitHub/Slack tokens baked
  into source or config instead of environment variables.
- 🌐 **Unsafe defaults** — binding to `0.0.0.0`, `trust`/`skip_auth` flags left
  enabled.

## Install

```bash
pip install mcp-sentinel
```

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

Use `--format json` for machine-readable output (great for CI), and
`--fail-on` to control what severity trips a non-zero exit code:

```bash
mcp-sentinel scan ./my-mcp-server --format json
mcp-sentinel scan ./my-mcp-server --fail-on medium   # fail CI on MEDIUM or higher
```

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
new check with a positive and negative fixture.

## License

MIT — see [LICENSE](LICENSE).
