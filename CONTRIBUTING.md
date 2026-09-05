# Contributing to mcp-audit

Thanks for considering it. This project is intentionally small and
regex/pattern-based rather than a full static-analysis engine, so most
contributions are self-contained and don't require deep familiarity with the
codebase — see [good first issues](https://github.com/YashkantG/mcp-audit/labels/good%20first%20issue)
for a concrete starting point.

## Setup

```bash
git clone https://github.com/YashkantG/mcp-audit.git
cd mcp-audit
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest -q
```

That's it — no build step, no external services, no network access needed to
run the tests.

## Project layout

```
src/mcp_audit/
  cli.py                  # Typer CLI: argument parsing, output format selection
  scanner.py               # orchestrates discovery + checks + config/suppression filtering
  config.py                 # .mcpaudit.toml loading (ignore rules/paths, severity, custom_rules)
  suppressions.py           # inline "# mcp-audit: ignore[...]" comment handling
  report.py                 # table / json / sarif rendering
  rules.py                  # rule ID -> human-readable title registry
  checks/
    manifest_checks.py      # tool description checks (JSON manifests + source-embedded strings)
    code_checks.py          # dangerous-sink checks (eval, shell=True, pickle.loads, ...)
    secrets_checks.py        # hardcoded credential regexes
    config_checks.py         # unsafe server defaults (bind-all, disabled auth)
    custom_checks.py         # runs user-defined [[custom_rules]] from .mcpaudit.toml
tests/
  fixtures/
    vulnerable_server/       # intentionally insecure — should trigger findings
    clean_server/            # intentionally clean — should trigger zero findings
```

## Adding a new rule

Every existing rule follows the same pattern, and new ones should too:

1. Pick the next unused rule ID in the right family (`MCP0xx` for
   manifest/description checks, `MCP1xx` for dangerous code paths, `MCP2xx`
   for secrets, `MCP3xx` for config/defaults) and add it to `RULES` in
   `rules.py`.
2. Implement the check in the relevant `checks/*.py` module, returning
   `Finding` objects (see `models.py`).
3. Add **both** a positive and a negative fixture:
   - Add the vulnerable pattern to `tests/fixtures/vulnerable_server/` (a new
     file if it doesn't fit an existing one).
   - Confirm `tests/fixtures/clean_server/` does *not* trigger it.
4. Write a test in `tests/test_<whatever>_checks.py` asserting the rule ID
   fires on the vulnerable fixture and doesn't fire on the clean one — that's
   the two-sided check that catches both missed detections and false
   positives later.
5. Update the Rules table in `README.md`.

## Adding language support

Source-code checks (`code_checks.py`, and description extraction in
`manifest_checks.scan_source_descriptions`) currently cover
`.py`/`.js`/`.ts`/`.mjs`/`.cjs`. Adding a new language means:

- Adding the suffix to `SOURCE_SUFFIXES` in `discovery.py`.
- Adding dangerous-sink patterns for that language to `code_checks.py`.
- Extending the name/description extraction regexes in `manifest_checks.py`
  if the language's string-literal or tool-registration syntax differs
  meaningfully from what's already handled.

## Running the checks against yourself

Useful sanity check before opening a PR — scan the project's own fixtures and
confirm nothing regressed:

```bash
mcp-audit scan tests/fixtures/vulnerable_server --format json
mcp-audit scan tests/fixtures/clean_server   # should print "No issues found."
```

## Pull requests

- Keep PRs scoped to one rule/feature — easier to review, easier to revert if
  something's wrong.
- Tests are required for new checks (see above); PRs that add detection logic
  without a fixture pair will get asked for one.
- No dependencies beyond `typer`, `rich`, and `tomli` (Python <3.11) without a
  good reason — part of the point of this tool is that it makes zero network
  calls and has a tiny, auditable dependency footprint.

## Reporting false positives / false negatives

Both are genuinely useful bug reports, not just feature requests — a
pattern-based scanner is only as good as its precision. Open an issue with
the snippet that was (mis)matched.
