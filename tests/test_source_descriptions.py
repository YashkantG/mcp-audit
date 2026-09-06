from pathlib import Path

from mcp_triage.checks.manifest_checks import scan_source_descriptions

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_prompt_injection_in_ts_source_description():
    findings = scan_source_descriptions(FIXTURES / "vulnerable_server" / "index.ts")
    rule_ids = {f.rule_id for f in findings}
    assert "MCP001" in rule_ids
    assert any(f.line == 4 for f in findings)


def test_clean_source_has_no_description_findings():
    findings = scan_source_descriptions(FIXTURES / "clean_server" / "server.py")
    assert findings == []
