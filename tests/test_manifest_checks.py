from pathlib import Path

from mcp_sentinel.checks.manifest_checks import scan_manifest_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_prompt_injection_and_broad_capability_and_open_schema():
    findings = scan_manifest_file(FIXTURES / "vulnerable_server" / "mcp.json")
    rule_ids = {f.rule_id for f in findings}
    assert "MCP001" in rule_ids  # prompt injection phrasing
    assert "MCP004" in rule_ids  # broad capability keyword ("shell")
    assert "MCP005" in rule_ids  # additionalProperties: true


def test_clean_manifest_has_no_manifest_findings():
    findings = scan_manifest_file(FIXTURES / "clean_server" / "mcp.json")
    assert findings == []
