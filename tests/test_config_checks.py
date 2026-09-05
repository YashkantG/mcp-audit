from pathlib import Path

from mcp_sentinel.checks.config_checks import scan_config_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_bind_all_and_disabled_trust():
    findings = scan_config_file(FIXTURES / "vulnerable_server" / "mcp.json")
    rule_ids = {f.rule_id for f in findings}
    assert "MCP301" in rule_ids  # host 0.0.0.0
    assert "MCP302" in rule_ids  # trust: true


def test_clean_config_has_no_findings():
    findings = scan_config_file(FIXTURES / "clean_server" / "mcp.json")
    assert findings == []
