from pathlib import Path

from mcp_triage.checks.code_checks import scan_source_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_dangerous_sinks():
    findings = scan_source_file(FIXTURES / "vulnerable_server" / "server.py")
    rule_ids = {f.rule_id for f in findings}
    assert "MCP101" in rule_ids  # eval()
    assert "MCP102" in rule_ids  # subprocess shell=True / os.system
    assert "MCP103" in rule_ids  # pickle.loads()


def test_clean_source_has_no_findings():
    findings = scan_source_file(FIXTURES / "clean_server" / "server.py")
    assert findings == []
