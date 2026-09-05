from pathlib import Path

from mcp_sentinel.checks.secrets_checks import scan_file_for_secrets

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_hardcoded_secrets():
    findings = scan_file_for_secrets(FIXTURES / "vulnerable_server" / "server.py")
    assert any(f.rule_id == "MCP201" for f in findings)

    findings = scan_file_for_secrets(FIXTURES / "vulnerable_server" / "mcp.json")
    assert any(f.rule_id == "MCP201" for f in findings)


def test_clean_files_have_no_secrets():
    findings = scan_file_for_secrets(FIXTURES / "clean_server" / "mcp.json")
    findings += scan_file_for_secrets(FIXTURES / "clean_server" / "server.py")
    assert findings == []
