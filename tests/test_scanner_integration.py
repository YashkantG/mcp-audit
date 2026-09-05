from pathlib import Path

from mcp_audit.models import Severity
from mcp_audit.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_vulnerable_server_produces_high_severity_findings():
    findings = scan(FIXTURES / "vulnerable_server", include_tests=True)
    assert findings
    assert any(f.severity == Severity.HIGH for f in findings)


def test_clean_server_produces_no_findings():
    findings = scan(FIXTURES / "clean_server", include_tests=True)
    assert findings == []
