import json
from pathlib import Path

from mcp_triage.models import Finding, Severity
from mcp_triage.report import grade, render_badge
from mcp_triage.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def _f(severity, rule_id="MCP001"):
    return Finding(rule_id=rule_id, severity=severity, file="x.py", message="m")


def test_grade_a_when_clean():
    assert grade([]) == "A"


def test_grade_b_for_few_mediums():
    assert grade([_f(Severity.MEDIUM)]) == "B"


def test_grade_c_for_many_mediums():
    assert grade([_f(Severity.MEDIUM) for _ in range(5)]) == "C"


def test_grade_d_for_a_high():
    assert grade([_f(Severity.HIGH)]) == "D"


def test_grade_f_for_many_highs():
    assert grade([_f(Severity.HIGH) for _ in range(5)]) == "F"


def test_high_dominates_medium():
    findings = [_f(Severity.HIGH)] + [_f(Severity.MEDIUM) for _ in range(10)]
    assert grade(findings) == "D"


def test_badge_is_valid_shields_endpoint_schema():
    badge = json.loads(render_badge([]))
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "mcp security"
    assert badge["color"] == "brightgreen"
    assert "A" in badge["message"]


def test_badge_reports_counts_for_dirty_target():
    findings = scan(FIXTURES / "vulnerable_server", include_tests=True)
    badge = json.loads(render_badge(findings))
    assert badge["color"] in {"red", "orange"}
    assert "high" in badge["message"]


def test_badge_message_stays_short_enough_to_render():
    findings = scan(FIXTURES / "vulnerable_server", include_tests=True)
    badge = json.loads(render_badge(findings))
    # shields.io renders long messages, but a badge nobody can read is useless.
    assert len(badge["message"]) <= 40
