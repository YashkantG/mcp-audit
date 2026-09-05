import json
from pathlib import Path

from mcp_sentinel.report import render_sarif
from mcp_sentinel.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_sarif_output_is_valid_json_with_expected_shape():
    target = FIXTURES / "vulnerable_server"
    findings = scan(target)
    sarif = json.loads(render_sarif(findings, target))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-sentinel"

    result_rule_ids = {r["ruleId"] for r in run["results"]}
    driver_rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert result_rule_ids <= driver_rule_ids

    high_result = next(r for r in run["results"] if r["ruleId"] == "MCP001")
    assert high_result["level"] == "error"


def test_sarif_paths_are_relative_to_root():
    target = FIXTURES / "vulnerable_server"
    findings = scan(target)
    sarif = json.loads(render_sarif(findings, target))
    for result in sarif["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not Path(uri).is_absolute()


def test_sarif_with_no_findings_is_still_valid():
    target = FIXTURES / "clean_server"
    findings = scan(target)
    sarif = json.loads(render_sarif(findings, target))
    assert sarif["runs"][0]["results"] == []
