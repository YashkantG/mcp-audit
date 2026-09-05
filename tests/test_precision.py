"""Precision regressions.

These encode lessons from surveying 143 public MCP server repositories, where
the large majority of raw findings turned out to be fake credentials in test
fixtures and deliberately-unsafe example code — not problems in shipped server
code. Each case below is a real pattern observed in that survey.
"""
import json

from mcp_audit.checks.manifest_checks import scan_manifest_file
from mcp_audit.scanner import scan

DANGEROUS = "import subprocess\nsubprocess.run('x', shell=True)\n"
LONG = "x " * 300  # over the MCP003 description-length threshold


def test_test_directories_are_skipped_by_default(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_thing.py").write_text(DANGEROUS)
    assert scan(tmp_path) == []


def test_include_tests_opts_back_in(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_thing.py").write_text(DANGEROUS)
    assert scan(tmp_path, include_tests=True)


def test_examples_and_benchmarks_are_skipped_by_default(tmp_path):
    for d in ("examples", "bench", "__mocks__", "fixtures"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "thing.py").write_text(DANGEROUS)
    assert scan(tmp_path) == []


def test_production_code_is_still_scanned(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text(DANGEROUS)
    findings = scan(tmp_path)
    assert any(f.rule_id == "MCP102" for f in findings)


def test_explicitly_named_test_file_is_still_scanned(tmp_path):
    """Pointing the scanner directly at a file means you meant it."""
    tests = tmp_path / "tests"
    tests.mkdir()
    target = tests / "test_thing.py"
    target.write_text(DANGEROUS)
    assert any(f.rule_id == "MCP102" for f in scan(target))


def test_vendored_code_is_never_scanned(tmp_path):
    for d in ("node_modules", "vendor", "third_party"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "thing.py").write_text(DANGEROUS)
    assert scan(tmp_path, include_tests=True) == []


def test_mock_credentials_are_not_reported_as_secrets(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "conf.py").write_text(
        'api_key = "local-mock-only-key-abcdef"\n'
        'token = "dummy-token-abcdefghijkl"\n'
        'password = "placeholder-value-1234"\n'
    )
    assert [f for f in scan(tmp_path) if f.rule_id == "MCP201"] == []


def test_a_real_looking_secret_is_still_reported(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "conf.py").write_text('api_key = "8f4b2c9d1e7a3f6b5c0d9e8a7b4f2c1d"\n')
    assert any(f.rule_id == "MCP201" for f in scan(tmp_path))


# --- JSON tool-detection precision -------------------------------------------
# Surveying real repos showed the manifest walker treating any JSON object with
# a "description" as an MCP tool: npm package manifests, OpenAPI operation
# summaries, and versioned schema files all matched.

def test_package_json_description_is_not_a_tool(tmp_path):
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"name": "some-package", "description": LONG}))
    assert scan_manifest_file(p) == []


def test_openapi_style_descriptions_are_not_tools(tmp_path):
    p = tmp_path / "openapi.sdk.json"
    p.write_text(json.dumps({
        "paths": {"/x": {"get": {"name": "getX", "description": LONG}}}
    }))
    assert scan_manifest_file(p) == []


def test_bare_name_description_pair_is_not_enough(tmp_path):
    p = tmp_path / "whatever.json"
    p.write_text(json.dumps({"name": "thing", "description": LONG}))
    assert scan_manifest_file(p) == []


def test_real_tool_with_input_schema_is_still_detected(tmp_path):
    p = tmp_path / "whatever.json"
    p.write_text(json.dumps({
        "name": "run_thing",
        "description": LONG,
        "inputSchema": {"type": "object", "properties": {}},
    }))
    assert any(f.rule_id == "MCP003" for f in scan_manifest_file(p))


def test_real_tool_nested_under_tools_key_is_still_detected(tmp_path):
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps({
        "tools": [{"name": "run_thing", "description": LONG}]
    }))
    assert any(f.rule_id == "MCP003" for f in scan_manifest_file(p))
