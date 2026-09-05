from mcp_sentinel.scanner import scan


def _write(path, content):
    path.write_text(content)
    return path


def test_ignored_rules_are_dropped(tmp_path):
    _write(tmp_path / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcpsentinel.toml", '[ignore]\nrules = ["MCP102"]\n')
    findings = scan(tmp_path)
    assert findings == []


def test_ignored_paths_are_dropped(tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    _write(vendor / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcpsentinel.toml", '[ignore]\npaths = ["*/vendor/*"]\n')
    findings = scan(tmp_path)
    assert findings == []


def test_severity_override(tmp_path):
    _write(tmp_path / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcpsentinel.toml", '[severity]\nMCP102 = "LOW"\n')
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "LOW"


def test_custom_rule_fires(tmp_path):
    _write(tmp_path / "server.py", "InternalOnlyApi.execute('x')\n")
    _write(
        tmp_path / ".mcpsentinel.toml",
        '[[custom_rules]]\n'
        'id = "CUSTOM001"\n'
        'pattern = "InternalOnlyApi\\\\.execute"\n'
        'message = "Banned internal API"\n'
        'severity = "HIGH"\n',
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM001"
    assert findings[0].severity.value == "HIGH"


def test_no_config_file_is_a_noop(tmp_path):
    _write(tmp_path / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    findings = scan(tmp_path)
    assert len(findings) == 1


def test_extra_ignored_rules_param_combines_with_config(tmp_path):
    _write(
        tmp_path / "server.py",
        "import subprocess, os\n"
        "subprocess.run('x', shell=True)\n"
        "os.system('y')\n",
    )
    _write(tmp_path / ".mcpsentinel.toml", '[ignore]\nrules = ["MCP102"]\n')
    findings = scan(tmp_path, extra_ignored_rules={"MCP102"})
    rule_ids = {f.rule_id for f in findings}
    assert "MCP102" not in rule_ids
