from mcp_sentinel.scanner import scan


def test_bracketed_suppression_only_suppresses_listed_rule(tmp_path):
    server = tmp_path / "server.py"
    server.write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd, shell=True)  # mcp-sentinel: ignore[MCP102]\n"
    )
    findings = scan(tmp_path)
    assert findings == []


def test_bare_suppression_suppresses_everything_on_the_line(tmp_path):
    server = tmp_path / "server.py"
    server.write_text(
        "import os\n"
        "def run(cmd):\n"
        "    os.system(cmd)  # mcp-sentinel: ignore\n"
    )
    findings = scan(tmp_path)
    assert findings == []


def test_unsuppressed_line_still_flagged(tmp_path):
    server = tmp_path / "server.py"
    server.write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    findings = scan(tmp_path)
    assert any(f.rule_id == "MCP102" for f in findings)


def test_suppression_does_not_affect_other_lines(tmp_path):
    server = tmp_path / "server.py"
    server.write_text(
        "import subprocess, os\n"
        "def run1(cmd):\n"
        "    subprocess.run(cmd, shell=True)  # mcp-sentinel: ignore[MCP102]\n"
        "def run2(cmd):\n"
        "    os.system(cmd)\n"
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP102"
    assert findings[0].line == 5
