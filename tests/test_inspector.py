from __future__ import annotations

import pytest

from aegis_vm import assert_safe, inspect_code, scan_code
from aegis_vm.exceptions import SafetyViolationError, SyntaxInspectionError
from aegis_vm.policy import SafetyPolicy


SAFE_SNIPPETS = [
    "x = 1 + 2",
    "def add(a, b):\n    return a + b",
    "items = [n * 2 for n in range(5)]",
    "result = {'ok': True}",
]


UNSAFE_CASES = [
    ("import os", "dangerous_import"),
    ("from subprocess import run", "dangerous_import"),
    ("import json", "import"),
    ("eval('1+1')", "eval"),
    ("exec('x = 1')", "exec"),
    ("compile('pass', '<s>', 'exec')", "dynamic_execution"),
    ("import os; os.system('ls')", "shell_execution"),
    ("import subprocess; subprocess.run(['ls'])", "subprocess"),
    ("run(['ls'])", "subprocess"),
    ("import socket; socket.create_connection(('127.0.0.1', 80))", "network_call"),
    ("import urllib.request; urllib.request.urlopen('http://example.com')", "network_call"),
    ("import requests; requests.get('http://example.com')", "network_call"),
    ("open('out.txt', 'w')", "file_write"),
    ("from pathlib import Path; Path('out.txt').write_text('hi')", "file_write"),
    ("obj.__globals__", "dunder_access"),
    ("().__class__.__bases__", "dunder_access"),
    ("getattr(obj, 'secret')", "dangerous_builtin"),
    ('path = "../etc/passwd"', "path_traversal"),
]


@pytest.mark.parametrize("source", SAFE_SNIPPETS)
def test_safe_code_passes(source: str) -> None:
    result = inspect_code(source)
    assert result.safe
    assert result.findings == []


@pytest.mark.parametrize("source,rule_id", UNSAFE_CASES)
def test_unsafe_code_is_flagged(source: str, rule_id: str) -> None:
    result = inspect_code(source)
    assert not result.safe
    assert any(finding.rule_id == rule_id for finding in result.errors)


def test_read_only_open_is_allowed_in_lenient_policy() -> None:
    result = inspect_code("open('/etc/passwd', 'r')", policy=SafetyPolicy.lenient())
    assert result.safe


def test_assert_safe_raises_for_violations() -> None:
    with pytest.raises(SafetyViolationError) as exc_info:
        assert_safe("import os")
    assert exc_info.value.result.errors[0].rule_id == "dangerous_import"


def test_syntax_error_is_reported() -> None:
    with pytest.raises(SyntaxInspectionError):
        inspect_code("def broken(")


def test_lenient_policy_allows_benign_imports() -> None:
    result = inspect_code("import json", policy=SafetyPolicy.lenient())
    assert result.safe


def test_lenient_policy_blocks_dangerous_imports() -> None:
    result = inspect_code("import subprocess", policy=SafetyPolicy.lenient())
    assert not result.safe
    assert result.errors[0].rule_id == "dangerous_import"


def test_lenient_policy_still_blocks_eval() -> None:
    result = inspect_code("eval('1')", policy=SafetyPolicy.lenient())
    assert not result.safe
    assert result.errors[0].rule_id == "eval"


def test_lenient_policy_still_blocks_network_calls() -> None:
    result = inspect_code(
        "import socket; socket.socket()",
        policy=SafetyPolicy.lenient(),
    )
    assert not result.safe
    assert any(error.rule_id == "network_call" for error in result.errors)


def test_finding_string_representation() -> None:
    result = inspect_code("eval('1')")
    finding = result.errors[0]
    assert "eval" in str(finding)
    assert "line" in str(finding)


def test_scan_code_returns_summary_dict() -> None:
    result = scan_code("eval('1')")

    assert result["severity"] == "error"
    assert len(result["reasons"]) == 1
    assert "eval()" in result["reasons"][0]
    assert len(result["flagged_nodes"]) == 1

    node = result["flagged_nodes"][0]
    assert node["rule_id"] == "eval"
    assert node["node_type"] == "Call"
    assert node["lineno"] >= 1
    assert node["reason"] == result["reasons"][0]
    assert node["severity"] == "error"


def test_scan_code_safe_source() -> None:
    result = scan_code("x = 1 + 2")
    assert result == {"severity": "safe", "reasons": [], "flagged_nodes": []}


def test_scan_code_syntax_error() -> None:
    result = scan_code("def broken(")
    assert result["severity"] == "error"
    assert result["reasons"][0].startswith("Syntax error:")
    assert result["flagged_nodes"] == []
