from __future__ import annotations

import pytest

from aegis_vm import inspect_code, scan_code

SAFE_SNIPPETS = [
    pytest.param("x = 1 + 2", id="arithmetic"),
    pytest.param("def add(a, b):\n    return a + b", id="function"),
    pytest.param("items = [n * 2 for n in range(5)]", id="comprehension"),
    pytest.param("result = {'ok': True, 'count': 3}", id="dict-literal"),
    pytest.param("total = sum([1, 2, 3, 4])", id="builtin-sum"),
    pytest.param(
        "class Calculator:\n    def mul(self, a, b):\n        return a * b",
        id="class-definition",
    ),
    pytest.param("label = f'value={42}'", id="f-string"),
    pytest.param("double = lambda n: n * 2", id="lambda"),
    pytest.param(
        "for item in ['a', 'b']:\n    value = item.upper()",
        id="for-loop",
    ),
    pytest.param(
        "try:\n    value = 10 / 2\nexcept ZeroDivisionError:\n    value = 0",
        id="try-except",
    ),
    pytest.param(
        "mapping = {key: key.upper() for key in ['a', 'b']}",
        id="dict-comprehension",
    ),
    pytest.param("open('notes.txt', 'r')", id="read-only-open"),
]

UNSAFE_SNIPPETS = [
    pytest.param("eval('1 + 1')", {"eval"}, id="eval"),
    pytest.param("exec('x = 1')", {"exec"}, id="exec"),
    pytest.param(
        "compile('pass', '<s>', 'exec')",
        {"dynamic_execution"},
        id="compile",
    ),
    pytest.param(
        "__import__('os')",
        {"dynamic_execution"},
        id="dunder-import",
    ),
    pytest.param("import os", {"dangerous_import"}, id="import-os"),
    pytest.param(
        "from subprocess import run",
        {"dangerous_import"},
        id="import-subprocess",
    ),
    pytest.param("import json", {"import"}, id="import-json-strict"),
    pytest.param(
        "import os\nos.system('ls')",
        {"dangerous_import", "shell_execution"},
        id="os-system",
    ),
    pytest.param(
        "import subprocess\nsubprocess.run(['ls'])",
        {"dangerous_import", "subprocess"},
        id="subprocess-run",
    ),
    pytest.param("Popen(['ls'])", {"subprocess"}, id="subprocess-popen"),
    pytest.param(
        "import socket\nsocket.create_connection(('127.0.0.1', 80))",
        {"dangerous_import", "network_call"},
        id="socket-connect",
    ),
    pytest.param(
        "import urllib.request\nurllib.request.urlopen('http://example.com')",
        {"dangerous_import", "network_call"},
        id="urllib-urlopen",
    ),
    pytest.param(
        "import requests\nrequests.post('http://example.com', data={})",
        {"dangerous_import", "network_call"},
        id="requests-post",
    ),
    pytest.param(
        "open('out.txt', 'w')",
        {"file_write"},
        id="open-write-mode",
    ),
    pytest.param(
        "from pathlib import Path\nPath('out.txt').write_text('hi')",
        {"dangerous_import", "file_write"},
        id="path-write-text",
    ),
    pytest.param(
        "import shutil\nshutil.rmtree('/tmp/data')",
        {"dangerous_import", "file_write"},
        id="shutil-rmtree",
    ),
    pytest.param("obj.__globals__", {"dunder_access"}, id="globals-access"),
    pytest.param(
        "().__class__.__bases__",
        {"dunder_access"},
        id="class-bases-access",
    ),
    pytest.param(
        "getattr(obj, 'secret')",
        {"dangerous_builtin"},
        id="getattr",
    ),
    pytest.param(
        'target = "../etc/passwd"',
        {"path_traversal"},
        id="path-traversal",
    ),
]


@pytest.mark.parametrize("source", SAFE_SNIPPETS)
def test_safe_snippets_pass_inspection(source: str) -> None:
    result = inspect_code(source)
    assert result.safe
    assert result.findings == []


@pytest.mark.parametrize("source", SAFE_SNIPPETS)
def test_safe_snippets_scan_as_safe(source: str) -> None:
    report = scan_code(source)
    assert report["severity"] == "safe"
    assert report["reasons"] == []
    assert report["flagged_nodes"] == []


@pytest.mark.parametrize("source,expected_rules", UNSAFE_SNIPPETS)
def test_unsafe_snippets_are_flagged(
    source: str,
    expected_rules: set[str],
) -> None:
    result = inspect_code(source)
    assert not result.safe
    flagged_rules = {finding.rule_id for finding in result.errors}
    assert expected_rules.issubset(flagged_rules)


@pytest.mark.parametrize("source,expected_rules", UNSAFE_SNIPPETS)
def test_unsafe_snippets_scan_as_error(
    source: str,
    expected_rules: set[str],
) -> None:
    report = scan_code(source)
    assert report["severity"] == "error"
    assert report["reasons"]
    assert len(report["flagged_nodes"]) >= len(expected_rules)

    flagged_rules = {node["rule_id"] for node in report["flagged_nodes"]}
    assert expected_rules.issubset(flagged_rules)

    for node in report["flagged_nodes"]:
        assert node["node_type"]
        assert node["lineno"] >= 1
        assert node["reason"] in report["reasons"]
        assert node["severity"] == "error"
