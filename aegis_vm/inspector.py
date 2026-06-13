from __future__ import annotations

import ast
from pathlib import Path

from aegis_vm.exceptions import SafetyViolationError, SyntaxInspectionError
from aegis_vm.policy import SafetyPolicy
from aegis_vm.types import Finding, InspectionResult, Severity


def scan_code(
    source: str,
    *,
    policy: SafetyPolicy | None = None,
    filename: str = "<string>",
) -> dict[str, object]:
    """Inspect *source* and return a summary dict for downstream tooling."""
    try:
        result = inspect_code(source, policy=policy, filename=filename)
    except SyntaxInspectionError as exc:
        return {
            "severity": Severity.ERROR.value,
            "reasons": [f"Syntax error: {exc.msg}"],
            "flagged_nodes": [],
        }

    if any(finding.severity is Severity.ERROR for finding in result.findings):
        severity = Severity.ERROR.value
    elif result.findings:
        severity = Severity.WARNING.value
    else:
        severity = "safe"

    return {
        "severity": severity,
        "reasons": [finding.message for finding in result.findings],
        "flagged_nodes": [finding.to_flagged_node() for finding in result.findings],
    }


def inspect_code(
    source: str,
    *,
    policy: SafetyPolicy | None = None,
    filename: str = "<string>",
) -> InspectionResult:
    """Parse *source* and return structural safety findings."""
    policy = policy or SafetyPolicy.strict()
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise SyntaxInspectionError(exc.msg, (filename, exc.lineno, exc.offset, source)) from exc

    inspector = SafetyInspector(policy)
    inspector.visit(tree)
    return InspectionResult(source=source, findings=inspector.findings)


def inspect_file(
    path: str | Path,
    *,
    policy: SafetyPolicy | None = None,
) -> InspectionResult:
    """Read a file and inspect its contents."""
    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8")
    return inspect_code(source, policy=policy, filename=str(file_path))


def assert_safe(
    source: str,
    *,
    policy: SafetyPolicy | None = None,
    filename: str = "<string>",
) -> InspectionResult:
    """Inspect *source* and raise ``SafetyViolationError`` when unsafe."""
    result = inspect_code(source, policy=policy, filename=filename)
    if not result.safe:
        raise SafetyViolationError(result)
    return result


class SafetyInspector(ast.NodeVisitor):
    """Walk a Python AST and collect policy violations."""

    def __init__(self, policy: SafetyPolicy | None = None) -> None:
        self.policy = policy or SafetyPolicy.strict()
        self.findings: list[Finding] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._report_import(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            qualified = f"{module}.{alias.name}" if module else alias.name
            self._report_import(node, qualified, from_module=module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qualified = _qualified_call_name(node.func)
        simple = _call_name(node.func)

        if self.policy.block_eval and simple == "eval":
            self._add("eval", "Call to forbidden builtin: eval()", node)

        if self.policy.block_exec and simple == "exec":
            self._add("exec", "Call to forbidden builtin: exec()", node)

        if self.policy.block_dynamic_execution and simple in self.policy.dynamic_execution_names:
            self._add(
                "dynamic_execution",
                f"Call to forbidden dynamic execution builtin: {simple}()",
                node,
            )

        if self.policy.block_shell_execution and qualified in self.policy.shell_execution_calls:
            self._add(
                "shell_execution",
                f"Call to forbidden shell execution API: {qualified}()",
                node,
            )

        if self.policy.block_subprocess and _is_subprocess_call(
            qualified, simple, self.policy
        ):
            self._add(
                "subprocess",
                f"Call to forbidden subprocess API: {qualified or simple}()",
                node,
            )

        if self.policy.block_network and _is_network_call(qualified, simple, self.policy):
            self._add(
                "network_call",
                f"Call to forbidden network API: {qualified or simple}()",
                node,
            )

        if self.policy.block_file_writes and _is_file_write_call(node, qualified, simple, self.policy):
            self._add(
                "file_write",
                f"Call to forbidden file write API: {qualified or simple}()",
                node,
            )

        if self.policy.block_dangerous_builtins and simple in self.policy.dangerous_builtin_names:
            self._add(
                "dangerous_builtin",
                f"Call to forbidden builtin: {simple}()",
                node,
            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self.policy.block_dunder_attributes and self._is_blocked_dunder(node.attr):
            self._add(
                "dunder_access",
                f"Access to forbidden attribute: {node.attr}",
                node,
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if self.policy.block_path_traversal and isinstance(node.value, str):
            if _contains_path_traversal(node.value):
                self._add(
                    "path_traversal",
                    "String literal contains parent-directory traversal ('..')",
                    node,
                )
        self.generic_visit(node)

    def _report_import(
        self,
        node: ast.AST,
        qualified_name: str,
        *,
        from_module: str = "",
    ) -> None:
        module_root = (
            from_module.split(".", 1)[0]
            if from_module
            else qualified_name.split(".", 1)[0]
        )
        is_dangerous = module_root in self.policy.blocked_import_roots

        if self.policy.block_imports:
            rule_id = "dangerous_import" if is_dangerous else "import"
            self._add(
                rule_id,
                f"Import of forbidden module: {qualified_name}",
                node,
            )
            return

        if self.policy.block_dangerous_imports and is_dangerous:
            self._add(
                "dangerous_import",
                f"Import of forbidden module: {qualified_name}",
                node,
            )

    def _is_blocked_dunder(self, attr: str) -> bool:
        if attr in self.policy.blocked_dunder_names:
            return True
        return attr.startswith("__") and attr.endswith("__")

    def _add(self, rule_id: str, message: str, node: ast.AST) -> None:
        node_type, lineno, col_offset, end_lineno, end_col_offset = _node_span(node)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                message=message,
                lineno=lineno,
                col_offset=col_offset,
                end_lineno=end_lineno,
                end_col_offset=end_col_offset,
                node_type=node_type,
                severity=Severity.ERROR,
            )
        )


def _node_span(node: ast.AST) -> tuple[str, int, int, int, int]:
    lineno = getattr(node, "lineno", 0)
    col_offset = getattr(node, "col_offset", 0)
    end_lineno = getattr(node, "end_lineno", lineno)
    end_col_offset = getattr(node, "end_col_offset", col_offset)
    return type(node).__name__, lineno, col_offset, end_lineno, end_col_offset


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _qualified_call_name(func: ast.AST) -> str | None:
    parts: list[str] = []
    current: ast.AST = func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _is_subprocess_call(
    qualified: str | None,
    simple: str | None,
    policy: SafetyPolicy,
) -> bool:
    if qualified and qualified.startswith("subprocess."):
        suffix = qualified.split(".", 1)[1]
        return suffix in policy.subprocess_call_names or suffix == "subprocess"
    return simple in policy.subprocess_call_names


def _is_network_call(
    qualified: str | None,
    simple: str | None,
    policy: SafetyPolicy,
) -> bool:
    if qualified:
        root = qualified.split(".", 1)[0]
        if root in policy.network_module_prefixes:
            return True
        if simple in policy.network_call_names and root in policy.network_module_prefixes:
            return True
    return False


def _is_file_write_call(
    node: ast.Call,
    qualified: str | None,
    simple: str | None,
    policy: SafetyPolicy,
) -> bool:
    if qualified in policy.file_write_qualified_calls:
        return True

    if simple in policy.file_write_call_names:
        return True

    if simple == "open" and _open_uses_write_mode(node):
        return True

    if simple == "write" and isinstance(node.func, ast.Attribute):
        return True

    return False


def _open_uses_write_mode(node: ast.Call) -> bool:
    if len(node.args) < 2:
        return False

    mode_node = node.args[1]
    mode = _string_value(mode_node)
    if mode is None:
        return True

    normalized = mode.replace(" ", "").lower()
    if not normalized:
        return False
    if normalized[0] in {"w", "a", "x"}:
        return True
    return "+" in normalized


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _contains_path_traversal(value: str) -> bool:
    normalized = value.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    return ".." in parts
