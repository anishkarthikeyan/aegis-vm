from __future__ import annotations

from aegis_vm.types import Finding, InspectionResult


class SyntaxInspectionError(SyntaxError):
    """Raised when source code cannot be parsed into an AST."""


class SafetyViolationError(Exception):
    """Raised when inspected code violates the active safety policy."""

    def __init__(self, result: InspectionResult) -> None:
        self.result = result
        messages = "\n".join(str(finding) for finding in result.errors)
        super().__init__(messages or "Code failed safety inspection.")


def format_findings(findings: list[Finding]) -> str:
    return "\n".join(str(finding) for finding in findings)
