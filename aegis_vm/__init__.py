"""AST-based safety inspection for untrusted Python code."""

from aegis_vm.exceptions import SafetyViolationError, SyntaxInspectionError
from aegis_vm.inspector import SafetyInspector, assert_safe, inspect_code, inspect_file, scan_code
from aegis_vm.policy import SafetyPolicy
from aegis_vm.types import Finding, InspectionResult, Severity

__all__ = [
    "Finding",
    "InspectionResult",
    "SafetyInspector",
    "SafetyPolicy",
    "SafetyViolationError",
    "Severity",
    "SyntaxInspectionError",
    "assert_safe",
    "inspect_code",
    "inspect_file",
    "scan_code",
]

__version__ = "0.1.0"
