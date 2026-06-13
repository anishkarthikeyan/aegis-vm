from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    message: str
    lineno: int
    col_offset: int
    severity: Severity = Severity.ERROR
    node_type: str = ""
    end_lineno: int = 0
    end_col_offset: int = 0

    def __str__(self) -> str:
        return (
            f"[{self.severity.value}] {self.rule_id} "
            f"(line {self.lineno}, col {self.col_offset}): {self.message}"
        )

    def to_flagged_node(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "node_type": self.node_type,
            "lineno": self.lineno,
            "col_offset": self.col_offset,
            "end_lineno": self.end_lineno,
            "end_col_offset": self.end_col_offset,
            "severity": self.severity.value,
            "reason": self.message,
        }


@dataclass(slots=True)
class InspectionResult:
    source: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not any(f.severity is Severity.ERROR for f in self.findings)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]
