from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    file: str
    message: str
    line: int | None = None
    snippet: str | None = None
