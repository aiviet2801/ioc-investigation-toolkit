from dataclasses import dataclass
from typing import Any


@dataclass
class InvestigationResult:
    ioc_type: str
    report: Any
