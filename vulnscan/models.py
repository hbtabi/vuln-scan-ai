from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str = ""  # always redacted for secrets
    fix: str = ""
    category: str = "config"  # secret | dependency | docker | ci | code | config

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file
