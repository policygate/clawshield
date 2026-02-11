from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Fact:
    key: str
    value: Any
    source: str


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    evidence: list[Fact]
    recommended_actions: list[str]
    autofix_available: bool = False
