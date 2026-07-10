"""Finding model and severity definitions shared by every collector.

A *finding* is a single triage observation with a severity. Collectors produce
findings alongside their raw rows; the Overview dashboard aggregates them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that a plain sort (reverse=True) puts CRITICAL first."""

    INFO = 0
    WARNING = 1
    CRITICAL = 2

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "INFO",
            Severity.WARNING: "WARN",
            Severity.CRITICAL: "CRIT",
        }[self]

    @property
    def color(self) -> str:
        """Textual/Rich color name used to render this severity."""
        return {
            Severity.INFO: "dim",
            Severity.WARNING: "yellow",
            Severity.CRITICAL: "red",
        }[self]


@dataclass
class Finding:
    """A single triage observation.

    Attributes:
        severity: how alarming this is.
        source: short collector tag ("proc", "net", "users", ...).
        title: one-line summary shown in the findings feed.
        detail: optional longer explanation / raw evidence.
        key: stable identifier used to link a finding back to a table row.
    """

    severity: Severity
    source: str
    title: str
    detail: str = ""
    key: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.label,
            "source": self.source,
            "title": self.title,
            "detail": self.detail,
            "key": self.key,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, stable within a severity level."""
    return sorted(findings, key=lambda f: f.severity, reverse=True)
