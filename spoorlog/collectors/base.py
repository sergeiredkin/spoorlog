"""Collector abstract base class and shared helpers.

Design goals:
- UI-free: collectors return plain data, never render.
- Read-only: collectors only read /proc, config files, and logs.
- Graceful under low privilege: helpers convert PermissionError into a
  ``needs_root`` signal instead of crashing.
"""

from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from ..findings import Finding, Severity


@dataclass
class Column:
    """A table column definition for a collector's rows."""

    key: str
    label: str
    width: int | None = None


@dataclass
class Row:
    """One table row.

    ``values`` maps column key -> display value. ``severity`` (if set) colors
    the row. ``key`` links the row to a finding and to a detail popup.
    ``detail`` holds the full evidence text shown on Enter.
    """

    values: dict[str, Any]
    severity: Severity | None = None
    key: str = ""
    detail: str = ""
    #: optional event time (epoch seconds). Rows that set this are merged into
    #: the cross-collector Timeline panel.
    timestamp: float | None = None


@dataclass
class CollectResult:
    """Everything a collector produces in one pass."""

    columns: list[Column]
    rows: list[Row]
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # e.g. "needs root for X"

    def add_finding(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))


class Collector(ABC):
    """Base class for all collectors."""

    #: short tag used as the finding source ("proc", "net", ...)
    source: str = "base"
    #: human title shown on the tab / panel header
    title: str = "Base"
    #: whether the app's slow auto-refresh loop should re-run this collector.
    #: File-walk and log-parse collectors set this False to limit footprint.
    cheap: bool = True

    @abstractmethod
    def collect(self) -> CollectResult:
        """Gather data and return rows + findings. Must not raise for expected
        permission errors — use the helpers below."""
        raise NotImplementedError

    # ---- shared helpers ---------------------------------------------------

    @staticmethod
    def is_root() -> bool:
        return os.geteuid() == 0

    @staticmethod
    def run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
        """Run a read-only command, returning (rc, stdout, stderr).

        Never raises for a missing binary or timeout — returns rc 127/124 so
        the collector can degrade gracefully on a stripped-down target.
        """
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"{cmd[0]}: not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"{cmd[0]}: timed out"
        except Exception as exc:  # pragma: no cover - defensive
            return 1, "", str(exc)

    @staticmethod
    def read_text(path: str) -> tuple[str | None, bool]:
        """Read a file. Returns (contents, needs_root).

        needs_root is True when the read failed on PermissionError.
        """
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read(), False
        except PermissionError:
            return None, True
        except (FileNotFoundError, IsADirectoryError, OSError):
            return None, False


def print_result(result: CollectResult) -> None:
    """Pretty-print a CollectResult to stdout for standalone collector runs."""
    from ..findings import sort_findings

    cols = result.columns
    header = "  ".join(c.label for c in cols)
    print(header)
    print("-" * len(header))
    for row in result.rows:
        mark = f"[{row.severity.label}] " if row.severity else ""
        print(mark + "  ".join(str(row.values.get(c.key, "")) for c in cols))
    print()
    if result.notes:
        for n in result.notes:
            print(f"note: {n}")
        print()
    print(f"== {len(result.findings)} finding(s) ==")
    for f in sort_findings(result.findings):
        print(f"[{f.severity.label}] {f.source}: {f.title}")
        if f.detail:
            print(f"    {f.detail}")
