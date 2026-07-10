"""Cross-collector timeline — Nikkel's MACB super-timeline, live edition.

This is not a new data source: it merges the timestamped rows every other
collector already produces (package installs, systemd unit / cron mtimes,
hot-dir file changes, authorized_keys & known_hosts edits) into one
chronologically sorted view — "what happened around the time of compromise" on
a single screen.

Two entry points:
- ``TimelineCollector.build(results)`` — the app calls this with the dict of
  already-collected ``CollectResult``s, so no work is repeated.
- ``TimelineCollector().collect()`` — for standalone/batch use it runs a default
  set of time-bearing collectors itself and then builds.
"""

from __future__ import annotations

import time

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

COLUMNS = [
    Column("when", "WHEN", 18),
    Column("age", "AGE", 8),
    Column("source", "SOURCE", 10),
    Column("event", "EVENT", 50),
    Column("flags", "FLAGS", 12),
]


class TimelineCollector(Collector):
    source = "timeline"
    title = "Timeline"
    cheap = False

    def collect(self) -> CollectResult:
        # standalone: run the time-bearing collectors and merge their rows
        from .files import FilesCollector
        from .integrity import IntegrityCollector
        from .persistence import PersistenceCollector
        from .users import UsersCollector

        results = {
            "persist": PersistenceCollector().collect(),
            "files": FilesCollector().collect(),
            "users": UsersCollector().collect(),
            "integrity": IntegrityCollector().collect(),
        }
        return self.build(results)

    @staticmethod
    def build(results: dict[str, CollectResult]) -> CollectResult:
        """Merge every timestamped row from ``results`` into one timeline."""
        out = CollectResult(columns=COLUMNS, rows=[])
        now = time.time()
        events: list[Row] = []
        for src, res in results.items():
            if src == "timeline":
                continue
            for row in res.rows:
                if row.timestamp is None:
                    continue
                when = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(row.timestamp)
                )
                events.append(Row(
                    values={
                        "when": when,
                        "age": _age(now - row.timestamp),
                        "source": src,
                        "event": _describe(row)[:50],
                        "flags": row.values.get("flags", ""),
                    },
                    severity=row.severity,
                    key=f"tl:{row.key}",
                    timestamp=row.timestamp,
                    detail=row.detail or _describe(row),
                ))
        events.sort(key=lambda r: r.timestamp or 0, reverse=True)  # newest first
        out.rows = events
        if not events:
            out.notes.append(
                "no timestamped events — run the file/persistence/integrity "
                "collectors first"
            )
        return out


def _describe(row: Row) -> str:
    """Best-effort one-line description from a source row's values."""
    v = row.values
    for key in ("path", "location", "subject", "detail"):
        if key in v and v[key]:
            return str(v[key])
    return str(next(iter(v.values()), ""))


def _age(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


if __name__ == "__main__":
    print_result(TimelineCollector().collect())
