"""JSON report export: dump all findings + panel snapshots to a file.

Written for minimal evidence capture — the export is the only thing the tool
ever writes, and it goes to a user-chosen path (ideally external media).
"""

from __future__ import annotations

import json
import os
import platform
import socket
import time

from .collectors.base import CollectResult
from .findings import sort_findings
from . import __version__


def build_report(
    results: dict[str, CollectResult],
    comparison: dict | None = None,
    sentry_context: dict | None = None,
) -> dict:
    """Assemble a serialisable report from each collector's CollectResult."""
    all_findings = []
    for res in results.values():
        all_findings.extend(res.findings)

    panels = {}
    for name, res in results.items():
        panels[name] = {
            "columns": [c.key for c in res.columns],
            # Keep row metadata as well as display values: this is evidence,
            # not merely a rendering snapshot.
            "rows": [
                {
                    "values": dict(r.values),
                    "severity": r.severity.label if r.severity else None,
                    "key": r.key,
                    "detail": r.detail,
                    "timestamp": r.timestamp,
                }
                for r in res.rows
            ],
            "notes": list(res.notes),
            "duration_ms": res.duration_ms,
            "error": res.error,
        }

    report = {
        "tool": "spoorlog",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": socket.gethostname(),
        "kernel": platform.release(),
        "euid": os.geteuid(),
        "as_root": os.geteuid() == 0,
        "finding_counts": _counts(all_findings),
        "findings": [f.to_dict() for f in sort_findings(all_findings)],
        "panels": panels,
    }
    if comparison is not None:
        report["comparison"] = comparison
    if sentry_context is not None:
        report["sentry_context"] = sentry_context
    return report


def _counts(findings) -> dict:
    counts = {"CRIT": 0, "WARN": 0, "INFO": 0}
    for f in findings:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    return counts


def write_report(
    results: dict[str, CollectResult],
    path: str | None = None,
    comparison: dict | None = None,
    sentry_context: dict | None = None,
) -> str:
    """Write the report to ``path`` (or a timestamped file in cwd) and return
    the path actually written."""
    if path is None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.abspath(f"spoorlog-report-{socket.gethostname()}-{stamp}.json")
    report = build_report(results, comparison=comparison, sentry_context=sentry_context)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    return path
