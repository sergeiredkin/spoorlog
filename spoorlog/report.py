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


def build_report(results: dict[str, CollectResult]) -> dict:
    """Assemble a serialisable report from each collector's CollectResult."""
    all_findings = []
    for res in results.values():
        all_findings.extend(res.findings)

    panels = {}
    for name, res in results.items():
        panels[name] = {
            "columns": [c.key for c in res.columns],
            "rows": [dict(r.values) for r in res.rows],
            "notes": list(res.notes),
        }

    return {
        "tool": "spoorlog",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": socket.gethostname(),
        "kernel": platform.release(),
        "euid": os.geteuid(),
        "as_root": os.geteuid() == 0,
        "finding_counts": _counts(all_findings),
        "findings": [f.to_dict() for f in sort_findings(all_findings)],
        "panels": panels,
    }


def _counts(findings) -> dict:
    counts = {"CRIT": 0, "WARN": 0, "INFO": 0}
    for f in findings:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    return counts


def write_report(results: dict[str, CollectResult], path: str | None = None) -> str:
    """Write the report to ``path`` (or a timestamped file in cwd) and return
    the path actually written."""
    if path is None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.abspath(f"spoorlog-report-{socket.gethostname()}-{stamp}.json")
    report = build_report(results)
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    return path
