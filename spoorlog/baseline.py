"""Portable baseline comparison for one-shot spoorlog reports.

Sentry owns long-lived monitoring and suppression. This module deliberately
stays small: it lets an investigator compare two manually captured spoorlog
reports without requiring Sentry's database.
"""

from __future__ import annotations

import json
from typing import Any


_VOLATILE_PANELS = {"timeline"}


def load_report(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    if report.get("tool") != "spoorlog":
        raise ValueError(f"{path} is not a spoorlog report")
    return report


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return added, removed, and changed rows for each comparable panel."""
    panels: dict[str, Any] = {}
    names = (set(baseline.get("panels", {})) | set(current.get("panels", {}))) - _VOLATILE_PANELS
    for name in sorted(names):
        before = _index_rows(baseline.get("panels", {}).get(name, {}).get("rows", []), name)
        after = _index_rows(current.get("panels", {}).get(name, {}).get("rows", []), name)
        added = [after[key] for key in sorted(set(after) - set(before))]
        removed = [before[key] for key in sorted(set(before) - set(after))]
        changed = [
            {"before": before[key], "after": after[key]}
            for key in sorted(set(before) & set(after))
            if _content(before[key]) != _content(after[key])
        ]
        panels[name] = {
            "added": added,
            "removed": removed,
            "changed": changed,
            "counts": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
            },
        }
    return {
        "baseline_generated_at": baseline.get("generated_at"),
        "current_generated_at": current.get("generated_at"),
        "panels": panels,
        "counts": {
            field: sum(panel["counts"][field] for panel in panels.values())
            for field in ("added", "removed", "changed")
        },
    }


def _index_rows(rows: list[dict[str, Any]], panel: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        # Reports before v1.0.0 used the values dict directly.
        normalized = row if "values" in row else {"values": row}
        key = _identity(normalized, panel)
        indexed[key] = normalized
    return indexed


def _identity(row: dict[str, Any], panel: str) -> str:
    values = row.get("values", {})
    key = row.get("key") or ""
    if panel == "proc" and values.get("pid") not in (None, ""):
        return f"pid:{values['pid']}"
    if panel == "net":
        return "net:" + "|".join(str(values.get(k, "")) for k in ("proto", "laddr", "raddr"))
    if key:
        return str(key)
    return "values:" + json.dumps(values, sort_keys=True, default=str)


def _content(row: dict[str, Any]) -> dict[str, Any]:
    """Exclude volatile evidence fields when deciding whether state changed."""
    return {k: row.get(k) for k in ("values", "severity")}
