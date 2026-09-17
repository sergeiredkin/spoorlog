"""Tests for evidence-preserving JSON reports."""

import json

from spoorlog.collectors.base import CollectResult, Column, Row
from spoorlog.findings import Finding, Severity
from spoorlog.report import build_report


def test_report_preserves_row_evidence_and_scan_metadata():
    result = CollectResult(
        columns=[Column("path", "PATH")],
        rows=[Row(
            values={"path": "/tmp/payload"},
            severity=Severity.CRITICAL,
            key="file:1",
            detail="Executable found in a temporary directory",
            timestamp=1700000000.0,
        )],
        findings=[Finding(
            Severity.CRITICAL, "files", "Executable in temp", key="file:1"
        )],
        notes=["needs root for /proc"],
        duration_ms=12.3,
    )
    report = build_report({"files": result})

    assert report["version"] == "1.0.0"
    assert report["finding_counts"] == {"CRIT": 1, "WARN": 0, "INFO": 0}
    row = report["panels"]["files"]["rows"][0]
    assert row == {
        "values": {"path": "/tmp/payload"},
        "severity": "CRIT",
        "key": "file:1",
        "detail": "Executable found in a temporary directory",
        "timestamp": 1700000000.0,
    }
    assert report["panels"]["files"]["duration_ms"] == 12.3
    assert report["panels"]["files"]["error"] is None


def test_report_is_json_serializable():
    result = CollectResult(columns=[], rows=[])
    encoded = json.dumps(build_report({"empty": result}))
    assert '"tool": "spoorlog"' in encoded
