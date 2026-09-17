"""Tests for portable baseline comparison."""

from spoorlog.baseline import compare_reports


def row(key, values, severity=None):
    return {"values": values, "severity": severity, "key": key, "detail": "evidence"}


def test_compare_reports_detects_added_removed_and_changed_rows():
    before = {"tool": "spoorlog", "generated_at": "old", "panels": {
        "proc": {"rows": [row("pid:1", {"pid": 1, "name": "old"})]},
        "timeline": {"rows": [row("tl:1", {"event": "old"})]},
    }}
    after = {"tool": "spoorlog", "generated_at": "new", "panels": {
        "proc": {"rows": [row("pid:1", {"pid": 1, "name": "new"}), row("pid:2", {"pid": 2})]},
    }}

    diff = compare_reports(before, after)

    assert diff["counts"] == {"added": 1, "removed": 0, "changed": 1}
    assert diff["panels"]["proc"]["changed"][0]["before"]["values"]["name"] == "old"
    assert "timeline" not in diff["panels"]


def test_network_identity_ignores_ephemeral_file_descriptor():
    before = {"tool": "spoorlog", "panels": {"net": {"rows": [
        row("net:3:a:b", {"proto": "tcp", "laddr": "0.0.0.0:22", "raddr": ""})
    ]}}}
    after = {"tool": "spoorlog", "panels": {"net": {"rows": [
        row("net:9:a:b", {"proto": "tcp", "laddr": "0.0.0.0:22", "raddr": ""})
    ]}}}

    assert compare_reports(before, after)["counts"] == {
        "added": 0, "removed": 0, "changed": 0
    }
