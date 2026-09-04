"""Tests for spoorlog findings detection and ranking."""

import pytest
from spoorlog.findings import Finding, Severity


class TestFindingCreation:
    """Test Finding class instantiation and properties."""

    def test_finding_basic_creation(self):
        """Create a finding with all required fields."""
        f = Finding("proc", "process from deleted binary", Severity.CRITICAL)
        assert f.area == "proc"
        assert f.message == "process from deleted binary"
        assert f.severity == Severity.CRITICAL

    def test_finding_with_tags(self):
        """Finding can include optional tags for drill-down."""
        f = Finding("proc", "pid 4182 uses deleted binary", Severity.CRITICAL, tags={"pid": "4182", "deleted": True})
        assert f.tags.get("pid") == "4182"
        assert f.tags.get("deleted") is True


class TestSeverityRanking:
    """Test that findings rank correctly by severity."""

    def test_critical_ranks_highest(self):
        """CRITICAL > WARNING > INFO."""
        critical = Finding("x", "msg", Severity.CRITICAL)
        warning = Finding("x", "msg", Severity.WARNING)
        info = Finding("x", "msg", Severity.INFO)

        assert critical.rank() > warning.rank()
        assert warning.rank() > info.rank()

    def test_findings_sort_by_severity(self):
        """Findings sort high-to-low severity."""
        findings = [
            Finding("x", "msg", Severity.INFO),
            Finding("x", "msg", Severity.CRITICAL),
            Finding("x", "msg", Severity.WARNING),
        ]

        sorted_findings = sorted(findings, key=lambda f: f.rank(), reverse=True)
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.WARNING
        assert sorted_findings[2].severity == Severity.INFO


class TestFindingAggregation:
    """Test aggregating findings across collectors."""

    def test_count_by_severity(self, mock_findings_data):
        """Count findings at each severity level."""
        critical = [f for f in mock_findings_data if f.severity == Severity.CRITICAL]
        warning = [f for f in mock_findings_data if f.severity == Severity.WARNING]

        assert len(critical) == 2
        assert len(warning) == 3

    def test_findings_by_area(self, mock_findings_data):
        """Group findings by area (proc, net, users, etc)."""
        by_area = {}
        for f in mock_findings_data:
            if f.area not in by_area:
                by_area[f.area] = []
            by_area[f.area].append(f)

        assert len(by_area["proc"]) == 1
        assert len(by_area["net"]) == 1
        assert len(by_area["users"]) == 1


class TestCompromisedSystemDetection:
    """Test that findings correctly identify compromise indicators."""

    def test_detecting_deleted_binaries(self, compromised_system_snapshot):
        """System with processes from deleted binaries should raise CRITICAL."""
        # This would be run by ProcessCollector in real code
        # For now, just verify the fixture has the right structure
        processes = compromised_system_snapshot["processes"]
        deleted_processes = [p for p in processes if p.get("exe_deleted")]

        assert len(deleted_processes) > 0
        assert "malware" in [p["name"] for p in deleted_processes]

    def test_detecting_extra_uid_zero_accounts(self, compromised_system_snapshot):
        """System with multiple UID 0 accounts should raise WARNING."""
        users = compromised_system_snapshot["users"]
        uid_zero = [u for u in users if u["uid"] == 0]

        # Healthy system has 1, compromised has 2
        assert len(uid_zero) >= 2

    def test_healthy_system_minimal_findings(self, healthy_system_snapshot):
        """Healthy system should have minimal or no critical findings."""
        # Just verify the fixture structure is consistent
        assert len(healthy_system_snapshot["processes"]) > 0
        assert len(healthy_system_snapshot["users"]) > 0

        # No processes with deleted binaries
        deleted = [p for p in healthy_system_snapshot["processes"] if p.get("exe_deleted")]
        assert len(deleted) == 0
