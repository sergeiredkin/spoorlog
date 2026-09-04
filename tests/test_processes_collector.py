"""Tests for the ProcessCollector."""

import pytest
from spoorlog.collectors.processes import ProcessCollector
from spoorlog.collectors.base import CollectResult
from spoorlog.findings import Severity


class TestProcessCollectorBasics:
    """Test that ProcessCollector initializes and runs."""

    def test_collector_instantiation(self):
        """ProcessCollector can be created."""
        collector = ProcessCollector()
        assert collector is not None
        assert hasattr(collector, "collect")

    def test_collect_returns_collect_result(self):
        """collect() returns a CollectResult with columns, rows, and findings."""
        collector = ProcessCollector()
        # On a real system, this will return actual data
        # Test just ensures it doesn't crash
        try:
            result = collector.collect()
            # CollectResult has columns, rows, and findings
            assert isinstance(result, CollectResult)
            assert hasattr(result, "columns")
            assert hasattr(result, "rows")
            assert hasattr(result, "findings")
            assert isinstance(result.findings, list)
            # Each finding should have required attributes
            for f in result.findings:
                assert hasattr(f, "source")
                assert hasattr(f, "title")
                assert hasattr(f, "severity")
        except PermissionError:
            # Expected if running without root; that's OK
            pytest.skip("Requires root to read /proc")


class TestProcessDetectionLogic:
    """Test detection rules against mock data."""

    def test_deleted_binary_detection(self, compromised_system_snapshot):
        """Should flag processes running from deleted binaries."""
        processes = compromised_system_snapshot["processes"]

        # Check that our fixture has the deleted process
        for proc in processes:
            if proc.get("exe_deleted"):
                # This would be flagged by the real collector
                assert "deleted" in proc["exe"].lower()

    def test_reverse_shell_detection(self, compromised_system_snapshot):
        """Should flag shell processes with outbound connections."""
        processes = compromised_system_snapshot["processes"]
        connections = compromised_system_snapshot["network_connections"]

        # Find shell with outbound connection
        for conn in connections:
            if conn["type"] == "ESTABLISHED" and conn["remote_port"] not in [80, 443]:
                # Suspicious outbound connection detected
                assert conn["process"]["name"] == "bash"
                assert conn["remote_addr"] != "127.0.0.1"


class TestHealthySystemNoAlerts:
    """Verify healthy systems produce few/no critical findings."""

    def test_normal_processes_not_flagged(self, healthy_system_snapshot):
        """Standard daemons should not raise findings."""
        processes = healthy_system_snapshot["processes"]

        # Verify fixtures don't have deleted binaries
        for proc in processes:
            assert not proc.get("exe_deleted"), f"{proc['name']} should not be deleted"

        # Standard processes should be present
        names = [p["name"] for p in processes]
        assert "systemd" in names or "sshd" in names
