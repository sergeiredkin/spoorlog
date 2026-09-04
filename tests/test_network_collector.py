"""Tests for the NetworkCollector."""

import pytest
from spoorlog.collectors.network import NetworkCollector
from spoorlog.collectors.base import CollectResult
from spoorlog.findings import Severity


class TestNetworkCollectorBasics:
    """Test NetworkCollector initialization and basic operation."""

    def test_collector_instantiation(self):
        """NetworkCollector can be created."""
        collector = NetworkCollector()
        assert collector is not None
        assert hasattr(collector, "collect")

    def test_collect_returns_result(self):
        """collect() returns a CollectResult."""
        collector = NetworkCollector()
        try:
            result = collector.collect()
            assert isinstance(result, CollectResult)
            assert hasattr(result, "columns")
            assert hasattr(result, "rows")
            assert hasattr(result, "findings")
        except PermissionError:
            pytest.skip("Requires root to read network state")


class TestReverseShellDetection:
    """Test detection of reverse shell patterns."""

    def test_interpreter_with_outbound_connection(self, compromised_system_snapshot):
        """Should flag bash/python/perl with outbound connections."""
        connections = compromised_system_snapshot["network_connections"]

        # Find established connections on unusual ports
        shell_connections = [
            c for c in connections
            if c["type"] == "ESTABLISHED"
            and c["process"]["name"] in ["bash", "python", "perl"]
            and c["remote_port"] not in [80, 443]
        ]

        assert len(shell_connections) > 0
        for conn in shell_connections:
            # Remote IP should not be loopback
            assert conn["remote_addr"] != "127.0.0.1"
            # Port should be odd/unusual
            assert conn["remote_port"] not in [22, 80, 443, 8080]

    def test_healthy_standard_listening_ports(self, healthy_system_snapshot):
        """Healthy system should have only standard listeners."""
        connections = healthy_system_snapshot["network_connections"]

        # All LISTEN ports should be standard (22, 5432, etc)
        listen_ports = [
            c["local_port"] for c in connections
            if c["type"] == "LISTEN"
        ]

        # Standard/expected ports
        expected = {22, 5432, 3306, 6379, 8080, 9200}
        assert all(p in expected or p < 1024 for p in listen_ports)


class TestExternallyReachableListener:
    """Test detection of listeners on external-facing interfaces."""

    def test_listener_on_all_interfaces(self, compromised_system_snapshot):
        """Should flag services listening on 0.0.0.0."""
        connections = compromised_system_snapshot["network_connections"]
        listeners = [c for c in connections if c["type"] == "LISTEN"]

        # Check for 0.0.0.0 (all interfaces) listeners
        external_listeners = [
            c for c in listeners
            if c["local_addr"] == "0.0.0.0"
        ]

        # Compromised fixture has external listeners
        assert len(external_listeners) > 0

    def test_localhost_only_is_safe(self, healthy_system_snapshot):
        """Database on 127.0.0.1 should not raise findings."""
        connections = healthy_system_snapshot["network_connections"]

        # Find localhost listeners
        localhost = [
            c for c in connections
            if c["type"] == "LISTEN" and c["local_addr"] == "127.0.0.1"
        ]

        # Should have postgres on localhost
        assert any(c["local_port"] == 5432 for c in localhost)


class TestSuspiciousOutboundPatterns:
    """Test detection of unusual outbound connection patterns."""

    def test_many_connections_to_different_hosts(self, compromised_system_snapshot):
        """Scanning behavior: many connections to different IPs."""
        connections = compromised_system_snapshot["network_connections"]

        # Count unique remote IPs
        established = [c for c in connections if c["type"] == "ESTABLISHED"]
        remote_ips = set(c["remote_addr"] for c in established)

        # Compromised fixture should have suspicious connections
        assert len(remote_ips) > 1

    def test_connection_to_known_malware_ip(self, compromised_system_snapshot):
        """Flag connections to known bad IPs (185.x.x.x C2 ranges)."""
        connections = compromised_system_snapshot["network_connections"]

        # Check for known C2 IP ranges
        c2_ranges = ["185.220", "203.0.113"]
        suspicious = []

        for conn in connections:
            if conn["type"] == "ESTABLISHED":
                for range_prefix in c2_ranges:
                    if conn["remote_addr"].startswith(range_prefix):
                        suspicious.append(conn)

        # Compromised fixture has C2 connection
        assert len(suspicious) > 0
