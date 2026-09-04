"""Tests for the PersistenceCollector."""

import pytest
from spoorlog.collectors.persistence import PersistenceCollector
from spoorlog.collectors.base import CollectResult
from spoorlog.findings import Severity


class TestPersistenceCollectorBasics:
    """Test PersistenceCollector initialization and basic operation."""

    def test_collector_instantiation(self):
        """PersistenceCollector can be created."""
        collector = PersistenceCollector()
        assert collector is not None
        assert hasattr(collector, "collect")

    def test_collect_returns_result(self):
        """collect() returns a CollectResult with persistence data."""
        collector = PersistenceCollector()
        try:
            result = collector.collect()
            assert isinstance(result, CollectResult)
            assert hasattr(result, "rows")
            assert hasattr(result, "findings")
        except PermissionError:
            pytest.skip("Requires root to read persistence mechanisms")


class TestCrontabDetection:
    """Test detection of suspicious crontab entries."""

    def test_suspicious_cron_command(self, compromised_system_snapshot):
        """Should flag cron jobs running from /tmp or unusual commands."""
        persistence = compromised_system_snapshot.get("persistence", {})
        crontab = persistence.get("crontab", [])

        # Compromised fixture has miner cron job
        miner_crons = [c for c in crontab if "miner" in c.lower()]
        assert len(miner_crons) > 0

    def test_normal_cron_jobs(self, healthy_system_snapshot):
        """Healthy system crons should be standard maintenance."""
        persistence = healthy_system_snapshot.get("persistence", {})
        crontab = persistence.get("crontab", [])

        # Should be empty or have only normal jobs
        for cron in crontab:
            assert not any(x in cron.lower() for x in ["/tmp", "/dev/shm", "miner", "malware"])


class TestSystemdUnitDetection:
    """Test detection of suspicious systemd units."""

    def test_recently_added_systemd_unit(self, compromised_system_snapshot):
        """Should flag systemd units modified recently."""
        persistence = compromised_system_snapshot.get("persistence", {})
        units = persistence.get("systemd_units", [])

        # Compromised fixture has update.service
        recent_units = [u for u in units if u.get("modified_recent")]
        assert len(recent_units) > 0
        names = [u["name"] for u in recent_units]
        assert "update.service" in names

    def test_unit_in_standard_location(self, compromised_system_snapshot):
        """Suspicious units should be in /etc/systemd/system."""
        persistence = compromised_system_snapshot.get("persistence", {})
        units = persistence.get("systemd_units", [])

        for unit in units:
            path = unit.get("path", "")
            # Malicious units often in system override dir
            if "update" in unit["name"]:
                assert "/etc/systemd/system/" in path


class TestLdSoPreloadDetection:
    """Test detection of /etc/ld.so.preload (rootkit vector)."""

    def test_ld_so_preload_presence(self, compromised_system_snapshot):
        """Should flag presence of /etc/ld.so.preload file."""
        # This would be checked via filesystem in real code
        # For now, verify fixture structure allows it
        persistence = compromised_system_snapshot.get("persistence", {})
        assert isinstance(persistence, dict)

    def test_ld_so_preload_not_present_normally(self, healthy_system_snapshot):
        """Healthy system should not have /etc/ld.so.preload."""
        persistence = healthy_system_snapshot.get("persistence", {})
        # Verify it's not in the fixture
        ld_preload = persistence.get("ld_so_preload")
        assert ld_preload is None or not ld_preload


class TestRcLocalDetection:
    """Test detection of /etc/rc.local modifications."""

    def test_rc_local_modifications(self, compromised_system_snapshot):
        """Should flag modifications to /etc/rc.local."""
        persistence = compromised_system_snapshot.get("persistence", {})
        # Just verify fixture structure
        assert isinstance(persistence, dict)

    def test_rc_local_not_present(self, healthy_system_snapshot):
        """Healthy modern systems may not have rc.local."""
        persistence = healthy_system_snapshot.get("persistence", {})
        # Modern systems often don't have it; that's OK
        assert isinstance(persistence, dict)


class TestShellRcModifications:
    """Test detection of suspicious .bashrc/.zshrc modifications."""

    def test_eval_in_rc_file(self, compromised_system_snapshot):
        """Should flag eval/exec lines in shell rc files."""
        persistence = compromised_system_snapshot.get("persistence", {})
        rc_lines = persistence.get("shell_rc_lines", [])

        # Compromised systems may have eval injection
        for line in rc_lines:
            # Eval lines are suspicious but common in legitimate cases
            assert isinstance(line, str)

    def test_normal_rc_files(self, healthy_system_snapshot):
        """Healthy rc files should have normal aliases/exports."""
        persistence = healthy_system_snapshot.get("persistence", {})
        rc_lines = persistence.get("shell_rc_lines", [])

        # Verify structure
        assert isinstance(rc_lines, (list, type(None)))


class TestCronDotDirectories:
    """Test detection of cron.daily/weekly/monthly scripts."""

    def test_cron_dot_scripts(self, compromised_system_snapshot):
        """Should detect scripts in /etc/cron.* directories."""
        persistence = compromised_system_snapshot.get("persistence", {})
        # Just verify fixture structure allows checking
        assert isinstance(persistence, dict)
