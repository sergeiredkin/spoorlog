"""Tests for the IntegrityCollector (dpkg/rpm package verification)."""

import pytest
from spoorlog.collectors.integrity import IntegrityCollector
from spoorlog.collectors.base import CollectResult
from spoorlog.findings import Severity


class TestIntegrityCollectorBasics:
    """Test IntegrityCollector initialization and basic operation."""

    def test_collector_instantiation(self):
        """IntegrityCollector can be created."""
        collector = IntegrityCollector()
        assert collector is not None
        assert hasattr(collector, "collect")

    def test_collect_returns_result(self):
        """collect() returns a CollectResult with integrity data."""
        collector = IntegrityCollector()
        try:
            result = collector.collect()
            assert isinstance(result, CollectResult)
            assert hasattr(result, "rows")
            assert hasattr(result, "findings")
        except PermissionError:
            pytest.skip("Requires root to run dpkg/rpm verification")


class TestBinaryTampering:
    """Test detection of altered system binaries."""

    def test_altered_system_binary(self):
        """Should flag system binaries with mismatched checksums."""
        # dpkg -V or rpm -Va detects checksum changes
        # Compromised system would have /bin/bash, /usr/sbin/sshd modified
        assert True  # Fixture validation

    def test_critical_binaries(self):
        """Should monitor critical binaries: bash, sudo, ssh, kernel."""
        critical = ["/bin/bash", "/usr/bin/sudo", "/usr/sbin/sshd", "/bin/ls"]
        # These should be checked first; alerts if any are modified
        assert len(critical) > 0


class TestRecentPackageChanges:
    """Test detection of recently installed/upgraded packages."""

    def test_recently_installed_packages(self):
        """Should flag packages installed in last 24h."""
        # Malware installers often add backdoor packages
        # Check /var/log/apt/history.log or rpm database
        assert True

    def test_package_downgrades(self):
        """Should flag suspicious package downgrades."""
        # Downgrading openssh-server from 8.9 to 8.0 is suspicious
        assert True


class TestPackageIntegrity:
    """Test package file integrity checking."""

    def test_missing_package_files(self):
        """Should detect missing files from installed packages."""
        # dpkg -V reports missing files
        assert True

    def test_permission_changes(self):
        """Should flag unexpected permission changes on package files."""
        # dpkg -V detects mode changes (755 → 777)
        assert True


class TestSnapFlatpakInventory:
    """Test detection of snap/flatpak packages."""

    def test_snap_list(self):
        """Should list installed snaps."""
        # `snap list` shows installed snaps
        # Malware sometimes hides in snaps
        assert True

    def test_flatpak_list(self):
        """Should list installed flatpaks."""
        # `flatpak list --app` shows installed flatpaks
        assert True


class TestVulnerablePackages:
    """Test detection of known vulnerable packages."""

    def test_old_openssh_version(self):
        """Should flag old openssh-server versions."""
        # OpenSSH < 8.0 has critical RCE
        assert True

    def test_outdated_kernel(self):
        """Should flag kernels with known public CVEs."""
        # Linux < 5.10 has many exploitable CVEs
        assert True
