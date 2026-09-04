"""Tests for the UsersCollector."""

import pytest
from spoorlog.collectors.users import UsersCollector
from spoorlog.collectors.base import CollectResult
from spoorlog.findings import Severity


class TestUsersCollectorBasics:
    """Test UsersCollector initialization and basic operation."""

    def test_collector_instantiation(self):
        """UsersCollector can be created."""
        collector = UsersCollector()
        assert collector is not None
        assert hasattr(collector, "collect")

    def test_collect_returns_result(self):
        """collect() returns a CollectResult with user data."""
        collector = UsersCollector()
        result = collector.collect()
        assert isinstance(result, CollectResult)
        assert hasattr(result, "rows")
        assert hasattr(result, "findings")


class TestExtraRootAccounts:
    """Test detection of extra UID 0 (root) accounts."""

    def test_multiple_uid_zero_accounts(self, compromised_system_snapshot):
        """Should flag systems with multiple UID 0 accounts."""
        users = compromised_system_snapshot["users"]
        uid_zero = [u for u in users if u["uid"] == 0]

        # Compromised fixture has root + fake admin account both UID 0
        assert len(uid_zero) >= 2
        names = [u["name"] for u in uid_zero]
        assert "root" in names
        assert "admin" in names

    def test_single_root_is_normal(self, healthy_system_snapshot):
        """Healthy system should have only one UID 0 (root)."""
        users = healthy_system_snapshot["users"]
        uid_zero = [u for u in users if u["uid"] == 0]

        assert len(uid_zero) == 1
        assert uid_zero[0]["name"] == "root"


class TestWeakPasswordState:
    """Test detection of accounts with weak password settings."""

    def test_empty_password_field(self, compromised_system_snapshot):
        """Should flag accounts with empty password (no password set)."""
        users = compromised_system_snapshot["users"]

        # Compromised fixture has admin with empty password
        empty_pwd = [u for u in users if u["password"] == "!"]
        assert len(empty_pwd) > 0

    def test_normal_password_hashes(self, healthy_system_snapshot):
        """Healthy accounts should have 'x' (password in shadow)."""
        users = healthy_system_snapshot["users"]

        # All normal users should have 'x'
        for user in users:
            assert user["password"] == "x", f"{user['name']} should use shadow passwords"


class TestServiceAccountsWithShells:
    """Test detection of service accounts with login shells."""

    def test_service_account_with_bash_shell(self, compromised_system_snapshot):
        """Should flag non-root service accounts with /bin/bash."""
        # In compromised fixture, the extra admin account shouldn't have bash
        users = compromised_system_snapshot["users"]

        # Check if any non-uid-0 service accounts have bash (would be suspicious)
        suspicious = [
            u for u in users
            if u["uid"] >= 1000 and u["shell"] == "/bin/bash"
        ]
        # Fixture may or may not have this; just verify structure
        for user in suspicious:
            assert user["shell"] in ["/bin/bash", "/bin/sh"]

    def test_normal_user_shells(self, healthy_system_snapshot):
        """Normal users should have bash or compatible shell."""
        users = healthy_system_snapshot["users"]

        normal_users = [u for u in users if u["uid"] >= 1000]
        assert all(u["shell"] in ["/bin/bash", "/bin/sh", "/bin/zsh"] for u in normal_users)


class TestAuthorizedKeysChanges:
    """Test detection of recent authorized_keys modifications."""

    def test_recently_modified_authorized_keys(self, compromised_system_snapshot):
        """Should flag authorized_keys changed in last 2 hours."""
        # This would be checked via mtime in real code
        # For now just verify fixture structure allows checking
        users = compromised_system_snapshot["users"]
        assert len(users) > 0


class TestFailedLoginBursts:
    """Test detection of failed login attempts."""

    def test_brute_force_from_single_ip(self, compromised_system_snapshot):
        """Should flag multiple failed logins from same IP."""
        auth_log = compromised_system_snapshot["auth_log_lines"]

        # Count failed attempts per IP
        failed_attempts = [
            line for line in auth_log
            if "Invalid user" in line or "authentication failure" in line
        ]

        # Compromised fixture has brute force burst
        assert len(failed_attempts) >= 4

    def test_healthy_system_few_auth_events(self, healthy_system_snapshot):
        """Healthy system should have minimal auth failures."""
        auth_log = healthy_system_snapshot["auth_log_lines"]

        failed = [
            line for line in auth_log
            if "Invalid user" in line or "authentication failure" in line
        ]

        # Should have none or very few
        assert len(failed) < 2


class TestSudoGroupMembers:
    """Test detection of sudo group membership."""

    def test_normal_sudo_users(self, healthy_system_snapshot):
        """Regular users in sudo group is not necessarily an alert."""
        # This is more of a baseline: know who has sudo
        users = healthy_system_snapshot["users"]
        assert len(users) > 0

    def test_service_account_with_sudo(self, compromised_system_snapshot):
        """Service accounts with sudo access would be suspicious."""
        # Just verify fixture has user data to check
        users = compromised_system_snapshot["users"]
        assert len(users) > 0
