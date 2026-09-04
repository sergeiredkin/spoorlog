"""pytest fixtures for spoorlog collectors."""

import pytest
from pathlib import Path


@pytest.fixture
def healthy_system_snapshot():
    """Mock data representing a healthy (uncompromised) Linux system."""
    return {
        "hostname": "ubuntu-server",
        "kernel_version": "6.1.0-25-generic",
        "processes": [
            {
                "pid": 1,
                "name": "systemd",
                "cmdline": "/lib/systemd/systemd --system --deserialize 30",
                "exe": "/lib/systemd/systemd",
                "exe_deleted": False,
            },
            {
                "pid": 100,
                "name": "sshd",
                "cmdline": "/usr/sbin/sshd -D",
                "exe": "/usr/sbin/sshd",
                "exe_deleted": False,
            },
            {
                "pid": 500,
                "name": "bash",
                "cmdline": "bash",
                "exe": "/bin/bash",
                "exe_deleted": False,
            },
        ],
        "network_connections": [
            {
                "type": "LISTEN",
                "protocol": "tcp",
                "local_addr": "0.0.0.0",
                "local_port": 22,
                "remote_addr": None,
                "remote_port": None,
                "process": {"name": "sshd", "pid": 100},
                "state": "LISTEN",
            },
            {
                "type": "LISTEN",
                "protocol": "tcp",
                "local_addr": "127.0.0.1",
                "local_port": 5432,
                "remote_addr": None,
                "remote_port": None,
                "process": {"name": "postgres", "pid": 200},
                "state": "LISTEN",
            },
        ],
        "users": [
            {"uid": 0, "name": "root", "shell": "/root/.bash_profile", "password": "x"},
            {"uid": 1000, "name": "sergei", "shell": "/bin/bash", "password": "x"},
        ],
        "auth_log_lines": [
            "Sep  4 10:30:45 ubuntu sshd[1234]: Accepted publickey for sergei from 192.168.1.100 port 54321 ssh2",
            "Sep  4 10:31:20 ubuntu sudo: sergei : TTY=pts/0 ; PWD=/home/sergei ; USER=root ; COMMAND=/bin/ls",
        ],
        "packages": [
            {"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.5", "status": "installed"},
            {"name": "curl", "version": "7.85.0-1ubuntu1.12", "status": "installed"},
        ],
    }


@pytest.fixture
def compromised_system_snapshot():
    """Mock data representing a compromised system with malware/rootkit indicators."""
    return {
        "hostname": "ubuntu-server",
        "kernel_version": "6.1.0-25-generic",
        "processes": [
            {
                "pid": 1,
                "name": "systemd",
                "cmdline": "/lib/systemd/systemd --system --deserialize 30",
                "exe": "/lib/systemd/systemd",
                "exe_deleted": False,
            },
            {
                # Process with deleted binary (rootkit indicator)
                "pid": 4182,
                "name": "malware",
                "cmdline": "/tmp/miner",
                "exe": "/tmp/miner (deleted)",
                "exe_deleted": True,
            },
            {
                # Shell process with reverse shell connection
                "pid": 5555,
                "name": "bash",
                "cmdline": "bash -i",
                "exe": "/bin/bash",
                "exe_deleted": False,
                "outbound_connection": {"remote_ip": "185.220.101.50", "remote_port": 4444},
            },
        ],
        "network_connections": [
            {
                # Suspicious outbound connection
                "type": "ESTABLISHED",
                "protocol": "tcp",
                "local_addr": "192.168.1.50",
                "local_port": 54321,
                "remote_addr": "185.220.101.50",
                "remote_port": 4444,
                "process": {"name": "bash", "pid": 5555},
                "state": "ESTABLISHED",
            },
        ],
        "users": [
            {"uid": 0, "name": "root", "shell": "/root/.bash_profile", "password": "x"},
            # Extra UID 0 account (rootkit)
            {"uid": 0, "name": "admin", "shell": "/bin/bash", "password": "!"},
        ],
        "auth_log_lines": [
            # Brute force attempt
            "Sep  4 02:15:30 ubuntu sshd[2001]: Invalid user admin from 203.0.113.45 port 54321",
            "Sep  4 02:15:31 ubuntu sshd[2002]: Invalid user admin from 203.0.113.45 port 54322",
            "Sep  4 02:15:32 ubuntu sshd[2003]: Invalid user admin from 203.0.113.45 port 54323",
            "Sep  4 02:15:33 ubuntu sshd[2004]: Invalid user admin from 203.0.113.45 port 54324",
        ],
        "packages": [],  # All packages removed (indicator)
        "persistence": {
            "crontab": [
                "*/5 * * * * /tmp/.miner >/dev/null 2>&1",
            ],
            "systemd_units": [
                {"name": "update.service", "path": "/etc/systemd/system/update.service", "modified_recent": True},
            ],
        },
    }


@pytest.fixture
def mock_findings_data():
    """Sample findings to test sorting and aggregation."""
    from spoorlog.findings import Finding, Severity

    return [
        Finding("proc", "pid 4182 from deleted binary", Severity.CRITICAL),
        Finding("net", "bash → 185.x.x.x:4444", Severity.CRITICAL),
        Finding("users", "extra UID-0 account detected", Severity.WARNING),
        Finding("auth", "240 failed SSH attempts from 203.x", Severity.WARNING),
        Finding("persist", "new systemd unit: update.service", Severity.WARNING),
    ]
