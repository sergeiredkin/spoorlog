"""Process collector: enumerate processes and flag forensic red flags.

Heuristics:
- binary deleted while running  (/proc/PID/exe -> "(deleted)")
- executable living in a temp / world-writable dir (/tmp, /dev/shm, ...)
- name masquerading (comm != exe basename)
- non-root process with no controlling terminal (daemonized shell)
- sustained high CPU (crude cryptominer signal)
"""

from __future__ import annotations

import os

import psutil

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh"}
INTERP_NAMES = {"python", "python3", "perl", "ruby", "php", "node", "lua"}
HIGH_CPU = 80.0


class ProcessCollector(Collector):
    source = "proc"
    title = "Processes"
    cheap = True

    COLUMNS = [
        Column("pid", "PID", 7),
        Column("user", "USER", 10),
        Column("cpu", "CPU%", 6),
        Column("mem", "MEM%", 6),
        Column("name", "NAME", 16),
        Column("exe", "EXE", 30),
        Column("flags", "FLAGS", 24),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        # prime cpu_percent so the second read has a delta
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        needs_root_seen = False
        for proc in psutil.process_iter(
            ["pid", "name", "username", "memory_percent", "terminal", "cmdline"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                name = info.get("name") or "?"
                user = info.get("username") or "?"
                mem = info.get("memory_percent") or 0.0
                cpu = proc.cpu_percent(None)
                exe, deleted, exe_denied = self._exe_of(pid)
                if exe_denied:
                    needs_root_seen = True

                flags: list[str] = []
                severity: Severity | None = None

                if deleted:
                    flags.append("deleted-bin")
                    severity = Severity.CRITICAL

                if exe and any(exe.startswith(d) for d in SUSPICIOUS_DIRS):
                    flags.append("temp-path")
                    severity = _raise(severity, Severity.CRITICAL)

                base = os.path.basename(exe) if exe else ""
                # comm is truncated to 15 chars in the kernel; browsers and
                # other apps legitimately rename their workers, so treat a bare
                # mismatch as INFO and only escalate when paired with a
                # suspicious path below.
                name_mismatch = bool(
                    exe and base and name and not base.startswith(name[:15])
                )
                if name_mismatch:
                    # flag only — severity stays driven by path/deleted checks
                    flags.append("name-mismatch")

                if (
                    user not in ("root", "?")
                    and not info.get("terminal")
                    and name in SHELL_NAMES
                ):
                    flags.append("no-tty-shell")
                    severity = _raise(severity, Severity.WARNING)

                if cpu >= HIGH_CPU:
                    flags.append(f"cpu {cpu:.0f}%")
                    severity = _raise(severity, Severity.WARNING)

                cmdline = " ".join(info.get("cmdline") or []) or name
                row = Row(
                    values={
                        "pid": pid,
                        "user": user,
                        "cpu": f"{cpu:.1f}",
                        "mem": f"{mem:.1f}",
                        "name": name,
                        "exe": exe or "-",
                        "flags": ",".join(flags),
                    },
                    severity=severity,
                    key=f"pid:{pid}",
                    detail=(
                        f"PID {pid}  user={user}\n"
                        f"name={name}\nexe={exe or '(unknown)'}\n"
                        f"cmdline={cmdline}\n"
                        f"cpu={cpu:.1f}%  mem={mem:.1f}%\n"
                        f"flags={', '.join(flags) or 'none'}"
                    ),
                )
                result.rows.append(row)

                # emit findings for the notable rows
                if deleted:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"pid {pid} ({name}) running from a deleted binary",
                        detail=cmdline, key=row.key,
                    )
                if "temp-path" in flags:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"pid {pid} ({name}) executing from {exe}",
                        detail=cmdline, key=row.key,
                    )
                if name_mismatch and "temp-path" in flags:
                    result.add_finding(
                        Severity.WARNING, self.source,
                        f"pid {pid} name '{name}' masquerades (binary '{base}')",
                        detail=cmdline, key=row.key,
                    )
                if "no-tty-shell" in flags:
                    result.add_finding(
                        Severity.WARNING, self.source,
                        f"pid {pid} detached {name} shell as {user}",
                        detail=cmdline, key=row.key,
                    )
                if cpu >= HIGH_CPU:
                    result.add_finding(
                        Severity.WARNING, self.source,
                        f"pid {pid} ({name}) at {cpu:.0f}% CPU",
                        detail=cmdline, key=row.key,
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # sort: flagged rows first, then by pid
        result.rows.sort(key=lambda r: (r.severity is None, r.values["pid"]))
        if needs_root_seen and not self.is_root():
            result.notes.append(
                "some /proc/PID/exe links unreadable — run as root for full view"
            )
        return result

    @staticmethod
    def _exe_of(pid: int) -> tuple[str | None, bool, bool]:
        """Return (exe_path, deleted, denied).

        Reads the /proc/PID/exe symlink directly so we can detect the
        "(deleted)" marker the kernel appends for a running-but-removed binary.
        """
        try:
            target = os.readlink(f"/proc/{pid}/exe")
        except PermissionError:
            return None, False, True
        except (FileNotFoundError, OSError):
            return None, False, False
        deleted = target.endswith(" (deleted)")
        if deleted:
            target = target[: -len(" (deleted)")]
        return target, deleted, False


def _raise(current: Severity | None, new: Severity) -> Severity:
    """Return the more severe of two (None counts as lowest)."""
    if current is None:
        return new
    return current if current >= new else new


if __name__ == "__main__":
    print_result(ProcessCollector().collect())
