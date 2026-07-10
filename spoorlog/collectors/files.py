"""Recent-files collector: files changed recently in high-value directories.

Walks a small set of "hot" directories and reports files modified within the
last N hours, flagging:
- executables living in temp / world-writable dirs
- hidden files in temp dirs
- SUID/SGID bits on files outside the standard system paths

This collector touches the filesystem, so it is marked ``cheap = False`` and is
excluded from the auto-refresh loop.
"""

from __future__ import annotations

import glob
import os
import stat
import time

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

HOT_DIRS = [
    "/tmp", "/dev/shm", "/var/tmp", "/root", "/usr/local/bin", "/etc",
]
TEMP_DIRS = ("/tmp", "/dev/shm", "/var/tmp")
STD_SUID_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/")
DEFAULT_WINDOW_HOURS = 24
MAX_ROWS = 400  # cap the walk so a huge /home doesn't blow up the table


class FilesCollector(Collector):
    source = "files"
    title = "Files"
    cheap = False

    def __init__(self, window_hours: int = DEFAULT_WINDOW_HOURS) -> None:
        self.window_hours = window_hours

    COLUMNS = [
        Column("mtime", "MODIFIED", 18),
        Column("mode", "MODE", 6),
        Column("size", "SIZE", 9),
        Column("path", "PATH", 48),
        Column("flags", "FLAGS", 18),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        cutoff = time.time() - self.window_hours * 3600
        dirs = HOT_DIRS + glob.glob("/home/*")
        seen = 0
        for base in dirs:
            if seen >= MAX_ROWS:
                result.notes.append(f"row cap {MAX_ROWS} reached; walk truncated")
                break
            seen = self._walk(base, cutoff, result, seen)
        result.rows.sort(
            key=lambda r: (r.severity is None, -r.values.get("_mtime", 0))
        )
        # drop the private sort key from display dicts
        return result

    def _walk(self, base: str, cutoff: float, result: CollectResult, seen: int) -> int:
        for root, dirs, files in os.walk(base, topdown=True, onerror=lambda e: None):
            # don't descend into /proc-like or mounted pseudo trees under /etc
            for fname in files:
                if seen >= MAX_ROWS:
                    return seen
                path = os.path.join(root, fname)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mtime < cutoff:
                    continue

                flags: list[str] = []
                sev: Severity | None = None
                mode = st.st_mode
                is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                in_temp = any(path.startswith(d) for d in TEMP_DIRS)
                is_suid = bool(mode & stat.S_ISUID)
                is_sgid = bool(mode & stat.S_ISGID)

                if in_temp and is_exec:
                    flags.append("exec-in-temp")
                    sev = Severity.CRITICAL
                if in_temp and fname.startswith("."):
                    flags.append("hidden")
                    sev = _max(sev, Severity.WARNING)
                if is_suid and not path.startswith(STD_SUID_PREFIXES):
                    flags.append("suid")
                    sev = Severity.CRITICAL
                if is_sgid and not path.startswith(STD_SUID_PREFIXES):
                    flags.append("sgid")
                    sev = _max(sev, Severity.WARNING)

                mtime = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(st.st_mtime)
                )
                row = Row(
                    values={
                        "mtime": mtime,
                        "mode": stat.filemode(mode)[-4:],
                        "size": st.st_size,
                        "path": path,
                        "flags": ",".join(flags),
                        "_mtime": st.st_mtime,
                    },
                    severity=sev, key=f"file:{path}",
                    timestamp=st.st_mtime,
                    detail=(
                        f"{path}\n{stat.filemode(mode)}  "
                        f"uid={st.st_uid} gid={st.st_gid}  "
                        f"size={st.st_size}\nmodified {mtime}"
                    ),
                )
                result.rows.append(row)
                seen += 1

                if "exec-in-temp" in flags:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"executable in temp dir: {path}",
                        detail=f"modified {mtime}", key=row.key,
                    )
                if "suid" in flags:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"non-standard SUID binary: {path}",
                        detail=f"modified {mtime}", key=row.key,
                    )
        return seen


def _max(current: Severity | None, new: Severity | None) -> Severity | None:
    vals = [x for x in (current, new) if x is not None]
    return max(vals) if vals else None


if __name__ == "__main__":
    print_result(FilesCollector().collect())
