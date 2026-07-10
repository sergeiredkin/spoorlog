"""Persistence collector: the classic autostart surfaces attackers abuse.

Covers:
- system + per-user crontabs and /etc/cron.*
- systemd units under /etc/systemd/system (recently modified)
- shell rc hooks (.bashrc / .profile) with suspicious lines
- /etc/rc.local, /etc/ld.so.preload (rootkit vector), /etc/profile.d
"""

from __future__ import annotations

import glob
import os
import time

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

RECENT_DAYS = 7
# High-signal patterns: reverse shells and download-and-run. Deliberately does
# NOT include bare "eval"/"curl"/"wget" — those appear in stock shell rc files
# (lesspipe, dircolors, conda) and would drown real findings in noise.
SUSPICIOUS_SNIPPETS = (
    "/dev/tcp/", "/dev/udp/",
    "|bash", "| bash", "|sh", "| sh", "|/bin/sh", "| /bin/sh",
    "base64 -d", "base64 --decode", "base64 -di",
    "curl -s", "wget -q",  # the quiet flags download tools use in droppers
    "python -c", "python3 -c", "perl -e",
    "nc -e", "ncat -e", "socat ", "bash -i",
)


class PersistenceCollector(Collector):
    source = "persist"
    title = "Persistence"
    cheap = True

    COLUMNS = [
        Column("kind", "KIND", 12),
        Column("location", "LOCATION", 40),
        Column("detail", "DETAIL", 40),
        Column("flags", "FLAGS", 16),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        self._crontabs(result)
        self._cron_dirs(result)
        self._systemd(result)
        self._rc_hooks(result)
        self._special_files(result)
        result.rows.sort(key=lambda r: (r.severity is None,))
        return result

    # ---- cron -------------------------------------------------------------

    def _crontabs(self, result: CollectResult) -> None:
        for path in ["/etc/crontab"] + glob.glob("/var/spool/cron/crontabs/*"):
            text, denied = self.read_text(path)
            if denied:
                result.notes.append(f"needs root: {path}")
                continue
            if text is None:
                continue
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                flags, sev = self._scan_line(s)
                result.rows.append(Row(
                    values={"kind": "crontab", "location": path,
                            "detail": s[:60], "flags": ",".join(flags)},
                    severity=sev, key=f"cron:{path}:{s[:20]}", detail=s,
                ))
                if sev == Severity.CRITICAL:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"suspicious cron entry in {path}", detail=s,
                    )

    def _cron_dirs(self, result: CollectResult) -> None:
        for d in glob.glob("/etc/cron.*"):
            for entry in sorted(glob.glob(os.path.join(d, "*"))):
                recent = self._is_recent(entry)
                sev = Severity.WARNING if recent else None
                result.rows.append(Row(
                    values={"kind": "cron.d", "location": entry,
                            "detail": self._mtime_str(entry),
                            "flags": "recent" if recent else ""},
                    severity=sev, key=f"crond:{entry}",
                    timestamp=self._epoch(entry),
                    detail=self._head(entry),
                ))
                if recent:
                    result.add_finding(
                        Severity.WARNING, self.source,
                        f"recently modified cron job {entry}",
                        detail=self._mtime_str(entry),
                    )

    # ---- systemd ----------------------------------------------------------

    def _systemd(self, result: CollectResult) -> None:
        for unit in glob.glob("/etc/systemd/system/*.service") + glob.glob(
            "/etc/systemd/system/*.timer"
        ):
            recent = self._is_recent(unit)
            text, _ = self.read_text(unit)
            execstart = ""
            flags: list[str] = []
            sev: Severity | None = None
            susp = False
            if text:
                for line in text.splitlines():
                    if line.strip().startswith("ExecStart"):
                        execstart = line.split("=", 1)[-1].strip()
                        break
                snip_flags, snip_sev = self._scan_line(execstart)
                if snip_flags:
                    flags += snip_flags
                    sev = snip_sev
                    susp = True
            if recent:
                flags.append("recent")
                sev = _max(sev, Severity.WARNING)
            result.rows.append(Row(
                values={"kind": "systemd", "location": os.path.basename(unit),
                        "detail": execstart[:60], "flags": ",".join(flags)},
                severity=sev, key=f"unit:{unit}",
                timestamp=self._epoch(unit),
                detail=f"{unit}\nExecStart={execstart}\n{self._mtime_str(unit)}",
            ))
            if susp:
                result.add_finding(
                    Severity.CRITICAL, self.source,
                    f"suspicious ExecStart in {os.path.basename(unit)}",
                    detail=execstart,
                )
            elif recent:
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"recently added/modified unit {os.path.basename(unit)}",
                    detail=self._mtime_str(unit),
                )

    # ---- shell rc & special files ----------------------------------------

    def _rc_hooks(self, result: CollectResult) -> None:
        homes = ["/root"] + glob.glob("/home/*")
        for home in homes:
            for rc in (".bashrc", ".profile", ".bash_profile", ".zshrc"):
                path = os.path.join(home, rc)
                text, denied = self.read_text(path)
                if denied:
                    result.notes.append(f"needs root: {path}")
                    continue
                if text is None:
                    continue
                for line in text.splitlines():
                    flags, sev = self._scan_line(line)
                    if flags:
                        result.rows.append(Row(
                            values={"kind": "shell-rc", "location": path,
                                    "detail": line.strip()[:60],
                                    "flags": ",".join(flags)},
                            severity=sev, key=f"rc:{path}:{line[:20]}",
                            detail=line.strip(),
                        ))
                        result.add_finding(
                            sev or Severity.WARNING, self.source,
                            f"suspicious line in {path}",
                            detail=line.strip(),
                        )

    def _special_files(self, result: CollectResult) -> None:
        # ld.so.preload existing at all is noteworthy (rootkit vector)
        preload = "/etc/ld.so.preload"
        if os.path.exists(preload):
            text, _ = self.read_text(preload)
            result.rows.append(Row(
                values={"kind": "ld.preload", "location": preload,
                        "detail": (text or "").strip()[:60], "flags": "present"},
                severity=Severity.CRITICAL, key="ldpreload",
                detail=text or "",
            ))
            result.add_finding(
                Severity.CRITICAL, self.source,
                "/etc/ld.so.preload present (library-injection rootkit vector)",
                detail=(text or "").strip(),
            )
        for path in ["/etc/rc.local"] + glob.glob("/etc/profile.d/*"):
            if not os.path.isfile(path):
                continue
            recent = self._is_recent(path)
            text, _ = self.read_text(path)
            flags: list[str] = ["recent"] if recent else []
            sev = Severity.WARNING if recent else None
            if text:
                for line in text.splitlines():
                    fl, s = self._scan_line(line)
                    if fl:
                        flags += fl
                        sev = _max(sev, s)
            if flags:
                result.rows.append(Row(
                    values={"kind": "startup", "location": path,
                            "detail": self._mtime_str(path),
                            "flags": ",".join(sorted(set(flags)))},
                    severity=sev, key=f"startup:{path}",
                    detail=self._head(path),
                ))

    # ---- helpers ----------------------------------------------------------

    def _scan_line(self, line: str) -> tuple[list[str], Severity | None]:
        low = line.lower()
        hits = [s.strip() for s in SUSPICIOUS_SNIPPETS if s in low]
        if hits:
            return ["susp"], Severity.CRITICAL
        return [], None

    @staticmethod
    def _is_recent(path: str, days: int = RECENT_DAYS) -> bool:
        try:
            return (time.time() - os.path.getmtime(path)) < days * 86400
        except OSError:
            return False

    @staticmethod
    def _mtime_str(path: str) -> str:
        try:
            t = os.path.getmtime(path)
            return "modified " + time.strftime("%Y-%m-%d %H:%M", time.localtime(t))
        except OSError:
            return "?"

    @staticmethod
    def _epoch(path: str) -> float | None:
        try:
            return os.path.getmtime(path)
        except OSError:
            return None

    def _head(self, path: str, n: int = 20) -> str:
        text, _ = self.read_text(path)
        if not text:
            return ""
        return "\n".join(text.splitlines()[:n])


def _max(current: Severity | None, new: Severity | None) -> Severity | None:
    vals = [x for x in (current, new) if x is not None]
    return max(vals) if vals else None


if __name__ == "__main__":
    print_result(PersistenceCollector().collect())
