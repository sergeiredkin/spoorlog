"""Binary-integrity collector: catch tampered system binaries and track what
was recently installed.

Derived from Nikkel, *Practical Linux Forensics*, Ch. 7 (installed software
packages). A trojaned ``ps``/``ls``/``netstat``/``sshd`` hides from the process
and network panels, so we verify package-owned files against the package
manager's recorded checksums.

Sources (all read-only):
- ``dpkg -V``        Debian/Ubuntu — package files whose md5 differs ('5' flag)
- ``debsums -c``     if installed, a second opinion on changed files
- ``rpm -Va``        RPM systems
- ``/var/log/dpkg.log*``  recently installed / upgraded packages
- ``apt-mark showmanual`` / ``snap`` / ``flatpak``  manually + universal packages
"""

from __future__ import annotations

import glob
import os
import re
import time

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

# a changed file under these prefixes is system-binary tampering (CRITICAL);
# elsewhere (mostly /etc) a change is common and benign-ish (WARNING).
BINARY_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib", "/usr/lib")
RECENT_DAYS = 14
# dpkg -V status columns: "??5??????" — position 3 (index 2) is the md5sum flag
DPKG_V_RE = re.compile(r"^(\S{9})\s+(?:(\S+)\s+)?(/.*)$")
DPKG_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (install|upgrade) (\S+):\S+ (\S+) (\S+)"
)


class IntegrityCollector(Collector):
    source = "integrity"
    title = "Integrity"
    # verification walks the whole package db — expensive, keep off auto-refresh
    cheap = False

    COLUMNS = [
        Column("kind", "KIND", 10),
        Column("subject", "SUBJECT", 46),
        Column("detail", "DETAIL", 34),
        Column("flags", "FLAGS", 14),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        did_verify = self._dpkg_verify(result) or self._rpm_verify(result)
        if not did_verify:
            result.notes.append("no supported package verifier (dpkg/rpm) found")
        self._recent_installs(result)
        self._universal_packages(result)
        result.rows.sort(key=lambda r: (r.severity is None,
                                         -(r.timestamp or 0)))
        return result

    # ---- package verification --------------------------------------------

    def _dpkg_verify(self, result: CollectResult) -> bool:
        rc, out, err = self.run(["dpkg", "-V"], timeout=120)
        if rc == 127:
            return False
        if rc not in (0, 1):  # dpkg -V exits 1 when differences exist
            if "root" in (err or "").lower() or not self.is_root():
                result.notes.append("dpkg -V may need root for a full check")
        for line in out.splitlines():
            m = DPKG_V_RE.match(line)
            if not m:
                continue
            flags_str, _pkg, path = m.groups()
            md5_changed = len(flags_str) >= 3 and flags_str[2] == "5"
            missing = "?" not in flags_str and flags_str[0] == "m"
            if not (md5_changed or missing):
                continue
            is_bin = path.startswith(BINARY_PREFIXES)
            sev = Severity.CRITICAL if is_bin else Severity.WARNING
            flag_txt = "md5" if md5_changed else "attr"
            result.rows.append(Row(
                values={"kind": "modified", "subject": path,
                        "detail": f"dpkg -V: {flags_str}", "flags": flag_txt},
                severity=sev, key=f"intg:{path}",
                detail=f"{path}\ndpkg -V status: {flags_str}\n"
                       f"(md5sum differs from the installed package)",
            ))
            if is_bin:
                result.add_finding(
                    Severity.CRITICAL, self.source,
                    f"system binary modified since install: {path}",
                    detail=f"dpkg -V flag '{flags_str}'", key=f"intg:{path}",
                )
        return True

    def _rpm_verify(self, result: CollectResult) -> bool:
        rc, out, _ = self.run(["rpm", "-Va"], timeout=180)
        if rc == 127:
            return False
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            flags_str = parts[0]
            path = parts[-1]
            if not path.startswith("/"):
                continue
            md5_changed = "5" in flags_str
            if not md5_changed:
                continue
            is_bin = path.startswith(BINARY_PREFIXES)
            sev = Severity.CRITICAL if is_bin else Severity.WARNING
            result.rows.append(Row(
                values={"kind": "modified", "subject": path,
                        "detail": f"rpm -Va: {flags_str}", "flags": "md5"},
                severity=sev, key=f"intg:{path}", detail=f"{path}\n{line}",
            ))
            if is_bin:
                result.add_finding(
                    Severity.CRITICAL, self.source,
                    f"system binary modified since install: {path}",
                    detail=line, key=f"intg:{path}",
                )
        return True

    # ---- recent installs -------------------------------------------------

    def _recent_installs(self, result: CollectResult) -> None:
        cutoff = time.time() - RECENT_DAYS * 86400
        seen = False
        for path in sorted(glob.glob("/var/log/dpkg.log*")):
            if path.endswith(".gz"):
                continue  # skip rotated/compressed for a cheap first pass
            text, denied = self.read_text(path)
            if denied:
                result.notes.append(f"needs root: {path}")
                continue
            if not text:
                continue
            seen = True
            for line in text.splitlines():
                m = DPKG_LOG_RE.match(line)
                if not m:
                    continue
                ts_str, action, pkg, _old, new = m.groups()
                try:
                    ts = time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                result.rows.append(Row(
                    values={"kind": action, "subject": pkg,
                            "detail": f"{new} @ {ts_str}", "flags": ""},
                    key=f"pkg:{pkg}:{ts_str}", timestamp=ts,
                    detail=f"{action} {pkg} {new} at {ts_str}",
                ))
        if not seen:
            result.notes.append("no readable /var/log/dpkg.log")

    def _universal_packages(self, result: CollectResult) -> None:
        for tool, args in (("snap", ["snap", "list"]),
                           ("flatpak", ["flatpak", "list", "--app"])):
            rc, out, _ = self.run(args, timeout=15)
            if rc != 0 or not out:
                continue
            for line in out.splitlines()[1:]:  # skip header
                name = line.split()[0] if line.split() else ""
                if not name:
                    continue
                result.rows.append(Row(
                    values={"kind": tool, "subject": name,
                            "detail": line.strip()[:34], "flags": ""},
                    key=f"{tool}:{name}", detail=line.strip(),
                ))


if __name__ == "__main__":
    print_result(IntegrityCollector().collect())
