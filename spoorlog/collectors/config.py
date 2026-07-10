"""Config-artifacts & privilege-posture collector.

Derived from Nikkel, *Practical Linux Forensics*, Ch. 4 (files/capabilities) and
Ch. 8 (network configuration). Surfaces read-only security posture that
attackers tamper with:

- ``/etc/hosts``        domain redirects (name → public IP)
- ``/etc/resolv.conf``  rogue DNS servers
- ``sshd_config``       weak SSH policy (root login, password auth, empty pw)
- firewall state        ufw / iptables / nft — active with rules, or wide open
- file capabilities     getcap sweep — cap_setuid & friends (SUID-equivalent)
"""

from __future__ import annotations

import glob
import ipaddress
import os
import time

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

# capabilities that grant real privilege — worth surfacing on any binary
DANGEROUS_CAPS = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_net_admin",
    "cap_chown", "cap_fowner",
}
RECENT_DAYS = 7


class ConfigCollector(Collector):
    source = "config"
    title = "Config"
    cheap = False  # getcap sweep touches the filesystem

    COLUMNS = [
        Column("kind", "KIND", 10),
        Column("subject", "SUBJECT", 40),
        Column("detail", "DETAIL", 40),
        Column("flags", "FLAGS", 14),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        self._hosts(result)
        self._resolv(result)
        self._sshd(result)
        self._firewall(result)
        self._capabilities(result)
        result.rows.sort(key=lambda r: (r.severity is None,))
        return result

    # ---- /etc/hosts -------------------------------------------------------

    def _hosts(self, result: CollectResult) -> None:
        text, _ = self.read_text("/etc/hosts")
        if not text:
            return
        recent = self._is_recent("/etc/hosts")
        for line in text.splitlines():
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            parts = s.split()
            ip, names = parts[0], parts[1:]
            fqdns = [n for n in names if "." in n and n != "localhost"]
            if fqdns and self._is_public(ip):
                # a real domain pointed at a public IP in /etc/hosts bypasses DNS
                result.rows.append(Row(
                    values={"kind": "hosts", "subject": ", ".join(fqdns)[:40],
                            "detail": f"→ {ip}", "flags": "redirect"},
                    severity=Severity.WARNING, key=f"hosts:{ip}",
                    detail=f"/etc/hosts maps {', '.join(fqdns)} → {ip}",
                ))
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"/etc/hosts redirects {', '.join(fqdns)} → {ip}",
                    detail="static host entry pointing a domain at a public IP",
                    key=f"hosts:{ip}",
                )
        if recent:
            result.add_finding(
                Severity.WARNING, self.source,
                "/etc/hosts modified recently",
                detail=self._mtime_str("/etc/hosts"), key="hosts:mtime",
            )

    # ---- /etc/resolv.conf -------------------------------------------------

    def _resolv(self, result: CollectResult) -> None:
        text, _ = self.read_text("/etc/resolv.conf")
        if not text:
            return
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("nameserver"):
                continue
            ip = s.split()[-1]
            public = self._is_public(ip)
            result.rows.append(Row(
                values={"kind": "dns", "subject": ip,
                        "detail": "nameserver", "flags": "public" if public else ""},
                severity=Severity.INFO if public else None,
                key=f"dns:{ip}", detail=f"resolv.conf nameserver {ip}",
            ))

    # ---- sshd_config ------------------------------------------------------

    def _sshd(self, result: CollectResult) -> None:
        files = ["/etc/ssh/sshd_config"] + sorted(
            glob.glob("/etc/ssh/sshd_config.d/*.conf")
        )
        checks = {
            "permitrootlogin": (("yes", "prohibit-password"),
                                "root SSH login allowed"),
            "passwordauthentication": (("yes",), "password auth enabled"),
            "permitemptypasswords": (("yes",), "empty passwords permitted"),
        }
        for path in files:
            text, denied = self.read_text(path)
            if denied:
                result.notes.append(f"needs root: {path}")
                continue
            if not text:
                continue
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 1)
                if len(parts) != 2:
                    continue
                key, val = parts[0].lower(), parts[1].strip().lower()
                if key in checks and val in checks[key][0]:
                    danger = checks[key][1]
                    sev = (Severity.CRITICAL if key == "permitemptypasswords"
                           else Severity.WARNING)
                    result.rows.append(Row(
                        values={"kind": "sshd", "subject": parts[0],
                                "detail": val, "flags": "weak"},
                        severity=sev, key=f"sshd:{key}",
                        detail=f"{path}: {s}\n{danger}",
                    ))
                    result.add_finding(
                        sev, self.source, f"sshd: {danger} ({parts[0]} {val})",
                        detail=path, key=f"sshd:{key}",
                    )

    # ---- firewall ---------------------------------------------------------

    def _firewall(self, result: CollectResult) -> None:
        rc, out, _ = self.run(["ufw", "status"])
        if rc == 0 and out:
            active = "Status: active" in out
            result.rows.append(Row(
                values={"kind": "firewall", "subject": "ufw",
                        "detail": "active" if active else "inactive",
                        "flags": "" if active else "open"},
                severity=None if active else Severity.INFO, key="fw:ufw",
                detail=out.strip()[:400],
            ))
            if not active:
                result.add_finding(
                    Severity.INFO, self.source, "ufw firewall is inactive",
                    key="fw:ufw",
                )
            return
        # no ufw — check iptables (needs root to read)
        rc, out, err = self.run(["iptables", "-S"])
        if rc == 0:
            rules = [l for l in out.splitlines() if l and not l.startswith("-P")]
            open_fw = len(rules) == 0
            result.rows.append(Row(
                values={"kind": "firewall", "subject": "iptables",
                        "detail": f"{len(rules)} rule(s)",
                        "flags": "open" if open_fw else ""},
                severity=Severity.INFO if open_fw else None, key="fw:iptables",
                detail=out.strip()[:400] or "no rules",
            ))
        elif rc == 127:
            result.notes.append("no ufw/iptables found")
        else:
            result.notes.append("firewall state needs root")

    # ---- capabilities -----------------------------------------------------

    def _capabilities(self, result: CollectResult) -> None:
        rc, out, err = self.run(
            ["getcap", "-r", "/usr", "/bin", "/sbin", "/opt", "/lib"],
            timeout=60,
        )
        if rc == 127:
            result.notes.append("getcap not installed (capability scan skipped)")
            return
        for line in out.splitlines():
            # format: "/path/bin cap_net_raw=ep" or "/path/bin = cap_net_raw+ep"
            if not line.strip():
                continue
            path = line.split()[0]
            caps_str = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            low = caps_str.lower()
            hit = sorted(c for c in DANGEROUS_CAPS if c in low)
            if not hit:
                continue
            # A capability on a package-owned binary is vendor-intended
            # (snap-confine, ping, gst-ptp-helper, ...). The real signal is a
            # privileged capability on a binary NO package owns — a dropped or
            # copied binary given caps for privesc/persistence.
            owned = self._pkg_owned(path)
            sev = None if owned else Severity.WARNING
            result.rows.append(Row(
                values={"kind": "capability", "subject": path,
                        "detail": caps_str.strip()[:40],
                        "flags": "pkg" if owned else "priv-cap"},
                severity=sev, key=f"cap:{path}",
                detail=f"{path}\ncapabilities: {caps_str.strip()}\n"
                       f"package-owned: {owned}",
            ))
            if not owned:
                worst = (Severity.CRITICAL
                         if ("cap_setuid" in low or "cap_sys_module" in low)
                         else Severity.WARNING)
                result.add_finding(
                    worst, self.source,
                    f"privileged capability on unowned binary {path}: "
                    f"{', '.join(hit)}",
                    detail=caps_str.strip(), key=f"cap:{path}",
                )

    def _pkg_owned(self, path: str) -> bool:
        """True if a package owns this path (dpkg or rpm). Unknown → assume
        owned (conservative: don't cry wolf when we can't tell)."""
        rc, _out, _ = self.run(["dpkg", "-S", path], timeout=5)
        if rc == 0:
            return True
        if rc == 1:  # dpkg ran and found no owner
            return False
        rc2, _o2, _ = self.run(["rpm", "-qf", path], timeout=5)
        if rc2 == 0:
            return True
        if rc2 == 1:
            return False
        return True  # no package manager available — can't judge, stay quiet

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _is_public(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_unspecified)

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


if __name__ == "__main__":
    print_result(ConfigCollector().collect())
