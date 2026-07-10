"""Auth-log collector: parse SSH/sudo/account events from the auth log.

Reads /var/log/auth.log (falls back to `journalctl` on systems that only keep
the journal). Detects:
- SSH failed-password bursts from a single source (brute force)
- accepted SSH logins with their source IPs
- sudo command invocations
- user add / delete / group changes
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

AUTH_PATHS = ["/var/log/auth.log", "/var/log/secure"]
MAX_LINES = 5000  # tail cap
BURST_THRESHOLD = 10  # failed attempts from one IP => brute-force finding

RE_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
RE_ACCEPTED = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
RE_SUDO = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)$")
RE_USERADD = re.compile(r"(useradd|userdel|usermod|groupadd)\[?\d*\]?:?\s*(.*)")


class LogsCollector(Collector):
    source = "logs"
    title = "Auth Log"
    cheap = False

    COLUMNS = [
        Column("time", "TIME", 16),
        Column("event", "EVENT", 12),
        Column("who", "WHO", 16),
        Column("detail", "DETAIL", 44),
        Column("flags", "FLAGS", 12),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        lines = self._read_log(result)
        if lines is None:
            return result

        failed_by_ip: dict[str, list[str]] = defaultdict(list)

        for line in lines:
            ts = line[:15]

            m = RE_FAILED.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                failed_by_ip[ip].append(user)
                result.rows.append(Row(
                    values={"time": ts, "event": "ssh-fail", "who": user,
                            "detail": f"from {ip}", "flags": ""},
                    severity=Severity.INFO, key=f"log:{line[:40]}",
                    detail=line.strip(),
                ))
                continue

            m = RE_ACCEPTED.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                result.rows.append(Row(
                    values={"time": ts, "event": "ssh-ok", "who": user,
                            "detail": f"from {ip}", "flags": "login"},
                    key=f"log:{line[:40]}", detail=line.strip(),
                ))
                continue

            m = RE_SUDO.search(line)
            if m:
                who, cmd = m.group(1), m.group(2).strip()
                result.rows.append(Row(
                    values={"time": ts, "event": "sudo", "who": who,
                            "detail": cmd[:44], "flags": ""},
                    key=f"log:{line[:40]}", detail=line.strip(),
                ))
                continue

            m = RE_USERADD.search(line)
            if m:
                result.rows.append(Row(
                    values={"time": ts, "event": m.group(1), "who": "",
                            "detail": m.group(2)[:44], "flags": "acct-change"},
                    severity=Severity.WARNING, key=f"log:{line[:40]}",
                    detail=line.strip(),
                ))
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"account management event: {m.group(1)}",
                    detail=line.strip(),
                )

        # brute-force bursts
        for ip, users in failed_by_ip.items():
            if len(users) >= BURST_THRESHOLD:
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"{len(users)} failed SSH logins from {ip}",
                    detail=f"targeted users: {', '.join(sorted(set(users))[:8])}",
                    key=f"burst:{ip}",
                )

        self._kernel_ring(result)

        result.rows.reverse()  # newest-ish first (log is chronological)
        result.rows.sort(key=lambda r: (r.severity is None,))
        return result

    def _kernel_ring(self, result: CollectResult) -> None:
        """Scan the kernel ring buffer (dmesg / journalctl -k) for forensic
        signals: sniffers, crashes, OOM kills, module loads, USB attach."""
        rc, out, _ = self.run(["dmesg", "--ctime"], timeout=15)
        if rc != 0 or not out:
            rc, out, _ = self.run(
                ["journalctl", "-k", "--no-pager", "-n", str(MAX_LINES)],
                timeout=15,
            )
        if rc != 0 or not out:
            if rc == 127:
                result.notes.append("no dmesg/journalctl -k for kernel ring")
            else:
                result.notes.append("kernel ring buffer needs root (dmesg_restrict)")
            return

        for line in out.splitlines()[-MAX_LINES:]:
            low = line.lower()
            event = flags = ""
            sev = None
            finding = None
            if "promiscuous mode" in low and "entered" in low:
                event, flags, sev = "promisc", "sniffer", Severity.WARNING
                finding = ("WARNING", "NIC entered promiscuous mode "
                           "(possible packet sniffer)")
            elif "segfault" in low:
                event, flags, sev = "segfault", "crash", Severity.INFO
            elif "out of memory" in low or "oom-kill" in low or \
                    "killed process" in low:
                event, flags, sev = "oom", "oom", Severity.INFO
            elif "new usb device" in low or "usb disconnect" in low:
                event, flags = "usb", "device"
            elif "module verification failed" in low or \
                    "loading out-of-tree module" in low or \
                    "module license" in low:
                event, flags, sev = "module", "taint", Severity.WARNING
                finding = ("WARNING", "kernel loaded a tainting module")
            else:
                continue
            result.rows.append(Row(
                values={"time": "kernel", "event": event, "who": "-",
                        "detail": line.strip()[-44:], "flags": flags},
                severity=sev, key=f"kmsg:{line[:40]}", detail=line.strip(),
            ))
            if finding:
                result.add_finding(
                    Severity.WARNING, self.source, finding[1],
                    detail=line.strip(), key=f"kmsg:{line[:40]}",
                )

    def _read_log(self, result: CollectResult) -> list[str] | None:
        for path in AUTH_PATHS:
            if os.path.exists(path):
                text, denied = self.read_text(path)
                if denied:
                    result.notes.append(f"needs root: {path}")
                    return None
                if text is not None:
                    return text.splitlines()[-MAX_LINES:]
        # fall back to the journal
        rc, out, err = self.run(
            ["journalctl", "-t", "sshd", "-t", "sudo", "--no-pager",
             "-n", str(MAX_LINES)],
            timeout=15,
        )
        if rc == 0 and out:
            return out.splitlines()
        if rc == 127:
            result.notes.append("no auth.log and journalctl unavailable")
        elif rc != 0:
            result.notes.append("journalctl read failed (try root)")
        return None


if __name__ == "__main__":
    print_result(LogsCollector().collect())
