"""Network collector: listening sockets and connections mapped to processes.

Heuristics:
- outbound connection owned by a shell/interpreter  (reverse-shell pattern)
- listener bound to a wildcard address on an uncommon port
- established connection to a public IP on an odd/high port
"""

from __future__ import annotations

import ipaddress

import psutil

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

SHELL_INTERP = {
    "sh", "bash", "dash", "zsh", "ksh",
    "python", "python3", "perl", "ruby", "php", "node", "nc", "ncat", "socat",
}
# ports we expect a normal server to speak on; anything else is worth a look
COMMON_PORTS = {
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 443, 465, 587,
    993, 995, 3000, 3306, 5432, 6379, 8080, 8443, 27017,
}


class NetworkCollector(Collector):
    source = "net"
    title = "Network"
    cheap = True

    COLUMNS = [
        Column("proto", "PROTO", 6),
        Column("state", "STATE", 12),
        Column("laddr", "LOCAL", 22),
        Column("raddr", "REMOTE", 22),
        Column("pid", "PID", 7),
        Column("proc", "PROCESS", 16),
        Column("flags", "FLAGS", 18),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            result.notes.append("net_connections denied — run as root")
            return result

        names = self._pid_names()
        for c in conns:
            proto = {1: "tcp", 2: "udp"}.get(int(c.type), str(c.type))
            laddr = self._fmt(c.laddr)
            raddr = self._fmt(c.raddr)
            pid = c.pid or ""
            pname = names.get(c.pid, "?") if c.pid else "-"

            flags: list[str] = []
            severity: Severity | None = None

            # reverse-shell pattern: an interpreter/shell with an outbound
            # connection to a *non-loopback* host (loopback would be a local
            # dev server talking to itself, e.g. streamlit/flask).
            if (
                c.status == "ESTABLISHED"
                and c.raddr
                and pname in SHELL_INTERP
                and c.raddr.ip not in ("127.0.0.1", "::1")
                and not c.raddr.ip.startswith("::ffff:127.")
            ):
                flags.append("shell-conn")
                # An interpreter talking to a public host on 80/443 is usually a
                # normal HTTPS/API call; on an odd port it's a reverse-shell
                # candidate. Grade accordingly instead of screaming at every
                # `requests.get`.
                public = self._is_public(c.raddr.ip)
                odd_port = c.raddr.port not in COMMON_PORTS
                if public and odd_port:
                    severity = Severity.CRITICAL
                else:
                    severity = Severity.WARNING

            if c.status == "LISTEN" and c.laddr:
                port = c.laddr.port
                loopback = c.laddr.ip in ("127.0.0.1", "::1")
                wildcard = c.laddr.ip in ("0.0.0.0", "::")
                # A loopback listener on a high port is normal (dev servers,
                # editors, IPC). Only externally-reachable listeners on
                # uncommon ports are worth flagging.
                if not loopback and port not in COMMON_PORTS:
                    flags.append("odd-listen")
                    severity = _max(severity, Severity.WARNING)
                    if wildcard:
                        flags.append("wildcard")

            if (
                c.status == "ESTABLISHED"
                and c.raddr
                and self._is_public(c.raddr.ip)
                and c.raddr.port not in COMMON_PORTS
            ):
                flags.append("odd-remote")
                severity = _max(severity, Severity.WARNING)

            row = Row(
                values={
                    "proto": proto,
                    "state": c.status or "-",
                    "laddr": laddr,
                    "raddr": raddr,
                    "pid": pid,
                    "proc": pname,
                    "flags": ",".join(flags),
                },
                severity=severity,
                key=f"net:{c.fd}:{laddr}:{raddr}",
                detail=(
                    f"{proto} {c.status}\n"
                    f"local={laddr}\nremote={raddr}\n"
                    f"pid={pid} ({pname})\nflags={', '.join(flags) or 'none'}"
                ),
            )
            result.rows.append(row)

            if "shell-conn" in flags:
                result.add_finding(
                    severity or Severity.WARNING, self.source,
                    f"{pname} (pid {pid}) connected out to {raddr}",
                    detail="possible reverse shell", key=row.key,
                )
            elif "odd-listen" in flags:
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"{pname} listening on {laddr}",
                    detail="uncommon port", key=row.key,
                )
            elif "odd-remote" in flags:
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"{pname} (pid {pid}) talking to {raddr}",
                    detail="public IP on uncommon port", key=row.key,
                )

        result.rows.sort(
            key=lambda r: (r.severity is None, r.values["state"] != "LISTEN")
        )
        return result

    @staticmethod
    def _pid_names() -> dict[int, str]:
        out: dict[int, str] = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                out[p.info["pid"]] = p.info["name"] or "?"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out

    @staticmethod
    def _fmt(addr) -> str:
        if not addr:
            return "-"
        try:
            return f"{addr.ip}:{addr.port}"
        except AttributeError:
            return str(addr)

    @staticmethod
    def _is_public(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )


def _max(current: Severity | None, new: Severity) -> Severity:
    if current is None:
        return new
    return current if current >= new else new


if __name__ == "__main__":
    print_result(NetworkCollector().collect())
