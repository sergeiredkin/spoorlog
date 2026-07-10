"""Users & logins collector: account audit + login history.

Covers:
- extra UID-0 accounts (backdoor root)
- accounts with empty passwords
- currently logged-in sessions (psutil.users)
- recent logins / failed logins (last / lastb)
- sudo group members
- per-user ~/.ssh/authorized_keys inventory + recent-mod flag
"""

from __future__ import annotations

import glob
import os
import time

import psutil

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

SYSTEM_SHELLS_OK = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}
# high-signal patterns in shell history (download-and-run, reverse shells,
# privilege/anti-forensics). Kept tight to avoid flagging normal admin work.
HISTORY_SNIPPETS = (
    "/dev/tcp/", "|bash", "| bash", "|sh", "| sh", "curl -s", "wget -q",
    "base64 -d", "base64 --decode", "nc -e", "ncat -e", "bash -i", "chmod +s",
    "chmod u+s", "unset histfile", "history -c", "chattr +i",
)
RECENT_DAYS = 7


class UsersCollector(Collector):
    source = "users"
    title = "Users"
    cheap = True

    COLUMNS = [
        Column("kind", "KIND", 10),
        Column("name", "NAME", 14),
        Column("detail", "DETAIL", 44),
        Column("flags", "FLAGS", 20),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        self._accounts(result)
        self._logged_in(result)
        self._sudo(result)
        self._ssh_keys(result)
        self._known_hosts(result)
        self._shell_history(result)
        self._login_history(result)
        result.rows.sort(key=lambda r: (r.severity is None,))
        return result

    def _accounts(self, result: CollectResult) -> None:
        passwd, _ = self.read_text("/etc/passwd")
        shadow, sh_denied = self.read_text("/etc/shadow")
        if sh_denied:
            result.notes.append("needs root: /etc/shadow (empty-password check)")

        empty_pw = set()
        if shadow:
            for line in shadow.splitlines():
                parts = line.split(":")
                if len(parts) > 1 and parts[1] == "":
                    empty_pw.add(parts[0])

        if not passwd:
            return
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid, _, _, home, shell = parts[:7]
            flags: list[str] = []
            sev: Severity | None = None
            if uid == "0" and name != "root":
                flags.append("uid0")
                sev = Severity.CRITICAL
            if name in empty_pw:
                flags.append("empty-pw")
                sev = Severity.CRITICAL
            # a login shell on a would-be service account
            if int(uid) < 1000 and uid != "0" and shell not in SYSTEM_SHELLS_OK \
                    and shell.endswith(("sh",)):
                flags.append("login-shell")
                sev = _max(sev, Severity.WARNING)
            if flags:
                result.rows.append(Row(
                    values={"kind": "account", "name": name,
                            "detail": f"uid={uid} shell={shell}",
                            "flags": ",".join(flags)},
                    severity=sev, key=f"acct:{name}",
                    detail=f"{name}: uid={uid} home={home} shell={shell}",
                ))
                if "uid0" in flags:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"non-root account '{name}' has UID 0",
                        detail=line, key=f"acct:{name}",
                    )
                if "empty-pw" in flags:
                    result.add_finding(
                        Severity.CRITICAL, self.source,
                        f"account '{name}' has an empty password",
                        key=f"acct:{name}",
                    )
                if "login-shell" in flags:
                    result.add_finding(
                        Severity.WARNING, self.source,
                        f"service account '{name}' has login shell {shell}",
                        key=f"acct:{name}",
                    )

    def _logged_in(self, result: CollectResult) -> None:
        for u in psutil.users():
            started = time.strftime("%Y-%m-%d %H:%M", time.localtime(u.started))
            host = getattr(u, "host", "") or "local"
            result.rows.append(Row(
                values={"kind": "session", "name": u.name,
                        "detail": f"tty={u.terminal} from={host} @ {started}",
                        "flags": ""},
                key=f"sess:{u.name}:{u.terminal}",
                detail=f"{u.name} on {u.terminal} from {host} since {started}",
            ))

    def _sudo(self, result: CollectResult) -> None:
        group, _ = self.read_text("/etc/group")
        if not group:
            return
        for line in group.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[0] in ("sudo", "wheel", "admin"):
                members = [m for m in parts[3].split(",") if m]
                for m in members:
                    result.rows.append(Row(
                        values={"kind": "sudoer", "name": m,
                                "detail": f"member of '{parts[0]}' group",
                                "flags": ""},
                        key=f"sudo:{m}",
                        detail=f"{m} is in the {parts[0]} group",
                    ))

    def _ssh_keys(self, result: CollectResult) -> None:
        for ak in glob.glob("/root/.ssh/authorized_keys") + glob.glob(
            "/home/*/.ssh/authorized_keys"
        ):
            text, denied = self.read_text(ak)
            if denied:
                result.notes.append(f"needs root: {ak}")
                continue
            if text is None:
                continue
            recent = self._is_recent(ak)
            n_keys = sum(
                1 for l in text.splitlines() if l.strip() and not l.startswith("#")
            )
            owner = ak.split("/")[2] if ak.startswith("/home/") else "root"
            sev = Severity.WARNING if recent else None
            result.rows.append(Row(
                values={"kind": "ssh-key", "name": owner,
                        "detail": f"{n_keys} key(s), {self._mtime_str(ak)}",
                        "flags": "recent" if recent else ""},
                severity=sev, key=f"ak:{ak}", timestamp=self._epoch(ak),
                detail=f"{ak}\n{text}",
            ))
            if recent:
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"authorized_keys for {owner} modified recently",
                    detail=f"{ak} — {self._mtime_str(ak)}", key=f"ak:{ak}",
                )

    def _known_hosts(self, result: CollectResult) -> None:
        # a map of hosts each account has SSH'd to — lateral-movement context
        for kh in glob.glob("/root/.ssh/known_hosts") + glob.glob(
            "/home/*/.ssh/known_hosts"
        ):
            text, denied = self.read_text(kh)
            if denied:
                continue
            if not text:
                continue
            owner = kh.split("/")[2] if kh.startswith("/home/") else "root"
            hosts = [l.split()[0] for l in text.splitlines()
                     if l.strip() and not l.startswith("#") and l.split()]
            n = len(hosts)
            result.rows.append(Row(
                values={"kind": "known-hosts", "name": owner,
                        "detail": f"{n} host(s): {', '.join(hosts[:3])[:34]}",
                        "flags": ""},
                key=f"kh:{kh}", timestamp=self._epoch(kh),
                detail=f"{kh}\n" + "\n".join(hosts[:30]),
            ))

    def _shell_history(self, result: CollectResult) -> None:
        homes = ["/root"] + glob.glob("/home/*")
        for home in homes:
            owner = os.path.basename(home)
            for hist in (".bash_history", ".zsh_history", ".sh_history"):
                path = os.path.join(home, hist)
                # tampering: history redirected to /dev/null to defeat logging
                try:
                    if os.path.islink(path) and os.path.realpath(path) == "/dev/null":
                        result.rows.append(Row(
                            values={"kind": "history", "name": owner,
                                    "detail": f"{hist} → /dev/null", "flags": "tamper"},
                            severity=Severity.WARNING, key=f"histtamper:{path}",
                            detail=f"{path} is symlinked to /dev/null "
                                   f"(shell history disabled)",
                        ))
                        result.add_finding(
                            Severity.WARNING, self.source,
                            f"{owner}'s {hist} redirected to /dev/null",
                            detail="anti-forensics: shell history disabled",
                            key=f"histtamper:{path}",
                        )
                        continue
                except OSError:
                    pass
                text, denied = self.read_text(path)
                if denied:
                    result.notes.append(f"needs root: {path}")
                    continue
                if text is None:
                    continue
                for line in text.splitlines():
                    low = line.lower()
                    hits = [s for s in HISTORY_SNIPPETS if s in low]
                    if hits:
                        result.rows.append(Row(
                            values={"kind": "history", "name": owner,
                                    "detail": line.strip()[:40], "flags": "susp"},
                            severity=Severity.WARNING, key=f"hist:{path}:{line[:16]}",
                            detail=f"{path}\n{line.strip()}",
                        ))
                        result.add_finding(
                            Severity.WARNING, self.source,
                            f"suspicious command in {owner}'s {hist}",
                            detail=line.strip(), key=f"hist:{path}:{line[:16]}",
                        )

    def _login_history(self, result: CollectResult) -> None:
        rc, out, _ = self.run(["last", "-n", "10", "-w"])
        if rc == 0 and out:
            for line in out.splitlines():
                if not line.strip() or line.startswith("wtmp"):
                    continue
                result.rows.append(Row(
                    values={"kind": "login", "name": line.split()[0],
                            "detail": line.strip()[:44], "flags": ""},
                    key=f"last:{line[:20]}", detail=line.strip(),
                ))
        rc, out, _ = self.run(["lastb", "-n", "10", "-w"])
        if rc == 0 and out:
            fails = [l for l in out.splitlines()
                     if l.strip() and not l.startswith("btmp")]
            if len(fails) >= 5:
                result.add_finding(
                    Severity.WARNING, self.source,
                    f"{len(fails)} recent failed login(s) recorded",
                    detail="\n".join(fails[:5]),
                )
            for line in fails:
                result.rows.append(Row(
                    values={"kind": "failed", "name": line.split()[0],
                            "detail": line.strip()[:44], "flags": "failed"},
                    severity=Severity.WARNING, key=f"lastb:{line[:20]}",
                    detail=line.strip(),
                ))
        elif rc == 127:
            result.notes.append("lastb unavailable (failed-login history)")

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
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))
        except OSError:
            return "?"

    @staticmethod
    def _epoch(path: str) -> float | None:
        try:
            return os.path.getmtime(path)
        except OSError:
            return None


def _max(current: Severity | None, new: Severity | None) -> Severity | None:
    vals = [x for x in (current, new) if x is not None]
    return max(vals) if vals else None


if __name__ == "__main__":
    print_result(UsersCollector().collect())
