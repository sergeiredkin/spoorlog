"""Overview dashboard: system summary + aggregated findings feed."""

from __future__ import annotations

import os
import platform
import socket
import time
from collections import deque

import psutil
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Static

from ..collectors.base import CollectResult
from ..findings import Finding, Severity, sort_findings
from .graphics import gauge_line, sparkline

# filesystem types that aren't real storage — skip in the disk gauges
_PSEUDO_FS = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "devpts",
    "cgroup", "cgroup2", "efivarfs", "autofs", "ramfs", "fuse.snapfuse",
}


class Overview(Vertical):
    """The landing dashboard (tab 1)."""

    def compose(self) -> ComposeResult:
        with Vertical(id="overview"):
            with Vertical(id="overview-left"):
                yield Static("", id="system-card", classes="card")
                yield Static("", id="activity-card", classes="card")
            with Vertical(id="overview-right"):
                with Vertical(id="findings-card"):
                    yield Static("", id="findings-title", classes="card-title")
                    with VerticalScroll(id="findings-list"):
                        yield Static("", id="findings-body")

    def on_mount(self) -> None:
        self._render_system()

    def _render_system(self) -> None:
        uptime = time.time() - psutil.boot_time()
        boot = time.strftime("%Y-%m-%d %H:%M", time.localtime(psutil.boot_time()))
        user = "root" if os.geteuid() == 0 else (os.getenv("USER") or "user")
        sys_lines = [
            "[b]System[/b]",
            f"Host    {socket.gethostname()}",
            f"Kernel  {platform.release()}",
            f"OS      {_os_pretty()}",
            f"Boot    {boot}",
            f"Uptime  {_fmt_dur(uptime)}",
            f"Running {'as root' if os.geteuid() == 0 else f'as {user} (limited)'}",
        ]
        self.query_one("#system-card", Static).update("\n".join(sys_lines))
        self._render_activity()

    def _render_activity(self) -> None:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        try:
            la1, la5, la15 = os.getloadavg()
            load = f"load {la1:.2f} {la5:.2f} {la15:.2f}"
        except OSError:
            load = ""

        lines: list[Text] = [Text("Vitals", style="bold")]
        lines.append(gauge_line("CPU", psutil.cpu_percent(), load))
        lines.append(gauge_line(
            "Mem", vm.percent,
            f"{_fmt_bytes(vm.used)} / {_fmt_bytes(vm.total)}"))
        if sm.total:
            lines.append(gauge_line(
                "Swap", sm.percent, f"{_fmt_bytes(sm.used)} / {_fmt_bytes(sm.total)}"))

        # network throughput sparkline from a rolling sample buffer
        lines.append(self._net_line())

        # per-mount disk usage
        for mount, pct, used, total in self._disks():
            lines.append(gauge_line(mount, pct, f"{_fmt_bytes(used)}/{_fmt_bytes(total)}"))

        lines.append(Text(
            f"{len(psutil.pids())} procs · {len(psutil.users())} users",
            style="dim"))

        body = Text("\n").join(lines)
        self.query_one("#activity-card", Static).update(body)

    def _net_line(self) -> Text:
        io = psutil.net_io_counters()
        now = time.time()
        total = io.bytes_sent + io.bytes_recv
        if not hasattr(self, "_net_hist"):
            self._net_hist: deque[float] = deque(maxlen=40)
            self._last_net = total
            self._last_net_t = now
        dt = max(now - self._last_net_t, 1e-6)
        rate = max(total - self._last_net, 0) / dt
        self._last_net, self._last_net_t = total, now
        self._net_hist.append(rate)
        line = Text("Net   ", style="bold")
        line.append_text(sparkline(self._net_hist))
        line.append(f"  {_fmt_bytes(rate)}/s", style="dim")
        return line

    def _disks(self, limit: int = 4) -> list[tuple[str, float, int, int]]:
        out: list[tuple[str, float, int, int]] = []
        seen: set[str] = set()
        for part in psutil.disk_partitions(all=False):
            if part.fstype.lower() in _PSEUDO_FS or part.device in seen:
                continue
            seen.add(part.device)
            try:
                u = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            mount = part.mountpoint if len(part.mountpoint) <= 5 else \
                part.mountpoint[:4] + "…"
            out.append((mount, u.percent, u.used, u.total))
            if len(out) >= limit:
                break
        return out

    def update_findings(self, results: dict[str, CollectResult]) -> None:
        """Aggregate findings from all collectors and render the feed."""
        self._render_activity()
        findings: list[Finding] = []
        for res in results.values():
            findings.extend(res.findings)
        findings = sort_findings(findings)

        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        warn = sum(1 for f in findings if f.severity == Severity.WARNING)
        info = sum(1 for f in findings if f.severity == Severity.INFO)
        title = Text("Findings  ", style="bold")
        title.append(f"{crit} CRIT ", style="red bold")
        title.append(f"{warn} WARN ", style="yellow")
        title.append(f"{info} INFO", style="dim")
        self.query_one("#findings-title", Static).update(title)

        body = self.query_one("#findings-body", Static)
        if not findings:
            body.update(Text("No findings yet — collectors still running or "
                             "system looks clean.", style="dim"))
            return
        out = Text()
        for f in findings:
            out.append("● ", style=f.severity.color)
            out.append(f"{f.severity.label}  ", style=f"{f.severity.color} bold")
            out.append(f"{f.source}: ", style="bold")
            out.append(f"{f.title}\n")
            if f.detail:
                out.append(f"      {f.detail}\n", style="dim")
        body.update(out)


def _os_pretty() -> str:
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


def _fmt_dur(seconds: float) -> str:
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}P"
