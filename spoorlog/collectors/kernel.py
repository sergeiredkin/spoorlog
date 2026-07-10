"""Kernel & rootkit-surface collector.

Derived from Nikkel, *Practical Linux Forensics*, Ch. 2/6 (kernel, /proc, boot).
Loadable-kernel-module rootkits are a classic Linux persistence + hiding
mechanism; this collector surfaces the tells:

- loaded module inventory (``/proc/modules``)
- tainted kernel (``/proc/sys/kernel/tainted``) with the bits decoded
- hidden modules: a name in ``/proc/modules`` but absent from ``/sys/module/``
  (or vice-versa) — the way LKM rootkits unlink themselves from one list
- out-of-tree / unsigned modules (taint 'O'/'E' via ``modinfo``)
"""

from __future__ import annotations

import os

from ..findings import Severity
from .base import Collector, CollectResult, Column, Row, print_result

# /proc/sys/kernel/tainted bit meanings (subset that matters for triage)
TAINT_BITS = {
    0: ("P", "proprietary module loaded"),
    1: ("F", "module force-loaded"),
    2: ("S", "kernel running on out-of-spec CPU"),
    3: ("R", "module force-unloaded"),
    5: ("B", "bad page / hardware error"),
    9: ("O", "out-of-tree module loaded"),
    10: ("E", "unsigned module loaded"),
    11: ("L", "soft lockup occurred"),
    12: ("K", "kernel live-patched"),
}
# modules commonly out-of-tree on desktops — don't cry rootkit over these
KNOWN_OOT = {"vboxdrv", "vboxnetflt", "vboxnetadp", "nvidia", "nvidia_modeset",
             "nvidia_uvm", "nvidia_drm", "wl", "zfs", "zunicode", "zavl",
             "znvpair", "zcommon", "spl", "v4l2loopback"}


class KernelCollector(Collector):
    source = "kernel"
    title = "Kernel"
    cheap = True

    COLUMNS = [
        Column("module", "MODULE", 24),
        Column("size", "SIZE", 10),
        Column("used_by", "USED BY", 30),
        Column("flags", "FLAGS", 24),
    ]

    def collect(self) -> CollectResult:
        result = CollectResult(columns=self.COLUMNS, rows=[])
        proc_mods = self._proc_modules()
        sys_mods = self._sys_modules()

        self._check_taint(result)
        self._check_hidden(result, proc_mods, set(sys_mods))

        for name, (size, used_by, users) in sorted(proc_mods.items()):
            flags: list[str] = []
            sev: Severity | None = None
            if name not in sys_mods:
                flags.append("hidden-from-sys")
                sev = Severity.CRITICAL
            oot, unsigned = self._module_taint(name)
            if oot and name not in KNOWN_OOT:
                flags.append("out-of-tree")
                sev = _max(sev, Severity.WARNING)
            if unsigned and name not in KNOWN_OOT:
                flags.append("unsigned")
                sev = _max(sev, Severity.WARNING)
            result.rows.append(Row(
                values={"module": name, "size": size,
                        "used_by": users or "-", "flags": ",".join(flags)},
                severity=sev, key=f"mod:{name}",
                detail=f"module {name}\nsize={size} used_by={used_by}\n"
                       f"flags={', '.join(flags) or 'none'}",
            ))
        result.rows.sort(key=lambda r: (r.severity is None, r.values["module"]))
        return result

    def _check_taint(self, result: CollectResult) -> None:
        text, denied = self.read_text("/proc/sys/kernel/tainted")
        if not text:
            return
        try:
            value = int(text.strip())
        except ValueError:
            return
        if value == 0:
            return
        active = [(f, d) for bit, (f, d) in TAINT_BITS.items() if value & (1 << bit)]
        letters = "".join(f for f, _ in active)
        desc = "; ".join(d for _, d in active)
        # Only 'O' (out-of-tree), 'E' (unsigned) and 'F'/'R' (force load/unload)
        # are rootkit-relevant. 'K' (livepatch), 'P' (proprietary, e.g. nvidia)
        # and 'S' are routine on desktops — show them, but don't raise a finding.
        interesting = {f for f, _ in active} & {"O", "E", "F", "R"}
        sev = Severity.WARNING if interesting else Severity.INFO
        result.rows.append(Row(
            values={"module": "<kernel>", "size": "-", "used_by": "-",
                    "flags": f"tainted:{letters}"},
            severity=sev, key="taint",
            detail=f"kernel tainted value={value} ({letters})\n{desc}",
        ))
        if interesting:
            result.add_finding(
                sev, self.source, f"kernel tainted ({letters}): {desc}",
                detail=f"/proc/sys/kernel/tainted = {value}", key="taint",
            )

    def _check_hidden(self, result: CollectResult, proc_mods: dict,
                      sys_mods: set) -> None:
        hidden = set(proc_mods) - sys_mods
        for name in sorted(hidden):
            result.add_finding(
                Severity.CRITICAL, self.source,
                f"module '{name}' loaded but hidden from /sys/module",
                detail="classic LKM-rootkit hiding tell", key=f"mod:{name}",
            )

    # ---- readers ----------------------------------------------------------

    @staticmethod
    def _proc_modules() -> dict[str, tuple[str, str, str]]:
        out: dict[str, tuple[str, str, str]] = {}
        try:
            with open("/proc/modules") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    name, size, refcnt, used_by = parts[0], parts[1], parts[2], parts[3]
                    users = "" if used_by == "-" else used_by.strip(",")
                    out[name] = (size, used_by, users)
        except OSError:
            pass
        return out

    @staticmethod
    def _sys_modules() -> list[str]:
        try:
            return os.listdir("/sys/module")
        except OSError:
            return []

    def _module_taint(self, name: str) -> tuple[bool, bool]:
        """Return (out_of_tree, unsigned) from modinfo, best-effort."""
        rc, out, _ = self.run(["modinfo", "-F", "intree", name], timeout=5)
        out_of_tree = rc == 0 and out.strip() != "Y"
        rc2, sig, _ = self.run(["modinfo", "-F", "signature", name], timeout=5)
        unsigned = rc2 == 0 and not sig.strip()
        return out_of_tree, unsigned


def _max(current: Severity | None, new: Severity | None) -> Severity | None:
    vals = [x for x in (current, new) if x is not None]
    return max(vals) if vals else None


if __name__ == "__main__":
    print_result(KernelCollector().collect())
