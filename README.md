# spoorlog

*Spoor* is the trail an animal leaves; a *log* is the trail a system leaves.
**spoorlog** reads the digital tracks on a live Linux box to answer *"has this
box been messed with?"* in one screen.

A terminal-based forensic **triage** tool for live Linux systems — think `btop`,
but instead of monitoring performance it hunts for signs of compromise.

`spoorlog` runs a set of read-only collectors over the running system, applies
compromise-detection heuristics, and surfaces ranked **findings**
(CRITICAL / WARNING / INFO) on a dashboard, with drill-down tabs for each area.

```
┌ spoorlog ─ ubuntu-web01 · 6.8.0 · root — 14:32 ───────────────────────┐
│ ① Overview ② Proc ③ Net ④ Users ⑤ Persist ⑥ Files ⑦ Logs             │
│ ⑧ Integrity ⑨ Kernel ⓪ Config ⌚ Timeline                             │
├───────────────────────────────────────────────────────────────────────┤
│ ┌ System ───────────────┐  ┌ Findings — 2 CRIT 5 WARN ───────────────┐│
│ │ Host   ubuntu-web01   │  │ ● CRIT proc: pid 4182 from deleted binary││
│ │ Kernel 6.8.0-51        │  │ ● CRIT net:  bash → 185.x.x.x:4444       ││
│ │ Uptime 14d 3h          │  │ ● WARN users: authorized_keys changed 2h ││
│ └────────────────────────┘  │ ● WARN persist: new unit update.service  ││
│ ┌ Vitals ────────────────┐  │ ● WARN logs: 240 failed ssh from 203.x   ││
│ │ CPU ▐████░░░░▌ 38% load │  └──────────────────────────────────────────┘│
│ │ Mem ▐██████░░▌ 82%      │                                              │
│ │ Net ▂▃▅▇█▅▃▂  1.2M/s    │                                              │
│ │ /   ▐███████░▌ 94%      │                                              │
│ └────────────────────────┘                                              │
├───────────────────────────────────────────────────────────────────────┤
│ q Quit  r Refresh  e Export  / Filter  ↑↓ Select  Enter Details        │
└───────────────────────────────────────────────────────────────────────┘
```

## What it checks

| Tab | Looks for |
|-----|-----------|
| **Processes** | binaries deleted while running, execution from `/tmp` `/dev/shm`, name masquerading, detached shells, high-CPU miners |
| **Network** | reverse-shell patterns (interpreter with an outbound connection), externally-reachable listeners on odd ports |
| **Users** | extra UID-0 accounts, empty passwords, service accounts with login shells, sudo group members, recently changed `authorized_keys`, failed-login bursts |
| **Persistence** | crontabs & `cron.*`, recently added systemd units, suspicious shell-rc lines, `/etc/rc.local`, **`/etc/ld.so.preload`** (rootkit vector) |
| **Files** | files changed in the last 24h in hot dirs, executables in temp dirs, non-standard SUID/SGID binaries |
| **Auth Log** | SSH brute-force bursts, accepted logins + source IPs, sudo usage, account-management events, and kernel-ring signals (promiscuous-mode NIC / sniffer, OOM kills, segfaults, USB attach, tainting module loads) |
| **Integrity** | package-owned system binaries altered on disk (`dpkg -V` / `rpm -Va` checksum mismatches), recently installed/upgraded packages, snap/flatpak inventory |
| **Kernel** | loaded-module inventory, decoded kernel taint bits, **hidden LKM rootkit** detection (`/proc/modules` vs `/sys/module` diff), unsigned / out-of-tree modules |
| **Config** | `/etc/hosts` domain→public-IP redirects, rogue `resolv.conf` nameservers, weak `sshd_config` (root login, password auth, empty passwords), firewall posture, **file capabilities** on unowned binaries (SUID-equivalent privesc) |
| **Timeline** | every timestamped artifact the other collectors produce — package installs, unit/cron mtimes, hot-dir file changes, `authorized_keys`/`known_hosts` edits — merged into one newest-first super-timeline, topped by an activity **histogram** (per-bucket event count, colored by the most severe event in the bucket — a red spike = a cluster of critical activity) |

The **Overview** shows a glances-style *Vitals* panel — CPU / memory / swap and
per-mount disk as color-graded gauges (green → amber → red) plus a live network
throughput sparkline — so system state reads at a glance alongside the findings.

## Install

**As a normal command (recommended)** — [pipx](https://pipx.pypa.io) puts
`spoorlog` on your `PATH` in its own isolated environment:

```bash
sudo apt install pipx && pipx ensurepath
pipx install git+https://github.com/YOUR-USERNAME/spoorlog.git
```

**From a local checkout:**

```bash
git clone https://github.com/YOUR-USERNAME/spoorlog.git
cd spoorlog
python3 -m venv .venv
.venv/bin/pip install -e .
```

> Replace `YOUR-USERNAME` with your GitHub handle. Requires Python ≥ 3.10 on
> Linux.

## Run

```bash
sudo -E spoorlog    # recommended — root sees the full picture
spoorlog            # works unprivileged; unreadable areas show "needs root"
```

(If you installed into a venv instead of pipx, call `.venv/bin/spoorlog`.)

Keys: `1`–`9` / `0` / `t` switch tabs · `r` refresh · `/` filter the current
table · `Enter` open full evidence for a row · `e` export a JSON report · `q`
quit.

**New here?** Read the [User Guide & Flag Reference](docs/GUIDE.md) — what every
flag means in each tab and what to do when one fires.

### Headless / over SSH

No TUI, just a report (handy on a server or in a script):

```bash
sudo spoorlog --report          # writes spoorlog-report-<host>-<ts>.json
sudo spoorlog --report /mnt/usb/case01.json
```

Each collector can also be run on its own:

```bash
python -m spoorlog.collectors.processes
```

## Design notes

- **Read-only.** The tool only reads `/proc`, config files, and logs. The single
  thing it ever writes is the report you ask for with `e` / `--report` — write it
  to external media to keep the evidence off the host.
- **Graceful under low privilege.** Unreadable files become a dim "needs root"
  note rather than a crash.
- **Low footprint.** Cheap collectors refresh every 10s; the filesystem walk and
  log parse run only on manual refresh, so the tool doesn't hammer a box you're
  investigating.
- **Heuristics, not verdicts.** Findings are leads for a human to confirm — tuned
  to minimise obvious false positives (loopback dev servers, browser worker
  renaming, stock `.bashrc` `eval` lines), but a WARNING is an invitation to look,
  not proof of compromise.

### Forensic soundness

Running *any* tool on a live system perturbs its state (memory, atimes, process
table). `spoorlog` is a **triage** aid for fast live response — not a substitute
for imaging the disk/RAM when you need court-defensible evidence. Capture volatile
data first if the box may become a formal case.

## Authorized use

`spoorlog` is a defensive / forensic tool that **only reads** the system. Run it
only on hosts you own or are explicitly authorized to inspect.

## Roadmap

`1.0` ships the full collector set above — including the package-integrity,
kernel / hidden-LKM, config & capability, and timeline capabilities derived from
Bruce Nikkel's *Practical Linux Forensics*.

Ideas for later: remembering a baseline to diff against on the next run, and a
time-window narrowing control (last 24h / 7d) on the Timeline tab.

## Contributing

Issues and pull requests are welcome. Keep the core principle intact: **the tool
must stay read-only on the host under investigation** — the only write is the
user-requested report. Test detection changes against fixtures or a disposable
VM, never by modifying the host.

## License

[MIT](LICENSE) © 2026 Sergei Redkin
