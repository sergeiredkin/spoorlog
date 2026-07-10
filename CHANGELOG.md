# Changelog

All notable changes to `spoorlog` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-07-10

First public release. A read-only, findings-first Textual TUI for live Linux
forensic triage.

### Collectors / tabs
- **Overview** — system summary, aggregated findings feed, and a glances-style
  *Vitals* panel (CPU / memory / swap / disk gauges + network sparkline).
- **Processes** — deleted-while-running binaries, execution from temp dirs,
  name masquerading, detached shells, high-CPU processes.
- **Network** — reverse-shell patterns, externally reachable listeners.
- **Users** — extra UID-0 accounts, empty passwords, service-account login
  shells, sudo members, recent `authorized_keys`/`known_hosts` edits, shell
  history mining + tamper detection, failed-login bursts.
- **Persistence** — cron, systemd units, shell rc hooks, `/etc/rc.local`,
  `/etc/ld.so.preload`.
- **Files** — recent changes in hot dirs, executables in temp, non-standard
  SUID/SGID.
- **Auth Log** — SSH brute force, accepted logins, sudo, account changes, and
  kernel-ring signals (promiscuous mode / OOM / segfault / USB / taint).
- **Integrity** — package-owned binary tampering (`dpkg -V` / `rpm -Va`),
  recent installs, snap/flatpak inventory.
- **Kernel** — module inventory, decoded taint bits, hidden-LKM rootkit diff
  (`/proc/modules` vs `/sys/module`), unsigned / out-of-tree modules.
- **Config** — `/etc/hosts` redirects, rogue DNS, weak `sshd_config`, firewall
  posture, file capabilities on unowned binaries.
- **Timeline** — cross-collector super-timeline with an activity histogram.

### Other
- JSON report export (`e` in the TUI, or `--report` headless).
- Graceful degradation without root (unreadable areas become "needs root").
