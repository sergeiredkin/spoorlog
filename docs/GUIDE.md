# spoorlog — User Guide & Flag Reference

This guide explains **how to read the app**, **what each flag means in every
section**, and **what to do when something lights up**.

`spoorlog` is a triage aid: it surfaces *leads*, not verdicts. A colored flag is an
invitation to look closer, not proof of compromise. On a healthy machine most
tabs show zero findings — that is the expected "nothing tampered" baseline.

---

## 1. How to read the app

**Severity colors** are consistent everywhere:

| Color | Level | Meaning |
|---|---|---|
| 🔴 red (bold) | **CRITICAL** | act now — strong compromise signal |
| 🟡 yellow | **WARNING** | verify soon — suspicious or risky |
| dim / uncolored | INFO / context | background, usually benign |

**Layout**
- **Overview (`1`)** — system summary, live *Vitals* gauges, and the aggregated
  findings feed from every collector. Start here.
- **Detail tabs (`2`–`0`)** — one table per area. Rows carry the raw evidence;
  the `FLAGS` column is why a row is interesting.
- **Timeline (`t`)** — every timestamped event merged chronologically, with an
  activity histogram on top.

**Keys:** `1`–`9` / `0` / `t` switch tabs · `r` refresh · `/` filter the current
table · `Enter` open the full evidence for the selected row · `e` export a JSON
report · `q` quit.

**Root vs not.** Run with `sudo -E spoorlog` for the full picture.
Without root, locked-down areas (`/etc/shadow`, full `dpkg -V`, kernel ring,
some capabilities) show a dim *"needs root"* note instead of crashing.

---

## 2. The golden rule — preserve before you remediate

Running *any* tool on a live host perturbs its state. If a finding might be a
real incident:

1. **Confirm** — press `Enter` on the row to read the full evidence.
2. **Preserve first.** Copy `/proc/<pid>/exe`, note remote IPs, capture RAM/disk
   **before** you kill processes or delete files. Remediation destroys evidence.
3. **Correlate across tabs** — a genuine compromise usually lights up several.
4. **Then remediate** — kill/quarantine, remove persistence *and* payload,
   reinstall tampered packages, rotate credentials.

`spoorlog` never modifies the system. The only thing it writes is the JSON report
you request — write that to external media to keep evidence off the host.

---

## 3. Flag reference by section

### Overview → Vitals (`1`)
Not findings — live system gauges, colored **green < 70% → amber < 90% → red**.
A full `/` or `/var` can mean log flooding or a dropped payload; a network
sparkline that never idles on a "quiet" box is worth a glance. Correlate spikes
with the other tabs.

### Processes (`2`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `deleted-bin` | CRIT | process running from a binary deleted off disk | Classic malware trick. `ls -l /proc/<pid>/exe`, dump it (`cp /proc/<pid>/exe /tmp/evidence`), check `cmdline` & parent, then act. |
| `temp-path` | CRIT | executable running from `/tmp`, `/dev/shm`, `/var/tmp` | Legit software rarely does this. Inspect the binary and its connections. |
| `name-mismatch` | info | process name ≠ its on-disk binary name | Masquerading (a "kworker" that isn't). Benign for browsers/electron; cross-check Net. |
| `no-tty-shell` | WARN | a shell with no controlling terminal | Often a reverse shell. Check Net for the same PID. |
| `cpu NN%` | info | sustained high CPU | Possible crypto-miner; confirm it's a known workload. |

### Network (`3`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `shell-conn` | CRIT | an interpreter/shell has an outbound connection to a non-loopback IP | Strongest reverse-shell signal. Record the remote IP:port, then preserve and kill. |
| `odd-listen` | WARN | listener on a non-standard port | Identify the owning service (`ss -ltnp`). |
| `wildcard` | WARN | listener bound to `0.0.0.0` / `::` (internet-reachable) | Should it be public? Firewall it if not. |
| `odd-remote` | info | established connection to an unusual remote | Reputation-check the IP. |

### Users (`4`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `uid0` | CRIT | non-root account with UID 0 | Backdoor root. Confirm in `/etc/passwd`, lock it. |
| `empty-pw` | CRIT | account with no password | `passwd -l` or set one. |
| `login-shell` | WARN | service account has a real login shell | Should be `nologin`; find out why it changed. |
| `recent` (ssh-key) | WARN | `authorized_keys` modified in last 7 days | Review the keys — did *you* add them? Remove unknown ones. |
| `tamper` (history) | WARN | shell history symlinked to `/dev/null` | Deliberate anti-forensics. Treat the account as suspect. |
| `susp` (history) | WARN | download-and-run / reverse-shell command in history | Read the full line (`Enter`); pivot from what it did. |
| `failed` (login) | WARN | failed-login record | Bursts = brute force; check source IP, consider fail2ban. |

### Persistence (`5`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `susp` | CRIT | reverse-shell / download-run pattern in cron, unit, or rc file | Find what it launches; remove the persistence **and** the payload. |
| `recent` | WARN | cron/unit/startup file modified in last 7 days | Did a legit install do this? Cross-check Integrity → recent installs. |
| `present` (ld.preload) | CRIT | `/etc/ld.so.preload` exists at all | Library-injection rootkit vector. Inspect the listed `.so` now. |

### Files (`6`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `exec-in-temp` | CRIT | executable in a temp dir | Inspect/preserve; correlate with Processes. |
| `suid` | CRIT | SUID binary outside standard system paths | Privesc backdoor. `ls -l`, remove the bit if rogue. |
| `sgid` | WARN | SGID binary in an unusual path | Same, lower urgency. |
| `hidden` | WARN | dotfile in a temp dir | Staging area; read the contents. |

### Auth Log (`7`) — event flags
`login` (accepted SSH, note the source IP) · `acct-change` (WARN — user/group
added; confirm it was you) · `sniffer` (WARN — NIC entered **promiscuous mode**,
i.e. a packet capture is running) · `oom` / `crash` (info — stability, sometimes
a failing exploit) · `device` (USB attach) · `taint` (WARN — a tainting module
loaded → check the Kernel tab).

### Integrity (`8`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `md5` | CRIT under `/bin /sbin /usr/bin /usr/sbin /lib`, else WARN | package-owned file's checksum no longer matches what was installed | **Binary:** possible trojaned tool — `apt install --reinstall <pkg>` and investigate how it changed. **Config under /etc:** usually your own edit — confirm it's expected. |
| `attr` | WARN | file's mode/owner changed, contents intact | Lower risk; verify the change was intentional. |

### Kernel (`9`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `hidden-from-sys` | CRIT | module in `/proc/modules` but not `/sys/module` | Textbook LKM rootkit hiding itself. Highest priority — isolate the host. |
| `out-of-tree` / `unsigned` | WARN | module isn't from the distro kernel / lacks a valid signature | Often legit (nvidia, VirtualBox, zfs). Confirm you installed it. |
| `tainted:XXX` | info/WARN | decoded taint bits | `K`/`P`/`S` benign (livepatch, proprietary driver). `O`/`E`/`F`/`R` (out-of-tree / unsigned / forced) warrant a look. |

### Config (`0`)
| Flag | Sev | Means | What to do |
|---|---|---|---|
| `redirect` | WARN/CRIT | `/etc/hosts` points a real domain at a public IP | DNS hijack. Remove the line, find who added it. |
| `public` | WARN | `resolv.conf` nameserver isn't gateway/localhost/known resolver | Verify it's your intended DNS. |
| `weak` | WARN | risky `sshd_config` (`PermitRootLogin yes`, `PasswordAuthentication yes`, empty passwords) | Harden: key-only auth, no root login, reload sshd. |
| `open` | WARN | firewall inactive / no rules | Enable ufw/nftables with a default-deny inbound policy. |
| `priv-cap` | WARN | dangerous capability (`cap_setuid`, `cap_sys_admin`…) on a binary **not owned by any package** | SUID-equivalent privesc. Inspect it; `setcap -r` if rogue. |
| `pkg` | none | binary has caps but is package-owned | Informational — expected (e.g. `ping`, `snap-confine`). |

### Timeline (`t`)
The **histogram** buckets every timestamped event across its time span: column
height = event count, column color = the most severe event in that bucket. A
**red spike is a cluster of critical activity**. Use it to answer *"when did
things happen?"* — a burst of file changes / installs / key edits at 03:00 jumps
out here even when it's buried in the tables.

---

## 4. A quick triage playbook

A real intrusion rarely shows in one place. The strongest signal is
**correlation**:

- a `shell-conn` (Net) that shares a PID with a `temp-path` process (Proc),
- a `susp` cron entry or new unit (Persist),
- a matching `md5` binary change (Integrity),
- all clustered as a spike on the **Timeline**.

Suggested order when a box looks "off":
1. **Overview** — how many CRIT/WARN, and are the Vitals abnormal?
2. **Timeline (`t`)** — is there an activity spike? When?
3. **Processes + Network** — anything running/connecting it shouldn't?
4. **Persistence + Kernel + Integrity** — how would it survive a reboot / hide?
5. **Users + Auth Log** — how did they get in, and what did they touch?
6. Export a report (`e`) to external media before you remediate.

---

## 5. Forensic soundness

`spoorlog` is a fast **live-response** aid, not a substitute for imaging the disk
and RAM when you need court-defensible evidence. If the box may become a formal
case, capture volatile data first. Everything `spoorlog` does is read-only, but the
act of reading still perturbs live state (atimes, memory, the process table).

## 6. Authorized use

Run `spoorlog` only on systems you own or are explicitly authorized to inspect. It
is a defensive/forensic tool; use it accordingly.
