# spoorlog — Troubleshooting & FAQ

## Installation Issues

### `pipx: command not found`

After installing pipx, you may need to add it to your PATH:

```bash
pipx ensurepath
```

Then reload your shell:
```bash
source ~/.bashrc
# or
source ~/.zshrc
```

### Python version error

spoorlog requires **Python ≥ 3.10**. Check your version:

```bash
python3 --version
```

If you have an older Python, install a newer version:
```bash
# Ubuntu/Debian
sudo apt install python3.11 python3.11-venv

# Then use explicitly:
python3.11 -m venv .venv
```

---

## Running spoorlog

### `sudo: spoorlog: command not found`

`sudo` doesn't see the pipx bin directory. Use one of these:

**Quick fix (works immediately):**
```bash
sudo /home/$USER/.local/bin/spoorlog
```

**Permanent fix (recommended, one-time setup):**
```bash
sudo visudo
```

Find the line that starts with `Defaults secure_path` and add `:/home/$USER/.local/bin` to the end. It should look like:

```
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/$USER/.local/bin"
```

Save (Ctrl+X if in nano, then Y, then Enter). Then:
```bash
sudo -E spoorlog
```

### `spoorlog: command not found` (without sudo)

pipx installed spoorlog, but your shell doesn't see it. Reload your PATH:

```bash
pipx ensurepath
source ~/.bashrc
# or: source ~/.zshrc
```

Then try again:
```bash
spoorlog
```

---

## Running spoorlog

### "needs root" on every tab

spoorlog works unprivileged but is limited. Many checks require root:

```bash
sudo -E spoorlog
```

The `-E` preserves your user environment while using sudo privileges.

### Blank screen / TUI doesn't render

Ensure you have a terminal that supports:
- ANSI colors (most modern terminals do)
- UTF-8 encoding
- Minimum 80×24 character size

Try:
```bash
sudo -E spoorlog
```

If it still doesn't work, try the headless mode:
```bash
sudo spoorlog --report /tmp/report.json
cat /tmp/report.json
```

### TUI hangs or is very slow

This usually means the filesystem walk is running (checking `/proc`, `/home`, etc).

- Press `r` to manually refresh only the fast collectors
- On very large systems, the first run takes longer
- Subsequent runs (with `r` refresh) are faster

---

## Reports & Export

### `spoorlog --report` takes too long

The first run walks the filesystem. Subsequent runs are faster.

To speed it up, limit what collectors run. For now, just wait — v1.2 will have options to exclude slow collectors.

### Report file location

By default, reports go to:
```
./spoorlog-report-<hostname>-<timestamp>.json
```

To save elsewhere:
```bash
sudo spoorlog --report /mnt/usb/my-case.json
```

### JSON report is hard to read

Pretty-print it:
```bash
cat report.json | jq .
```

(Requires `jq` installed; `apt install jq`)

---

## Findings & Detections

### False positives: Why is my system flagged?

Read the evidence. Press `Enter` on a finding to see the raw data.

Common false positives:
- **Loopback web servers** — localhost listeners are usually safe
- **Browser workers** — Firefox/Chrome rename processes; not malware
- **Stock eval in .bashrc** — some distros include eval lines in default `.bashrc`

Not a false positive? Open an issue on GitHub.

### Missing detections: Why didn't spoorlog flag this?

spoorlog catches common compromise patterns. Some attacks:
- Use legitimate admin tools (`kubectl`, `terraform`, etc) — hard to distinguish
- Happen offline (outside the time window spoorlog checks)
- Leave few traces on the running system

If you found something real that spoorlog missed, open an issue with details.

---

## Upgrading

### Upgrade to the latest version

```bash
pipx upgrade spoorlog
```

### Downgrade to a previous version

```bash
pipx install --force spoorlog==1.0.0
```

---

## Getting Help

- **[User Guide & Flag Reference](docs/GUIDE.md)** — what each finding means
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to report bugs and suggest features
- **GitHub Issues** — https://github.com/sergeiredkin/spoorlog/issues

---

## Known Limitations (v1.0)

- No baseline comparison (planned for v1.1)
- No time-window filter on Timeline (planned for v1.2)
- Some collectors slow on systems with millions of files
- Cannot run multiple instances concurrently on the same host

These will be addressed in future releases.
