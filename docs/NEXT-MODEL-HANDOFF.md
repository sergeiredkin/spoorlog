# spoorlog — Next Model Handoff

Read this file before changing the repository. It records the current state,
completed work, product boundary, and the intended roadmap.

## Repository

- Path: `/home/sergei/Documents/linux forensic cle app`
- GitHub: `https://github.com/sergeiredkin/spoorlog`
- Branch: `main`
- At handoff: clean and synchronized with `origin/main`
- Current HEAD: `bae577a feat: accept Sentry investigation context`

Do not reset or rewrite existing commits. Commit completed changes and push them
to `origin/main`, unless the user explicitly requests a branch or PR.

## Product purpose

`spoorlog` is a read-only, local Linux forensic triage tool. It performs a
broad live-host inspection and presents analyst-oriented findings through a
Textual TUI or a headless JSON report.

Its complementary product is Sentry (`~/Documents/linux thread hunting app`):

- **Sentry owns:** continuous monitoring, SQLite state, persistent baseline,
  warmup, suppressions, alert history, and collector health.
- **spoorlog owns:** fresh broad triage, cross-panel correlation, timeline
  context, and self-contained evidence export.

Do not introduce a shared database or make spoorlog depend on Sentry. Keep the
handoff JSON-based and local.

## Completed work

### MVP collectors and UI

The repository contains collectors for processes, network, users, persistence,
files, authentication logs, package integrity, kernel state, and configuration.
It has a Textual dashboard, findings feed, detail views, filtering, timeline,
headless mode, and JSON export.

### Evidence-preserving reports — `3e4f352`

Reports preserve row values plus severity, stable key, detail/evidence, and
timestamp. Reports also include tool version, per-collector duration, notes,
and collector errors. Collector failures are represented rather than crashing
the entire scan.

### Bounded scan performance — `ca4bfc2`

Profiling identified `dpkg -V` as the dominant bottleneck (roughly 98–115s on
the development host). Headless collection uses a bounded four-worker pool.
`dpkg -V` and `rpm -Va` have a 30-second timeout. The timeout is explicitly
reported as an incomplete integrity check. A real headless scan completed in
about 30 seconds after this change.

Important: a timeout is not a successful integrity verification. Preserve this
limitation in UX and reports.

### Portable baseline comparison — `bb4ec6c`

Commands:

```bash
sudo spoorlog --baseline /mnt/usb/baseline.json
sudo spoorlog --compare /mnt/usb/baseline.json --output /mnt/usb/current.json
```

`spoorlog/baseline.py` reports added, removed, and changed rows per panel and
preserves before/after evidence. Timeline is excluded because it is derived.
Process identity uses PID; network identity ignores the ephemeral socket file
descriptor. This is a manual, portable comparison aid—not Sentry's persistent
baseline system.

### Sentry context handoff — `bae577a`

Sentry can produce a JSON alert context and spoorlog accepts it with:

```bash
spoorlog --context alert-context.json --report investigation.json
```

The context is preserved under `sentry_context` in the report. Supported
combined usage includes `--compare PATH --context PATH` with `--output PATH`.
The context loader fails safely with exit code 2 for unreadable/invalid JSON.

The intended Sentry workflow is:

```bash
sentry investigate ALERT_ID --output investigation-context.json
spoorlog --context investigation-context.json --report investigation.json
```

Check the Sentry repository's current CLI before documenting or modifying this
flow; another development process may be working there.

## Verification at handoff

- **133 tests passed** at the last full test run.
- Baseline comparison was tested against real reports.
- Syntax and fatal flake8 checks passed.
- `spoorlog` main branch is pushed and clean.

Run before committing:

```bash
cd /home/sergei/Documents/linux\ forensic\ cle\ app
pytest -q
python -m py_compile spoorlog/*.py
flake8 spoorlog --count --select=E9,F63,F7,F82 --show-source
```

## Roadmap

### Immediate next priority: validate the handoff end to end

1. Inspect Sentry's current `sentry investigate` implementation and tests.
2. Confirm its output schema matches spoorlog's `--context` expectations.
3. Add a cross-repository contract fixture or documented JSON schema without
   importing Python code across repositories.
4. Test: Sentry alert context -> spoorlog scan -> report containing both
   `sentry_context` and fresh collector evidence.
5. Ensure alert evidence is displayed prominently in the spoorlog TUI or at
   least in the headless report summary.

### Near-term product validation

1. Dogfood Sentry on the developer workstation for 1–2 weeks.
2. Classify every alert as expected, useful, or incorrect.
3. For useful alerts, measure whether spoorlog explains the event in under
   five minutes.
4. Record missing evidence, permission gaps, false positives, and stale data.
5. Tune existing rules before adding new detectors.

### After validation

- Add Sentry-to-spoorlog launch UX/TUI action only after the CLI contract is
  stable.
- Improve report time-window filtering (for example last 24h / 7d).
- Improve baseline identity rules based on workstation observations.
- Consider configurable integrity timeout or an explicit `--deep-integrity`
  mode, but do not hide incomplete verification.
- Add report schema versioning and migration/compatibility tests.

## Do not do next

- Do not duplicate Sentry's SQLite baseline, warmup, suppressions, or alert
  history inside spoorlog.
- Do not add generic monitoring, packet capture, malware signatures, cloud
  ingestion, or a large rule marketplace without validation evidence.
- Do not treat heuristic findings as verdicts.
- Do not silently discard collector failures or permission limitations.
- Do not weaken the read-only guarantee.

## Engineering notes

- The report schema changed from rows-as-values to rows containing a `values`
  object and evidence metadata. Keep backward compatibility in baseline loading
  for old reports.
- `spoorlog/__init__.py` reports version `1.0.0`; `pyproject.toml` also has
  version `1.0.0`.
- `.coverage` is ignored. Do not commit generated reports or host evidence.
- The Engineering Knowledge repository contains related packets under
  `~/Documents/Engineering-Knowledge/00-INBOX/`, including the Sentry/spoorlog
  integration decision and current progress notes.
