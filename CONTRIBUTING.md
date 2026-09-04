# Contributing to spoorlog

spoorlog is a defensive forensic tool — **it must stay read-only on the host under investigation**.

## Before you PR

- **Test on a VM, not your production box.** Test detection changes and new collectors on a disposable Linux VM, never a live system you care about.
- **Keep the core principle.** The tool only reads. Never add writes except the user-requested JSON report (`e` / `--report`). Write evidence to external media, never the host.
- **Check what already exists.** Review the collectors in `spoorlog/collectors/` before adding a new one — avoid duplication.
- **Heuristics, not verdicts.** Findings are leads for a human to confirm, not proof. Tune detection to minimize obvious false positives (loopback servers, browser worker renames, stock `.bashrc` `eval` lines) but accept that a WARNING is an invitation to look, not certainty.

## How to run locally

```bash
git clone https://github.com/sergeiredkin/spoorlog.git
cd spoorlog
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
sudo -E spoorlog
```

**Without root:** Most areas work unprivileged; unreadable sections show "needs root".

## Submitting a PR

1. **Link an issue** if one exists (or create one to discuss first).
2. **Describe what you're detecting and why** — what compromise signal are you looking for?
3. **Test it** — include fixture data, a VM repro, or a description of where you tested.
4. **Keep it focused** — one collector improvement or one detection per PR.

## Code style

- Follow PEP 8 (flake8 linting runs on CI).
- Use type hints where clear.
- Keep functions focused — collectors are easier to maintain when they're small and single-purpose.

## Questions?

Open an issue or start a discussion. This is a forensic tool used by security pros — your feedback helps make it better.

---

**License:** MIT © 2026 Sergei Redkin
