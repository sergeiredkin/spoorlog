"""Entry point: ``spoorlog`` / ``python -m spoorlog``.

Flags:
    --report [PATH]   run all collectors once, write a JSON report, and exit
                      (no TUI — handy over SSH or in scripts)
"""

from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spoorlog",
        description="Terminal forensic triage for live Linux systems.",
    )
    parser.add_argument(
        "--report",
        nargs="?",
        const="",
        metavar="PATH",
        help="run once headless and write a JSON report to PATH "
             "(default: ./spoorlog-report-<host>-<ts>.json), then exit",
    )
    args = parser.parse_args(argv)

    if args.report is not None:
        return _batch_report(args.report or None)

    # interactive TUI
    from .app import run
    run()
    return 0


def _collect_one(collector):
    """Run one collector and turn failures into reportable evidence."""
    from .collectors.base import CollectResult

    started = time.perf_counter()
    try:
        result = collector.collect()
    except Exception as exc:  # keep one broken collector from losing the case
        result = CollectResult(columns=[], rows=[])
        result.error = f"{type(exc).__name__}: {exc}"
        result.notes.append(f"collector error: {result.error}")
    result.duration_ms = round((time.perf_counter() - started) * 1000, 1)
    return result


def _batch_report(path: str | None) -> int:
    from .collectors.config import ConfigCollector
    from .collectors.files import FilesCollector
    from .collectors.integrity import IntegrityCollector
    from .collectors.kernel import KernelCollector
    from .collectors.logs import LogsCollector
    from .collectors.network import NetworkCollector
    from .collectors.persistence import PersistenceCollector
    from .collectors.processes import ProcessCollector
    from .collectors.timeline import TimelineCollector
    from .collectors.users import UsersCollector
    from .report import write_report

    collectors = {
        "proc": ProcessCollector(),
        "net": NetworkCollector(),
        "users": UsersCollector(),
        "persist": PersistenceCollector(),
        "files": FilesCollector(),
        "logs": LogsCollector(),
        "integrity": IntegrityCollector(),
        "kernel": KernelCollector(),
        "config": ConfigCollector(),
    }
    # Collectors are read-only and independent. A bounded pool keeps the
    # headless scan responsive without creating one thread per collector.
    results = {}
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="spoorlog") as pool:
        futures = {}
        for name, collector in collectors.items():
            print(f"[*] {name}…", file=sys.stderr)
            futures[pool.submit(_collect_one, collector)] = name
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    # timeline is an aggregator over the collected rows — build it last
    print("[*] timeline…", file=sys.stderr)
    results["timeline"] = TimelineCollector.build(results)
    out = write_report(results, path)
    total = sum(len(r.findings) for r in results.values())
    print(f"[+] {total} findings — report written to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
