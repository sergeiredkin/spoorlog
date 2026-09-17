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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--report",
        nargs="?",
        const="",
        metavar="PATH",
        help="run once headless and write a JSON report to PATH "
             "(default: ./spoorlog-report-<host>-<ts>.json), then exit",
    )
    mode.add_argument(
        "--baseline", metavar="PATH",
        help="capture a report to PATH for a later --compare run",
    )
    mode.add_argument(
        "--compare", metavar="PATH",
        help="compare a fresh scan with baseline PATH and include the diff",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="output path for --compare (defaults to a timestamped report)",
    )
    args = parser.parse_args(argv)

    if args.baseline:
        return _batch_report(args.baseline)
    if args.compare:
        return _batch_report(args.output, compare_path=args.compare)
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


def _batch_report(path: str | None, compare_path: str | None = None) -> int:
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
    from .baseline import compare_reports, load_report
    from .report import build_report, write_report

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
    comparison = None
    if compare_path:
        try:
            current = build_report(results)
            comparison = compare_reports(load_report(compare_path), current)
            counts = comparison["counts"]
            print(
                f"[=] baseline diff: +{counts['added']} "
                f"-{counts['removed']} ~{counts['changed']}",
                file=sys.stderr,
            )
        except (OSError, ValueError) as exc:
            print(f"[!] baseline comparison failed: {exc}", file=sys.stderr)
            return 2
    out = write_report(results, path, comparison=comparison)
    total = sum(len(r.findings) for r in results.values())
    print(f"[+] {total} findings — report written to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
