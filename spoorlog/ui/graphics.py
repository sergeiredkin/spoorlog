"""Terminal chart primitives — text gauges, sparklines, a time histogram.

Everything returns a Rich ``Text`` so it drops straight into a ``Static``.
Coloring follows a *status* palette (healthy → elevated → critical), which is
the correct encoding for ratio meters and severity-bucketed activity — not a
categorical rainbow.
"""

from __future__ import annotations

import time
from typing import Iterable, Sequence

from rich.text import Text

from ..findings import Severity

_BLOCKS = "▁▂▃▄▅▆▇█"


def gauge(pct: float, width: int = 12, good: float = 70, warn: float = 90) -> Text:
    """A horizontal fill meter. Green under ``good``, amber under ``warn``, red above."""
    pct = max(0.0, min(100.0, pct))
    filled = int(round(pct / 100 * width))
    if pct >= warn:
        color = "red"
    elif pct >= good:
        color = "yellow"
    else:
        color = "green"
    t = Text()
    t.append("▐", style="dim")
    t.append("█" * filled, style=color)
    t.append("░" * (width - filled), style="dim")
    t.append("▌", style="dim")
    return t


def gauge_line(label: str, pct: float, suffix: str = "", width: int = 12) -> Text:
    t = Text(f"{label:5} ", style="bold")
    t.append_text(gauge(pct, width))
    t.append(f" {pct:3.0f}% ", style="")
    if suffix:
        t.append(f" {suffix}", style="dim")
    return t


def sparkline(values: Sequence[float], color: str = "cyan") -> Text:
    """A one-line block sparkline scaled to its own min/max."""
    vals = [v for v in values]
    if not vals:
        return Text("—", style="dim")
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    t = Text()
    for v in vals:
        idx = int((v - lo) / span * (len(_BLOCKS) - 1))
        t.append(_BLOCKS[idx], style=color)
    return t


def _sev_rank(sev: Severity | None) -> int:
    if sev == Severity.CRITICAL:
        return 3
    if sev == Severity.WARNING:
        return 2
    if sev == Severity.INFO:
        return 1
    return 0


_RANK_COLOR = {3: "red", 2: "yellow", 1: "cyan", 0: "dim"}


def time_histogram(
    events: Iterable[tuple[float | None, Severity | None]], cols: int = 48
) -> tuple[Text, float, float, int] | None:
    """Bucket ``(timestamp, severity)`` events across their own time span.

    Returns ``(bar, lo, hi, peak)`` or ``None`` when nothing is timestamped.
    Each column's height is its event count; its color is the most severe event
    that fell in that bucket — so a red spike is a cluster of critical activity.
    """
    evs = [(t, s) for t, s in events if t]
    if not evs:
        return None
    times = [t for t, _ in evs]
    lo, hi = min(times), max(times)
    span = (hi - lo) or 1.0
    counts = [0] * cols
    ranks = [0] * cols
    for t, s in evs:
        idx = int((t - lo) / span * (cols - 1))
        counts[idx] += 1
        r = _sev_rank(s)
        if r > ranks[idx]:
            ranks[idx] = r
    peak = max(counts) or 1
    bar = Text()
    for c, r in zip(counts, ranks):
        if not c:
            bar.append(" ")
            continue
        ch = _BLOCKS[int(c / peak * (len(_BLOCKS) - 1))]
        bar.append(ch, style=_RANK_COLOR[r])
    return bar, lo, hi, peak


def hms(ts: float) -> str:
    return time.strftime("%m-%d %H:%M", time.localtime(ts))
