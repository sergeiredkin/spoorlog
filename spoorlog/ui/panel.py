"""Generic data panel: a filterable, sortable DataTable for one collector.

Each detail tab (Processes, Network, ...) is a DataPanel. It renders a
CollectResult, colours flagged rows by severity, supports a `/` filter, and
opens a detail popup on Enter.
"""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Input, Static

from ..collectors.base import CollectResult, Row
from ..findings import Severity
from .detail import DetailScreen
from .graphics import hms, time_histogram


class DataPanel(Vertical):
    """A collector-backed table panel."""

    def __init__(self, source: str) -> None:
        super().__init__(classes="panel")
        self.source = source
        self._result: CollectResult | None = None
        self._filter = ""

    def compose(self) -> ComposeResult:
        yield Input(placeholder="filter… (Esc to clear)", classes="filter")
        yield Static("", classes="panel-status")
        yield DataTable(zebra_stripes=True, cursor_type="row")

    # ---- data loading -----------------------------------------------------

    def load(self, result: CollectResult) -> None:
        """Populate the table from a fresh CollectResult."""
        self._result = result
        self._rebuild()

    def _rebuild(self) -> None:
        if self._result is None:
            return
        table = self.query_one(DataTable)
        table.clear(columns=True)
        for col in self._result.columns:
            table.add_column(col.label, key=col.key, width=col.width)

        rows = self._visible_rows()
        for row in rows:
            table.add_row(*self._render_cells(row), key=row.key or None)

        self._update_status(len(rows))

    def _render_cells(self, row: Row) -> list[Text]:
        cells = []
        for col in self._result.columns:  # type: ignore[union-attr]
            val = row.values.get(col.key, "")
            text = Text(str(val))
            if row.severity is not None:
                text.stylize(row.severity.color)
            cells.append(text)
        return cells

    def _visible_rows(self) -> list[Row]:
        assert self._result is not None
        if not self._filter:
            return self._result.rows
        needle = self._filter.lower()
        out = []
        for row in self._result.rows:
            hay = " ".join(str(v) for v in row.values.values()).lower()
            if needle in hay:
                out.append(row)
        return out

    def _update_status(self, shown: int) -> None:
        status = self.query_one(".panel-status", Static)
        assert self._result is not None
        total = len(self._result.rows)
        n_find = len(self._result.findings)
        parts = [f"{shown}/{total} rows", f"{n_find} findings"]
        if self._filter:
            parts.append(f"filter: '{self._filter}'")
        if self._result.notes:
            parts.append("⚠ " + "; ".join(self._result.notes))
        status.update("  ·  ".join(parts))

    # ---- interaction ------------------------------------------------------

    def show_filter(self) -> None:
        inp = self.query_one(Input)
        inp.add_class("-visible")
        inp.focus()

    def hide_filter(self) -> None:
        inp = self.query_one(Input)
        inp.remove_class("-visible")
        inp.value = ""
        self._filter = ""
        self._rebuild()
        self.query_one(DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._filter = event.value
        self._rebuild()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.query_one(DataTable).focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row = self._row_by_key(event.row_key.value if event.row_key else None)
        if row is None:
            return
        title = f"{self.source}: {row.key}" if row.key else self.source
        self.app.push_screen(DetailScreen(title, row.detail))

    def _row_by_key(self, key: str | None):
        if self._result is None:
            return None
        if key is None:
            return None
        for row in self._result.rows:
            if row.key == key:
                return row
        return None


class TimelinePanel(DataPanel):
    """The Timeline tab — a normal DataPanel with an activity histogram on top.

    The bar buckets every timestamped event across its own time span; each
    column's height is its event count and its color is the most severe event
    in that bucket, so a red spike reads as a cluster of critical activity.
    """

    def compose(self) -> ComposeResult:
        yield Static("", classes="timeline-hist")
        yield from super().compose()

    def load(self, result: CollectResult) -> None:
        super().load(result)
        self._render_hist(result)

    def _render_hist(self, result: CollectResult) -> None:
        banner = self.query_one(".timeline-hist", Static)
        hist = time_histogram((r.timestamp, r.severity) for r in result.rows)
        if hist is None:
            banner.update(Text("no timestamped events yet", style="dim"))
            return
        bar, lo, hi, peak = hist
        title = Text("Activity over time  ", style="bold")
        title.append(f"(peak {peak}/bucket, {len(result.rows)} events)", style="dim")
        span = Text(hms(lo), style="dim")
        span.append(" " + "─" * max(bar.cell_len - 12, 1) + " ", style="dim")
        span.append(hms(hi), style="dim")
        banner.update(Text("\n").join([title, bar, span]))
