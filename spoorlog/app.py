"""spoorlog — the Textual application: tabbed panels, workers, keybindings."""

from __future__ import annotations

import os

from textual import work
from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from .collectors.base import CollectResult, Collector
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
from .ui.overview import Overview
from .ui.panel import DataPanel, TimelinePanel

# (tab id, hotkey, collector factory). Overview and Timeline have no collector
# of their own — Overview aggregates findings, Timeline aggregates timestamped
# rows, both rebuilt from self.results.
PANELS = [
    ("proc", "2", ProcessCollector),
    ("net", "3", NetworkCollector),
    ("users", "4", UsersCollector),
    ("persist", "5", PersistenceCollector),
    ("files", "6", FilesCollector),
    ("logs", "7", LogsCollector),
    ("integrity", "8", IntegrityCollector),
    ("kernel", "9", KernelCollector),
    ("config", "0", ConfigCollector),
]

AUTO_REFRESH_SECONDS = 10


class TriageApp(App):
    CSS_PATH = "ui/styles.tcss"
    TITLE = "spoorlog"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("e", "export", "Export"),
        ("slash", "filter", "Filter"),
        ("escape", "clear_filter", "Clear filter"),
        ("1", "tab('overview')", "Overview"),
        ("2", "tab('proc')", "Proc"),
        ("3", "tab('net')", "Net"),
        ("4", "tab('users')", "Users"),
        ("5", "tab('persist')", "Persist"),
        ("6", "tab('files')", "Files"),
        ("7", "tab('logs')", "Logs"),
        ("8", "tab('integrity')", "Integrity"),
        ("9", "tab('kernel')", "Kernel"),
        ("0", "tab('config')", "Config"),
        ("t", "tab('timeline')", "Timeline"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.collectors: dict[str, Collector] = {
            name: factory() for name, _, factory in PANELS
        }
        self.results: dict[str, CollectResult] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="overview"):
            with TabPane("① Overview", id="overview"):
                yield Overview()
            with TabPane("② Proc", id="proc"):
                yield DataPanel("proc")
            with TabPane("③ Net", id="net"):
                yield DataPanel("net")
            with TabPane("④ Users", id="users"):
                yield DataPanel("users")
            with TabPane("⑤ Persist", id="persist"):
                yield DataPanel("persist")
            with TabPane("⑥ Files", id="files"):
                yield DataPanel("files")
            with TabPane("⑦ Logs", id="logs"):
                yield DataPanel("logs")
            with TabPane("⑧ Integrity", id="integrity"):
                yield DataPanel("integrity")
            with TabPane("⑨ Kernel", id="kernel"):
                yield DataPanel("kernel")
            with TabPane("⓪ Config", id="config"):
                yield DataPanel("config")
            with TabPane("⌚ Timeline", id="timeline"):
                yield TimelinePanel("timeline")
        yield Footer()

    def on_mount(self) -> None:
        priv = "root" if os.geteuid() == 0 else "limited privileges"
        self.sub_title = f"{priv} — scanning…"
        self.action_refresh()
        self.set_interval(AUTO_REFRESH_SECONDS, self._auto_refresh)

    # ---- collection workers ----------------------------------------------

    def action_refresh(self) -> None:
        self.sub_title = "scanning…"
        for name, collector in self.collectors.items():
            self._collect(name, collector)

    def _auto_refresh(self) -> None:
        # only the cheap collectors run on the timer to limit footprint
        for name, collector in self.collectors.items():
            if collector.cheap:
                self._collect(name, collector)

    @work(thread=True, group="collect", exclusive=False)
    def _collect(self, name: str, collector: Collector) -> None:
        try:
            result = collector.collect()
        except Exception as exc:  # pragma: no cover - defensive
            result = CollectResult(columns=[], rows=[])
            result.notes.append(f"collector error: {exc}")
        self.call_from_thread(self._apply, name, result)

    def _apply(self, name: str, result: CollectResult) -> None:
        self.results[name] = result
        try:
            pane = self.query_one(f"#{name}", TabPane)
            pane.query_one(DataPanel).load(result)
        except Exception:
            pass
        self.query_one(Overview).update_findings(self.results)
        self._rebuild_timeline()
        n = sum(len(r.findings) for r in self.results.values())
        priv = "root" if os.geteuid() == 0 else "limited"
        self.sub_title = f"{priv} — {n} findings"

    def _rebuild_timeline(self) -> None:
        # aggregate every timestamped row collected so far into one view;
        # build() ignores the "timeline" key, so there's no recursion
        timeline = TimelineCollector.build(self.results)
        self.results["timeline"] = timeline
        try:
            pane = self.query_one("#timeline", TabPane)
            pane.query_one(DataPanel).load(timeline)
        except Exception:
            pass

    # ---- key actions ------------------------------------------------------

    def action_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_filter(self) -> None:
        panel = self._active_panel()
        if panel is not None:
            panel.show_filter()

    def action_clear_filter(self) -> None:
        panel = self._active_panel()
        if panel is not None:
            panel.hide_filter()

    def action_export(self) -> None:
        if not self.results:
            self.notify("Nothing to export yet.", severity="warning")
            return
        path = write_report(self.results)
        self.notify(f"Report written to {path}", timeout=6)

    def _active_panel(self) -> DataPanel | None:
        active = self.query_one(TabbedContent).active
        if active == "overview":
            return None
        try:
            pane = self.query_one(f"#{active}", TabPane)
            return pane.query_one(DataPanel)
        except Exception:
            return None


def run() -> None:
    TriageApp().run()
