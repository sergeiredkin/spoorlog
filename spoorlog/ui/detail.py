"""Modal screen showing the full evidence text for a selected row/finding."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static


class DetailScreen(ModalScreen):
    """Dismissable popup with a monospace evidence dump."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("enter", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
    ]

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self._title = title
        self._body = body or "(no additional detail)"

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-box"):
            yield Static(f"[b]{self._title}[/b]", id="detail-title")
            yield Static(self._body, id="detail-body")
            yield Static("[dim]esc / enter to close[/dim]")

    def action_dismiss(self) -> None:
        self.dismiss()
