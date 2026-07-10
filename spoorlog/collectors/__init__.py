"""Collectors: UI-free data gatherers, one per triage panel.

Each collector subclasses :class:`spoorlog.collectors.base.Collector` and returns
a :class:`CollectResult` (rows + findings). Collectors never touch the UI, so
they can be run standalone (``python -m spoorlog.collectors.processes``) or reused
by the batch ``--report`` mode.
"""

from .base import Collector, CollectResult, Column

__all__ = ["Collector", "CollectResult", "Column"]
