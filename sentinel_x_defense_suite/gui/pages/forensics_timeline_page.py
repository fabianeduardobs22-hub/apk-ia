from __future__ import annotations

from PyQt6.QtWidgets import QLabel, QMessageBox, QVBoxLayout, QWidget

from sentinel_x_defense_suite.gui.sections.forensics.models import TimelineEvent
from sentinel_x_defense_suite.gui.sections.workflow import DrillDownWorkflowWidget, ModuleExportToolbar, export_records


class ForensicsTimelinePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Timeline forense con drill-down uniforme"))
        self.export_toolbar = ModuleExportToolbar()
        layout.addWidget(self.export_toolbar)

        self.workflow = DrillDownWorkflowWidget()
        layout.addWidget(self.workflow)

        self._events: list[TimelineEvent] = []
        self.export_toolbar.exportRequested.connect(self._export)
        self.workflow.actionRequested.connect(self._on_action_requested)

    def push_event(self, payload: dict[str, str]) -> None:
        idx = len(self._events) + 1
        event = TimelineEvent(
            identifier=f"forensic-{idx}",
            time=payload.get("time", "-"),
            severity=payload.get("severity", "LOW"),
            entity=payload.get("entity", "unknown"),
            kind=payload.get("kind", "network"),
            summary=payload.get("summary", "-"),
            evidence=[f"Estado: {payload.get('state', 'open')}", f"Tipo: {payload.get('kind', 'network')}"],
            recommendation="Preservar evidencia y abrir ticket de seguimiento",
        )
        self._events.append(event)
        self.workflow.set_records([item.to_drilldown() for item in self._events])

    def _export(self, export_format: str) -> None:
        export_records("forensics_timeline", [event.to_drilldown() for event in self._events], export_format, self)

    def _on_action_requested(self, action_id: str, identifier: str) -> None:
        QMessageBox.information(self, "Acción defensiva", f"{action_id} solicitado desde evidencia {identifier}.")
