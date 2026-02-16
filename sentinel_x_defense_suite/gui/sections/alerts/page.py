from __future__ import annotations

from PyQt6.QtWidgets import QLabel, QMessageBox, QVBoxLayout, QWidget

from sentinel_x_defense_suite.gui.sections.alerts.models import AlertRecord
from sentinel_x_defense_suite.gui.sections.workflow import DrillDownWorkflowWidget, ModuleExportToolbar, export_records


class AlertsPage(QWidget):
    pivotToHuntingRequested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Alerts Center · Gestión operativa"))

        self.export_toolbar = ModuleExportToolbar()
        root.addWidget(self.export_toolbar)

        self.workflow = DrillDownWorkflowWidget()
        root.addWidget(self.workflow)

        self.ack_button = self.workflow.open_ticket_button
        self.escalate_button = self.workflow.escalate_incident_button

        self._records: list[AlertRecord] = []
        self._load_seed_data()

        self.export_toolbar.exportRequested.connect(self._export)
        self.workflow.actionRequested.connect(self._on_action_requested)

    def _load_seed_data(self) -> None:
        self._records = [
            AlertRecord(
                identifier="alert-1",
                time="10:00:00",
                severity="HIGH",
                entity="host-01",
                detection="beaconing",
                state="open",
                evidence=["DNS saliente anómalo", "Flujo repetitivo cada 60s"],
                recommendation="Aislar host y elevar incidente",
            )
        ]
        self.workflow.set_records([row.to_drilldown() for row in self._records])

    def _export(self, export_format: str) -> None:
        export_records("alerts", [record.to_drilldown() for record in self._records], export_format, self)

    def _on_action_requested(self, action_id: str, identifier: str) -> None:
        QMessageBox.information(self, "Acción defensiva", f"{action_id} solicitado para alerta {identifier}.")
