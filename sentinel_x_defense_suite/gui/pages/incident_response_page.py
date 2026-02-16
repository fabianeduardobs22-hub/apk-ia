from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.gui.sections.incident_response.models import ResponseTask
from sentinel_x_defense_suite.gui.sections.workflow import DrillDownWorkflowWidget, ModuleExportToolbar, export_records


class IncidentResponsePage(QWidget):
    playbookExecuted = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)

        controls = QGroupBox("Incident Response · Modo seguro")
        controls_layout = QHBoxLayout(controls)
        self.safe_mode = QCheckBox("Ejecutar playbooks en modo seguro")
        self.safe_mode.setChecked(True)
        self.run_containment = QPushButton("Ejecutar contención")
        self.run_eradication = QPushButton("Ejecutar erradicación")
        controls_layout.addWidget(self.safe_mode)
        controls_layout.addWidget(self.run_containment)
        controls_layout.addWidget(self.run_eradication)
        controls_layout.addStretch(1)
        root.addWidget(controls)

        self.export_toolbar = ModuleExportToolbar()
        root.addWidget(self.export_toolbar)

        self.workflow = DrillDownWorkflowWidget()
        root.addWidget(self.workflow)

        self.status = QLabel("Sin ejecuciones")
        self.status.setObjectName("statusBadge")
        root.addWidget(self.status)

        self._records: list[ResponseTask] = []
        self._load_default_tasks()

        self.run_containment.clicked.connect(lambda: self._execute("Containment"))
        self.run_eradication.clicked.connect(lambda: self._execute("Eradication"))
        self.export_toolbar.exportRequested.connect(self._export)
        self.workflow.actionRequested.connect(self._on_action_requested)

    def _load_default_tasks(self) -> None:
        self._records = [
            ResponseTask("ir-1", "Contención", "SOC L2", "pending", ["Host con beacon C2"], "Aislar host"),
            ResponseTask("ir-2", "Contención", "SOC L2", "pending", ["Destino malicioso 203.0.113.44"], "Bloquear destino"),
            ResponseTask("ir-3", "Coordinación", "IR Lead", "pending", ["Caso regulatorio"], "Elevar incidente"),
            ResponseTask("ir-4", "Seguimiento", "Service Desk", "pending", ["Remediación en progreso"], "Abrir ticket"),
        ]
        self.workflow.set_records([record.to_drilldown() for record in self._records])

    def _execute(self, playbook: str) -> None:
        mode = "SAFE" if self.safe_mode.isChecked() else "LIVE"
        state = "simulado" if mode == "SAFE" else "ejecutado"
        self.status.setText(f"Última ejecución: {playbook} ({mode}/{state})")
        self.playbookExecuted.emit(playbook)

    def _export(self, export_format: str) -> None:
        output = export_records("incident_response", [record.to_drilldown() for record in self._records], export_format, self)
        if output is not None:
            self.status.setText(f"Última exportación: {output.name}")

    def _on_action_requested(self, action_id: str, identifier: str) -> None:
        QMessageBox.information(self, "Acción defensiva", f"{action_id} solicitado para {identifier} en modo seguro.")
