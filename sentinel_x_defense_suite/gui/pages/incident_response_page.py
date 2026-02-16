from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


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

        self.checklist = QListWidget()
        for item in [
            "Aislar host comprometido",
            "Revocar credenciales expuestas",
            "Bloquear IOC en firewall/IDS",
            "Capturar evidencia de memoria y disco",
            "Notificar a legal y compliance",
        ]:
            QListWidgetItem(item, self.checklist)

        self.execution_table = QTableWidget(0, 4)
        self.execution_table.setHorizontalHeaderLabels(["Playbook", "Modo", "Estado", "Badge"])
        self.execution_table.setSortingEnabled(True)

        root.addWidget(QLabel("Checklist de contención"))
        root.addWidget(self.checklist, 2)
        root.addWidget(QLabel("Ejecuciones"))
        root.addWidget(self.execution_table, 2)

        self.status = QLabel("Sin ejecuciones")
        self.status.setObjectName("statusBadge")
        root.addWidget(self.status)

        self.run_containment.clicked.connect(lambda: self._execute("Containment"))
        self.run_eradication.clicked.connect(lambda: self._execute("Eradication"))

    def _execute(self, playbook: str) -> None:
        mode = "SAFE" if self.safe_mode.isChecked() else "LIVE"
        row = self.execution_table.rowCount()
        self.execution_table.insertRow(row)
        state = "simulado" if mode == "SAFE" else "ejecutado"
        badge = "🛡️" if mode == "SAFE" else "⚠️"
        for col, value in enumerate([playbook, mode, state, badge]):
            self.execution_table.setItem(row, col, QTableWidgetItem(value))
        self.status.setText(f"Última ejecución: {playbook} ({mode})")
        self.playbookExecuted.emit(playbook)
