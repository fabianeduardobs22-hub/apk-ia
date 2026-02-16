from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
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

from sentinel_x_defense_suite.gui.widgets.ui_components import ActionDrawer, MetricTile, RiskCard, TimelineRow
from sentinel_x_defense_suite.gui.widgets.ui_iconography import ICONS


class IncidentResponsePage(QWidget):
    playbookExecuted = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)

        controls = RiskCard("Incident Response · Modo seguro")
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

        kpi_row = QHBoxLayout()
        self.exec_tile = MetricTile("Playbooks ejecutados", "0")
        kpi_row.addWidget(self.exec_tile)
        kpi_row.addStretch(1)
        root.addLayout(kpi_row)

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

        self.action_drawer = ActionDrawer(
            "Acciones guiadas",
            ["Crear ticket", "Notificar liderazgo", "Exportar evidencia"],
        )
        root.addWidget(self.action_drawer)

        self.status = QLabel("Sin ejecuciones")
        self.status.setObjectName("statusBadge")
        root.addWidget(self.status)

        self.run_containment.clicked.connect(lambda: self._execute("Containment"))
        self.run_eradication.clicked.connect(lambda: self._execute("Eradication"))

    def _execute(self, playbook: str) -> None:
        mode = "SAFE" if self.safe_mode.isChecked() else "LIVE"
        state = "simulado" if mode == "SAFE" else "ejecutado"
        badge = ICONS["safe"] if mode == "SAFE" else ICONS["live"]
        TimelineRow.append(self.execution_table, [playbook, mode, state, badge])
        self.status.setText(f"Última ejecución: {playbook} ({mode})")
        self.exec_tile.set_value(str(self.execution_table.rowCount()))
        self.playbookExecuted.emit(playbook)
