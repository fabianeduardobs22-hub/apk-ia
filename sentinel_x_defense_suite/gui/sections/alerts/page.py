from __future__ import annotations

from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTableWidget, QVBoxLayout, QWidget


class AlertsPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Alerts Center · Gestión operativa"))

        self.alerts_table = QTableWidget(0, 5)
        self.alerts_table.setHorizontalHeaderLabels(["Hora", "Severidad", "Entidad", "Resumen", "Estado"])
        self.alerts_table.setSortingEnabled(True)

        action_row = QHBoxLayout()
        self.ack_button = QPushButton("Reconocer alerta")
        self.escalate_button = QPushButton("Escalar a IR")
        action_row.addWidget(self.ack_button)
        action_row.addWidget(self.escalate_button)
        action_row.addStretch(1)

        root.addLayout(action_row)
        root.addWidget(self.alerts_table)
