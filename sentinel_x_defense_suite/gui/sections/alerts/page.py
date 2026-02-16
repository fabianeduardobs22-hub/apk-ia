from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTableWidget, QVBoxLayout, QWidget


class AlertsPage(QWidget):
    pivotToHuntingRequested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Alerts Center · Gestión operativa"))

        self.alerts_table = QTableWidget(0, 5)
        self.alerts_table.setHorizontalHeaderLabels(["Hora", "Severidad", "Entidad", "Resumen", "Estado"])
        self.alerts_table.setSortingEnabled(True)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        action_row = QHBoxLayout()
        self.ack_button = QPushButton("Reconocer alerta")
        self.escalate_button = QPushButton("Escalar a IR")
        self.pivot_hunting_button = QPushButton("Pivot a Hunting")
        self.pivot_hunting_button.clicked.connect(self._emit_pivot_request)
        action_row.addWidget(self.ack_button)
        action_row.addWidget(self.escalate_button)
        action_row.addWidget(self.pivot_hunting_button)
        action_row.addStretch(1)

        root.addLayout(action_row)
        root.addWidget(self.alerts_table)

    def selected_entity(self) -> str:
        row = self.alerts_table.currentRow()
        if row < 0:
            return ""
        cell = self.alerts_table.item(row, 2)
        return cell.text().strip() if cell else ""

    def _emit_pivot_request(self) -> None:
        entity = self.selected_entity()
        if entity:
            self.pivotToHuntingRequested.emit(entity)
