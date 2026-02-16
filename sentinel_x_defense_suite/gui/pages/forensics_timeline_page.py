from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class ForensicsTimelinePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)

        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels(
            ["Hora", "Severidad", "Entidad", "Tipo", "Resumen", "Estado"]
        )
        self.timeline_table.setSortingEnabled(True)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.itemDoubleClicked.connect(self._open_drill_down)
        layout.addWidget(self.timeline_table)

    def push_event(self, payload: dict[str, str]) -> None:
        row = self.timeline_table.rowCount()
        self.timeline_table.insertRow(row)
        values = [
            payload.get("time", "-"),
            payload.get("severity", "LOW"),
            payload.get("entity", "unknown"),
            payload.get("kind", "network"),
            payload.get("summary", "-"),
            payload.get("state", "open"),
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if col == 1 and value in {"HIGH", "CRITICAL"}:
                item.setData(Qt.ItemDataRole.ToolTipRole, "Evento de alta prioridad")
            self.timeline_table.setItem(row, col, item)

    def _open_drill_down(self, item: QTableWidgetItem) -> None:
        row = item.row()
        values = [
            self.timeline_table.item(row, col).text() if self.timeline_table.item(row, col) else ""
            for col in range(self.timeline_table.columnCount())
        ]
        dialog = QDialog(self)
        dialog.setWindowTitle("Drill-down forense")
        layout = QVBoxLayout(dialog)
        details = QTableWidget(6, 2)
        details.setHorizontalHeaderLabels(["Campo", "Valor"])
        labels = ["Hora", "Severidad", "Entidad", "Tipo", "Resumen", "Estado"]
        for idx, label in enumerate(labels):
            details.setItem(idx, 0, QTableWidgetItem(label))
            details.setItem(idx, 1, QTableWidgetItem(values[idx]))
        layout.addWidget(details)
        dialog.resize(560, 380)
        dialog.exec()
