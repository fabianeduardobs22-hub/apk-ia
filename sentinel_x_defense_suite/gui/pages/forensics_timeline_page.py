from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from sentinel_x_defense_suite.gui.widgets.ui_components import RiskCard, TimelineRow


class ForensicsTimelinePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)

        frame = RiskCard("Timeline forense")
        frame_layout = QVBoxLayout(frame)

        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels(
            ["Hora", "Severidad", "Entidad", "Tipo", "Resumen", "Estado"]
        )
        self.timeline_table.setSortingEnabled(True)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.itemDoubleClicked.connect(self._open_drill_down)
        frame_layout.addWidget(self.timeline_table)
        layout.addWidget(frame)

    def push_event(self, payload: dict[str, str]) -> None:
        values = [
            payload.get("time", "-"),
            payload.get("severity", "LOW"),
            payload.get("entity", "unknown"),
            payload.get("kind", "network"),
            payload.get("summary", "-"),
            payload.get("state", "open"),
        ]
        TimelineRow.append(self.timeline_table, values)
        row = self.timeline_table.rowCount() - 1
        severity = values[1]
        if severity in {"HIGH", "CRITICAL"}:
            item = self.timeline_table.item(row, 1)
            if item is not None:
                item.setData(Qt.ItemDataRole.ToolTipRole, "Evento de alta prioridad")

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
