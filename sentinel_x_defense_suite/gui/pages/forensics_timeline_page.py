from __future__ import annotations

from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PyQt6.QtWidgets import QDialog, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from sentinel_x_defense_suite.gui.widgets.ui_components import MetricTile, RiskCard, TimelineRow


class ForensicsTimelinePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.export_button = QPushButton("Exportar evidencia")
        self.chain_button = QPushButton("Validar cadena")
        self.status_badge = QLabel("Estado: monitoreo")
        self.status_badge.setObjectName("statusBadge")
        self.events_tile = MetricTile("Eventos", "0")
        controls.addWidget(self.export_button)
        controls.addWidget(self.chain_button)
        controls.addWidget(self.status_badge)
        controls.addWidget(self.events_tile)
        controls.addStretch(1)
        layout.addLayout(controls)

        frame = RiskCard("Timeline forense")
        frame_layout = QVBoxLayout(frame)

        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels(["Hora", "Severidad", "Entidad", "Tipo", "Resumen", "Estado"])
        self.timeline_table.setSortingEnabled(True)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.itemDoubleClicked.connect(self._open_drill_down)
        frame_layout.addWidget(self.timeline_table)

        layout.addWidget(frame)

        self._status_effect = QGraphicsOpacityEffect(self.status_badge)
        self.status_badge.setGraphicsEffect(self._status_effect)
        self._status_anim = QPropertyAnimation(self._status_effect, b"opacity", self)
        self._status_anim.setDuration(650)
        self._status_anim.setStartValue(0.35)
        self._status_anim.setEndValue(1.0)
        self._status_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

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
        self.events_tile.set_value(str(self.timeline_table.rowCount()))
        self.status_badge.setText(f"Estado: evento registrado ({values[1]})")
        self._status_anim.stop()
        self._status_anim.start()

        row = self.timeline_table.rowCount() - 1
        severity = str(values[1]).upper()
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
