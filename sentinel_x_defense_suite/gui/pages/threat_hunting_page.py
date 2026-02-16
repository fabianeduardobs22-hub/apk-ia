from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class ThreatHuntingPage(QWidget):
    queryChanged = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)

        filters_box = QGroupBox("Threat Hunting · Queries y filtros compuestos")
        filters_layout = QGridLayout(filters_box)

        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("query: src.ip:198.51.* AND dst.port:443")
        self.entity_pivot = QComboBox()
        self.entity_pivot.addItems(["IP", "Proceso", "Puerto"])
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Todas", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.apply_button = QPushButton("Aplicar")

        filters_layout.addWidget(QLabel("Query"), 0, 0)
        filters_layout.addWidget(self.query_input, 0, 1, 1, 3)
        filters_layout.addWidget(QLabel("Pivot"), 1, 0)
        filters_layout.addWidget(self.entity_pivot, 1, 1)
        filters_layout.addWidget(QLabel("Severidad"), 1, 2)
        filters_layout.addWidget(self.severity_filter, 1, 3)
        filters_layout.addWidget(self.apply_button, 0, 4, 2, 1)

        root.addWidget(filters_box)

        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(["Hora", "Entidad", "Valor", "Severidad", "Detección", "Badge"])
        self.results_table.setSortingEnabled(True)

        root.addWidget(self.results_table)

        status_row = QHBoxLayout()
        self.status_badge = QLabel("Estado: idle")
        self.status_badge.setObjectName("statusBadge")
        status_row.addWidget(self.status_badge)
        status_row.addStretch(1)
        root.addLayout(status_row)

        self.apply_button.clicked.connect(self._emit_query)
        self.query_input.returnPressed.connect(self._emit_query)

    def _emit_query(self) -> None:
        query = self.query_input.text().strip()
        self.status_badge.setText(f"Estado: query ejecutada ({self.entity_pivot.currentText()})")
        self.queryChanged.emit(query)

    def set_results(self, rows: list[dict[str, str]]) -> None:
        self.results_table.setRowCount(0)
        for row in rows:
            idx = self.results_table.rowCount()
            self.results_table.insertRow(idx)
            values = [
                row.get("time", "-"),
                row.get("entity", "-"),
                row.get("value", "-"),
                row.get("severity", "LOW"),
                row.get("detection", "n/a"),
                row.get("badge", "observed"),
            ]
            for col, value in enumerate(values):
                self.results_table.setItem(idx, col, QTableWidgetItem(value))
