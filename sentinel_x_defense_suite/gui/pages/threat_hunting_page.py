from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.gui.sections.hunting.models import HuntingFinding
from sentinel_x_defense_suite.gui.sections.workflow import DrillDownRecord, DrillDownWorkflowWidget, ModuleExportToolbar, export_records


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

        self.export_toolbar = ModuleExportToolbar()
        root.addWidget(self.export_toolbar)

        self.workflow = DrillDownWorkflowWidget()
        root.addWidget(self.workflow)

        status_row = QHBoxLayout()
        self.status_badge = QLabel("Estado: idle")
        self.status_badge.setObjectName("statusBadge")
        status_row.addWidget(self.status_badge)
        status_row.addStretch(1)
        root.addLayout(status_row)

        self._records: list[HuntingFinding] = []
        self.apply_button.clicked.connect(self._emit_query)
        self.query_input.returnPressed.connect(self._emit_query)
        self.export_toolbar.exportRequested.connect(self._export)
        self.workflow.actionRequested.connect(self._on_action_requested)

    def _emit_query(self) -> None:
        query = self.query_input.text().strip()
        self.status_badge.setText(f"Estado: query ejecutada ({self.entity_pivot.currentText()})")
        self.queryChanged.emit(query)

    def set_results(self, rows: list[dict[str, str]]) -> None:
        self._records = [
            HuntingFinding(
                identifier=f"hunt-{idx+1}",
                time=row.get("time", "-"),
                entity=row.get("entity", "-"),
                value=row.get("value", "-"),
                severity=row.get("severity", "LOW"),
                detection=row.get("detection", "n/a"),
                evidence=[f"Badge: {row.get('badge', 'observed')}", f"Query: {self.query_input.text().strip() or 'default'}"],
                recommendation="Bloquear destino y elevar incidente si la severidad es HIGH/CRITICAL",
            )
            for idx, row in enumerate(rows)
        ]
        drilldown_rows: list[DrillDownRecord] = [finding.to_drilldown() for finding in self._records]
        self.workflow.set_records(drilldown_rows)

    def _export(self, export_format: str) -> None:
        records = [record.to_drilldown() for record in self._records]
        output = export_records("threat_hunting", records, export_format, self)
        if output is not None:
            self.status_badge.setText(f"Estado: exportado {export_format.upper()} -> {output.name}")

    def _on_action_requested(self, action_id: str, identifier: str) -> None:
        QMessageBox.information(self, "Acción defensiva", f"{action_id} solicitado para {identifier} (modo defensivo seguro).")
