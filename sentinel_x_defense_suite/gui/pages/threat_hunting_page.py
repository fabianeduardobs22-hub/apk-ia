from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.gui.sections.hunting.models import HuntingFinding
from sentinel_x_defense_suite.gui.sections.workflow import DrillDownWorkflowWidget, ModuleExportToolbar, export_records
from sentinel_x_defense_suite.gui.widgets.ui_components import MetricTile, RiskCard, SeverityBadge


class ThreatHuntingPage(QWidget):
    queryChanged = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)

        filters_box = RiskCard("Threat Hunting · Queries y filtros compuestos")
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

        metrics_row = QHBoxLayout()
        self.matches_tile = MetricTile("Resultados", "0")
        self.severity_badge = SeverityBadge("low")
        metrics_row.addWidget(self.matches_tile)
        metrics_row.addWidget(self.severity_badge)
        metrics_row.addStretch(1)
        root.addLayout(metrics_row)

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
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        top_severity = "low"

        records: list[HuntingFinding] = []
        for idx, row in enumerate(rows, start=1):
            severity = str(row.get("severity", "LOW")).upper()
            finding = HuntingFinding(
                identifier=str(row.get("id") or f"hunt-{idx}"),
                time=str(row.get("time", "-")),
                entity=str(row.get("entity", "-")),
                value=str(row.get("value", "-")),
                severity=severity,
                detection=str(row.get("detection", "n/a")),
                evidence=[f"Badge: {row.get('badge', 'observed')}"] if row.get("badge") else [],
                recommendation="Escalar al SOC si la severidad es HIGH o CRITICAL",
            )
            records.append(finding)

            sev_key = severity.lower()
            if rank.get(sev_key, 1) > rank.get(top_severity, 1):
                top_severity = sev_key

        self._records = records
        self.workflow.set_records([record.to_drilldown() for record in self._records])
        self.matches_tile.set_value(str(len(rows)))
        self.severity_badge.setText(top_severity.upper())
        self.severity_badge.setProperty("severity", top_severity)
        self.severity_badge.style().unpolish(self.severity_badge)
        self.severity_badge.style().polish(self.severity_badge)

    def _export(self, export_format: str) -> None:
        output = export_records("threat_hunting", [record.to_drilldown() for record in self._records], export_format, self)
        if output is not None:
            self.status_badge.setText(f"Última exportación: {output.name}")

    def _on_action_requested(self, action_id: str, identifier: str) -> None:
        QMessageBox.information(self, "Acción defensiva", f"{action_id} solicitado para hallazgo {identifier}.")
