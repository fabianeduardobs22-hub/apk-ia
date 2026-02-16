from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import csv
import json
from pathlib import Path

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtCore import QMarginsF
from PyQt6.QtGui import QAction, QPageSize, QTextDocument
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)


@dataclass(slots=True)
class DrillDownRecord:
    identifier: str
    summary: str
    detail: dict[str, str]
    evidence: list[str]
    recommended_action: str


class DrillDownWorkflowWidget(QWidget):
    actionRequested = pyqtSignal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QHBoxLayout(self)

        self.list_widget = QListWidget()
        self.list_widget.currentItemChanged.connect(self._on_record_changed)

        self.detail_table = QTableWidget(0, 2)
        self.detail_table.setHorizontalHeaderLabels(["Detalle", "Valor"])

        self.evidence_list = QListWidget()

        action_box = QGroupBox("Acción recomendada")
        action_layout = QVBoxLayout(action_box)
        self.recommended_action_label = QLabel("-")
        self.recommended_action_label.setWordWrap(True)
        action_layout.addWidget(self.recommended_action_label)

        self.isolate_host_button = QPushButton("Aislar host")
        self.block_destination_button = QPushButton("Bloquear destino")
        self.escalate_incident_button = QPushButton("Elevar incidente")
        self.open_ticket_button = QPushButton("Abrir ticket")
        for label, button in (
            ("isolate_host", self.isolate_host_button),
            ("block_destination", self.block_destination_button),
            ("escalate_incident", self.escalate_incident_button),
            ("open_ticket", self.open_ticket_button),
        ):
            button.clicked.connect(lambda _checked=False, action=label: self._emit_action(action))
            action_layout.addWidget(button)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(QLabel("Detalle"))
        right_layout.addWidget(self.detail_table)
        right_layout.addWidget(QLabel("Evidencia"))
        right_layout.addWidget(self.evidence_list)
        right_layout.addWidget(action_box)

        root.addWidget(self.list_widget, 1)
        root.addWidget(right, 2)

        self._records: list[DrillDownRecord] = []

    def set_records(self, records: list[DrillDownRecord]) -> None:
        self._records = records
        self.list_widget.clear()
        for record in records:
            item = QListWidgetItem(f"{record.identifier} · {record.summary}")
            item.setData(256, record.identifier)
            self.list_widget.addItem(item)
        if records:
            self.list_widget.setCurrentRow(0)
        else:
            self._render_details(None)

    def selected_record(self) -> DrillDownRecord | None:
        row = self.list_widget.currentRow()
        if row < 0 or row >= len(self._records):
            return None
        return self._records[row]

    def _on_record_changed(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is None:
            self._render_details(None)
            return
        row = self.list_widget.row(current)
        if row < 0 or row >= len(self._records):
            self._render_details(None)
            return
        self._render_details(self._records[row])

    def _render_details(self, record: DrillDownRecord | None) -> None:
        self.detail_table.setRowCount(0)
        self.evidence_list.clear()
        if record is None:
            self.recommended_action_label.setText("-")
            return

        for key, value in record.detail.items():
            row = self.detail_table.rowCount()
            self.detail_table.insertRow(row)
            self.detail_table.setItem(row, 0, QTableWidgetItem(key))
            self.detail_table.setItem(row, 1, QTableWidgetItem(value))

        for evidence in record.evidence:
            self.evidence_list.addItem(evidence)
        self.recommended_action_label.setText(record.recommended_action)

    def _emit_action(self, action_id: str) -> None:
        record = self.selected_record()
        if record is None:
            return
        self.actionRequested.emit(action_id, record.identifier)


class ModuleExportToolbar(QToolBar):
    exportRequested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMovable(False)
        for export_format, label in (("json", "Exportar JSON"), ("csv", "Exportar CSV"), ("pdf", "Exportar PDF")):
            action = QAction(label, self)
            action.triggered.connect(lambda _checked=False, fmt=export_format: self.exportRequested.emit(fmt))
            self.addAction(action)


def export_records(module_name: str, records: list[DrillDownRecord], export_format: str, parent: QWidget) -> Path | None:
    if not records:
        QMessageBox.information(parent, "Exportación", "No hay registros para exportar.")
        return None

    extension = export_format
    output_path, _ = QFileDialog.getSaveFileName(parent, "Guardar exportación", f"{module_name}.{extension}")
    if not output_path:
        return None

    path = Path(output_path)
    rows = [
        {
            "id": record.identifier,
            "summary": record.summary,
            "detail": json.dumps(record.detail, ensure_ascii=False),
            "evidence": " | ".join(record.evidence),
            "recommended_action": record.recommended_action,
        }
        for record in records
    ]

    if export_format == "json":
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    elif export_format == "csv":
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    elif export_format == "pdf":
        html_rows = "".join(
            f"<tr><td>{r['id']}</td><td>{r['summary']}</td><td>{r['evidence']}</td><td>{r['recommended_action']}</td></tr>"
            for r in rows
        )
        html = (
            f"<h2>{module_name}</h2>"
            "<table border='1' cellspacing='0' cellpadding='4'>"
            "<tr><th>ID</th><th>Resumen</th><th>Evidencia</th><th>Acción recomendada</th></tr>"
            f"{html_rows}</table>"
        )
        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(str(path))
        printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
        printer.setPageMargins(QMarginsF(12, 12, 12, 12))
        document = QTextDocument()
        document.setHtml(html)
        document.print(printer)
    else:
        raise ValueError(f"Unsupported export format: {export_format}")

    _write_audit_log(module_name, export_format, len(rows), path)
    return path


def _write_audit_log(module_name: str, export_format: str, count: int, output_path: Path) -> None:
    audit_dir = Path.home() / ".local" / "share" / "decktroy"
    audit_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "module": module_name,
        "format": export_format,
        "records": count,
        "path": str(output_path),
    }
    with (audit_dir / "audit_exports.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
