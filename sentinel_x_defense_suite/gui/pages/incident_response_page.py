from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.gui.sections.incident_response.models import ResponseTask
from sentinel_x_defense_suite.gui.sections.workflow import DrillDownWorkflowWidget, ModuleExportToolbar, export_records
from sentinel_x_defense_suite.gui.widgets.ui_components import ActionDrawer, MetricTile, RiskCard, TimelineRow
from sentinel_x_defense_suite.gui.widgets.ui_iconography import ICONS


class IncidentResponsePage(QWidget):
    playbookExecuted = pyqtSignal(str)
    templateApplied = pyqtSignal(str)

    RESPONSE_TEMPLATES: dict[str, list[str]] = {
        "Brute force": [
            "Bloquear IPs con >10 intentos/min",
            "Forzar MFA para cuentas objetivo",
            "Rotar credenciales comprometidas",
            "Correlacionar origen en SIEM y WAF",
        ],
        "Beaconing": [
            "Aislar endpoint con patrón periódico",
            "Bloquear C2 en proxy/firewall",
            "Capturar memoria para IOC de malware",
            "Lanzar hunting por dominios DGAs",
        ],
        "Exposición de servicio": [
            "Aplicar ACL temporal al servicio expuesto",
            "Validar versión y CVEs asociadas",
            "Habilitar inspección TLS/IPS",
            "Registrar evidencia para post-mortem",
        ],
    }

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

        templates = RiskCard("Plantillas de respuesta")
        templates_layout = QHBoxLayout(templates)
        self.template_selector = QComboBox()
        self.template_selector.addItems(list(self.RESPONSE_TEMPLATES.keys()))
        self.apply_template_button = QPushButton("Aplicar plantilla")
        templates_layout.addWidget(QLabel("Incidente"))
        templates_layout.addWidget(self.template_selector)
        templates_layout.addWidget(self.apply_template_button)
        templates_layout.addStretch(1)
        root.addWidget(templates)

        self.export_toolbar = ModuleExportToolbar()
        root.addWidget(self.export_toolbar)

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
        root.addWidget(self.checklist)

        self.execution_table = QTableWidget(0, 4)
        self.execution_table.setHorizontalHeaderLabels(["Playbook", "Modo", "Estado", "Badge"])
        self.execution_table.setSortingEnabled(True)
        root.addWidget(self.execution_table)

        self.workflow = DrillDownWorkflowWidget()
        root.addWidget(self.workflow)

        self.action_drawer = ActionDrawer(
            "Acciones guiadas",
            ["Crear ticket", "Notificar liderazgo", "Exportar evidencia"],
        )
        root.addWidget(self.action_drawer)

        self.status = QLabel("Sin ejecuciones")
        self.status.setObjectName("statusBadge")
        root.addWidget(self.status)

        self._records: list[ResponseTask] = []
        self._load_default_tasks()

        self.run_containment.clicked.connect(lambda: self._execute("Containment"))
        self.run_eradication.clicked.connect(lambda: self._execute("Eradication"))
        self.apply_template_button.clicked.connect(self._apply_template)
        self.export_toolbar.exportRequested.connect(self._export)
        self.workflow.actionRequested.connect(self._on_action_requested)

    def _load_default_tasks(self) -> None:
        self._records = [
            ResponseTask("ir-1", "Contención", "SOC L2", "pending", ["Host con beacon C2"], "Aislar host"),
            ResponseTask(
                "ir-2",
                "Contención",
                "SOC L2",
                "pending",
                ["Destino malicioso 203.0.113.44"],
                "Bloquear destino",
            ),
            ResponseTask("ir-3", "Coordinación", "IR Lead", "pending", ["Caso regulatorio"], "Elevar incidente"),
            ResponseTask(
                "ir-4",
                "Seguimiento",
                "Service Desk",
                "pending",
                ["Remediación en progreso"],
                "Abrir ticket",
            ),
        ]
        self.workflow.set_records([record.to_drilldown() for record in self._records])

    def _apply_template(self) -> None:
        template = self.template_selector.currentText()
        self.templateApplied.emit(template)
        self.status.setText(f"Plantilla aplicada: {template}")

    def _execute(self, playbook: str) -> None:
        mode = "SAFE" if self.safe_mode.isChecked() else "LIVE"
        state = "simulado" if mode == "SAFE" else "ejecutado"
        badge = ICONS["safe"] if mode == "SAFE" else ICONS["live"]
        TimelineRow.append(self.execution_table, [playbook, mode, state, badge])
        self.status.setText(f"Última ejecución: {playbook} ({mode})")
        self.exec_tile.set_value(str(self.execution_table.rowCount()))
        self.playbookExecuted.emit(playbook)

    def _export(self, export_format: str) -> None:
        output = export_records("incident_response", [record.to_drilldown() for record in self._records], export_format, self)
        if output is not None:
            self.status.setText(f"Última exportación: {output.name}")

    def _on_action_requested(self, action_id: str, identifier: str) -> None:
        QMessageBox.information(self, "Acción defensiva", f"{action_id} solicitado para {identifier} en modo seguro.")
