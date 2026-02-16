from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QTimer
from PyQt6.QtGui import QAction, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.gui.navigation.rbac import DEFAULT_POLICY, ROLE_LABELS, Role
from sentinel_x_defense_suite.gui.navigation.router import GuiRouter, RouteEntry
from sentinel_x_defense_suite.gui.runtime_data import build_incremental_runtime_snapshot
from sentinel_x_defense_suite.models.events import PacketRecord
from sentinel_x_defense_suite.gui.widgets.theme_manager import THEMES, apply_theme

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ConnectionViewRow:
    packet: PacketRecord
    risk_level: str
    risk_score: float
    country: str
    analysis_summary: str
    recommendation: str


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DECKTROY · SENTINEL X DEFENSE SUITE")
        self.resize(1820, 1020)

        self.settings = QSettings("Decktroy", "SentinelXDefenseSuite")
        self._rows: list[ConnectionViewRow] = []
        self._runtime_snapshot: dict[str, object] = {}
        self._route_widgets: dict[str, QWidget] = {}
        self._route_indices: dict[str, int] = {}

        self._router = GuiRouter(
            [
                RouteEntry("dashboard", "Dashboard SOC", ("soc", "overview", "metricas"), "sentinel_x_defense_suite.gui.sections.dashboard.page", "DashboardPage"),
                RouteEntry("alerts", "Alerts Center", ("alertas", "triage", "incidentes"), "sentinel_x_defense_suite.gui.sections.alerts.page", "AlertsPage"),
                RouteEntry("hunting", "Threat Hunting", ("hunt", "queries", "pivot"), "sentinel_x_defense_suite.gui.sections.hunting.page", "HuntingPage"),
                RouteEntry("incident_response", "Incident Response", ("playbook", "containment", "response"), "sentinel_x_defense_suite.gui.sections.incident_response.page", "IncidentResponseModulePage"),
                RouteEntry("forensics", "Forensics Timeline", ("timeline", "drill-down", "evidence"), "sentinel_x_defense_suite.gui.sections.forensics.page", "ForensicsPage"),
            ]
        )

        self.current_role = Role(str(self.settings.value("ui/role", Role.ANALYST.value)))
        self._build_ui()
        self._restore_persistent_state()

        self._runtime_timer = QTimer(self)
        self._runtime_timer.timeout.connect(self._refresh_runtime_watch)
        self._runtime_timer.start(1200)
        self._refresh_runtime_watch()

    def _build_ui(self) -> None:
        self._build_menu_bar()
        self._build_toolbar()

        root = QWidget()
        layout = QHBoxLayout(root)

        self.nav_list = QListWidget()
        self.nav_list.setObjectName("navMenu")
        self.nav_list.currentRowChanged.connect(self._switch_page_by_index)

        self.page_stack = QStackedWidget()
        layout.addWidget(self.nav_list, 1)
        layout.addWidget(self.page_stack, 6)
        self.setCentralWidget(root)

        self._populate_navigation()

        status = QStatusBar()
        status.showMessage("Listo · Plataforma defensiva activa")
        self.setStatusBar(status)

    def _build_menu_bar(self) -> None:
        bar = self.menuBar()
        menu_file = bar.addMenu("Archivo")
        export_action = QAction("Exportar resumen de sesión", self)
        export_action.triggered.connect(self._show_export_summary_popup)
        menu_file.addAction(export_action)
        menu_file.addAction(QAction("Salir", self, triggered=self.close))

        menu_view = bar.addMenu("Vista")
        action_preferences = QAction("Editar preferencias de visualización", self)
        action_preferences.triggered.connect(self._show_view_options_popup)
        menu_view.addAction(action_preferences)

        menu_tools = bar.addMenu("Herramientas")
        settings_action = QAction("Configuración rápida", self)
        settings_action.triggered.connect(self._show_runtime_settings_popup)
        demo_action = QAction("Generar evento de demostración", self)
        demo_action.triggered.connect(self._simulate_demo_event)
        menu_tools.addAction(settings_action)
        menu_tools.addAction(demo_action)

        menu_help = bar.addMenu("Ayuda")
        about_action = QAction("Acerca de SENTINEL X", self)
        about_action.triggered.connect(self._show_about_popup)
        menu_help.addAction(about_action)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")

        self.quick_filter_input = QLineEdit()
        self.quick_filter_input.setPlaceholderText("Filtro rápido")
        self.quick_filter_input.textChanged.connect(self._apply_quick_filter)

        self.nav_search_input = QLineEdit()
        self.nav_search_input.setPlaceholderText("Ir a módulo/función")
        self.nav_search_input.returnPressed.connect(self._go_to_navigation_query)
        completer = QCompleter([r.sidebar_label for r in self._router.routes], self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.nav_search_input.setCompleter(completer)

        self.role_selector = QComboBox()
        self.role_selector.addItem(ROLE_LABELS[Role.READ_ONLY], Role.READ_ONLY.value)
        self.role_selector.addItem(ROLE_LABELS[Role.ANALYST], Role.ANALYST.value)
        self.role_selector.addItem(ROLE_LABELS[Role.OPERATOR], Role.OPERATOR.value)
        self.role_selector.addItem(ROLE_LABELS[Role.ADMIN], Role.ADMIN.value)
        self.role_selector.currentIndexChanged.connect(self._on_role_changed)

        self.quick_action_button = QPushButton("Evento demo")
        self.quick_action_button.clicked.connect(self._simulate_demo_event)

        toolbar.addWidget(QLabel("SOC View"))
        toolbar.addWidget(self.quick_filter_input)
        toolbar.addWidget(self.nav_search_input)
        toolbar.addWidget(self.role_selector)
        toolbar.addWidget(self.quick_action_button)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

    def _populate_navigation(self) -> None:
        self.nav_list.clear()
        for route in self._router.routes:
            item = QListWidgetItem(route.sidebar_label)
            item.setData(Qt.ItemDataRole.UserRole, route.route_id)
            enabled = DEFAULT_POLICY.allows_view(self.current_role, route.route_id)
            if not enabled:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                item.setToolTip(f"Requiere rol: {ROLE_LABELS[DEFAULT_POLICY.view_roles[route.route_id]]}")
            self.nav_list.addItem(item)

        first_enabled = 0
        for row in range(self.nav_list.count()):
            if self.nav_list.item(row).flags() & Qt.ItemFlag.ItemIsEnabled:
                first_enabled = row
                break
        self.nav_list.setCurrentRow(first_enabled)
        self._sync_rbac_actions()

    def _switch_page_by_index(self, index: int) -> None:
        if index < 0:
            return
        item = self.nav_list.item(index)
        if item is None:
            return
        route_id = str(item.data(Qt.ItemDataRole.UserRole))
        self._switch_to_route(route_id)

    def _switch_to_route(self, route_id: str) -> None:
        if not DEFAULT_POLICY.allows_view(self.current_role, route_id):
            QMessageBox.warning(self, "Acceso denegado", "No tienes permisos para abrir esta vista.")
            return

        page = self._route_widgets.get(route_id)
        if page is None:
            page = self._router.build_page(route_id)
            self._wire_page(route_id, page)
            self._route_widgets[route_id] = page
            self._route_indices[route_id] = self.page_stack.addWidget(page)

        self.page_stack.setCurrentIndex(self._route_indices[route_id])
        self.settings.setValue("ui/last_route", route_id)

    def _wire_page(self, route_id: str, page: QWidget) -> None:
        if route_id == "dashboard":
            self.dashboard_page = page
            self.table = page.table
            self.details_tabs = page.details_tabs
            self.ops_tabs = page.ops_tabs
            self.incoming_connections_list = page.incoming_connections_list
            self.service_versions_list = page.service_versions_list
            self.globe_widget = page.globe_widget
            self.table.itemSelectionChanged.connect(self._on_row_selected)
            self.incoming_connections_list.itemDoubleClicked.connect(self._open_incoming_connection_detail)
            self.service_versions_list.itemDoubleClicked.connect(self._open_service_version_detail)
        elif route_id == "hunting":
            self.threat_hunting_page = page
            self.threat_hunting_page.queryChanged.connect(self._on_threat_query)
        elif route_id == "incident_response":
            self.incident_response_page = page
        elif route_id == "forensics":
            self.forensics_page = page
        elif route_id == "alerts":
            self.alerts_page = page
            self.alerts_page.ack_button.clicked.connect(lambda: self._run_action("alerts.acknowledge"))
            self.alerts_page.escalate_button.clicked.connect(lambda: self._run_action("alerts.escalate"))

    def _go_to_navigation_query(self) -> None:
        route = self._router.route_for_query(self.nav_search_input.text())
        if route is None:
            self.statusBar().showMessage("No se encontró módulo/función", 3000)
            return
        self._switch_to_route(route.route_id)
        self.statusBar().showMessage(f"Ruta abierta: {route.sidebar_label}", 3000)

    def _on_role_changed(self) -> None:
        self.current_role = Role(str(self.role_selector.currentData()))
        self.settings.setValue("ui/role", self.current_role.value)
        self._populate_navigation()

    def _sync_rbac_actions(self) -> None:
        self.quick_action_button.setEnabled(DEFAULT_POLICY.allows_action(self.current_role, "demo.event.generate"))

    def _run_action(self, action_id: str) -> bool:
        if DEFAULT_POLICY.allows_action(self.current_role, action_id):
            return True
        QMessageBox.warning(self, "Acción bloqueada", f"Permiso insuficiente para {action_id}.")
        return False

    def _restore_persistent_state(self) -> None:
        apply_theme(QApplication.instance() or QApplication([]), str(self.settings.value("ui/theme", "midnight")))
        self.role_selector.setCurrentIndex(max(0, self.role_selector.findData(self.current_role.value)))
        last_route = str(self.settings.value("ui/last_route", "dashboard"))
        self._switch_to_route(last_route)

    def _on_threat_query(self, query: str) -> None:
        self.settings.setValue("hunting/last_query", query)
        if not hasattr(self, "threat_hunting_page"):
            return
        filtered: list[dict[str, str]] = []
        for row in self._rows[-100:]:
            if query and query.lower() not in row.analysis_summary.lower() and query not in row.packet.src_ip:
                continue
            filtered.append(
                {
                    "time": row.packet.timestamp.strftime("%H:%M:%S"),
                    "entity": self.threat_hunting_page.entity_pivot.currentText(),
                    "value": row.packet.src_ip,
                    "severity": row.risk_level,
                    "detection": row.analysis_summary,
                    "badge": "triaged" if row.risk_level in {"HIGH", "CRITICAL"} else "watch",
                }
            )
        self.threat_hunting_page.set_results(filtered)

    def _risk_color(self, risk: str) -> QColor:
        return {
            "LOW": QColor("#12311b"),
            "MEDIUM": QColor("#3d3615"),
            "HIGH": QColor("#4a2718"),
            "CRITICAL": QColor("#5a1b1b"),
        }.get(risk.upper(), QColor("#1c2a36"))

    def add_packet(
        self,
        packet: PacketRecord,
        risk_level: str = "LOW",
        risk_score: float = 0.0,
        country: str = "Unknown",
        analysis_summary: str = "Sin anomalías detectadas",
        recommendation: str = "Mantener monitoreo continuo y registro forense.",
    ) -> None:
        if not hasattr(self, "table"):
            self._switch_to_route("dashboard")
        row_data = ConnectionViewRow(packet, risk_level.upper(), risk_score, country, analysis_summary, recommendation)
        self._rows.append(row_data)
        row = self.table.rowCount()
        self.table.insertRow(row)
        data = [
            packet.timestamp.strftime("%H:%M:%S"),
            packet.src_ip,
            packet.dst_ip,
            str(packet.dst_port),
            packet.protocol,
            row_data.risk_level,
            row_data.analysis_summary,
        ]
        for col, value in enumerate(data):
            item = QTableWidgetItem(value)
            item.setBackground(self._risk_color(row_data.risk_level))
            self.table.setItem(row, col, item)

        if hasattr(self, "forensics_page"):
            self.forensics_page.push_event(
                {
                    "time": packet.timestamp.strftime("%H:%M:%S"),
                    "severity": row_data.risk_level,
                    "entity": packet.src_ip,
                    "kind": packet.protocol,
                    "summary": analysis_summary,
                    "state": "open",
                }
            )

    def _apply_quick_filter(self, expression: str) -> None:
        if not hasattr(self, "table"):
            return
        expr = expression.lower().strip()
        for row_idx, row in enumerate(self._rows):
            target = f"{row.packet.src_ip} {row.packet.dst_ip} {row.packet.protocol} {row.analysis_summary}".lower()
            self.table.setRowHidden(row_idx, bool(expr and expr not in target))

    def _on_row_selected(self) -> None:
        if not hasattr(self, "table"):
            return
        selected = self.table.selectedItems()
        if not selected:
            return
        idx = selected[0].row()
        if idx >= len(self._rows):
            return
        row = self._rows[idx]
        self._fill_kv_table(self.dashboard_page.packet_inspector, [("Timestamp", row.packet.timestamp.isoformat()), ("Origen", row.packet.src_ip), ("Destino", row.packet.dst_ip)])
        self._fill_kv_table(self.dashboard_page.anomaly_inspector, [("Riesgo", row.risk_level), ("Score", f"{row.risk_score:.1f}"), ("País", row.country)])
        self._fill_kv_table(self.dashboard_page.response_inspector, [("Contención", row.recommendation), ("Correlación", "SIEM + IDS"), ("Estado", "en curso")])
        self._fill_kv_table(self.dashboard_page.timeline_tab, [(row.packet.timestamp.strftime("%H:%M:%S"), row.risk_level, row.packet.src_ip, row.analysis_summary)])

    def _fill_kv_table(self, table: QTableWidget, rows: list[tuple[str, ...]]) -> None:
        table.setRowCount(0)
        for values in rows:
            row = table.rowCount()
            table.insertRow(row)
            for col, value in enumerate(values):
                table.setItem(row, col, QTableWidgetItem(value))

    def _simulate_demo_event(self) -> None:
        if not self._run_action("demo.event.generate"):
            return
        packet = PacketRecord(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip="198.51.100.42",
            dst_ip="10.0.0.15",
            src_port=53211,
            dst_port=443,
            protocol="TCP",
            length=256,
            payload=b"GET /health HTTP/1.1\r\nHost: demo.internal\r\n\r\n",
            metadata={"service": "https", "sensor": "demo-generator", "tag": "simulated"},
        )
        self.add_packet(packet, "HIGH", 8.2, "US", "Evento simulado", "Bloquear IP temporalmente")

    def _refresh_runtime_watch(self) -> None:
        snapshot_pack = build_incremental_runtime_snapshot(self._runtime_snapshot or None, include_service_versions=True)
        snapshot = snapshot_pack.get("full_snapshot", {}) if isinstance(snapshot_pack, dict) else {}
        self._runtime_snapshot = snapshot if isinstance(snapshot, dict) else {}

        if hasattr(self, "incoming_connections_list"):
            self.incoming_connections_list.clear()
            for conn in self._runtime_snapshot.get("incoming_connections", [])[:120]:
                if not isinstance(conn, dict):
                    continue
                label = f"{conn.get('state', 'STATE')} · {conn.get('src_ip')}:{conn.get('src_port')} -> {conn.get('dst_ip')}:{conn.get('dst_port')}"
                item = QListWidgetItem(label)
                item.setData(Qt.ItemDataRole.UserRole, conn)
                self.incoming_connections_list.addItem(item)

        if hasattr(self, "service_versions_list"):
            self.service_versions_list.clear()
            for service in self._runtime_snapshot.get("service_versions", [])[:120]:
                if not isinstance(service, dict):
                    continue
                label = f"{service.get('service', 'unknown')} · {service.get('version', 'unknown')}"
                item = QListWidgetItem(label)
                item.setData(Qt.ItemDataRole.UserRole, service)
                self.service_versions_list.addItem(item)

        if hasattr(self, "globe_widget"):
            globe_points = self._runtime_snapshot.get("globe_points", [])
            if isinstance(globe_points, list):
                self.globe_widget.set_points(globe_points)

    def _open_incoming_connection_detail(self, item: QListWidgetItem) -> None:
        payload = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(payload, dict):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Drill-down conexión")
        layout = QVBoxLayout(dialog)
        table = QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(["Campo", "Valor"])
        for key in ["protocol", "state", "src_ip", "src_port", "dst_ip", "dst_port", "service"]:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(key))
            table.setItem(r, 1, QTableWidgetItem(str(payload.get(key, "-"))))
        layout.addWidget(table)
        dialog.resize(620, 420)
        dialog.exec()

    def _open_service_version_detail(self, item: QListWidgetItem) -> None:
        payload = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(payload, dict):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Drill-down servicio")
        layout = QVBoxLayout(dialog)
        table = QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(["Campo", "Valor"])
        for key in ["service", "version", "status", "port", "command"]:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(key))
            table.setItem(r, 1, QTableWidgetItem(str(payload.get(key, "-"))))
        layout.addWidget(table)
        dialog.resize(620, 420)
        dialog.exec()

    def _build_theme_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Tema premium")
        form = QFormLayout(dialog)
        selector = QComboBox()
        for theme in THEMES.values():
            selector.addItem(theme.name, theme.key)
        selector.setCurrentIndex(max(0, selector.findData(self.settings.value("ui/theme", "midnight"))))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)

        def _save() -> None:
            selected = str(selector.currentData())
            self.settings.setValue("ui/theme", selected)
            apply_theme(QApplication.instance() or QApplication([]), selected)
            dialog.accept()

        buttons.accepted.connect(_save)
        buttons.rejected.connect(dialog.reject)
        form.addRow("Tema", selector)
        form.addRow(buttons)
        dialog.exec()

    def _show_runtime_settings_popup(self) -> None:
        if not self._run_action("runtime.settings.write"):
            return
        cfg_path = "sentinel_x.yaml"
        settings = SettingsLoader.load(cfg_path)
        dialog = QDialog(self)
        dialog.setWindowTitle("Configuración rápida (GUI)")
        form = QFormLayout(dialog)
        interface_input = QLineEdit(settings.capture.interface)
        form.addRow("Interfaz de captura", interface_input)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)

        def _save() -> None:
            settings.capture.interface = interface_input.text().strip() or "any"
            Path(cfg_path).write_text(SettingsLoader._dumps({"app_name": settings.app_name, "capture": {"interface": settings.capture.interface}}), encoding="utf-8")
            dialog.accept()

        buttons.accepted.connect(_save)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        dialog.exec()

    def _show_view_options_popup(self) -> None:
        self._build_theme_dialog()

    def _show_export_summary_popup(self) -> None:
        QMessageBox.information(self, "Exportación de sesión", "Use la CLI para exportar evidencia.")

    def _show_about_popup(self) -> None:
        QMessageBox.information(self, "Acerca de SENTINEL X", "Plataforma Linux 100% defensiva")


def launch_gui() -> None:
    app = QApplication([])
    win = MainWindow()
    win.show()
    app.exec()
