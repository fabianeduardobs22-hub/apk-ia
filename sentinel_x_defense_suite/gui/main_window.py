from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QPainter, QPen, QRadialGradient
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QComboBox,
)

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.gui.pages import ForensicsTimelinePage, IncidentResponsePage, ThreatHuntingPage
from sentinel_x_defense_suite.gui.runtime_data import build_runtime_snapshot
from sentinel_x_defense_suite.models.events import PacketRecord
from sentinel_x_defense_suite.gui.widgets.theme_manager import THEMES, apply_theme


@dataclass(slots=True)
class ConnectionViewRow:
    packet: PacketRecord
    risk_level: str
    risk_score: float
    country: str
    analysis_summary: str
    recommendation: str


class TacticalGlobeWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(220)
        self._rotation = 0.0
        self._points: list[dict[str, float | str | int]] = []
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance_rotation)
        self._timer.start(80)

    def set_points(self, points: list[dict[str, float | str | int]]) -> None:
        self._points = points[:120]
        self.update()

    def _advance_rotation(self) -> None:
        self._rotation = (self._rotation + 1.8) % 360.0
        self.update()

    def _project(self, lat: float, lon: float, radius: float) -> tuple[float, float, float]:
        lat_r = math.radians(lat)
        lon_r = math.radians(lon + self._rotation)
        return (
            radius * math.cos(lat_r) * math.sin(lon_r),
            radius * math.sin(lat_r),
            math.cos(lat_r) * math.cos(lon_r),
        )

    def paintEvent(self, event: object) -> None:  # noqa: ARG002
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        radius = min(w, h) * 0.36
        cx, cy = w / 2, h / 2

        grad = QRadialGradient(cx - radius * 0.3, cy - radius * 0.3, radius * 1.25)
        grad.setColorAt(0.0, QColor("#4db4ff"))
        grad.setColorAt(0.35, QColor("#1f6feb"))
        grad.setColorAt(1.0, QColor("#0b1622"))
        p.setPen(QPen(QColor("#5fc9ff"), 2))
        p.setBrush(grad)
        p.drawEllipse(int(cx - radius), int(cy - radius), int(radius * 2), int(radius * 2))

        for point in self._points:
            lat = float(point.get("lat", 0.0))
            lon = float(point.get("lon", 0.0))
            severity = int(point.get("severity", 1))
            x, y, z = self._project(lat, lon, radius)
            if z <= -0.03:
                continue
            color = QColor("#77e4ff") if severity <= 2 else QColor("#ffd166") if severity == 3 else QColor("#ff5a5a")
            p.setPen(QPen(color, 1))
            p.setBrush(color)
            p.drawEllipse(int(cx + x - 3), int(cy - y - 3), 6 + severity, 6 + severity)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DECKTROY · SENTINEL X DEFENSE SUITE")
        self.resize(1820, 1020)
        self.settings = QSettings("Decktroy", "SentinelXDefenseSuite")
        self._rows: list[ConnectionViewRow] = []
        self._runtime_snapshot: dict[str, object] = {}

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
        root_layout = QHBoxLayout(root)

        self.nav_list = QListWidget()
        self.nav_list.setObjectName("navMenu")
        self.nav_list.addItems(["SOC", "Threat Hunting", "Incident Response", "Forensics Timeline"])
        self.nav_list.currentRowChanged.connect(self._switch_page)

        self.page_stack = QStackedWidget()
        self.page_stack.addWidget(self._build_soc_page())
        self.page_stack.addWidget(self._build_threat_hunting_page())
        self.page_stack.addWidget(self._build_incident_response_page())
        self.page_stack.addWidget(self._build_forensics_page())

        root_layout.addWidget(self.nav_list, 1)
        root_layout.addWidget(self.page_stack, 6)
        self.setCentralWidget(root)

        status = QStatusBar()
        status.showMessage("Listo · Plataforma defensiva activa")
        self.setStatusBar(status)

    def _build_soc_page(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)

        center = QWidget()
        center_layout = QVBoxLayout(center)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Hora", "IP origen", "IP destino", "Puerto", "Protocolo", "Riesgo", "Resumen"])
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_row_selected)

        self.details_tabs = QTabWidget()
        self.packet_inspector = QTableWidget(0, 2)
        self.packet_inspector.setHorizontalHeaderLabels(["Campo", "Valor"])
        self.anomaly_inspector = QTableWidget(0, 2)
        self.anomaly_inspector.setHorizontalHeaderLabels(["Indicador", "Valor"])
        self.response_inspector = QTableWidget(0, 2)
        self.response_inspector.setHorizontalHeaderLabels(["Paso", "Estado"])
        self.timeline_tab = QTableWidget(0, 4)
        self.timeline_tab.setHorizontalHeaderLabels(["Hora", "Severidad", "Entidad", "Resumen"])
        self.capability_tab = QTableWidget(0, 3)
        self.capability_tab.setHorizontalHeaderLabels(["Capacidad", "SENTINEL", "Referencia"])
        self.mission_tab = QTableWidget(0, 3)
        self.mission_tab.setHorizontalHeaderLabels(["Misión", "Estado", "Badge"])

        self.details_tabs.addTab(self.packet_inspector, "Inspector de paquete")
        self.details_tabs.addTab(self.anomaly_inspector, "Anomalías y riesgo")
        self.details_tabs.addTab(self.response_inspector, "Respuesta defensiva")
        self.details_tabs.addTab(self.timeline_tab, "Timeline")
        self.details_tabs.addTab(self.capability_tab, "Benchmark defensivo")
        self.details_tabs.addTab(self.mission_tab, "Mission control")
        self.details_tabs.currentChanged.connect(lambda idx: self.settings.setValue("ui/last_workspace_tab", idx))

        center_layout.addWidget(self.table, 3)
        center_layout.addWidget(self.details_tabs, 2)

        self.ops_tabs = QTabWidget()
        self.ops_tabs.addTab(self._build_features_tab(), "Funciones")
        self.ops_tabs.addTab(self._build_globe_tab(), "Globo 3D")
        self.ops_tabs.addTab(self._build_connections_tab(), "Conexiones")
        self.ops_tabs.addTab(self._build_services_tab(), "Servicios")

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(center)
        splitter.addWidget(self.ops_tabs)
        splitter.setSizes([1200, 500])
        layout.addWidget(splitter)
        return page

    def _build_features_tab(self) -> QWidget:
        tab = QWidget()
        v = QVBoxLayout(tab)
        self.features_list = QListWidget()
        self.features_list.addItems([
            "Threat hunting con filtros compuestos",
            "Playbooks de respuesta con safe mode",
            "Timeline forense con drill-down",
            "Navegación lateral persistente",
            "Tema premium configurable",
        ])
        v.addWidget(self.features_list)
        return tab

    def _build_globe_tab(self) -> QWidget:
        tab = QWidget()
        v = QVBoxLayout(tab)
        self.globe_widget = TacticalGlobeWidget()
        v.addWidget(self.globe_widget)
        return tab

    def _build_connections_tab(self) -> QWidget:
        tab = QWidget()
        v = QVBoxLayout(tab)
        self.incoming_connections_list = QListWidget()
        self.incoming_connections_list.itemDoubleClicked.connect(self._open_incoming_connection_detail)
        v.addWidget(self.incoming_connections_list)
        return tab

    def _build_services_tab(self) -> QWidget:
        tab = QWidget()
        v = QVBoxLayout(tab)
        self.service_versions_list = QListWidget()
        self.service_versions_list.itemDoubleClicked.connect(self._open_service_version_detail)
        v.addWidget(self.service_versions_list)
        return tab

    def _build_threat_hunting_page(self) -> QWidget:
        self.threat_hunting_page = ThreatHuntingPage()
        self.threat_hunting_page.queryChanged.connect(self._on_threat_query)
        self.threat_hunting_page.entity_pivot.currentTextChanged.connect(
            lambda v: self.settings.setValue("hunting/last_pivot", v)
        )
        self.threat_hunting_page.severity_filter.currentTextChanged.connect(
            lambda v: self.settings.setValue("hunting/last_severity", v)
        )
        return self.threat_hunting_page

    def _build_incident_response_page(self) -> QWidget:
        self.incident_response_page = IncidentResponsePage()
        self.incident_response_page.playbookExecuted.connect(
            lambda p: self.settings.setValue("ir/last_playbook", p)
        )
        return self.incident_response_page

    def _build_forensics_page(self) -> QWidget:
        self.forensics_page = ForensicsTimelinePage()
        return self.forensics_page

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
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtro rápido")
        self.search_input.textChanged.connect(self._apply_quick_filter)

        self.analyst_preset = QComboBox()
        self.analyst_preset.addItems(["SOC L1", "Threat Hunter", "IR Lead"])
        self.analyst_preset.currentTextChanged.connect(lambda v: self.settings.setValue("ui/analyst_preset", v))

        self.quick_action_button = QPushButton("Evento demo")
        self.quick_action_button.clicked.connect(self._simulate_demo_event)

        toolbar.addWidget(QLabel("SOC View"))
        toolbar.addWidget(self.search_input)
        toolbar.addWidget(self.analyst_preset)
        toolbar.addWidget(self.quick_action_button)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

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

    def _restore_persistent_state(self) -> None:
        apply_theme(QApplication.instance() or QApplication([]), str(self.settings.value("ui/theme", "midnight")))
        self.nav_list.setCurrentRow(int(self.settings.value("ui/last_page", 0)))
        self.details_tabs.setCurrentIndex(int(self.settings.value("ui/last_workspace_tab", 0)))
        self.search_input.setText(str(self.settings.value("hunting/last_query", "")))
        self.threat_hunting_page.query_input.setText(str(self.settings.value("hunting/last_query", "")))
        self.threat_hunting_page.entity_pivot.setCurrentText(str(self.settings.value("hunting/last_pivot", "IP")))
        self.threat_hunting_page.severity_filter.setCurrentText(str(self.settings.value("hunting/last_severity", "Todas")))
        self.analyst_preset.setCurrentText(str(self.settings.value("ui/analyst_preset", "SOC L1")))

    def _switch_page(self, index: int) -> None:
        if 0 <= index < self.page_stack.count():
            self.page_stack.setCurrentIndex(index)
            self.settings.setValue("ui/last_page", index)

    def _on_threat_query(self, query: str) -> None:
        self.settings.setValue("hunting/last_query", query)
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
        expr = expression.lower().strip()
        for row_idx, row in enumerate(self._rows):
            target = f"{row.packet.src_ip} {row.packet.dst_ip} {row.packet.protocol} {row.analysis_summary}".lower()
            self.table.setRowHidden(row_idx, bool(expr and expr not in target))

    def _on_row_selected(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            return
        idx = selected[0].row()
        if idx >= len(self._rows):
            return
        row = self._rows[idx]

        self._fill_kv_table(
            self.packet_inspector,
            [("Timestamp", row.packet.timestamp.isoformat()), ("Origen", row.packet.src_ip), ("Destino", row.packet.dst_ip)],
        )
        self._fill_kv_table(
            self.anomaly_inspector,
            [("Riesgo", row.risk_level), ("Score", f"{row.risk_score:.1f}"), ("País", row.country)],
        )
        self._fill_kv_table(
            self.response_inspector,
            [("Contención", row.recommendation), ("Correlación", "SIEM + IDS"), ("Estado", "en curso")],
        )
        self._fill_kv_table(
            self.timeline_tab,
            [(row.packet.timestamp.strftime("%H:%M:%S"), row.risk_level, row.packet.src_ip, row.analysis_summary)],
        )

    def _fill_kv_table(self, table: QTableWidget, rows: list[tuple[str, ...]]) -> None:
        table.setRowCount(0)
        for values in rows:
            row = table.rowCount()
            table.insertRow(row)
            for col, value in enumerate(values):
                table.setItem(row, col, QTableWidgetItem(value))

    def _simulate_demo_event(self) -> None:
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
        snapshot = build_runtime_snapshot()
        self._runtime_snapshot = snapshot

        self.incoming_connections_list.clear()
        for conn in snapshot.get("incoming_connections", [])[:120]:
            if not isinstance(conn, dict):
                continue
            label = f"{conn.get('state', 'STATE')} · {conn.get('src_ip')}:{conn.get('src_port')} -> {conn.get('dst_ip')}:{conn.get('dst_port')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, conn)
            self.incoming_connections_list.addItem(item)

        self.service_versions_list.clear()
        for service in snapshot.get("service_versions", [])[:120]:
            if not isinstance(service, dict):
                continue
            label = f"{service.get('service', 'unknown')} · {service.get('version', 'unknown')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, service)
            self.service_versions_list.addItem(item)

        globe_points = snapshot.get("globe_points", [])
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

    def _show_runtime_settings_popup(self) -> None:
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
