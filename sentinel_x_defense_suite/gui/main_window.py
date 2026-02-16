from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import logging
import math
from pathlib import Path
from typing import Any, TypedDict

from PyQt6.QtCore import QSettings, Qt, QTimer
from PyQt6.QtGui import QColor, QPainter, QPen, QRadialGradient
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
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
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.capture.engine import resolve_capture_status
from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.gui.navigation.rbac import DEFAULT_POLICY, Role
from sentinel_x_defense_suite.gui.runtime_data import build_incremental_runtime_snapshot
from sentinel_x_defense_suite.models.events import PacketRecord
from sentinel_x_defense_suite.gui.widgets.theme_manager import THEMES, apply_theme
from sentinel_x_defense_suite.gui.widgets.ui_iconography import ICONS
from sentinel_x_defense_suite.gui.pages.forensics_timeline_page import ForensicsTimelinePage
from sentinel_x_defense_suite.gui.pages.incident_response_page import IncidentResponsePage
from sentinel_x_defense_suite.gui.pages.threat_hunting_page import ThreatHuntingPage

LOGGER = logging.getLogger(__name__)


class SnapshotContract(TypedDict, total=False):
    services: list[dict[str, Any]]
    incoming_connections: list[dict[str, Any]]
    service_versions: list[dict[str, Any]]
    globe_points: list[dict[str, Any]]
    capture_status: str


class AlertContract(TypedDict):
    time: str
    severity: str
    entity: str
    detection: str


class PlaybookContract(TypedDict):
    last_playbook: str
    mode: str


class AssetContract(TypedDict):
    name: str
    kind: str
    state: str


class AnalystTask(TypedDict):
    task: str
    source: str
    priority: str
    status: str


class AuditEntry(TypedDict):
    time: str
    action: str
    module: str
    detail: str


@dataclass(slots=True)
class ShellContracts:
    snapshot: SnapshotContract = field(default_factory=dict)
    alerts: list[AlertContract] = field(default_factory=list)
    playbook: PlaybookContract = field(default_factory=lambda: {"last_playbook": "none", "mode": "SAFE"})
    assets: list[AssetContract] = field(default_factory=list)

    def as_shared_context(self) -> dict[str, object]:
        return {
            "snapshot": self.snapshot,
            "alerts": self.alerts,
            "playbook": self.playbook,
            "assets": self.assets,
        }


@dataclass(slots=True)
class ConnectionViewRow:
    packet: PacketRecord
    risk_level: str
    risk_score: float
    country: str
    analysis_summary: str
    recommendation: str


class ViewRouter:
    def __init__(self, stack: QStackedWidget, settings: QSettings) -> None:
        self._stack = stack
        self._settings = settings
        self._route_map: dict[str, int] = {}
        self._history: list[str] = []
        self._cursor = -1

    def register_route(self, route: str, widget: QWidget) -> None:
        self._route_map[route] = self._stack.addWidget(widget)

    def navigate(self, route: str, track_history: bool = True) -> None:
        index = self._route_map.get(route)
        if index is None:
            return
        self._stack.setCurrentIndex(index)
        self._settings.setValue("router/last_module", route)
        if track_history:
            if self._cursor < len(self._history) - 1:
                self._history = self._history[: self._cursor + 1]
            self._history.append(route)
            self._cursor = len(self._history) - 1

    def can_go_back(self) -> bool:
        return self._cursor > 0

    def can_go_forward(self) -> bool:
        return 0 <= self._cursor < len(self._history) - 1

    def back(self) -> str | None:
        if not self.can_go_back():
            return None
        self._cursor -= 1
        route = self._history[self._cursor]
        self.navigate(route, track_history=False)
        return route

    def forward(self) -> str | None:
        if not self.can_go_forward():
            return None
        self._cursor += 1
        route = self._history[self._cursor]
        self.navigate(route, track_history=False)
        return route

    def current_route(self) -> str | None:
        if self._cursor < 0 or self._cursor >= len(self._history):
            return None
        return self._history[self._cursor]


class ModuleRoute(StrEnum):
    SOC = "soc"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    FORENSICS_TIMELINE = "forensics_timeline"


ROUTE_LABELS: dict[ModuleRoute, str] = {
    ModuleRoute.SOC: "SOC",
    ModuleRoute.THREAT_HUNTING: "Threat Hunting",
    ModuleRoute.INCIDENT_RESPONSE: "Incident Response",
    ModuleRoute.FORENSICS_TIMELINE: "Forensics Timeline",
}

LEGACY_ROUTE_ALIASES: dict[str, ModuleRoute] = {
    "SOC": ModuleRoute.SOC,
    "Threat Hunting": ModuleRoute.THREAT_HUNTING,
    "Incident Response": ModuleRoute.INCIDENT_RESPONSE,
    "Forensics Timeline": ModuleRoute.FORENSICS_TIMELINE,
    "dashboard": ModuleRoute.SOC,
    "hunting": ModuleRoute.THREAT_HUNTING,
    "incident_response": ModuleRoute.INCIDENT_RESPONSE,
    "forensics": ModuleRoute.FORENSICS_TIMELINE,
}


class TacticalGlobeWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(220)
        self._rotation = 0.0
        self._points: list[dict[str, float | str | int]] = []
        self._estimated_points_visible = False
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance_rotation)
        self._timer.start(80)

    def set_points(self, points: list[dict[str, float | str | int]]) -> None:
        self._points = points[:120]
        self._estimated_points_visible = any(point.get("geo_source") == "estimated" for point in self._points)
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
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        radius = min(w, h) * 0.36
        cx, cy = w / 2, h / 2

        gradient = QRadialGradient(cx - radius * 0.3, cy - radius * 0.3, radius * 1.25)
        gradient.setColorAt(0.0, QColor("#4db4ff"))
        gradient.setColorAt(0.35, QColor("#1f6feb"))
        gradient.setColorAt(1.0, QColor("#0b1622"))
        painter.setPen(QPen(QColor("#5fc9ff"), 2))
        painter.setBrush(gradient)
        painter.drawEllipse(int(cx - radius), int(cy - radius), int(radius * 2), int(radius * 2))

        for point in self._points:
            lat = float(point.get("lat", 0.0))
            lon = float(point.get("lon", 0.0))
            severity = int(point.get("severity", 1))
            x, y, z = self._project(lat, lon, radius)
            if z <= -0.03:
                continue
            color = QColor("#77e4ff") if severity <= 2 else QColor("#ffd166") if severity == 3 else QColor("#ff5a5a")
            painter.setPen(QPen(color, 1))
            painter.setBrush(color)
            painter.drawEllipse(int(cx + x - 3), int(cy - y - 3), 6 + severity, 6 + severity)

        if self._estimated_points_visible:
            label = "⚠ Geolocalización estimada (sin base GeoIP local)"
            painter.setPen(QPen(QColor("#ffcd57"), 1))
            painter.setBrush(QColor("#2a1d00"))
            painter.drawRoundedRect(12, 12, 340, 26, 6, 6)
            painter.drawText(22, 30, label)


class MainWindow(QMainWindow):
    MODULES = list(ModuleRoute)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DECKTROY · SENTINEL X DEFENSE SUITE")
        self.resize(1820, 1020)

        self.settings = QSettings("Decktroy", "SentinelXDefenseSuite")
        self._rows: list[ConnectionViewRow] = []
        self.contracts = ShellContracts()
        self.analyst_tasks: list[AnalystTask] = []
        self.audit_trail: list[AuditEntry] = []
        self._last_snapshot: dict[str, Any] | None = None
        self._sidebar_syncing = False
        self.capture_status = self._resolve_capture_status()

        self.current_role = Role(str(self.settings.value("ui/role", Role.ANALYST.value)))
        self._build_ui()
        self._restore_persistent_state()

        self._runtime_timer = QTimer(self)
        self._runtime_timer.timeout.connect(self._refresh_runtime_watch)
        self._runtime_timer.start(1500)
        self._refresh_runtime_watch()


    def _resolve_capture_status(self) -> str:
        config_path = Path("sentinel_x.yaml")
        if not config_path.exists():
            return "error"
        settings = SettingsLoader.load(config_path)
        return resolve_capture_status(settings.capture.interface, settings.capture.replay_pcap, settings.capture.simulate)

    def _render_capture_status_banner(self) -> None:
        labels = {
            "live": ("LIVE", "#0f5132", "#d1e7dd"),
            "replay": ("REPLAY", "#664d03", "#fff3cd"),
            "simulated": ("SIMULATED", "#055160", "#cff4fc"),
            "error": ("ERROR", "#842029", "#f8d7da"),
        }
        label, fg, bg = labels.get(self.capture_status, labels["error"])
        self.capture_status_banner.setText(f"Estado de captura: {label}")
        self.capture_status_banner.setStyleSheet(
            f"font-weight: 700; padding: 6px 10px; border-radius: 6px; color: {fg}; background: {bg};"
        )

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)

        self.capture_status_banner = QLabel()
        self.capture_status_banner.setObjectName("captureStatusBanner")
        root_layout.addWidget(self.capture_status_banner)
        self._render_capture_status_banner()

        # 1) sidebar · 2) workspace
        self.shell_splitter = QSplitter(Qt.Orientation.Horizontal)
        root_layout.addWidget(self.shell_splitter, 1)

        self.nav_list = QListWidget()
        self.nav_list.setObjectName("navMenu")
        self.nav_list.addItems([ROUTE_LABELS[module] for module in self.MODULES])
        self.nav_list.currentRowChanged.connect(self._on_sidebar_navigation)

        self.page_stack = QStackedWidget()
        self.router = ViewRouter(self.page_stack, self.settings)
        self.router.register_route(ModuleRoute.SOC.value, self._build_soc_page())
        self.router.register_route(ModuleRoute.THREAT_HUNTING.value, self._build_threat_hunting_page())
        self.router.register_route(ModuleRoute.INCIDENT_RESPONSE.value, self._build_incident_response_page())
        self.router.register_route(ModuleRoute.FORENSICS_TIMELINE.value, self._build_forensics_page())

        self.shell_splitter.addWidget(self.nav_list)
        self.shell_splitter.addWidget(self.page_stack)
        self.shell_splitter.setStretchFactor(0, 0)
        self.shell_splitter.setStretchFactor(1, 1)
        self.shell_splitter.setSizes([320, 1500])

        self.setCentralWidget(root)

        self._populate_navigation()

        status = QStatusBar()
        status.showMessage("Listo · Plataforma defensiva activa")
        self.setStatusBar(status)

    def _build_action_panel(self) -> QWidget:
        panel = QWidget()
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        self.btn_back = QPushButton("←")
        self.btn_back.clicked.connect(self._go_back)
        self.btn_forward = QPushButton("→")
        self.btn_forward.clicked.connect(self._go_forward)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtro rápido")
        self.search_input.textChanged.connect(self._apply_quick_filter)
        self.search_input.textChanged.connect(lambda value: self.settings.setValue("filters/quick", value))

        self.analyst_preset = QComboBox()
        self.analyst_preset.addItems(["SOC L1", "Threat Hunter", "IR Lead"])
        self.analyst_preset.currentTextChanged.connect(lambda v: self.settings.setValue("ui/analyst_preset", v))

        self.quick_action_button = QPushButton("Evento demo")
        self.quick_action_button.clicked.connect(self._simulate_demo_event)

        preferences_button = QPushButton("Preferencias")
        preferences_button.clicked.connect(self._show_view_options_popup)
        export_session_button = QPushButton("Exportar resumen")
        export_session_button.clicked.connect(self._show_export_summary_popup)
        export_audit_button = QPushButton("Exportar auditoría")
        export_audit_button.clicked.connect(self._export_audit_history)
        quick_settings_button = QPushButton("Configuración rápida")
        quick_settings_button.clicked.connect(self._show_runtime_settings_popup)
        about_button = QPushButton("Acerca de")
        about_button.clicked.connect(self._show_about_popup)

        layout.addWidget(QLabel("SOC View"))
        layout.addWidget(self.btn_back)
        layout.addWidget(self.btn_forward)
        layout.addWidget(self.search_input, 1)
        layout.addWidget(self.analyst_preset)
        layout.addWidget(self.quick_action_button)
        layout.addWidget(preferences_button)
        layout.addWidget(export_session_button)
        layout.addWidget(export_audit_button)
        layout.addWidget(quick_settings_button)
        layout.addWidget(about_button)
        return panel


    def _build_contextual_panel(self) -> QTabWidget:
        tabs = QTabWidget()

        self.context_snapshot = QTableWidget(0, 2)
        self.context_snapshot.setHorizontalHeaderLabels(["Clave", "Valor"])

        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(alerts_tab)
        self.context_alerts = QListWidget()
        self.context_alerts.itemDoubleClicked.connect(lambda item: self._pivot_alert_to_hunting(item.data(Qt.ItemDataRole.UserRole)))
        self.pivot_alert_button = QPushButton("Pivot alerta → hunting")
        self.pivot_alert_button.clicked.connect(self._pivot_selected_alert)
        alerts_layout.addWidget(self.context_alerts)
        alerts_layout.addWidget(self.pivot_alert_button)

        self.context_assets = QListWidget()

        self.workbench_table = QTableWidget(0, 4)
        self.workbench_table.setHorizontalHeaderLabels(["Tarea", "Origen", "Prioridad", "Estado"])

        audit_tab = QWidget()
        audit_layout = QVBoxLayout(audit_tab)
        self.audit_table = QTableWidget(0, 4)
        self.audit_table.setHorizontalHeaderLabels(["Hora", "Acción", "Módulo", "Detalle"])
        self.export_audit_button = QPushButton("Exportar auditoría (CSV)")
        self.export_audit_button.clicked.connect(self._export_audit_history)
        audit_layout.addWidget(self.audit_table)
        audit_layout.addWidget(self.export_audit_button)

        tabs.addTab(self.context_snapshot, "snapshot")
        tabs.addTab(alerts_tab, "alerts")
        tabs.addTab(self.context_assets, "assets")
        tabs.addTab(self.workbench_table, "workbench")
        tabs.addTab(audit_tab, "auditoría")
        return tabs

    def _build_soc_page(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)

        center = QWidget()
        center_layout = QVBoxLayout(center)
        center_layout.addWidget(self._build_action_panel())

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

        self.details_tabs.addTab(self.packet_inspector, "Inspector de paquete")
        self.details_tabs.addTab(self.anomaly_inspector, "Anomalías y riesgo")
        self.details_tabs.addTab(self.response_inspector, "Respuesta defensiva")
        self.details_tabs.addTab(self.timeline_tab, "Timeline")
        self.details_tabs.currentChanged.connect(lambda idx: self.settings.setValue("ui/last_workspace_tab", idx))

        center_layout.addWidget(self.table, 3)
        center_layout.addWidget(self.details_tabs, 2)

        self.ops_tabs = QTabWidget()
        self.ops_tabs.addTab(self._build_globe_tab(), "Globo 3D")
        self.ops_tabs.addTab(self._build_connections_tab(), "Conexiones")
        self.ops_tabs.addTab(self._build_services_tab(), "Servicios")
        self.context_tabs = self._build_contextual_panel()
        self.ops_tabs.addTab(self.context_tabs, "Contexto")

        self.soc_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.soc_splitter.addWidget(center)
        self.soc_splitter.addWidget(self.ops_tabs)
        self.soc_splitter.setSizes([1200, 500])
        layout.addWidget(self.soc_splitter)
        return page

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
        self.threat_hunting_page.entity_pivot.currentTextChanged.connect(lambda v: self.settings.setValue("filters/pivot", v))
        self.threat_hunting_page.severity_filter.currentTextChanged.connect(lambda v: self.settings.setValue("filters/severity", v))
        return self.threat_hunting_page

    def _build_incident_response_page(self) -> QWidget:
        self.incident_response_page = IncidentResponsePage()
        self.incident_response_page.playbookExecuted.connect(self._on_playbook_executed)
        self.incident_response_page.templateApplied.connect(self._on_incident_template_applied)
        return self.incident_response_page

    def _build_forensics_page(self) -> QWidget:
        self.forensics_page = ForensicsTimelinePage()
        return self.forensics_page

    def _on_role_changed(self) -> None:
        self.current_role = Role(str(self.role_selector.currentData()))
        self.settings.setValue("ui/role", self.current_role.value)
        self._populate_navigation()

    def _populate_navigation(self) -> None:
        for idx, module in enumerate(self.MODULES):
            item = self.nav_list.item(idx)
            if item is None:
                continue
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEnabled)
            item.setHidden(False)

            if not DEFAULT_POLICY.allows_view(self.current_role, module.value):
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)

        current = self.nav_list.currentRow()
        if current < 0 or not self.nav_list.item(current) or not (self.nav_list.item(current).flags() & Qt.ItemFlag.ItemIsEnabled):
            for idx in range(self.nav_list.count()):
                item = self.nav_list.item(idx)
                if item is not None and (item.flags() & Qt.ItemFlag.ItemIsEnabled):
                    self.nav_list.setCurrentRow(idx)
                    self.router.navigate(self.MODULES[idx].value)
                    break

        self._sync_rbac_actions()
        self._update_router_buttons()

    def _sync_rbac_actions(self) -> None:
        self.quick_action_button.setEnabled(DEFAULT_POLICY.allows_action(self.current_role, "demo.event.generate"))

    def _run_action(self, action_id: str) -> bool:
        if DEFAULT_POLICY.allows_action(self.current_role, action_id):
            return True
        QMessageBox.warning(self, "Acción bloqueada", f"Permiso insuficiente para {action_id}.")
        return False

    def _restore_persistent_state(self) -> None:
        apply_theme(QApplication.instance() or QApplication([]), str(self.settings.value("ui/theme", "dark_premium")))

        self.search_input.setText(str(self.settings.value("filters/quick", "")))
        self.threat_hunting_page.query_input.setText(str(self.settings.value("filters/query", "")))
        self.threat_hunting_page.entity_pivot.setCurrentText(str(self.settings.value("filters/pivot", "IP")))
        self.threat_hunting_page.severity_filter.setCurrentText(str(self.settings.value("filters/severity", "Todas")))
        self.analyst_preset.setCurrentText(str(self.settings.value("ui/analyst_preset", "SOC L1")))

        self.details_tabs.setCurrentIndex(int(self.settings.value("ui/last_workspace_tab", 0)))

        shell_sizes = self.settings.value("ui/main_splitter_sizes")
        if isinstance(shell_sizes, list) and len(shell_sizes) == 2:
            self.shell_splitter.setSizes([int(size) for size in shell_sizes])
        soc_sizes = self.settings.value("ui/soc_splitter_sizes")
        if isinstance(soc_sizes, list) and soc_sizes:
            self.soc_splitter.setSizes([int(size) for size in soc_sizes])

        last_module_setting = str(self.settings.value("router/last_module", ModuleRoute.SOC.value))
        last_module = self._normalize_route(last_module_setting) or ModuleRoute.SOC
        self.router.navigate(last_module.value)
        self._sync_sidebar_with_route(last_module)
        self._update_router_buttons()

    def closeEvent(self, event: object) -> None:
        self.settings.setValue("ui/main_splitter_sizes", self.shell_splitter.sizes())
        self.settings.setValue("ui/soc_splitter_sizes", self.soc_splitter.sizes())
        super().closeEvent(event)

    def _sync_sidebar_with_route(self, route: ModuleRoute | str) -> None:
        normalized_route = self._normalize_route(route)
        if normalized_route is None:
            return
        self._sidebar_syncing = True
        self.nav_list.setCurrentRow(self.MODULES.index(normalized_route))
        self._sidebar_syncing = False

    def _on_sidebar_navigation(self, index: int) -> None:
        if self._sidebar_syncing or not (0 <= index < len(self.MODULES)):
            return
        route = self.MODULES[index]
        self.router.navigate(route.value)
        self._update_router_buttons()

    def _go_back(self) -> None:
        route = self.router.back()
        if route:
            self._sync_sidebar_with_route(route)
        self._update_router_buttons()

    def _go_forward(self) -> None:
        route = self.router.forward()
        if route:
            self._sync_sidebar_with_route(route)
        self._update_router_buttons()

    def _update_router_buttons(self) -> None:
        self.btn_back.setEnabled(self.router.can_go_back())
        self.btn_forward.setEnabled(self.router.can_go_forward())

    def _on_threat_query(self, query: str) -> None:
        self.settings.setValue("filters/query", query)
        filtered: list[dict[str, str]] = []
        for row in self._rows[-120:]:
            if query and query.lower() not in row.analysis_summary.lower() and query not in row.packet.src_ip:
                continue
            filtered.append(
                {
                    "time": row.packet.timestamp.strftime("%H:%M:%S"),
                    "entity": self.threat_hunting_page.entity_pivot.currentText(),
                    "value": row.packet.src_ip,
                    "severity": row.risk_level,
                    "detection": row.analysis_summary,
                    "badge": ICONS["triaged"] if row.risk_level in {"HIGH", "CRITICAL"} else ICONS["watch"],
                }
            )
        self.threat_hunting_page.set_results(filtered)
        self._record_audit_action("query.hunting", "Threat Hunting", f"query={query or '*'} resultados={len(filtered)}")

    def _on_playbook_executed(self, playbook: str) -> None:
        mode = "SAFE" if self.incident_response_page.safe_mode.isChecked() else "LIVE"
        self.contracts.playbook = {"last_playbook": playbook, "mode": mode}
        self.settings.setValue("playbook/last", playbook)
        self._record_audit_action("playbook.execute", "Incident Response", f"{playbook} modo={mode}")

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
        self._record_audit_action("demo.event.generate", "SOC", "Se inyectó evento simulado para validación")

    def _refresh_runtime_watch(self) -> None:
        incremental = build_incremental_runtime_snapshot(self._last_snapshot, include_service_versions=True)
        snapshot = incremental.get("full_snapshot", {})
        snapshot["capture_status"] = self.capture_status
        self.contracts.snapshot = snapshot
        self._last_snapshot = snapshot

        alerts: list[AlertContract] = []
        for conn in snapshot.get("incoming_connections", [])[:30]:
            if not isinstance(conn, dict):
                continue
            alerts.append(
                {
                    "time": datetime.now(tz=timezone.utc).strftime("%H:%M:%S"),
                    "severity": "MEDIUM" if conn.get("state") == "ESTAB" else "LOW",
                    "entity": str(conn.get("dst_ip", "unknown")),
                    "detection": f"{conn.get('protocol', 'tcp')}:{conn.get('dst_port', '-')}",
                }
            )
        self.contracts.alerts = alerts

        assets: list[AssetContract] = []
        for service in snapshot.get("service_versions", [])[:30]:
            if not isinstance(service, dict):
                continue
            assets.append(
                {
                    "name": str(service.get("service", "unknown")),
                    "kind": "service",
                    "state": "active" if service.get("active") else "inactive",
                }
            )
        self.contracts.assets = assets
        self._sync_analyst_workbench()

        self._render_contract_panels()
        self._propagate_contracts_to_modules()

    def _render_contract_panels(self) -> None:
        self.context_snapshot.setRowCount(0)
        rows = [
            ("services", str(len(self.contracts.snapshot.get("services", [])))),
            ("incoming_connections", str(len(self.contracts.snapshot.get("incoming_connections", [])))),
            ("service_versions", str(len(self.contracts.snapshot.get("service_versions", [])))),
            ("playbook", self.contracts.playbook.get("last_playbook", "none")),
            ("capture_status", str(self.contracts.snapshot.get("capture_status", "error"))),
        ]
        for key, value in rows:
            row = self.context_snapshot.rowCount()
            self.context_snapshot.insertRow(row)
            self.context_snapshot.setItem(row, 0, QTableWidgetItem(key))
            self.context_snapshot.setItem(row, 1, QTableWidgetItem(value))

        self.context_alerts.clear()
        for alert in self.contracts.alerts[:40]:
            item = QListWidgetItem(f"[{alert['severity']}] {alert['time']} · {alert['entity']} · {alert['detection']}")
            item.setData(Qt.ItemDataRole.UserRole, alert.get("entity", ""))
            self.context_alerts.addItem(item)

        self.context_assets.clear()
        for asset in self.contracts.assets[:40]:
            self.context_assets.addItem(f"{asset['name']} · {asset['kind']} · {asset['state']}")

        self.incoming_connections_list.clear()
        for conn in self.contracts.snapshot.get("incoming_connections", [])[:120]:
            if not isinstance(conn, dict):
                continue
            label = f"{conn.get('state', 'STATE')} · {conn.get('src_ip')}:{conn.get('src_port')} -> {conn.get('dst_ip')}:{conn.get('dst_port')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, conn)
            self.incoming_connections_list.addItem(item)

        snapshot = self.contracts.snapshot

        if hasattr(self, "hunting_results"):
            self.hunting_results.setPlainText(
                "Threat Hunting Workspace\n"
                f"- Conexiones activas evaluadas: {len(snapshot.get('active_connections', []))}\n"
                f"- Destinos remotos sospechosos: {len(snapshot.get('remote_suspicious', []))}\n"
                "- Recomendación: priorizar entidades con severidad alta y puertos de autenticación."
            )
        if hasattr(self, "forensics_timeline_text"):
            self.forensics_timeline_text.setPlainText(
                "Forense y cadena de custodia\n"
                f"- Eventos geográficos correlacionados: {len(snapshot.get('globe_points', []))}\n"
                f"- Conexiones entrantes observadas: {len(snapshot.get('incoming_connections', []))}\n"
                "- Exporta evidencia y valida hash de registros para auditoría."
            )
        if hasattr(self, "reports_text"):
            pb = snapshot.get("defense_playbook", {}) if isinstance(snapshot, dict) else {}
            summary = pb.get("summary", "Sin resumen") if isinstance(pb, dict) else "Sin resumen"
            self.reports_text.setPlainText(
                "Reportes y cumplimiento\n"
                f"- {summary}\n"
                f"- Servicios expuestos: {snapshot.get('public_service_count', 0)}\n"
                f"- Acciones sugeridas: {len(snapshot.get('actions', []))}"
            )

        self.service_versions_list.clear()
        for service in self.contracts.snapshot.get("service_versions", [])[:120]:
            if not isinstance(service, dict):
                continue
            label = f"{service.get('service', 'unknown')} · {service.get('version', 'unknown')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, service)
            self.service_versions_list.addItem(item)

        self.workbench_table.setRowCount(0)
        for task in self.analyst_tasks[:80]:
            row = self.workbench_table.rowCount()
            self.workbench_table.insertRow(row)
            self.workbench_table.setItem(row, 0, QTableWidgetItem(task["task"]))
            self.workbench_table.setItem(row, 1, QTableWidgetItem(task["source"]))
            self.workbench_table.setItem(row, 2, QTableWidgetItem(task["priority"]))
            self.workbench_table.setItem(row, 3, QTableWidgetItem(task["status"]))

        self.audit_table.setRowCount(0)
        for entry in self.audit_trail[-120:]:
            row = self.audit_table.rowCount()
            self.audit_table.insertRow(row)
            self.audit_table.setItem(row, 0, QTableWidgetItem(entry["time"]))
            self.audit_table.setItem(row, 1, QTableWidgetItem(entry["action"]))
            self.audit_table.setItem(row, 2, QTableWidgetItem(entry["module"]))
            self.audit_table.setItem(row, 3, QTableWidgetItem(entry["detail"]))

        globe_points = self.contracts.snapshot.get("globe_points", [])
        if isinstance(globe_points, list):
            self.globe_widget.set_points(globe_points)

    def _sync_analyst_workbench(self) -> None:
        pending = sum(1 for alert in self.contracts.alerts if alert.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"})
        tasks: list[AnalystTask] = [
            {
                "task": "Triar alertas activas",
                "source": "Alerts",
                "priority": "Alta" if pending > 4 else "Media",
                "status": "pendiente" if pending else "bloqueado",
            },
            {
                "task": "Validar exposición de servicios",
                "source": "SOC",
                "priority": "Alta" if self.contracts.snapshot.get("public_service_count", 0) else "Baja",
                "status": "en curso" if self.contracts.snapshot.get("services") else "pendiente",
            },
            {
                "task": "Actualizar timeline forense",
                "source": "Forensics",
                "priority": "Media",
                "status": "pendiente",
            },
        ]
        if self.contracts.playbook.get("last_playbook", "none") != "none":
            tasks.append(
                {
                    "task": f"Cerrar acciones de {self.contracts.playbook['last_playbook']}",
                    "source": "Incident Response",
                    "priority": "Alta",
                    "status": "en revisión",
                }
            )
        self.analyst_tasks = tasks

    def _pivot_selected_alert(self) -> None:
        item = self.context_alerts.currentItem()
        if item is None:
            return
        self._pivot_alert_to_hunting(item.data(Qt.ItemDataRole.UserRole))

    def _pivot_alert_to_hunting(self, entity: object) -> None:
        target = str(entity or "").strip()
        if not target:
            return
        self.threat_hunting_page.query_input.setText(target)
        self.threat_hunting_page.entity_pivot.setCurrentText("IP")
        self.router.navigate(ModuleRoute.THREAT_HUNTING.value)
        self._sync_sidebar_with_route(ModuleRoute.THREAT_HUNTING)
        self._update_router_buttons()
        self._on_threat_query(target)
        self._record_audit_action("pivot.alert_to_hunting", "Threat Hunting", f"entity={target}")

    def _normalize_route(self, route: ModuleRoute | str) -> ModuleRoute | None:
        if isinstance(route, ModuleRoute):
            return route
        legacy = LEGACY_ROUTE_ALIASES.get(route)
        if legacy is not None:
            return legacy
        try:
            return ModuleRoute(route)
        except ValueError:
            return None

    def _on_incident_template_applied(self, template_name: str) -> None:
        self._record_audit_action("ir.template.apply", "Incident Response", template_name)

    def _record_audit_action(self, action: str, module: str, detail: str) -> None:
        entry: AuditEntry = {
            "time": datetime.now(tz=timezone.utc).strftime("%H:%M:%S"),
            "action": action,
            "module": module,
            "detail": detail,
        }
        self.audit_trail.append(entry)
        if len(self.audit_trail) > 400:
            self.audit_trail = self.audit_trail[-400:]

    def _export_audit_history(self) -> None:
        if not self.audit_trail:
            self.statusBar().showMessage("Sin acciones para exportar", 3000)
            return
        default_name = f"audit-history-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "Exportar auditoría", default_name, "CSV (*.csv)")
        if not path:
            return
        lines = ["time,action,module,detail"]
        for entry in self.audit_trail:
            escaped = [entry["time"], entry["action"], entry["module"], entry["detail"].replace('"', "''")]
            lines.append(",".join(f'"{value}"' for value in escaped))
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.statusBar().showMessage(f"Auditoría exportada en {path}", 4000)

    def _propagate_contracts_to_modules(self) -> None:
        shared = self.contracts.as_shared_context()
        self.threat_hunting_page.setProperty("shell_contracts", shared)
        self.incident_response_page.setProperty("shell_contracts", shared)
        self.forensics_page.setProperty("shell_contracts", shared)

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
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(key))
            table.setItem(row, 1, QTableWidgetItem(str(payload.get(key, "-"))))
        layout.addWidget(table)
        dialog.resize(620, 420)
        dialog.exec()
        self._record_audit_action("connection.drilldown.open", "SOC", f"{payload.get('src_ip', '-')}->{payload.get('dst_ip', '-')}")

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
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(key))
            table.setItem(row, 1, QTableWidgetItem(str(payload.get(key, "-"))))
        layout.addWidget(table)
        dialog.resize(620, 420)
        dialog.exec()
        self._record_audit_action("service.drilldown.open", "SOC", str(payload.get('service', 'unknown')))

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

        theme_selector = QComboBox()
        for theme in THEMES.values():
            theme_selector.addItem(theme.name, theme.key)
        theme_selector.setCurrentIndex(max(0, theme_selector.findData(self.settings.value("ui/theme", "dark_premium"))))
        form.addRow("Tema de interfaz", theme_selector)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)

        def _save() -> None:
            settings.capture.interface = interface_input.text().strip() or "any"
            selected_theme = str(theme_selector.currentData())
            self.settings.setValue("ui/theme", selected_theme)
            apply_theme(QApplication.instance() or QApplication([]), selected_theme)
            Path(cfg_path).write_text(
                SettingsLoader._dumps({"app_name": settings.app_name, "capture": {"interface": settings.capture.interface}}),
                encoding="utf-8",
            )
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
