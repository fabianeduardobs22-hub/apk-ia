from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from datetime import datetime, timezone
from pathlib import Path
import subprocess

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QFont, QPainter, QPen, QRadialGradient
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.core.capability_matrix import default_capability_matrix, summarize_matrix
from sentinel_x_defense_suite.gui.runtime_data import (
    build_runtime_snapshot,
    suggested_connection_defense_commands,
    suggested_service_admin_commands,
)
from sentinel_x_defense_suite.gui.viewmodels import RowMetrics, compute_dashboard_metrics
from sentinel_x_defense_suite.models.events import PacketRecord


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
        self.setMinimumHeight(250)
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
        x = radius * math.cos(lat_r) * math.sin(lon_r)
        y = radius * math.sin(lat_r)
        z = math.cos(lat_r) * math.cos(lon_r)
        return x, y, z

    def paintEvent(self, event: object) -> None:  # noqa: ARG002
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        radius = min(w, h) * 0.38
        cx = w / 2
        cy = h / 2

        gradient = QRadialGradient(cx - radius * 0.35, cy - radius * 0.35, radius * 1.25)
        gradient.setColorAt(0.0, QColor('#4db4ff'))
        gradient.setColorAt(0.35, QColor('#1f6feb'))
        gradient.setColorAt(1.0, QColor('#0b1622'))
        painter.setPen(QPen(QColor('#5fc9ff'), 2))
        painter.setBrush(gradient)
        painter.drawEllipse(int(cx - radius), int(cy - radius), int(radius * 2), int(radius * 2))

        painter.setPen(QPen(QColor('#5ba9e6'), 1))
        for line_lat in (-60, -30, 0, 30, 60):
            ry = radius * math.cos(math.radians(line_lat))
            y = cy + radius * math.sin(math.radians(line_lat))
            painter.drawEllipse(int(cx - ry), int(y - ry * 0.22), int(ry * 2), int(ry * 0.44))

        painter.setPen(QPen(QColor('#9ed8ff'), 1))
        for line_lon in range(0, 360, 30):
            lon_r = math.radians(line_lon + self._rotation)
            x = radius * math.sin(lon_r)
            painter.drawLine(int(cx + x), int(cy - radius), int(cx + x), int(cy + radius))

        for point in self._points:
            lat = float(point.get('lat', 0.0))
            lon = float(point.get('lon', 0.0))
            severity = int(point.get('severity', 1))
            _, _, z = self._project(lat, lon, radius)
            if z <= -0.03:
                continue
            x, y, _ = self._project(lat, lon, radius)
            px = cx + x
            py = cy - y
            color = QColor('#77e4ff') if severity <= 2 else QColor('#ffd166') if severity == 3 else QColor('#ff5a5a')
            size = 4 + severity
            painter.setPen(QPen(color, 1))
            painter.setBrush(color)
            painter.drawEllipse(int(px - size / 2), int(py - size / 2), size, size)

        painter.setPen(QColor('#d9eeff'))
        painter.drawText(12, 20, 'Globo táctico (simulación 3D defensiva)')


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DECKTROY · SENTINEL X DEFENSE SUITE")
        self.resize(1820, 1020)
        self._rows: list[ConnectionViewRow] = []
        self._runtime_snapshot: dict[str, object] = {}
        self._build_ui()
        self._apply_dark_theme()
        self._runtime_timer = QTimer(self)
        self._runtime_timer.timeout.connect(self._refresh_runtime_watch)
        self._runtime_timer.start(1000)
        self._refresh_runtime_watch()

    def _build_ui(self) -> None:
        self._build_menu_bar()
        self._build_toolbar()

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)

        self.nav_menu = QListWidget()
        self.nav_menu.setObjectName("navMenu")
        self.nav_menu.setFixedWidth(260)
        self.nav_menu.addItems(
            [
                "Centro SOC",
                "Mapa táctico 3D",
                "Conexiones en vivo",
                "Servicios y versiones",
                "Terminal operativa",
            ]
        )

        self.page_stack = QStackedWidget()
        self.page_stack.addWidget(self._build_soc_page())
        self.page_stack.addWidget(self._build_globe_page())
        self.page_stack.addWidget(self._build_connections_page())
        self.page_stack.addWidget(self._build_services_page())
        self.page_stack.addWidget(self._build_terminal_page())
        self.nav_menu.currentRowChanged.connect(self._switch_page)
        self.nav_menu.setCurrentRow(0)

        root_layout.addWidget(self.nav_menu)
        root_layout.addWidget(self.page_stack, 1)
        self.setCentralWidget(root)

        status = QStatusBar()
        status.showMessage("Listo · Plataforma defensiva activa")
        self.setStatusBar(status)

    def _switch_page(self, index: int) -> None:
        if 0 <= index < self.page_stack.count():
            self.page_stack.setCurrentIndex(index)

    def _build_soc_page(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.sidebar = self._build_sidebar()
        workspace = self._build_workspace()
        layout.addWidget(self.sidebar, 1)
        layout.addWidget(workspace, 4)
        return page

    def _build_globe_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.globe_widget = TacticalGlobeWidget()
        self.earth_globe_view = QPlainTextEdit(readOnly=True)
        self.earth_globe_view.setPlainText("Telemetría global en tiempo real")
        layout.addWidget(QLabel("Mapa táctico 3D de eventos remotos"))
        layout.addWidget(self.globe_widget, 3)
        layout.addWidget(self.earth_globe_view, 2)
        return page

    def _build_connections_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.incoming_connections_list = QListWidget()
        self.incoming_connections_list.itemDoubleClicked.connect(self._open_incoming_connection_detail)
        self.connection_terminal = QLineEdit()
        self.connection_terminal.setPlaceholderText("Terminal interactiva: comando y Enter para ejecutar")
        self.connection_terminal_output = QPlainTextEdit(readOnly=True)
        self.connection_terminal.returnPressed.connect(
            lambda: self._run_live_command(self.connection_terminal, self.connection_terminal_output)
        )
        layout.addWidget(QLabel("Conexiones entrantes (doble clic para informe)"))
        layout.addWidget(self.incoming_connections_list, 3)
        layout.addWidget(QLabel("Terminal de respuesta defensiva"))
        layout.addWidget(self.connection_terminal)
        layout.addWidget(self.connection_terminal_output, 2)
        return page

    def _build_services_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.service_versions_list = QListWidget()
        self.service_versions_list.itemDoubleClicked.connect(self._open_service_version_detail)
        self.service_terminal = QLineEdit()
        self.service_terminal.setPlaceholderText("Terminal de servicios: escribe comando y Enter")
        self.service_terminal_output = QPlainTextEdit(readOnly=True)
        self.service_terminal.returnPressed.connect(
            lambda: self._run_live_command(self.service_terminal, self.service_terminal_output)
        )
        layout.addWidget(QLabel("Inventario de servicios y versiones"))
        layout.addWidget(self.service_versions_list, 3)
        layout.addWidget(QLabel("Terminal de administración"))
        layout.addWidget(self.service_terminal)
        layout.addWidget(self.service_terminal_output, 2)
        return page

    def _build_terminal_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.global_terminal_input = QLineEdit()
        self.global_terminal_input.setPlaceholderText("Terminal operativa global (ejemplo: ss -tulpen)")
        self.global_terminal_output = QPlainTextEdit(readOnly=True)
        run_btn = QPushButton("Ejecutar")
        run_btn.clicked.connect(lambda: self._run_live_command(self.global_terminal_input, self.global_terminal_output))
        self.global_terminal_input.returnPressed.connect(
            lambda: self._run_live_command(self.global_terminal_input, self.global_terminal_output)
        )
        layout.addWidget(QLabel("Terminal operativa en tiempo real"))
        layout.addWidget(self.global_terminal_input)
        layout.addWidget(run_btn)
        layout.addWidget(self.global_terminal_output, 1)
        return page

    def _run_live_command(self, entry: QLineEdit, output: QPlainTextEdit) -> None:
        command = entry.text().strip()
        if not command:
            return
        output.appendPlainText(f"$ {command}")
        try:
            proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=8, check=False)
            merged = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            output.appendPlainText((merged.strip() or "(sin salida)")[:5000])
            output.appendPlainText(f"[exit={proc.returncode}]\n")
        except Exception as exc:
            output.appendPlainText(f"Error ejecutando comando: {exc}\n")
        entry.clear()
        self._refresh_runtime_watch()


    def _build_menu_bar(self) -> None:
        bar = self.menuBar()

        menu_file = bar.addMenu("Archivo")
        action_export = QAction("Exportar resumen de sesión", self)
        action_export.triggered.connect(self._show_export_summary_popup)
        action_exit = QAction("Salir", self)
        action_exit.triggered.connect(self.close)
        menu_file.addAction(action_export)
        menu_file.addSeparator()
        menu_file.addAction(action_exit)

        menu_view = bar.addMenu("Vista")
        action_filters = QAction("Editar preferencias de visualización", self)
        action_filters.triggered.connect(self._show_view_options_popup)
        menu_view.addAction(action_filters)

        menu_tools = bar.addMenu("Herramientas")
        action_settings = QAction("Configuración rápida", self)
        action_settings.triggered.connect(self._show_runtime_settings_popup)
        action_simulate = QAction("Generar evento de demostración", self)
        action_simulate.triggered.connect(self._simulate_demo_event)
        action_ioc = QAction("Copiar IOC de conexión seleccionada", self)
        action_ioc.triggered.connect(self._copy_selected_ioc)
        menu_tools.addAction(action_settings)
        menu_tools.addSeparator()
        menu_tools.addAction(action_simulate)
        menu_tools.addAction(action_ioc)

        menu_help = bar.addMenu("Ayuda")
        action_about = QAction("Acerca de SENTINEL X", self)
        action_about.triggered.connect(self._show_about_popup)
        menu_help.addAction(action_about)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)

        title = QLabel("SOC View")
        title.setStyleSheet("font-weight: 700; color: #9ec8ff;")

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtro rápido (ej: ip.src == 10.0.0.2 | tcp.port == 443 | dns)")
        self.search_input.textChanged.connect(self._apply_quick_filter)

        toolbar.addWidget(title)
        toolbar.addSeparator()
        toolbar.addWidget(self.search_input)

        self.quick_action_button = QPushButton("Evento demo")
        self.quick_action_button.clicked.connect(self._simulate_demo_event)
        toolbar.addSeparator()
        toolbar.addWidget(self.quick_action_button)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        layout = QVBoxLayout(side)
        layout.setSpacing(8)

        threat_box = QGroupBox("Nivel global de amenaza")
        threat_layout = QVBoxLayout(threat_box)
        self.threat_level = QLabel("LOW")
        self.threat_level.setStyleSheet("font-size: 22px; font-weight: 700;")
        self.threat_resume = QLabel("Resumen de prueba: Sin hallazgos críticos persistentes")
        self.threat_resume.setWordWrap(True)
        threat_layout.addWidget(self.threat_level)
        threat_layout.addWidget(self.threat_resume)

        interfaces_box = QGroupBox("Interfaces activas")
        interfaces_layout = QVBoxLayout(interfaces_box)
        self.interfaces_list = QListWidget()
        self.interfaces_list.addItems(["any (captura global)", "eth0", "wlan0"])
        interfaces_layout.addWidget(self.interfaces_list)

        alerts_box = QGroupBox("Alertas en tiempo real")
        alerts_layout = QVBoxLayout(alerts_box)
        self.alerts_list = QListWidget()
        alerts_layout.addWidget(self.alerts_list)

        protocol_box = QGroupBox("Actividad por protocolo")
        protocol_layout = QVBoxLayout(protocol_box)
        self.protocol_stats = QPlainTextEdit()
        self.protocol_stats.setReadOnly(True)
        self.protocol_stats.setPlainText("TCP: 0\nUDP: 0\nDNS: 0\nICMP: 0")
        protocol_layout.addWidget(self.protocol_stats)

        globe_box = QGroupBox("Globo terráqueo (telemetría textual)")
        globe_layout = QVBoxLayout(globe_box)
        self.globe_text = QPlainTextEdit()
        self.globe_text.setReadOnly(True)
        self.globe_text.setPlainText("Conexiones geolocalizadas:\n• Sin datos")
        globe_layout.addWidget(self.globe_text)

        services_box = QGroupBox("Servicios expuestos (tiempo real)")
        services_layout = QVBoxLayout(services_box)
        self.services_text = QPlainTextEdit()
        self.services_text.setReadOnly(True)
        self.services_text.setPlainText("Sin datos de servicios expuestos")
        services_layout.addWidget(self.services_text)

        exposure_box = QGroupBox("Superficie expuesta")
        exposure_layout = QVBoxLayout(exposure_box)
        self.exposure_text = QPlainTextEdit()
        self.exposure_text.setReadOnly(True)
        self.exposure_text.setPlainText("Sin resumen de exposición")
        exposure_layout.addWidget(self.exposure_text)

        connections_box = QGroupBox("Conexiones activas del host")
        connections_layout = QVBoxLayout(connections_box)
        self.connections_text = QPlainTextEdit()
        self.connections_text.setReadOnly(True)
        self.connections_text.setPlainText("Sin conexiones activas")
        connections_layout.addWidget(self.connections_text)

        actions_box = QGroupBox("Centro de respuesta (comandos listos)")
        actions_layout = QVBoxLayout(actions_box)
        self.actions_text = QPlainTextEdit()
        self.actions_text.setReadOnly(True)
        self.actions_text.setPlainText("Comandos defensivos se mostrarán aquí")
        actions_layout.addWidget(self.actions_text)

        topology_box = QGroupBox("Topología dinámica de red")
        topology_layout = QVBoxLayout(topology_box)
        self.topology_text = QPlainTextEdit()
        self.topology_text.setReadOnly(True)
        self.topology_text.setPlainText("Topología dinámica (enlaces más activos):\n- Sin datos")
        topology_layout.addWidget(self.topology_text)

        for widget in (threat_box, interfaces_box, alerts_box, protocol_box, globe_box, services_box, exposure_box, connections_box, actions_box, topology_box):
            layout.addWidget(widget)
        layout.addStretch(1)
        return side

    def _build_workspace(self) -> QWidget:
        workspace = QWidget()
        grid = QGridLayout(workspace)
        grid.setSpacing(8)

        cards_widget = self._build_soc_cards()

        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels(
            [
                "Hora",
                "IP origen",
                "IP destino",
                "Puerto",
                "Protocolo",
                "Estado",
                "Riesgo",
                "Score",
                "País",
                "Servicio",
                "Resumen",
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        self.table.itemSelectionChanged.connect(self._on_row_selected)

        tabs = QTabWidget()
        self.packet_inspector = QPlainTextEdit(readOnly=True)
        self.anomaly_inspector = QPlainTextEdit(readOnly=True)
        self.response_inspector = QPlainTextEdit(readOnly=True)
        self.timeline_tab = QPlainTextEdit(readOnly=True)
        self.capability_tab = QPlainTextEdit(readOnly=True)
        self.mission_tab = QPlainTextEdit(readOnly=True)
        self._refresh_capability_tab()

        tabs.addTab(self.packet_inspector, "Inspector de paquete")
        tabs.addTab(self.anomaly_inspector, "Anomalías y riesgo")
        tabs.addTab(self.response_inspector, "Respuesta defensiva")
        tabs.addTab(self.timeline_tab, "Timeline")
        tabs.addTab(self.capability_tab, "Benchmark defensivo")
        tabs.addTab(self.mission_tab, "Mission control")

        self.hex_ascii = QPlainTextEdit()
        self.hex_ascii.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.StyleHint.TypeWriter)
        self.hex_ascii.setFont(mono)

        center_split = QSplitter(Qt.Orientation.Vertical)
        center_split.addWidget(self.table)
        center_split.addWidget(tabs)
        center_split.addWidget(self.hex_ascii)
        center_split.setSizes([520, 260, 220])

        grid.addWidget(cards_widget, 0, 0)
        grid.addWidget(center_split, 1, 0)
        return workspace


    def _build_right_operations_panel(self) -> QWidget:
        panel = QGroupBox("Centro operacional (panel derecho)")
        layout = QVBoxLayout(panel)

        self.ops_tabs = QTabWidget()

        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        self.features_list = QListWidget()
        self.features_list.addItems(
            [
                "Globo 3D táctico de ciberataques",
                "Conexiones entrantes y análisis profundo",
                "Inventario de versiones y estado de servicios",
                "Comandos defensivos de mitigación",
                "Módulo de investigación forense y timeline",
                "Alertas de alta prioridad en tiempo real",
                "Vista SOC ejecutiva de riesgo",
            ]
        )
        summary_layout.addWidget(QLabel("Todas las funciones del programa"))
        summary_layout.addWidget(self.features_list)

        globe_tab = QWidget()
        globe_layout = QVBoxLayout(globe_tab)
        self.globe_widget = TacticalGlobeWidget()
        self.earth_globe_view = QPlainTextEdit()
        self.earth_globe_view.setReadOnly(True)
        self.earth_globe_view.setPlainText(
            "Visor de inteligencia geográfica:\n"
            "- La esfera rota automáticamente para inspección visual.\n"
            "- Los puntos se colorean por severidad de eventos remotos."
        )
        globe_layout.addWidget(self.globe_widget)
        globe_layout.addWidget(self.earth_globe_view)

        connections_tab = QWidget()
        connections_layout = QVBoxLayout(connections_tab)
        self.incoming_connections_list = QListWidget()
        self.incoming_connections_list.itemDoubleClicked.connect(self._open_incoming_connection_detail)
        connections_layout.addWidget(QLabel("Conexiones entrantes / activas (doble clic para informe ampliado)"))
        connections_layout.addWidget(self.incoming_connections_list)

        services_tab = QWidget()
        services_layout = QVBoxLayout(services_tab)
        self.service_versions_list = QListWidget()
        self.service_versions_list.itemDoubleClicked.connect(self._open_service_version_detail)
        services_layout.addWidget(QLabel("Versiones, estado y administración de servicios"))
        services_layout.addWidget(self.service_versions_list)

        self.ops_tabs.addTab(summary_tab, "Funciones")
        self.ops_tabs.addTab(globe_tab, "Globo 3D")
        self.ops_tabs.addTab(connections_tab, "Conexiones")
        self.ops_tabs.addTab(services_tab, "Servicios")

        layout.addWidget(self.ops_tabs)
        return panel


    def _build_soc_cards(self) -> QWidget:
        cards = QWidget()
        row = QHBoxLayout(cards)
        row.setSpacing(8)

        self.card_events = self._create_card("Eventos", "0")
        self.card_critical = self._create_card("Críticos", "0")
        self.card_unique_ips = self._create_card("IPs únicas", "0")
        self.card_protocol = self._create_card("Protocolo top", "-", value_size=16)

        for card in (self.card_events, self.card_critical, self.card_unique_ips, self.card_protocol):
            row.addWidget(card)
        return cards

    def _create_card(self, title: str, value: str, value_size: int = 24) -> QFrame:
        card = QFrame()
        card.setObjectName("socCard")
        layout = QVBoxLayout(card)
        label_title = QLabel(title)
        label_title.setObjectName("socCardTitle")
        label_value = QLabel(value)
        label_value.setObjectName("socCardValue")
        label_value.setStyleSheet(f"font-size: {value_size}px;")
        layout.addWidget(label_title)
        layout.addWidget(label_value)
        card._value_label = label_value  # type: ignore[attr-defined]
        return card

    def _refresh_capability_tab(self) -> None:
        matrix = default_capability_matrix()
        summary = summarize_matrix(matrix)
        lines = ["Comparativa defensiva de referencia (categorías públicas):", ""]
        for entry in matrix:
            lines.append(f"- {entry.name}: SENTINEL={entry.sentinel_score}/10 | referencia={entry.reference_score}/10")
            lines.append(f"  Justificación: {entry.rationale}")
        lines.extend(
            [
                "",
                f"Promedio SENTINEL: {summary['sentinel_avg']}",
                f"Promedio referencia: {summary['reference_avg']}",
                f"Delta: {summary['delta']}",
                "",
                "Objetivo operativo: mejora continua en visibilidad, respuesta y trazabilidad forense.",
            ]
        )
        self.capability_tab.setPlainText("\n".join(lines))

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
"""
            QMainWindow, QWidget { background-color: #0b1118; color: #ecf4ff; }
            QGroupBox { border: 1px solid #1f3348; border-radius: 8px; margin-top: 8px; font-weight: 600; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #9fd1ff; }
            QTableWidget { background-color: #0f1a25; gridline-color: #22384b; border-radius: 6px; }
            QHeaderView::section { background-color: #17293b; color: #e4eefc; padding: 4px; border: 0px; }
            QPlainTextEdit, QListWidget, QLineEdit { background-color: #0f1a25; border: 1px solid #243d54; border-radius: 6px; }
            QListWidget#navMenu { background-color: #0d1724; border: 1px solid #2b435c; padding: 6px; }
            QListWidget#navMenu::item { padding: 10px 12px; margin: 3px; border-radius: 8px; font-weight: 600; }
            QListWidget#navMenu::item:selected { background-color: #1f6feb; color: #ffffff; }
            QToolBar { background-color: #101b28; border-bottom: 1px solid #22384d; spacing: 8px; }
            QTabWidget::pane { border: 1px solid #22384d; border-radius: 6px; }
            QPushButton { background-color: #1f6feb; color: white; border-radius: 6px; padding: 6px 12px; font-weight: 700; }
            QPushButton:hover { background-color: #2c81ff; }
            QFrame#socCard { background-color: #101e2d; border: 1px solid #28415a; border-radius: 10px; }
            QLabel#socCardTitle { color: #86b9ee; font-size: 11px; text-transform: uppercase; }
            QLabel#socCardValue { color: #f2f8ff; font-size: 24px; font-weight: 800; }
            """
        )

    def _apply_quick_filter(self, expression: str) -> None:
        expression = expression.lower().strip()
        for row_idx, row in enumerate(self._rows):
            target = (
                f"{row.packet.src_ip} {row.packet.dst_ip} {row.packet.protocol} "
                f"{row.packet.dst_port} {row.country} {row.analysis_summary}"
            ).lower()
            self.table.setRowHidden(row_idx, bool(expression and expression not in target))

    def _risk_color(self, risk: str) -> QColor:
        color_map = {
            "LOW": QColor("#12311b"),
            "MEDIUM": QColor("#3d3615"),
            "HIGH": QColor("#4a2718"),
            "CRITICAL": QColor("#5a1b1b"),
        }
        return color_map.get(risk.upper(), QColor("#1c2a36"))

    def add_packet(
        self,
        packet: PacketRecord,
        risk_level: str = "LOW",
        risk_score: float = 0.0,
        country: str = "Unknown",
        analysis_summary: str = "Sin anomalías detectadas",
        recommendation: str = "Mantener monitoreo continuo y registro forense.",
    ) -> None:
        row_data = ConnectionViewRow(
            packet=packet,
            risk_level=risk_level.upper(),
            risk_score=risk_score,
            country=country,
            analysis_summary=analysis_summary,
            recommendation=recommendation,
        )
        self._rows.append(row_data)

        row = self.table.rowCount()
        self.table.insertRow(row)
        values = [
            packet.timestamp.strftime("%H:%M:%S"),
            packet.src_ip,
            packet.dst_ip,
            str(packet.dst_port),
            packet.protocol,
            "ACTIVE",
            row_data.risk_level,
            f"{row_data.risk_score:.1f}",
            row_data.country,
            str(packet.metadata.get("service", "UNKNOWN")),
            row_data.analysis_summary,
        ]

        risk_color = self._risk_color(row_data.risk_level)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setBackground(risk_color)
            self.table.setItem(row, col, item)

        self._refresh_sidebar_metrics()
        self._refresh_timeline_tab()
        if row == 0:
            self.table.selectRow(0)

    def _refresh_sidebar_metrics(self) -> None:
        metrics_rows = [
            RowMetrics(
                src_ip=row.packet.src_ip,
                dst_ip=row.packet.dst_ip,
                protocol=row.packet.protocol,
                risk_level=row.risk_level,
                country=row.country,
            )
            for row in self._rows
        ]
        metrics = compute_dashboard_metrics(metrics_rows)

        self.threat_level.setText(metrics.threat_level)
        self.threat_resume.setText(metrics.threat_resume)
        self.protocol_stats.setPlainText("\n".join(metrics.protocol_lines))
        self.globe_text.setPlainText("\n".join(metrics.geo_lines))
        self.topology_text.setPlainText("\n".join(metrics.topology_lines))
        self._refresh_soc_cards(metrics.protocol_lines)


    def _refresh_soc_cards(self, protocol_lines: list[str]) -> None:
        total_events = len(self._rows)
        critical_count = sum(1 for row in self._rows if row.risk_level in {"HIGH", "CRITICAL"})
        unique_ips = len({row.packet.src_ip for row in self._rows})
        protocol_top = protocol_lines[0].split(":")[0] if protocol_lines else "-"

        self.card_events._value_label.setText(str(total_events))  # type: ignore[attr-defined]
        self.card_critical._value_label.setText(str(critical_count))  # type: ignore[attr-defined]
        self.card_unique_ips._value_label.setText(str(unique_ips))  # type: ignore[attr-defined]
        self.card_protocol._value_label.setText(protocol_top)  # type: ignore[attr-defined]

    def _refresh_timeline_tab(self) -> None:
        lines = ["Timeline de eventos recientes (hasta 100):"]
        for row in self._rows[-100:]:
            p = row.packet
            lines.append(
                f"[{p.timestamp.strftime('%H:%M:%S')}] {row.risk_level} {p.src_ip}:{p.src_port} -> "
                f"{p.dst_ip}:{p.dst_port} {p.protocol} | {row.analysis_summary}"
            )
        if len(lines) == 1:
            lines.append("Sin eventos.")
        self.timeline_tab.setPlainText("\n".join(lines))

    def _selected_row(self) -> ConnectionViewRow | None:
        selected = self.table.selectedItems()
        if not selected:
            return None
        row_idx = selected[0].row()
        if row_idx >= len(self._rows):
            return None
        return self._rows[row_idx]

    def _on_row_selected(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        packet = row.packet

        self.packet_inspector.setPlainText(
            "\n".join(
                [
                    "=== Encabezados ===",
                    f"Timestamp: {packet.timestamp.isoformat()}",
                    f"Origen: {packet.src_ip}:{packet.src_port}",
                    f"Destino: {packet.dst_ip}:{packet.dst_port}",
                    f"Protocolo: {packet.protocol}",
                    f"Longitud: {packet.length}",
                    f"Servicio: {packet.metadata.get('service', 'UNKNOWN')}",
                    "",
                    "=== Metadatos (texto plano) ===",
                    "; ".join(f"{k}={v}" for k, v in packet.metadata.items()) or "Sin metadatos",
                ]
            )
        )

        self.anomaly_inspector.setPlainText(
            "\n".join(
                [
                    f"Nivel de riesgo: {row.risk_level}",
                    f"Score dinámico: {row.risk_score:.1f}",
                    f"País estimado: {row.country}",
                    "",
                    f"Análisis (prueba): {row.analysis_summary}",
                    "Respuesta (resumen): revisar IOC, validar autenticaciones y aplicar hardening.",
                    "",
                    "Acciones ofensivas: NO PERMITIDAS por política defensiva del sistema.",
                ]
            )
        )

        self.response_inspector.setPlainText(
            "\n".join(
                [
                    "Playbook recomendado (defensivo):",
                    f"1) {row.recommendation}",
                    "2) Correlacionar con eventos del SIEM y timeline forense.",
                    "3) Aplicar listas de bloqueo / reglas IDS según evidencia.",
                    "4) Documentar incidente y cerrar con lecciones aprendidas.",
                ]
            )
        )

        hex_part = packet.payload.hex(" ") if packet.payload else ""
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in packet.payload)
        self.hex_ascii.setPlainText(
            "\n".join(
                [
                    "=== Vista hexadecimal ===",
                    hex_part or "(sin payload)",
                    "",
                    "=== Vista ASCII ===",
                    ascii_part or "(sin payload)",
                ]
            )
        )

        if row.risk_level in {"HIGH", "CRITICAL"}:
            stamp = datetime.now().strftime("%H:%M:%S")
            self.alerts_list.insertItem(0, f"[{stamp}] {row.risk_level} {packet.src_ip} -> {packet.dst_ip}")

    def _on_table_context_menu(self, pos: object) -> None:
        if self._selected_row() is None:
            return

        menu = QMenu(self)
        action_details = QAction("Abrir resumen técnico", self)
        action_copy_ioc = QAction("Copiar IOC", self)
        action_details.triggered.connect(self._show_selected_details_popup)
        action_copy_ioc.triggered.connect(self._copy_selected_ioc)
        menu.addAction(action_details)
        menu.addAction(action_copy_ioc)

        global_pos = self.table.viewport().mapToGlobal(pos)  # type: ignore[arg-type]
        menu.exec(global_pos)

    def _show_selected_details_popup(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        msg = QMessageBox(self)
        msg.setWindowTitle("Resumen técnico de conexión")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(
            f"IP origen: {row.packet.src_ip}\n"
            f"IP destino: {row.packet.dst_ip}\n"
            f"Riesgo: {row.risk_level} ({row.risk_score:.1f})\n"
            f"Servicio: {row.packet.metadata.get('service', 'UNKNOWN')}\n"
            f"Resumen: {row.analysis_summary}\n\n"
            "Política: solo acciones defensivas y forenses."
        )
        msg.exec()

    def _copy_selected_ioc(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        ioc = (
            f"src={row.packet.src_ip};dst={row.packet.dst_ip};port={row.packet.dst_port};"
            f"proto={row.packet.protocol};risk={row.risk_level}"
        )
        QApplication.clipboard().setText(ioc)
        self.statusBar().showMessage("IOC copiado al portapapeles", 2500)

    def _show_export_summary_popup(self) -> None:
        msg = QMessageBox(self)
        msg.setWindowTitle("Exportación de sesión")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(
            "Use el comando CLI para exportar evidencia:\n"
            "sentinel-x --config sentinel_x.yaml export-alerts --output alerts.json"
        )
        msg.exec()

    def _show_about_popup(self) -> None:
        msg = QMessageBox(self)
        msg.setWindowTitle("Acerca de SENTINEL X")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(
            "SENTINEL X DEFENSE SUITE\n"
            "Plataforma Linux 100% defensiva para monitoreo, detección y forense de red."
        )
        msg.exec()

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
        self.add_packet(
            packet,
            risk_level="HIGH",
            risk_score=8.2,
            country="US",
            analysis_summary="Evento simulado: patrón de escaneo con huella HTTP sospechosa.",
            recommendation="Bloquear IP en firewall temporalmente y validar trazas relacionadas.",
        )
        self.statusBar().showMessage("Evento de demostración agregado", 2500)

    def _refresh_runtime_watch(self) -> None:
        snapshot = build_runtime_snapshot()
        self._runtime_snapshot = snapshot

        services = snapshot.get("services", [])
        if services:
            service_lines = [
                f"• {svc['protocol'].upper()} {svc['bind_ip']}:{svc['port']} svc={svc['service']} proc={svc['process']}"
                for svc in services[:25]
            ]
            self.services_text.setPlainText("\n".join(service_lines))
        else:
            self.services_text.setPlainText("Sin datos de servicios expuestos")

        active = snapshot.get("active_connections", [])
        if active:
            conn_lines = [
                f"• {conn['state']} {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']} ({conn['service']})"
                for conn in active[:25]
            ]
            self.connections_text.setPlainText("\n".join(conn_lines))
        else:
            self.connections_text.setPlainText("Sin conexiones activas")

        self.globe_text.setPlainText("\n".join(snapshot.get("globe_lines", ["Conexiones geolocalizadas:\n• Sin datos"])))
        self.exposure_text.setPlainText("\n".join(snapshot.get("exposure_lines", ["Sin resumen de exposición"])))
        self.actions_text.setPlainText("\n".join(snapshot.get("actions", ["Sin recomendaciones disponibles"])))
        self.earth_globe_view.setPlainText("\n".join(snapshot.get("globe_lines", ["Sin eventos geográficos"])))
        globe_points = snapshot.get("globe_points", [])
        if isinstance(globe_points, list):
            self.globe_widget.set_points(globe_points)

        self.incoming_connections_list.clear()
        for conn in snapshot.get("incoming_connections", [])[:120]:
            if not isinstance(conn, dict):
                continue
            label = (
                f"{conn.get('state', 'STATE')} · {conn.get('src_ip')}:{conn.get('src_port')}"
                f" -> {conn.get('dst_ip')}:{conn.get('dst_port')} ({conn.get('service', 'unknown')})"
            )
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, conn)
            self.incoming_connections_list.addItem(item)

        self.service_versions_list.clear()
        for service in snapshot.get("service_versions", [])[:120]:
            if not isinstance(service, dict):
                continue
            state = "activo" if service.get("active") else "inactivo"
            label = f"{service.get('service', 'unknown')} · {state} · {service.get('version', 'unknown')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, service)
            self.service_versions_list.addItem(item)


    def _open_incoming_connection_detail(self, item: QListWidgetItem) -> None:
        payload = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(payload, dict):
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Informe ampliado de conexión")
        dialog.resize(980, 760)
        layout = QVBoxLayout(dialog)

        details = QPlainTextEdit()
        details.setReadOnly(True)
        details.setPlainText(
            "\n".join(
                [
                    "=== Detalle de conexión seleccionada ===",
                    f"Tipo de conexión: {payload.get('protocol', 'unknown').upper()} / {payload.get('state', 'UNKNOWN')}",
                    f"Origen: {payload.get('src_ip')}:{payload.get('src_port')}",
                    f"Destino: {payload.get('dst_ip')}:{payload.get('dst_port')}",
                    f"Servicio detectado: {payload.get('service', 'unknown')}",
                    "Resultado de escaneo: revisión heurística activa, correlacionar con IDS/SIEM.",
                    f"Registro raw: {payload.get('raw', '')}",
                    "",
                    "Política: solo mitigación y defensa. No se permite contraataque activo.",
                ]
            )
        )

        commands = QPlainTextEdit()
        commands.setReadOnly(True)
        commands.setPlainText("\n".join(suggested_connection_defense_commands(payload)))

        terminal = QLineEdit()
        terminal.setPlaceholderText("Mini terminal defensiva: escriba un comando de verificación o mitigación")

        result = QPlainTextEdit()
        result.setReadOnly(True)

        def _run_terminal_command() -> None:
            cmd = terminal.text().strip()
            if not cmd:
                return
            result.appendPlainText(f"$ {cmd}")
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8, check=False)
                merged = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
                result.appendPlainText((merged.strip() or "(sin salida)")[:5000])
                result.appendPlainText(f"[exit={proc.returncode}]")
            except Exception as exc:
                result.appendPlainText(f"Error: {exc}")
            result.appendPlainText("")
            terminal.clear()
            self._refresh_runtime_watch()

        terminal.returnPressed.connect(_run_terminal_command)
        run_btn = QPushButton("Enviar comando")
        run_btn.clicked.connect(_run_terminal_command)

        layout.addWidget(QLabel("Informe técnico"))
        layout.addWidget(details, 3)
        layout.addWidget(QLabel("Comandos sugeridos"))
        layout.addWidget(commands, 2)
        layout.addWidget(QLabel("Terminal de acciones defensivas"))
        layout.addWidget(terminal)
        layout.addWidget(run_btn)
        layout.addWidget(result, 2)
        dialog.exec()

    def _open_service_version_detail(self, item: QListWidgetItem) -> None:
        payload = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(payload, dict):
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Detalle de servicio y versión")
        dialog.resize(980, 760)
        layout = QVBoxLayout(dialog)

        info = QPlainTextEdit()
        info.setReadOnly(True)
        info.setPlainText(
            "\n".join(
                [
                    "=== Servicio seleccionado ===",
                    f"Servicio: {payload.get('service', 'unknown')}",
                    f"Versión: {payload.get('version', 'unknown')}",
                    f"Estado: {payload.get('status', 'unknown')}",
                    f"Tipo de conexión: {payload.get('connection_type', 'local-service')}",
                    f"Puerto asociado: {payload.get('port', 'unknown')}",
                    f"Comando de detección: {payload.get('command', 'n/a')}",
                ]
            )
        )

        commands = QPlainTextEdit()
        commands.setReadOnly(True)
        commands.setPlainText("\n".join(suggested_service_admin_commands(payload)))

        terminal = QLineEdit()
        terminal.setPlaceholderText("Terminal para mantenimiento del servicio (diagnóstico/actualización)")

        result = QPlainTextEdit()
        result.setReadOnly(True)

        def _run_terminal_command() -> None:
            cmd = terminal.text().strip()
            if not cmd:
                return
            result.appendPlainText(f"$ {cmd}")
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8, check=False)
                merged = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
                result.appendPlainText((merged.strip() or "(sin salida)")[:5000])
                result.appendPlainText(f"[exit={proc.returncode}]")
            except Exception as exc:
                result.appendPlainText(f"Error: {exc}")
            result.appendPlainText("")
            terminal.clear()
            self._refresh_runtime_watch()

        terminal.returnPressed.connect(_run_terminal_command)
        run_btn = QPushButton("Ejecutar")
        run_btn.clicked.connect(_run_terminal_command)

        layout.addWidget(QLabel("Información de servicio"))
        layout.addWidget(info, 3)
        layout.addWidget(QLabel("Comandos útiles sugeridos"))
        layout.addWidget(commands, 2)
        layout.addWidget(QLabel("Terminal interactiva de mantenimiento"))
        layout.addWidget(terminal)
        layout.addWidget(run_btn)
        layout.addWidget(result, 2)
        dialog.exec()


    def _show_runtime_settings_popup(self) -> None:
        cfg_path = "sentinel_x.yaml"
        settings = SettingsLoader.load(cfg_path)

        dialog = QDialog(self)
        dialog.setWindowTitle("Configuración rápida (GUI)")
        layout = QFormLayout(dialog)

        interface_input = QLineEdit(settings.capture.interface)
        bpf_input = QLineEdit(settings.capture.bpf_filter)
        log_input = QLineEdit(settings.log_level)
        max_conn_input = QLineEdit(str(settings.detection.max_connections_per_ip))

        layout.addRow("Interfaz de captura", interface_input)
        layout.addRow("Filtro BPF", bpf_input)
        layout.addRow("Nivel de log", log_input)
        layout.addRow("Máx conexiones/IP", max_conn_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)

        def _save() -> None:
            settings.capture.interface = interface_input.text().strip() or "any"
            settings.capture.bpf_filter = bpf_input.text().strip()
            settings.log_level = log_input.text().strip().upper() or "INFO"
            try:
                settings.detection.max_connections_per_ip = max(1, int(max_conn_input.text().strip()))
            except ValueError:
                QMessageBox.warning(dialog, "Configuración", "Máx conexiones/IP debe ser número entero.")
                return
            payload = {
                "app_name": settings.app_name,
                "log_level": settings.log_level,
                "timezone": settings.timezone,
                "database": asdict(settings.database),
                "capture": asdict(settings.capture),
                "detection": asdict(settings.detection),
            }
            Path(cfg_path).write_text(SettingsLoader._dumps(payload), encoding="utf-8")
            self.statusBar().showMessage("Configuración actualizada desde GUI", 3000)
            dialog.accept()

        buttons.accepted.connect(_save)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        dialog.exec()

    def _show_view_options_popup(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Preferencias de visualización")
        layout = QFormLayout(dialog)

        cb_alerts = QCheckBox("Resaltar filas HIGH/CRITICAL")
        cb_alerts.setChecked(True)
        cb_geo = QCheckBox("Mostrar panel de telemetría geográfica textual")
        cb_geo.setChecked(True)
        cb_topology = QCheckBox("Mostrar panel de topología dinámica")
        cb_topology.setChecked(True)

        layout.addRow(cb_alerts)
        layout.addRow(cb_geo)
        layout.addRow(cb_topology)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addRow(buttons)
        dialog.exec()



def launch_gui() -> None:
    app = QApplication([])
    win = MainWindow()
    win.show()
    app.exec()
