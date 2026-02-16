from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QFont
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
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.core.capability_matrix import default_capability_matrix, summarize_matrix
from sentinel_x_defense_suite.gui.runtime_data import build_runtime_snapshot
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


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DECKTROY · SENTINEL X DEFENSE SUITE")
        self.resize(1820, 1020)
        self._rows: list[ConnectionViewRow] = []
        self._build_ui()
        self._apply_dark_theme()
        self._runtime_timer = QTimer(self)
        self._runtime_timer.timeout.connect(self._refresh_runtime_watch)
        self._runtime_timer.start(3500)
        self._refresh_runtime_watch()

    def _build_ui(self) -> None:
        self._build_menu_bar()
        self._build_toolbar()

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.setSpacing(8)

        self.sidebar = self._build_sidebar()
        workspace = self._build_workspace()

        root_layout.addWidget(self.sidebar, 1)
        root_layout.addWidget(workspace, 5)
        self.setCentralWidget(root)

        status = QStatusBar()
        status.showMessage("Listo · Plataforma defensiva activa")
        self.setStatusBar(status)

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
        action_refresh_now = QAction("Refrescar telemetría en vivo", self)
        action_refresh_now.triggered.connect(self._refresh_runtime_watch)
        action_ioc = QAction("Copiar IOC de conexión seleccionada", self)
        action_ioc.triggered.connect(self._copy_selected_ioc)
        menu_tools.addAction(action_settings)
        menu_tools.addAction(action_refresh_now)
        menu_tools.addSeparator()
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

        self.refresh_button = QPushButton("Refrescar ahora")
        self.refresh_button.clicked.connect(self._refresh_runtime_watch)
        self.contain_button = QPushButton("Playbook contención")
        self.contain_button.clicked.connect(self._run_containment_playbook)
        toolbar.addSeparator()
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.contain_button)
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


    def _build_soc_cards(self) -> QWidget:
        cards = QWidget()
        row = QHBoxLayout(cards)
        row.setSpacing(8)

        self.card_events = self._create_card("Eventos", "0")
        self.card_critical = self._create_card("Críticos", "0")
        self.card_unique_ips = self._create_card("IPs únicas", "0")
        self.card_protocol = self._create_card("Protocolo top", "-", value_size=16)
        self.card_exposed = self._create_card("Servicios públicos", "0", value_size=20)

        for card in (self.card_events, self.card_critical, self.card_unique_ips, self.card_protocol, self.card_exposed):
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

    def _refresh_runtime_watch(self) -> None:
        snapshot = build_runtime_snapshot()

        services = snapshot["services"][:60]
        if services:
            lines = ["PROTO  ESTADO   BIND                PUERTO  SERVICIO      PROCESO"]
            for svc in services:
                lines.append(
                    f"{svc['protocol']:<6} {svc['state']:<8} {svc['bind_ip']:<18} {svc['port']:<6} {svc['service']:<12} {svc['process']}"
                )
            self.services_text.setPlainText("\n".join(lines))
        else:
            self.services_text.setPlainText("No se detectaron sockets en escucha")

        active = snapshot["active_connections"][:80]
        if active:
            lines = ["PROTO ESTADO     ORIGEN                 DESTINO"]
            for conn in active:
                lines.append(
                    f"{conn['protocol']:<5} {conn['state']:<9} {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}"
                )
            self.connections_text.setPlainText("\n".join(lines))
        else:
            self.connections_text.setPlainText("Sin conexiones activas detectadas")

        self.globe_text.setPlainText("\n".join(snapshot["globe_lines"]))
        self.actions_text.setPlainText("\n".join(snapshot["actions"]))
        self.exposure_text.setPlainText("\n".join(snapshot["exposure_lines"]))
        self.card_exposed._value_label.setText(str(snapshot["public_service_count"]))  # type: ignore[attr-defined]
        self._sync_services_to_table(snapshot["services"], snapshot["active_connections"])

        mission_lines = [
            "Centro de misión defensivo:",
            f"- Servicios públicos detectados: {snapshot['public_service_count']}",
            f"- Conexiones activas: {len(snapshot['active_connections'])}",
            f"- Conexiones remotas sospechosas: {len(snapshot['remote_suspicious'])}",
            "",
            *snapshot["actions"],
        ]
        self.mission_tab.setPlainText("\n".join(mission_lines))

        suspicious = snapshot["remote_suspicious"]
        if suspicious:
            top = suspicious[0]
            self.statusBar().showMessage(
                f"Monitoreo activo: conexiones remotas detectadas ({top['dst_ip']}:{top['dst_port']})",
                2500,
            )

    def _sync_services_to_table(self, services: list[dict], active_connections: list[dict]) -> None:
        self.table.setRowCount(0)
        self._rows.clear()

        for svc in services[:120]:
            bind_ip = str(svc.get("bind_ip", "unknown"))
            port = int(svc.get("port", 0) or 0)
            protocol = str(svc.get("protocol", "tcp")).upper()
            process = str(svc.get("process", "unknown"))
            service_name = str(svc.get("service", "unknown"))
            exposed = bind_ip in {"0.0.0.0", "::"}
            risk = "MEDIUM" if exposed else "LOW"
            score = 65.0 if exposed else 25.0
            summary = (
                f"Servicio detectado: {service_name} | proceso={process} | bind={bind_ip}:{port}"
                + (" | expuesto públicamente" if exposed else " | alcance local/restringido")
            )
            recommendation = (
                "Validar necesidad de exposición pública y limitar por firewall/ACL."
                if exposed
                else "Mantener monitoreo y hardening del servicio."
            )

            packet = PacketRecord.now(
                src_ip=bind_ip,
                dst_ip="0.0.0.0",
                src_port=port,
                dst_port=port,
                protocol=protocol,
                length=0,
                payload=b"",
                metadata={"service": service_name, "process": process, "state": svc.get("state", "UNKNOWN")},
            )
            self.add_packet(
                packet=packet,
                risk_level=risk,
                risk_score=score,
                country="LOCAL",
                analysis_summary=summary,
                recommendation=recommendation,
            )

        # Add active remote connections as operational context
        for conn in active_connections[:80]:
            if str(conn.get("state", "")).upper() not in {"ESTAB", "SYN-RECV", "SYN-SENT"}:
                continue
            dst_ip = str(conn.get("dst_ip", "unknown"))
            dst_port = int(conn.get("dst_port", 0) or 0)
            src_ip = str(conn.get("src_ip", "unknown"))
            src_port = int(conn.get("src_port", 0) or 0)
            protocol = str(conn.get("protocol", "tcp")).upper()
            service_name = str(conn.get("service", "unknown"))
            summary = f"Conexión activa: {src_ip}:{src_port} -> {dst_ip}:{dst_port} svc={service_name}"

            packet = PacketRecord.now(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=0,
                payload=b"",
                metadata={"service": service_name, "state": conn.get("state", "UNKNOWN")},
            )
            self.add_packet(
                packet=packet,
                risk_level="MEDIUM",
                risk_score=55.0,
                country="Unknown",
                analysis_summary=summary,
                recommendation="Correlacionar con baseline para descartar exfiltración o C2.",
            )

    def _run_containment_playbook(self) -> None:
        commands = [
            "sudo ss -tulpen | sort",
            "sudo ufw status numbered",
            "sudo journalctl -n 200 --no-pager | grep -Ei 'failed|invalid|denied|attack'",
            "decktroy connection-guard --mode analyze --duration 60",
        ]
        QApplication.clipboard().setText("\n".join(commands))
        self.actions_text.setPlainText("Playbook copiado al portapapeles:\n" + "\n".join(commands))
        self.statusBar().showMessage("Playbook de contención copiado", 3000)

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
