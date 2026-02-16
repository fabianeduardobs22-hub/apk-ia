from __future__ import annotations

import math

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor, QPainter, QPen, QRadialGradient
from PyQt6.QtWidgets import QListWidget, QSplitter, QTabWidget, QTableWidget, QVBoxLayout, QWidget, QHBoxLayout


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


class DashboardPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)

        center = QWidget()
        center_layout = QVBoxLayout(center)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Hora", "IP origen", "IP destino", "Puerto", "Protocolo", "Riesgo", "Resumen"])
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

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

        center_layout.addWidget(self.table, 3)
        center_layout.addWidget(self.details_tabs, 2)

        self.ops_tabs = QTabWidget()
        self.features_list = QListWidget()
        self.features_list.addItems([
            "Threat hunting con filtros compuestos",
            "Playbooks de respuesta con safe mode",
            "Timeline forense con drill-down",
            "Navegación lateral persistente",
            "Tema premium configurable",
        ])
        self.globe_widget = TacticalGlobeWidget()
        self.incoming_connections_list = QListWidget()
        self.service_versions_list = QListWidget()

        features_tab = QWidget()
        features_layout = QVBoxLayout(features_tab)
        features_layout.addWidget(self.features_list)

        globe_tab = QWidget()
        globe_layout = QVBoxLayout(globe_tab)
        globe_layout.addWidget(self.globe_widget)

        conn_tab = QWidget()
        conn_layout = QVBoxLayout(conn_tab)
        conn_layout.addWidget(self.incoming_connections_list)

        svc_tab = QWidget()
        svc_layout = QVBoxLayout(svc_tab)
        svc_layout.addWidget(self.service_versions_list)

        self.ops_tabs.addTab(features_tab, "Funciones")
        self.ops_tabs.addTab(globe_tab, "Globo 3D")
        self.ops_tabs.addTab(conn_tab, "Conexiones")
        self.ops_tabs.addTab(svc_tab, "Servicios")

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(center)
        splitter.addWidget(self.ops_tabs)
        splitter.setSizes([1200, 500])
        layout.addWidget(splitter)
