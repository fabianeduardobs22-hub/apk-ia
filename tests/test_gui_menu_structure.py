import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QTabWidget

from sentinel_x_defense_suite.gui.main_window import MainWindow


def test_main_window_menus_and_tabs() -> None:
    app = QApplication.instance() or QApplication([])
    win = MainWindow()

    menu_titles = [action.text() for action in win.menuBar().actions()]
    assert menu_titles == ["Archivo", "Vista", "Herramientas", "Ayuda"]

    tabs = win.findChild(QTabWidget)
    assert tabs is not None
    tab_titles = [tabs.tabText(i) for i in range(tabs.count())]
    assert "Inspector de paquete" in tab_titles
    assert "Anomalías y riesgo" in tab_titles
    assert "Respuesta defensiva" in tab_titles
    assert "Timeline" in tab_titles
    assert "Benchmark defensivo" in tab_titles
    assert "Mission control" in tab_titles

    win.close()
    app.processEvents()


def test_right_operations_panel_lists_are_present(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])

    def _fake_snapshot():
        return {
            "services": [],
            "active_connections": [],
            "incoming_connections": [
                {
                    "state": "ESTAB",
                    "src_ip": "10.0.0.2",
                    "src_port": 443,
                    "dst_ip": "198.51.100.9",
                    "dst_port": 51234,
                    "service": "https",
                    "protocol": "tcp",
                    "raw": "x",
                }
            ],
            "globe_lines": ["mapa"],
            "actions": ["a"],
            "exposure_lines": ["e"],
            "service_versions": [
                {"service": "python", "active": True, "version": "Python 3.x", "status": "running"}
            ],
            "globe_points": [{"lat": 0.0, "lon": 0.0, "severity": 2}],
        }

    monkeypatch.setattr("sentinel_x_defense_suite.gui.main_window.build_runtime_snapshot", _fake_snapshot)
    win = MainWindow()
    win._refresh_runtime_watch()

    assert win.incoming_connections_list.count() == 1
    assert win.service_versions_list.count() == 1
    assert win.ops_tabs.count() == 4

    win.close()
    app.processEvents()
