import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from sentinel_x_defense_suite.gui.main_window import MainWindow


def test_sidebar_navigation_contains_all_modules_without_global_menu() -> None:
    app = QApplication.instance() or QApplication([])
    win = MainWindow()

    assert win.nav_list is not None
    modules = [win.nav_list.item(i).text() for i in range(win.nav_list.count())]
    assert modules == MainWindow.MODULES
    assert win.menuBar().actions() == []

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

    def _fake_incremental(previous_snapshot=None, include_service_versions=True):
        return {"full_snapshot": _fake_snapshot(), "incremental_snapshot": {"changed_sections": ["all"]}}

    monkeypatch.setattr("sentinel_x_defense_suite.gui.main_window.build_incremental_runtime_snapshot", _fake_incremental)
    win = MainWindow()
    win._refresh_runtime_watch()

    assert win.incoming_connections_list.count() == 1
    assert win.service_versions_list.count() == 1
    assert win.ops_tabs.count() == 5
    assert "Playbook" in [win.ops_tabs.tabText(i) for i in range(win.ops_tabs.count())]
    assert "Postura defensiva" in win.defense_status_label.text()

    win.close()
    app.processEvents()


def test_sidebar_selection_routes_across_all_modules() -> None:
    app = QApplication.instance() or QApplication([])
    win = MainWindow()

    for idx, module in enumerate(MainWindow.MODULES):
        win.nav_list.setCurrentRow(idx)
        assert win.router.current_route() == module

    win.close()
    app.processEvents()


def test_regression_rejects_reintroduced_global_menubar_actions() -> None:
    app = QApplication.instance() or QApplication([])
    win = MainWindow()

    assert len(win.menuBar().actions()) == 0

    win.close()
    app.processEvents()
