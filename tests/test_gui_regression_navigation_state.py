import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication

from sentinel_x_defense_suite.gui.main_window import MainWindow


def _patch_runtime_snapshot(monkeypatch) -> None:
    def _fake_incremental(previous_snapshot=None, include_service_versions=True):
        return {
            "full_snapshot": {
                "services": [],
                "incoming_connections": [],
                "service_versions": [],
                "globe_points": [],
                "actions": [],
                "exposure_lines": [],
                "active_connections": [],
                "remote_suspicious": [],
            },
            "incremental_snapshot": {"changed_sections": []},
        }

    monkeypatch.setattr(
        "sentinel_x_defense_suite.gui.main_window.build_incremental_runtime_snapshot",
        _fake_incremental,
    )


def test_navigation_history_back_and_forward(monkeypatch) -> None:
    _patch_runtime_snapshot(monkeypatch)
    app = QApplication.instance() or QApplication([])
    win = MainWindow()
    win._runtime_timer.stop()

    win.nav_list.setCurrentRow(1)
    win.nav_list.setCurrentRow(2)

    assert win.router.current_route() == "Incident Response"
    assert win.btn_back.isEnabled()

    win._go_back()
    assert win.router.current_route() == "Threat Hunting"
    assert win.btn_forward.isEnabled()

    win._go_forward()
    assert win.router.current_route() == "Incident Response"

    win.close()
    app.processEvents()


def test_persistent_state_restores_last_module_and_tab(monkeypatch, tmp_path) -> None:
    _patch_runtime_snapshot(monkeypatch)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)

    app = QApplication.instance() or QApplication([])

    first = MainWindow()
    first._runtime_timer.stop()
    first.details_tabs.setCurrentIndex(2)
    first.search_input.setText("dns beacon")
    first.nav_list.setCurrentRow(3)
    first.settings.sync()
    first.close()
    app.processEvents()

    second = MainWindow()
    second._runtime_timer.stop()

    assert second.router.current_route() == "Forensics Timeline"
    assert second.details_tabs.currentIndex() == 2
    assert second.search_input.text() == "dns beacon"

    second.close()
    app.processEvents()


def test_critical_soc_components_render_structure(monkeypatch) -> None:
    _patch_runtime_snapshot(monkeypatch)
    app = QApplication.instance() or QApplication([])

    win = MainWindow()
    win._runtime_timer.stop()

    assert win.table.columnCount() == 7
    assert win.details_tabs.count() == 4
    assert win.ops_tabs.count() == 3
    assert win.context_tabs.count() == 3

    expected_workspace_tabs = {
        "Inspector de paquete",
        "Anomalías y riesgo",
        "Respuesta defensiva",
        "Timeline",
    }
    rendered_workspace_tabs = {win.details_tabs.tabText(i) for i in range(win.details_tabs.count())}
    assert expected_workspace_tabs.issubset(rendered_workspace_tabs)

    win.close()
    app.processEvents()
