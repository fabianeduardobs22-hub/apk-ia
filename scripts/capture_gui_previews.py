from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox

from sentinel_x_defense_suite.gui.main_window import MainWindow


OUT_DIR = Path("artifacts/gui_previews")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def save_widget(widget, name: str) -> None:
    pix = widget.grab()
    pix.save(str(OUT_DIR / name), "PNG")


def main() -> int:
    app = QApplication([])
    win = MainWindow()
    win.show()
    app.processEvents()

    # Runtime data is loaded automatically from real host sockets/connections

    save_widget(win, "00_main_dashboard.png")

    # Menus
    menu_map = {
        "01_menu_archivo.png": win.menuBar().actions()[0].menu(),
        "02_menu_vista.png": win.menuBar().actions()[1].menu(),
        "03_menu_herramientas.png": win.menuBar().actions()[2].menu(),
        "04_menu_ayuda.png": win.menuBar().actions()[3].menu(),
    }

    for filename, menu in menu_map.items():
        if menu is None:
            continue
        menu.popup(win.menuBar().mapToGlobal(win.menuBar().rect().bottomLeft()))
        app.processEvents()
        save_widget(menu, filename)
        menu.hide()
        app.processEvents()

    # Tabs / inspectors
    # explicit captures from known widgets
    save_widget(win.packet_inspector, "05_tab_inspector_paquete.png")
    save_widget(win.anomaly_inspector, "06_tab_anomalias_riesgo.png")
    save_widget(win.response_inspector, "07_tab_respuesta_defensiva.png")
    save_widget(win.timeline_tab, "08_tab_timeline.png")
    save_widget(win.capability_tab, "09_tab_benchmark.png")
    save_widget(win.mission_tab, "10_tab_mission_control.png")

    # Open dialogs and capture
    QTimer.singleShot(10, lambda: save_active_modal("11_dialog_exportacion.png"))
    win._show_export_summary_popup()

    QTimer.singleShot(10, lambda: save_active_modal("12_dialog_acerca_de.png"))
    win._show_about_popup()

    QTimer.singleShot(10, lambda: save_active_modal("13_dialog_preferencias_vista.png"))
    win._show_view_options_popup()

    QTimer.singleShot(10, lambda: save_active_modal("14_dialog_configuracion_rapida.png"))
    win._show_runtime_settings_popup()

    save_widget(win.services_text, "15_panel_servicios_expuestos.png")
    save_widget(win.connections_text, "16_panel_conexiones_activas.png")
    save_widget(win.globe_text, "17_panel_globo_ataques.png")
    save_widget(win.exposure_text, "18_panel_superficie_expuesta.png")
    save_widget(win.actions_text, "19_panel_respuesta_rapida.png")

    win.close()
    app.processEvents()
    return 0


def save_active_modal(filename: str) -> None:
    app = QApplication.instance()
    if app is None:
        return
    widget = app.activeModalWidget()
    if widget is None:
        # fallback to active window
        widget = app.activeWindow()
    if widget is not None:
        save_widget(widget, filename)
        if isinstance(widget, QMessageBox):
            widget.accept()
        else:
            try:
                widget.accept()  # type: ignore[attr-defined]
            except Exception:
                widget.close()


if __name__ == "__main__":
    raise SystemExit(main())
