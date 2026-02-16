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
