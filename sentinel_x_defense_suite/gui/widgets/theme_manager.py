from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication


@dataclass(frozen=True, slots=True)
class PremiumTheme:
    key: str
    name: str
    style: str
    font_family: str
    density: int


THEMES = {
    "midnight": PremiumTheme(
        key="midnight",
        name="Midnight Ops",
        font_family="Segoe UI",
        density=6,
        style="""
        QWidget { background-color: #0b1118; color: #ecf4ff; }
        QGroupBox { border: 1px solid #23384c; border-radius: 10px; margin-top: 8px; font-weight: 600; }
        QPushButton { background: #1f6feb; border-radius: 6px; padding: 6px 12px; font-weight: 700; color: white; }
        QLineEdit, QListWidget, QTableWidget, QComboBox { background-color: #0f1a25; border: 1px solid #2d475f; border-radius: 6px; }
        QLabel#statusBadge { background: #183049; border-radius: 10px; padding: 5px 10px; color: #d4e9ff; }
        """,
    ),
    "graphite": PremiumTheme(
        key="graphite",
        name="Graphite Analyst",
        font_family="Inter",
        density=4,
        style="""
        QWidget { background-color: #151618; color: #f5f6f7; }
        QGroupBox { border: 1px solid #36393f; border-radius: 8px; margin-top: 8px; }
        QPushButton { background: #5964f2; border-radius: 4px; padding: 4px 10px; color: white; }
        QLineEdit, QListWidget, QTableWidget, QComboBox { background-color: #202226; border: 1px solid #3a3e44; border-radius: 5px; }
        QLabel#statusBadge { background: #2b2e35; border-radius: 8px; padding: 4px 8px; color: #f0f3f8; }
        """,
    ),
}


def apply_theme(app: QApplication, theme_key: str) -> str:
    theme = THEMES.get(theme_key, THEMES["midnight"])
    app.setStyleSheet(theme.style)
    app.setFont(QFont(theme.font_family, 10))
    return theme.key
