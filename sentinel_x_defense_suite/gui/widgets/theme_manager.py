from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication

from sentinel_x_defense_suite.gui.widgets.visual_tokens import TOKENS, VisualTokens


@dataclass(frozen=True, slots=True)
class PremiumTheme:
    key: str
    name: str
    token_key: str
    density: int


THEMES = {
    "dark_premium": PremiumTheme(
        key="dark_premium",
        name="Dark Premium",
        token_key="dark_premium",
        density=6,
    ),
    "high_contrast": PremiumTheme(
        key="high_contrast",
        name="High Contrast",
        token_key="high_contrast",
        density=4,
    ),
}


def _build_stylesheet(tokens: VisualTokens) -> str:
    return f"""
    QWidget {{
        background-color: {tokens.background};
        color: {tokens.text};
        selection-background-color: {tokens.surface_selected};
        selection-color: {tokens.text};
    }}
    QGroupBox#riskCard, QGroupBox {{
        border: 1px solid {tokens.border};
        border-radius: {tokens.radius.lg}px;
        margin-top: {tokens.spacing.sm}px;
        font-weight: 600;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: {tokens.spacing.sm}px;
        padding: 0 {tokens.spacing.xs}px;
    }}
    QPushButton {{
        background: {tokens.primary};
        border: 1px solid {tokens.primary};
        border-radius: {tokens.radius.md}px;
        padding: {tokens.spacing.xs}px {tokens.spacing.md}px;
        font-weight: 700;
        color: {tokens.text_on_primary};
    }}
    QPushButton:hover {{ background: {tokens.primary_hover}; }}
    QPushButton:focus {{ border: 2px solid {tokens.border_focus}; }}
    QPushButton:pressed {{ background: {tokens.surface_selected}; color: {tokens.text}; }}
    QPushButton:disabled {{ background: {tokens.primary_disabled}; border-color: {tokens.primary_disabled}; color: {tokens.disabled}; }}
    QListWidget::item:hover, QTableWidget::item:hover {{ background: {tokens.surface_hover}; }}
    QListWidget::item:selected, QTableWidget::item:selected {{ background: {tokens.surface_selected}; }}
    QLineEdit, QListWidget, QTableWidget, QComboBox, QTabWidget::pane, QMenu {{
        background-color: {tokens.background_alt};
        border: 1px solid {tokens.border};
        border-radius: {tokens.radius.md}px;
    }}
    QLineEdit:focus, QListWidget:focus, QTableWidget:focus, QComboBox:focus {{ border: 2px solid {tokens.border_focus}; }}
    QLabel#statusBadge {{
        background: {tokens.surface};
        border-radius: {tokens.radius.lg}px;
        border: 1px solid {tokens.border};
        padding: {tokens.spacing.xs}px {tokens.spacing.sm}px;
        color: {tokens.text};
    }}
    QLabel#severityBadge[severity="low"] {{ background: {tokens.severity.low}; color: #08120b; border-radius: {tokens.radius.md}px; padding: 2px 8px; }}
    QLabel#severityBadge[severity="medium"] {{ background: {tokens.severity.medium}; color: #2a2200; border-radius: {tokens.radius.md}px; padding: 2px 8px; }}
    QLabel#severityBadge[severity="high"] {{ background: {tokens.severity.high}; color: #2b0f00; border-radius: {tokens.radius.md}px; padding: 2px 8px; }}
    QLabel#severityBadge[severity="critical"] {{ background: {tokens.severity.critical}; color: #ffffff; border-radius: {tokens.radius.md}px; padding: 2px 8px; }}
    QFrame#metricTile, QFrame#actionDrawer {{
        background: {tokens.surface};
        border: 1px solid {tokens.border};
        border-radius: {tokens.radius.lg}px;
        padding: {tokens.spacing.sm}px;
    }}
    QLabel#metricValue {{ font-size: {tokens.fonts.size_title + 2}pt; font-weight: 800; }}
    QLabel#metricLabel {{ color: {tokens.text_muted}; font-size: {tokens.fonts.size_small}pt; }}
    QLabel#drawerTitle {{ font-size: {tokens.fonts.size_title}pt; font-weight: 700; }}
    QPushButton#drawerAction {{ margin-top: {tokens.spacing.xs}px; }}
    QWidget#moduleShortcuts {{
        background: transparent;
    }}
    QWidget#moduleShortcuts QToolButton {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {tokens.surface}, stop:1 {tokens.background_alt});
        border: 1px solid {tokens.border};
        border-radius: {tokens.radius.lg}px;
        padding: {tokens.spacing.sm}px;
        min-width: 140px;
        font-weight: 700;
    }}
    QWidget#moduleShortcuts QToolButton:hover {{
        border-color: {tokens.border_focus};
        background: {tokens.surface_hover};
    }}
    QLabel#summaryValue {{ font-size: {tokens.fonts.size_title}pt; font-weight: 700; }}
    """


def apply_theme(app: QApplication, theme_key: str) -> str:
    theme = THEMES.get(theme_key, THEMES["dark_premium"])
    tokens = TOKENS[theme.token_key]
    app.setStyleSheet(_build_stylesheet(tokens))
    app.setFont(QFont(tokens.fonts.family, tokens.fonts.size_base))
    return theme.key
