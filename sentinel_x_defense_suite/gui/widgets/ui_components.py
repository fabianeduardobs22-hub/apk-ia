from __future__ import annotations

from PyQt6.QtWidgets import (
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class RiskCard(QGroupBox):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(title, parent)
        self.setObjectName("riskCard")


class SeverityBadge(QLabel):
    def __init__(self, severity: str, parent: QWidget | None = None) -> None:
        super().__init__(severity.upper(), parent)
        self.setObjectName("severityBadge")
        self.setProperty("severity", severity.lower())


class MetricTile(QFrame):
    def __init__(self, label: str, value: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("metricTile")
        layout = QVBoxLayout(self)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        self.text_label = QLabel(label)
        self.text_label.setObjectName("metricLabel")
        layout.addWidget(self.value_label)
        layout.addWidget(self.text_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class TimelineRow:
    @staticmethod
    def append(table: QTableWidget, values: list[str]) -> None:
        row = table.rowCount()
        table.insertRow(row)
        for col, value in enumerate(values):
            table.setItem(row, col, QTableWidgetItem(value))


class ActionDrawer(QFrame):
    def __init__(self, title: str, actions: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("actionDrawer")
        layout = QVBoxLayout(self)
        header = QLabel(title)
        header.setObjectName("drawerTitle")
        layout.addWidget(header)
        self.buttons: list[QPushButton] = []
        for action in actions:
            button = QPushButton(action)
            button.setObjectName("drawerAction")
            self.buttons.append(button)
            layout.addWidget(button)
        layout.addStretch(1)

    def add_to_layout(self, layout: QHBoxLayout | QVBoxLayout) -> None:
        layout.addWidget(self)
