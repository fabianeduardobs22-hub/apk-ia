from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Protocol

from sentinel_x_defense_suite.models.events import PacketRecord


class PacketPlugin(Protocol):
    name: str

    def on_packet(self, packet: PacketRecord) -> None: ...


class PluginManager:
    def __init__(self, plugins_dir: str) -> None:
        self.plugins_dir = Path(plugins_dir)
        self.plugins: list[PacketPlugin] = []

    def load(self) -> None:
        self.plugins.clear()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        for py_file in self.plugins_dir.glob("*.py"):
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin_cls = getattr(module, "Plugin", None)
            if plugin_cls:
                self.plugins.append(plugin_cls())

    def dispatch_packet(self, packet: PacketRecord) -> None:
        for plugin in self.plugins:
            plugin.on_packet(packet)
