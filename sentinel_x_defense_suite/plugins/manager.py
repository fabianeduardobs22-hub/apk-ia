from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
from json import JSONDecodeError
from pathlib import Path
from typing import Protocol

from sentinel_x_defense_suite.models.events import PacketRecord

logger = logging.getLogger(__name__)


class PacketPlugin(Protocol):
    name: str

    def on_packet(self, packet: PacketRecord) -> None: ...


class PluginManager:
    def __init__(
        self,
        plugins_dir: str,
        allowlist_manifest_path: str | Path | None = None,
        dynamic_plugins_enabled: bool = True,
    ) -> None:
        self.plugins_dir = Path(plugins_dir)
        self.allowlist_manifest_path = Path(allowlist_manifest_path) if allowlist_manifest_path else self.plugins_dir / "allowlist.json"
        self.dynamic_plugins_enabled = dynamic_plugins_enabled
        self.plugins: list[PacketPlugin] = []

    def _read_allowlist(self) -> dict[str, str]:
        if not self.allowlist_manifest_path.exists():
            return {}
        try:
            content = json.loads(self.allowlist_manifest_path.read_text(encoding="utf-8"))
        except JSONDecodeError:
            self._log_security_event("plugin_load_blocked", self.allowlist_manifest_path, "invalid_allowlist_manifest")
            return {}
        if not isinstance(content, dict):
            return {}
        normalized: dict[str, str] = {}
        for file_name, sha256 in content.items():
            if not isinstance(file_name, str) or not isinstance(sha256, str):
                continue
            normalized[file_name] = sha256.lower()
        return normalized

    @staticmethod
    def _sha256_for_file(path: Path) -> str:
        digest = hashlib.sha256()
        digest.update(path.read_bytes())
        return digest.hexdigest()

    def _log_security_event(self, action: str, plugin: Path, reason: str, expected_hash: str | None = None, actual_hash: str | None = None) -> None:
        logger.warning(
            "SECURITY_EVENT action=%s plugin=%s reason=%s expected_sha256=%s actual_sha256=%s",
            action,
            plugin.name,
            reason,
            expected_hash or "-",
            actual_hash or "-",
        )

    def load(self) -> None:
        self.plugins.clear()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        if not self.dynamic_plugins_enabled:
            self._log_security_event("plugin_load_blocked", self.plugins_dir / "*", "dynamic_plugins_disabled")
            return

        allowlist = self._read_allowlist()
        for py_file in self.plugins_dir.glob("*.py"):
            expected_hash = allowlist.get(py_file.name)
            actual_hash = self._sha256_for_file(py_file)
            if expected_hash is None:
                self._log_security_event(
                    "plugin_load_rejected",
                    py_file,
                    "plugin_not_allowlisted",
                    actual_hash=actual_hash,
                )
                continue
            if actual_hash != expected_hash:
                self._log_security_event(
                    "plugin_load_rejected",
                    py_file,
                    "plugin_hash_mismatch",
                    expected_hash=expected_hash,
                    actual_hash=actual_hash,
                )
                continue

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
