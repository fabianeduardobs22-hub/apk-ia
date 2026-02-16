from __future__ import annotations

from typing import Any


class ServiceContainer:
    """Contenedor simple de dependencias para desacoplar módulos."""

    def __init__(self) -> None:
        self._services: dict[str, Any] = {}

    def register(self, name: str, service: Any) -> None:
        if name in self._services:
            raise KeyError(f"Servicio duplicado: {name}")
        self._services[name] = service

    def get(self, name: str) -> Any:
        if name not in self._services:
            raise KeyError(f"Servicio no encontrado: {name}")
        return self._services[name]
