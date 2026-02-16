from __future__ import annotations

from dataclasses import dataclass
import importlib
from typing import Any


@dataclass(frozen=True, slots=True)
class RouteEntry:
    route_id: str
    sidebar_label: str
    search_terms: tuple[str, ...]
    module_path: str
    class_name: str


class GuiRouter:
    def __init__(self, routes: list[RouteEntry]) -> None:
        self._routes = routes
        self._cache: dict[str, Any] = {}

    @property
    def routes(self) -> list[RouteEntry]:
        return self._routes

    def route_for_query(self, query: str) -> RouteEntry | None:
        token = query.lower().strip()
        if not token:
            return None
        for route in self._routes:
            haystack = " ".join((route.route_id, route.sidebar_label, *route.search_terms)).lower()
            if token in haystack:
                return route
        return None

    def build_page(self, route_id: str) -> Any:
        if route_id in self._cache:
            return self._cache[route_id]

        route = next((item for item in self._routes if item.route_id == route_id), None)
        if route is None:
            raise KeyError(f"Unknown route: {route_id}")

        module = importlib.import_module(route.module_path)
        page_cls = getattr(module, route.class_name)
        page = page_cls()
        self._cache[route_id] = page
        return page
