from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests


@dataclass(slots=True)
class ThreatIntelService:
    blacklist: set[str] = field(default_factory=set)
    whitelist: set[str] = field(default_factory=set)
    _last_call_ts: float = 0.0
    min_interval_s: float = 0.25

    def reputation(self, ip: str) -> dict[str, str | int]:
        if ip in self.whitelist:
            return {"reputation": "trusted", "score": 0}
        if ip in self.blacklist:
            return {"reputation": "known_bad", "score": 90}
        return {"reputation": "unknown", "score": 30}

    def geolocate(self, ip: str) -> dict[str, str]:
        now = time.time()
        if now - self._last_call_ts < self.min_interval_s:
            return {"country": "RATE_LIMITED", "city": "N/A"}
        self._last_call_ts = now
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
            data = response.json()
            return {
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
            }
        except Exception:
            return {"country": "Unknown", "city": "Unknown"}
