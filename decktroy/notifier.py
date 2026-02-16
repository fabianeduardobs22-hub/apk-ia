#!/usr/bin/env python3
"""DECKTROY notifier (defensive alert delivery)."""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def send_webhook(url: str, payload: dict[str, Any], timeout: int = 8) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body = resp.read().decode("utf-8", errors="ignore")
            return {"ok": True, "status": resp.status, "response": body[:500], "ts": utc_now()}
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": str(exc), "ts": utc_now()}
