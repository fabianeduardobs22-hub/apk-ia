from collections import defaultdict
from typing import Any

from fastapi import WebSocket

connected_clients: dict[int, set[WebSocket]] = defaultdict(set)


async def connect(tenant_id: int, websocket: WebSocket):
    await websocket.accept()
    connected_clients[tenant_id].add(websocket)


def disconnect(tenant_id: int, websocket: WebSocket):
    connected_clients[tenant_id].discard(websocket)


async def notify_tenant(tenant_id: int, message: dict[str, Any]):
    stale = []
    for ws in connected_clients[tenant_id]:
        try:
            await ws.send_json(message)
        except Exception:
            stale.append(ws)
    for ws in stale:
        connected_clients[tenant_id].discard(ws)


async def notify_all(message: dict[str, Any]):
    for tenant_id in list(connected_clients.keys()):
        await notify_tenant(tenant_id, message)
