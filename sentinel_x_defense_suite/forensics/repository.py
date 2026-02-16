from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from sentinel_x_defense_suite.models.events import DetectionAlert, PacketRecord


class ForensicsRepository:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS packet_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    length INTEGER NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    details TEXT NOT NULL,
                    prev_hash TEXT,
                    record_hash TEXT NOT NULL
                )
                """
            )

    def save_packet(self, packet: PacketRecord) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO packet_log (ts, src_ip, dst_ip, src_port, dst_port, protocol, length, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.timestamp.isoformat(),
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                    packet.length,
                    json.dumps(packet.metadata, ensure_ascii=False),
                ),
            )

    def save_alert(self, alert: DetectionAlert) -> None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT record_hash FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = row[0] if row else ""
            raw = f"{alert.timestamp.isoformat()}|{alert.rule_id}|{alert.src_ip}|{alert.dst_ip}|{prev_hash}"
            record_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            conn.execute(
                """
                INSERT INTO alerts (ts, rule_id, title, severity, src_ip, dst_ip, confidence, details, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp.isoformat(),
                    alert.rule_id,
                    alert.title,
                    alert.severity,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.confidence,
                    json.dumps(alert.details, ensure_ascii=False),
                    prev_hash,
                    record_hash,
                ),
            )

    def export_json(self) -> list[dict[str, str]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()
            return [dict(row) for row in rows]
