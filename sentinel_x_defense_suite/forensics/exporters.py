from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path


def export_alerts_json(db_path: str, output: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()]
    Path(output).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


def export_alerts_csv(db_path: str, output: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()]

    if not rows:
        Path(output).write_text("", encoding="utf-8")
        return

    with Path(output).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
