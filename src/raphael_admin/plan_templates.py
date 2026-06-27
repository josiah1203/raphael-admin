"""Plan template catalog — Postgres or SQLite."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any


class PlanTemplateStore:
    def __init__(self, db_path: Path | None = None) -> None:
        from raphael_contracts import db as rdb

        self._postgres = rdb.is_postgres()
        if self._postgres:
            rdb.ensure_migrations()
        else:
            path = db_path or Path(os.environ.get("RAPHAEL_ADMIN_DB", "/tmp/raphael-admin-billing.db"))
            self.db_path = path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS plan_templates (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        seats INTEGER NOT NULL,
                        stripe_price_id TEXT,
                        sort_order INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO plan_templates (id, name, seats, sort_order)
                    VALUES ('team', 'Team', 25, 1), ('enterprise', 'Enterprise', -1, 2)
                    """
                )

    def list_templates(self) -> list[dict[str, Any]]:
        if self._postgres:
            from raphael_contracts import db as rdb

            rows = rdb.pg_fetchall(
                "SELECT id, name, seats, stripe_price_id, sort_order "
                "FROM admin_plan_templates ORDER BY sort_order, id"
            )
        else:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT id, name, seats, stripe_price_id, sort_order "
                    "FROM plan_templates ORDER BY sort_order, id"
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: Any) -> dict[str, Any]:
        if isinstance(row, dict):
            return {
                "id": row["id"],
                "name": row["name"],
                "seats": row["seats"],
                "stripe_price_id": row.get("stripe_price_id"),
            }
        return {
            "id": row[0],
            "name": row[1],
            "seats": row[2],
            "stripe_price_id": row[3],
        }
