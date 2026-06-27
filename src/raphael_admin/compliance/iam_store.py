"""Persisted IAM database for PII isolation and compliance holds."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from raphael_audit.core.paths import calliope_home
from raphael_audit.core.security.encryption import DataKeyManager


class IAMStore:
    """Postgres or SQLite-backed PII map and hold registry."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        encrypt: DataKeyManager | None = None,
    ) -> None:
        from raphael_contracts import db as rdb

        self._postgres = rdb.is_postgres()
        self._encrypt = encrypt or DataKeyManager(enabled=False)
        if self._postgres:
            rdb.ensure_migrations()
            self.db_path = Path("postgres")
            self._conn = None
        else:
            self.db_path = db_path or Path(
                os.environ.get("RAPHAEL_IAM_DB", str(calliope_home() / "iam.db"))
            )
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_schema_sqlite()

    def _pii_table(self) -> str:
        return "admin_pii_map" if self._postgres else "pii_map"

    def _hold_table(self) -> str:
        return "admin_hold_registry" if self._postgres else "hold_registry"

    def _init_schema_sqlite(self) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pii_map (
                opaque_id TEXT PRIMARY KEY,
                pii_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hold_registry (
                entity_id TEXT PRIMARY KEY,
                created_at_utc TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        if self._postgres:
            from raphael_contracts.db import pg_execute

            pg_execute(sql, params)
            return
        assert self._conn is not None
        self._conn.execute(sql, params)
        self._conn.commit()

    def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> Any | None:
        if self._postgres:
            from raphael_contracts.db import pg_fetchone

            return pg_fetchone(sql, params)
        assert self._conn is not None
        return self._conn.execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        if self._postgres:
            from raphael_contracts.db import pg_fetchall

            return pg_fetchall(sql, params)
        assert self._conn is not None
        return self._conn.execute(sql, params).fetchall()

    def store_pii(self, opaque_id: str, pii_data: dict[str, str], created_at_utc: str) -> None:
        payload = self._encrypt.encrypt(json.dumps(pii_data, separators=(",", ":")))
        table = self._pii_table()
        if self._postgres:
            from raphael_contracts.db import adapt_insert_or_replace

            sql = adapt_insert_or_replace(
                f"""
                INSERT OR REPLACE INTO {table} (opaque_id, pii_json, created_at_utc)
                VALUES (?, ?, ?)
                """,
                "opaque_id",
                "pii_json = EXCLUDED.pii_json, created_at_utc = EXCLUDED.created_at_utc",
            )
            self._execute(sql, (opaque_id, payload, created_at_utc))
        else:
            self._execute(
                f"INSERT OR REPLACE INTO {table} (opaque_id, pii_json, created_at_utc) VALUES (?, ?, ?)",
                (opaque_id, payload, created_at_utc),
            )

    def get_subject(self, opaque_id: str) -> dict[str, Any] | None:
        table = self._pii_table()
        row = self._fetchone(
            f"SELECT opaque_id, pii_json, created_at_utc FROM {table} WHERE opaque_id = ?",
            (opaque_id,),
        )
        if not row:
            return None
        if isinstance(row, dict):
            opaque = row["opaque_id"]
            pii_raw = row["pii_json"]
            created = row["created_at_utc"]
        else:
            opaque, pii_raw, created = row[0], row[1], row[2]
        pii = json.loads(self._encrypt.decrypt(pii_raw))
        return {
            "opaque_id": opaque,
            "status": pii.get("status", "active"),
            "created_at_utc": str(created),
            "has_hold": self.has_hold(opaque_id),
        }

    def anonymize(self, opaque_id: str) -> bool:
        table = self._pii_table()
        row = self._fetchone(f"SELECT 1 FROM {table} WHERE opaque_id = ?", (opaque_id,))
        if not row:
            return False
        payload = self._encrypt.encrypt(json.dumps({"status": "anonymized"}))
        self._execute(
            f"UPDATE {table} SET pii_json = ? WHERE opaque_id = ?",
            (payload, opaque_id),
        )
        return True

    def add_hold(self, entity_id: str, created_at_utc: str) -> None:
        table = self._hold_table()
        if self._postgres:
            from raphael_contracts.db import adapt_sql

            self._execute(
                adapt_sql(
                    f"INSERT OR IGNORE INTO {table} (entity_id, created_at_utc) VALUES (?, ?)"
                ),
                (entity_id, created_at_utc),
            )
        else:
            self._execute(
                f"INSERT OR IGNORE INTO {table} (entity_id, created_at_utc) VALUES (?, ?)",
                (entity_id, created_at_utc),
            )

    def has_hold(self, entity_id: str) -> bool:
        table = self._hold_table()
        row = self._fetchone(f"SELECT 1 FROM {table} WHERE entity_id = ?", (entity_id,))
        return row is not None

    def list_holds(self) -> list[dict[str, str]]:
        table = self._hold_table()
        rows = self._fetchall(
            f"SELECT entity_id, created_at_utc FROM {table} ORDER BY created_at_utc"
        )
        holds: list[dict[str, str]] = []
        for row in rows:
            if isinstance(row, dict):
                holds.append(
                    {"entity_id": row["entity_id"], "created_at": str(row["created_at_utc"])}
                )
            else:
                holds.append({"entity_id": row[0], "created_at": row[1]})
        return holds

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
