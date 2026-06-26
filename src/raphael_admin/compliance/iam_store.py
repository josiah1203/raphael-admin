"""Persisted IAM database for PII isolation and compliance holds."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from raphael_audit.core.paths import calliope_home
from raphael_audit.core.security.encryption import DataKeyManager


class IAMStore:
    """SQLite-backed PII map and hold registry."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        encrypt: DataKeyManager | None = None,
    ) -> None:
        self.db_path = db_path or calliope_home() / "iam.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._encrypt = encrypt or DataKeyManager(enabled=False)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
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

    def store_pii(self, opaque_id: str, pii_data: dict[str, str], created_at_utc: str) -> None:
        payload = self._encrypt.encrypt(json.dumps(pii_data, separators=(",", ":")))
        self._conn.execute(
            "INSERT OR REPLACE INTO pii_map (opaque_id, pii_json, created_at_utc) VALUES (?, ?, ?)",
            (opaque_id, payload, created_at_utc),
        )
        self._conn.commit()

    def get_subject(self, opaque_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT opaque_id, pii_json, created_at_utc FROM pii_map WHERE opaque_id = ?",
            (opaque_id,),
        ).fetchone()
        if not row:
            return None
        pii = json.loads(self._encrypt.decrypt(row["pii_json"]))
        return {
            "opaque_id": row["opaque_id"],
            "status": pii.get("status", "active"),
            "created_at_utc": row["created_at_utc"],
            "has_hold": self.has_hold(opaque_id),
        }

    def anonymize(self, opaque_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM pii_map WHERE opaque_id = ?", (opaque_id,)
        ).fetchone()
        if not row:
            return False
        payload = self._encrypt.encrypt(json.dumps({"status": "anonymized"}))
        self._conn.execute(
            "UPDATE pii_map SET pii_json = ? WHERE opaque_id = ?",
            (payload, opaque_id),
        )
        self._conn.commit()
        return True

    def add_hold(self, entity_id: str, created_at_utc: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO hold_registry (entity_id, created_at_utc) VALUES (?, ?)",
            (entity_id, created_at_utc),
        )
        self._conn.commit()

    def has_hold(self, entity_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM hold_registry WHERE entity_id = ?", (entity_id,)
        ).fetchone()
        return row is not None

    def close(self) -> None:
        self._conn.close()
