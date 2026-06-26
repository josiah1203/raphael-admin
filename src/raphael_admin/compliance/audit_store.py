"""Append-only SQLite audit log for platform actions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from raphael_audit.core.paths import calliope_home
from raphael_audit.core.security.encryption import DataKeyManager
from raphael_audit.core.uuid7 import uuid7_str


def _entry_hash(entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


class AuditStore:
    """Persist audit entries alongside in-memory ComplianceManager."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        encrypted_at_rest: bool = False,
        data_key_path: Path | None = None,
    ) -> None:
        self.db_path = db_path or calliope_home() / "audit.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._encryption = DataKeyManager(enabled=encrypted_at_rest, key_path=data_key_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._last_entry_hash: str | None = None
        self._init_schema()
        self._hydrate_last_hash()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT,
                previous_entry_hash TEXT
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp_utc)"
        )
        self._ensure_previous_hash_column()
        self._conn.commit()

    def _ensure_previous_hash_column(self) -> None:
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(audit_log)")}
        if "previous_entry_hash" not in cols:
            self._conn.execute(
                "ALTER TABLE audit_log ADD COLUMN previous_entry_hash TEXT"
            )

    def _hydrate_last_hash(self) -> None:
        row = self._conn.execute(
            """
            SELECT entry_id, timestamp_utc, action, resource_id, actor, details, previous_entry_hash
            FROM audit_log ORDER BY timestamp_utc DESC LIMIT 1
            """
        ).fetchone()
        if not row:
            return
        entry = {
            "entry_id": row["entry_id"],
            "timestamp_utc": row["timestamp_utc"],
            "action": row["action"],
            "resource_id": row["resource_id"],
            "actor": row["actor"],
            "details": json.loads(self._encryption.decrypt(row["details"] or "{}")),
            "previous_entry_hash": row["previous_entry_hash"],
        }
        self._last_entry_hash = _entry_hash(entry)

    def append(self, action: str, resource_id: str, actor: str, details: dict[str, Any] | None = None) -> str:
        entry_id = uuid7_str()
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        details_raw = json.dumps(details or {})
        encrypted_details = self._encryption.encrypt(details_raw)
        entry = {
            "entry_id": entry_id,
            "timestamp_utc": ts,
            "action": action,
            "resource_id": resource_id,
            "actor": actor,
            "details": details or {},
            "previous_entry_hash": self._last_entry_hash,
        }
        current_hash = _entry_hash(entry)
        self._conn.execute(
            """
            INSERT INTO audit_log (entry_id, timestamp_utc, action, resource_id, actor, details, previous_entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (entry_id, ts, action, resource_id, actor, encrypted_details, self._last_entry_hash),
        )
        self._conn.commit()
        self._last_entry_hash = current_hash
        return entry_id

    def list_entries(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if since:
            rows = self._conn.execute(
                """
                SELECT entry_id, timestamp_utc, action, resource_id, actor, details, previous_entry_hash
                FROM audit_log WHERE timestamp_utc >= ? ORDER BY timestamp_utc DESC LIMIT ?
                """,
                (since, limit),
            )
        else:
            rows = self._conn.execute(
                """
                SELECT entry_id, timestamp_utc, action, resource_id, actor, details, previous_entry_hash
                FROM audit_log ORDER BY timestamp_utc DESC LIMIT ?
                """,
                (limit,),
            )
        return [
            {
                "entry_id": r["entry_id"],
                "timestamp_utc": r["timestamp_utc"],
                "action": r["action"],
                "resource_id": r["resource_id"],
                "actor": r["actor"],
                "details": json.loads(self._encryption.decrypt(r["details"] or "{}")),
                "previous_entry_hash": r["previous_entry_hash"],
            }
            for r in rows
        ]

    def verify_chain(self) -> dict[str, Any]:
        rows = self._conn.execute(
            """
            SELECT entry_id, timestamp_utc, action, resource_id, actor, details, previous_entry_hash
            FROM audit_log ORDER BY timestamp_utc ASC
            """
        )
        previous_hash: str | None = None
        failures: list[str] = []
        checked = 0
        for row in rows:
            entry = {
                "entry_id": row["entry_id"],
                "timestamp_utc": row["timestamp_utc"],
                "action": row["action"],
                "resource_id": row["resource_id"],
                "actor": row["actor"],
                "details": json.loads(self._encryption.decrypt(row["details"] or "{}")),
                "previous_entry_hash": previous_hash,
            }
            if row["previous_entry_hash"] != previous_hash:
                failures.append(row["entry_id"])
            previous_hash = _entry_hash(entry)
            checked += 1
        return {"valid": len(failures) == 0, "entries_checked": checked, "failures": failures}

    def close(self) -> None:
        self._conn.close()
