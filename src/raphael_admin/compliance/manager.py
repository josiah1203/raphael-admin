"""Compliance, Privacy & Integrity."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from raphael_admin.compliance.iam_store import IAMStore
from raphael_admin.compliance.integrity import compute_integrity_link
from raphael_audit.core.uuid7 import uuid7_str

logger = logging.getLogger(__name__)


class ComplianceManager:
    """Manages PII isolation, GDPR, and Audit Chains."""

    def __init__(self, iam_store: IAMStore | None = None) -> None:
        self._iam_store = iam_store
        self._iam_pii_map: dict[str, dict[str, str]] = {}
        self._hold_registry: set[str] = set()
        self._last_event_hash: str | None = None

    def isolate_pii(self, user_id: str, pii_data: dict[str, str]) -> str:
        """Decouple identity layer: Map UUID to PII in isolated IAM database."""
        opaque_id = uuid7_str()
        if self._iam_store:
            ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self._iam_store.store_pii(opaque_id, pii_data, ts)
        else:
            self._iam_pii_map[opaque_id] = pii_data
        return opaque_id

    def gdpr_delete(self, opaque_id: str) -> bool:
        """GDPR: Implement deletion workflow (Anonymize IAM mapping)."""
        if self._has_hold(opaque_id):
            logger.warning("Cannot delete %s: Active compliance hold", opaque_id)
            return False

        if self._iam_store:
            return self._iam_store.anonymize(opaque_id)

        if opaque_id in self._iam_pii_map:
            self._iam_pii_map[opaque_id] = {"status": "anonymized"}
            return True
        return False

    def set_compliance_hold(self, entity_id: str) -> None:
        """Build Append-only Hold Registry for compliance holds."""
        if self._iam_store:
            ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self._iam_store.add_hold(entity_id, ts)
        self._hold_registry.add(entity_id)

    def get_subject(self, opaque_id: str) -> dict[str, Any] | None:
        if self._iam_store:
            return self._iam_store.get_subject(opaque_id)
        if opaque_id not in self._iam_pii_map:
            return None
        return {
            "opaque_id": opaque_id,
            "status": self._iam_pii_map[opaque_id].get("status", "active"),
            "has_hold": self._has_hold(opaque_id),
        }

    def _has_hold(self, entity_id: str) -> bool:
        if self._iam_store and self._iam_store.has_hold(entity_id):
            return True
        return entity_id in self._hold_registry

    def compute_integrity_link(self, event: dict[str, Any]) -> str:
        """Implement cryptographic hash chain (event N contains hash of N-1)."""
        link, current_hash = compute_integrity_link(event, self._last_event_hash)
        self._last_event_hash = current_hash
        return link

    def set_last_event_hash(self, last_hash: str | None) -> None:
        self._last_event_hash = last_hash

    def record_action(self, action: str, resource_id: str, actor: str) -> None:
        """Append audit log entry for platform actions."""
        logger.info("audit: %s %s by %s", action, resource_id, actor)


def filter_assertions(graph_nodes: list[dict[str, Any]], assertion_type: str) -> list[dict[str, Any]]:
    """Enable filtering Knowledge Graph by assertion type (Human vs. AI)."""
    return [node for node in graph_nodes if node.get("assertion_source") == assertion_type]
