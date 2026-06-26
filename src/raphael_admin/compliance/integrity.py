"""Event integrity hash chain verification."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_event_hash(event: dict[str, Any]) -> str:
    event_copy = dict(event)
    event_copy.pop("integrity_chain", None)
    payload = json.dumps(event_copy, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def compute_integrity_link(event: dict[str, Any], previous_hash: str | None) -> tuple[str, str]:
    """Return (integrity_chain link hash, current event hash)."""
    current_hash = compute_event_hash(event)
    chain_link = {
        "current_hash": current_hash,
        "previous_hash": previous_hash,
    }
    link_hash = hashlib.sha256(json.dumps(chain_link, sort_keys=True).encode()).hexdigest()
    return link_hash, current_hash


def verify_integrity_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute hash chain and compare to stored integrity_chain values."""
    previous_hash: str | None = None
    verified = 0
    failures: list[str] = []

    for event in events:
        expected_link, current_hash = compute_integrity_link(event, previous_hash)
        stored = event.get("integrity_chain")
        if stored and stored != expected_link:
            failures.append(event.get("event_id", "unknown"))
        elif stored:
            verified += 1
        previous_hash = current_hash

    return {
        "valid": len(failures) == 0,
        "events_checked": len(events),
        "events_with_chain": sum(1 for e in events if e.get("integrity_chain")),
        "verified_links": verified,
        "failures": failures,
    }
