"""Admin API — compliance, billing hooks."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter

router = APIRouter(tags=["admin"])


@router.get("")
def admin_status() -> dict[str, str]:
    return {"service": "raphael-admin", "status": "ok"}


@router.get("/billing")
def billing_status() -> dict[str, Any]:
    stripe_key = os.environ.get("RAPHAEL_STRIPE_SECRET_KEY", "")
    metronome_key = os.environ.get("RAPHAEL_METRONOME_API_KEY", "")
    return {
        "stripe_configured": bool(stripe_key),
        "metronome_configured": bool(metronome_key),
        "plan": "team",
    }


@router.post("/gdpr-delete")
def gdpr_delete(body: dict[str, Any]) -> dict[str, str]:
    return {"status": "scheduled", "subject_id": body.get("subject_id", "")}


@router.get("/subjects/{subject_id}")
def get_subject(subject_id: str) -> dict[str, Any]:
    return {"subject_id": subject_id, "pii_fields": [], "holds": []}
